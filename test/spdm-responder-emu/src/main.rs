// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use log::LevelFilter;
use simple_logger::SimpleLogger;
use spdmlib::common::SpdmOpaqueSupport;
use spdmlib::common::{DMTF_SECURE_SPDM_VERSION_10, DMTF_SECURE_SPDM_VERSION_11};

use std::net::{TcpListener, TcpStream};
use std::u32;

use codec::{Codec, Reader, Writer};
use common::SpdmTransportEncap;
use common::ST1;
use mctp_transport::MctpTransportEncap;
use pcidoe_transport::{
    PciDoeDataObjectType, PciDoeMessageHeader, PciDoeTransportEncap, PciDoeVendorId,
};
use spdm_emu::crypto_callback::SECRET_ASYM_IMPL_INSTANCE;
use spdm_emu::socket_io_transport::SocketIoTransport;
use spdm_emu::spdm_emu::*;
use spdm_emu::{secret_impl_sample::*, EMU_STACK_SIZE};
use spdmlib::{common, config, protocol::*, responder};

use spin::Mutex;
extern crate alloc;
use alloc::sync::Arc;
use core::ops::DerefMut;

async fn process_socket_message(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    buffer: Arc<[u8]>,
) -> bool {
    if buffer.len() < SOCKET_HEADER_LEN {
        return false;
    }
    let mut reader = Reader::init(&buffer[..SOCKET_HEADER_LEN]);
    let socket_header = SpdmSocketHeader::read(&mut reader).unwrap();

    let res = (
        socket_header.transport_type.to_be(),
        socket_header.command.to_be(),
        &buffer[SOCKET_HEADER_LEN..],
    );

    match socket_header.command.to_be() {
        SOCKET_SPDM_COMMAND_TEST => {
            send_hello(stream.clone(), transport_encap.clone(), res.0).await;
            true
        }
        SOCKET_SPDM_COMMAND_STOP => {
            send_stop(stream.clone(), transport_encap.clone(), res.0).await;
            false
        }
        SOCKET_SPDM_COMMAND_NORMAL => true,
        _ => {
            if USE_PCIDOE {
                send_pci_discovery(stream.clone(), transport_encap.clone(), res.0, buffer).await
            } else {
                send_unknown(stream, transport_encap, res.0).await;
                false
            }
        }
    }
}

// A new logger enables the user to choose log level by setting a `SPDM_LOG` environment variable.
// Use the `Trace` level by default.
fn new_logger_from_env() -> SimpleLogger {
    let level = match std::env::var("SPDM_LOG") {
        Ok(x) => match x.to_lowercase().as_str() {
            "trace" => LevelFilter::Trace,
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            _ => LevelFilter::Error,
        },
        _ => LevelFilter::Trace,
    };

    SimpleLogger::new().with_utc_timestamps().with_level(level)
}

fn emu_main() {
    new_logger_from_env().init().unwrap();

    #[cfg(feature = "spdm-mbedtls")]
    spdm_emu::crypto::crypto_mbedtls_register_handles();

    spdmlib::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
    spdmlib::secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

    let listener = TcpListener::bind("127.0.0.1:2323").expect("Couldn't bind to the server");
    println!("server start!");

    let pcidoe_transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync)>> =
        Arc::new(Mutex::new(PciDoeTransportEncap {}));
    let mctp_transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync)>> =
        Arc::new(Mutex::new(MctpTransportEncap {}));

    // Create the runtime
    let rt = tokio::runtime::Runtime::new().unwrap();

    for stream in listener.incoming() {
        let stream = stream.expect("Read stream error!");
        let stream = Arc::new(Mutex::new(stream));
        println!("new connection!");
        let mut need_continue;
        loop {
            let res = rt.block_on(handle_message(
                stream.clone(),
                if USE_PCIDOE {
                    pcidoe_transport_encap.clone()
                } else {
                    mctp_transport_encap.clone()
                },
            ));

            match res {
                Ok(_spdm_result) => {
                    need_continue = true;
                }
                Err((_used, buffer)) => {
                    let buffer = Arc::new(buffer);
                    need_continue = rt.block_on(process_socket_message(
                        stream.clone(),
                        if USE_PCIDOE {
                            pcidoe_transport_encap.clone()
                        } else {
                            mctp_transport_encap.clone()
                        },
                        buffer,
                    ));
                }
            }
            if !need_continue {
                // TBD: return or break??
                return;
            }
        }
    }
}

async fn handle_message(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
) -> Result<bool, (usize, [u8; config::RECEIVER_BUFFER_SIZE])> {
    println!("handle_message!");
    let socket_io_transport = SocketIoTransport::new(stream);
    let socket_io_transport = Arc::new(Mutex::new(socket_io_transport));
    let rsp_capabilities = SpdmResponseCapabilityFlags::CERT_CAP
        | SpdmResponseCapabilityFlags::CHAL_CAP
        | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
        | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
        | SpdmResponseCapabilityFlags::ENCRYPT_CAP
        | SpdmResponseCapabilityFlags::MAC_CAP
        | SpdmResponseCapabilityFlags::KEY_EX_CAP
        | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
        | SpdmResponseCapabilityFlags::ENCAP_CAP
        | SpdmResponseCapabilityFlags::HBEAT_CAP
        | SpdmResponseCapabilityFlags::KEY_UPD_CAP;
    // | SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
    // | SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP
    let rsp_capabilities = if cfg!(feature = "mut-auth") {
        rsp_capabilities | SpdmResponseCapabilityFlags::MUT_AUTH_CAP
    } else {
        rsp_capabilities
    };

    let config_info = common::SpdmConfigInfo {
        spdm_version: [
            SpdmVersion::SpdmVersion10,
            SpdmVersion::SpdmVersion11,
            SpdmVersion::SpdmVersion12,
        ],
        rsp_capabilities,
        rsp_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
        base_asym_algo: if USE_ECDSA {
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        } else {
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        },
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,
        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: if USE_ECDSA {
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        } else {
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072
        },
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        opaque_support: SpdmOpaqueSupport::OPAQUE_DATA_FMT1,
        data_transfer_size: config::MAX_SPDM_MSG_SIZE as u32,
        max_spdm_msg_size: config::MAX_SPDM_MSG_SIZE as u32,
        heartbeat_period: config::HEARTBEAT_PERIOD,
        secure_spdm_version: [DMTF_SECURE_SPDM_VERSION_10, DMTF_SECURE_SPDM_VERSION_11],
        ..Default::default()
    };

    let mut my_cert_chain_data = SpdmCertChainData {
        ..Default::default()
    };

    let ca_file_path = if USE_ECDSA {
        "test_key/ecp384/ca.cert.der"
    } else {
        "test_key/rsa3072/ca.cert.der"
    };
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = if USE_ECDSA {
        "test_key/ecp384/inter.cert.der"
    } else {
        "test_key/rsa3072/inter.cert.der"
    };
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = if USE_ECDSA {
        "test_key/ecp384/end_responder.cert.der"
    } else {
        "test_key/rsa3072/end_responder.cert.der"
    };
    let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

    let ca_len = ca_cert.len();
    let inter_len = inter_cert.len();
    let leaf_len = leaf_cert.len();
    println!(
        "total cert size - {:?} = {:?} + {:?} + {:?}",
        ca_len + inter_len + leaf_len,
        ca_len,
        inter_len,
        leaf_len
    );
    my_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
    my_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
    my_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
    my_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
        .copy_from_slice(leaf_cert.as_ref());

    let provision_info = common::SpdmProvisionInfo {
        my_cert_chain_data: [
            Some(my_cert_chain_data),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ],
        my_cert_chain: [None, None, None, None, None, None, None, None],
        peer_root_cert_data: None,
    };

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    let mut context = responder::ResponderContext::new(
        socket_io_transport,
        transport_encap,
        config_info,
        provision_info,
    );
    loop {
        // if failed, receieved message can't be processed. then the message will need caller to deal.
        // now caller need to deal with message in context.
        let res = context.process_message(ST1, &[0]).await;
        match res {
            Ok(spdm_result) => {
                if spdm_result {
                    continue;
                } else {
                    // send unknown spdm command
                    return Ok(false);
                }
            }
            Err((used, buffer)) => {
                return Err((used, buffer));
            }
        }
    }
}

pub async fn send_hello(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    tranport_type: u32,
) {
    println!("get hello");

    let mut payload = [0u8; 1024];

    let mut transport_encap = transport_encap.lock();
    let transport_encap = transport_encap.deref_mut();

    let used = transport_encap
        .encap(
            Arc::new(b"Server Hello!\0"),
            Arc::new(Mutex::new(&mut payload[..])),
            false,
        )
        .await
        .unwrap();

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        tranport_type,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_TEST,
        &payload[..used],
    );
}

pub async fn send_unknown(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    transport_type: u32,
) {
    println!("get unknown");

    let mut payload = [0u8; 1024];
    let mut transport_encap = transport_encap.lock();
    let transport_encap = transport_encap.deref_mut();
    let used = transport_encap
        .encap(Arc::new(b""), Arc::new(Mutex::new(&mut payload[..])), false)
        .await
        .unwrap();

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        transport_type,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_UNKOWN,
        &payload[..used],
    );
}

pub async fn send_stop(
    stream: Arc<Mutex<TcpStream>>,
    _transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    transport_type: u32,
) {
    println!("get stop");

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        transport_type,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_STOP,
        &[],
    );
}

pub async fn send_pci_discovery(
    stream: Arc<Mutex<TcpStream>>,
    transport_encap: Arc<Mutex<dyn SpdmTransportEncap + Send + Sync>>,
    transport_type: u32,
    buffer: Arc<[u8]>,
) -> bool {
    let mut reader = Reader::init(&buffer);
    let mut unknown_message = false;
    match PciDoeMessageHeader::read(&mut reader) {
        Some(pcidoe_header) => {
            match pcidoe_header.vendor_id {
                PciDoeVendorId::PciDoeVendorIdPciSig => {}
                _ => unknown_message = true,
            }
            match pcidoe_header.data_object_type {
                PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery => {}
                _ => unknown_message = true,
            }
        }
        None => unknown_message = true,
    }

    let payload = &mut [1u8, 0u8, 0u8, 0u8];

    match u8::read(&mut reader) {
        None => unknown_message = true,
        Some(discovery_index) => match discovery_index {
            0 => {
                payload[2] = 0;
                payload[3] = 1;
            }
            1 => {
                payload[2] = 1;
                payload[3] = 2;
            }
            2 => {
                payload[2] = 2;
                payload[3] = 0;
            }
            _ => unknown_message = true,
        },
    }
    if unknown_message {
        send_unknown(stream.clone(), transport_encap, transport_type).await;
        return false;
    }

    let payload_len = 4;
    let mut transport_buffer = [0u8; 1024];
    let mut writer = Writer::init(&mut transport_buffer);
    let pcidoe_header = PciDoeMessageHeader {
        vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
        data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery,
        payload_length: 4,
    };
    assert!(pcidoe_header.encode(&mut writer).is_ok());
    let header_size = writer.used();
    transport_buffer[header_size..(header_size + payload_len)].copy_from_slice(payload);
    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        SOCKET_TRANSPORT_TYPE_PCI_DOE,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_NORMAL,
        &transport_buffer[..(header_size + payload_len)],
    );
    //need continue
    true
}

fn main() {
    use std::thread;

    thread::Builder::new()
        .stack_size(EMU_STACK_SIZE)
        .spawn(emu_main)
        .unwrap()
        .join()
        .unwrap();
}
