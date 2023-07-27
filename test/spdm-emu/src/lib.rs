// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

pub mod crypto;
pub mod crypto_callback;
pub mod secret_impl_sample;
pub mod socket_io_transport;
pub mod spdm_emu;

use std::mem::size_of;

use mctp_transport::MctpTransportEncap;
use pcidoe_transport::PciDoeTransportEncap;
use socket_io_transport::SocketIoTransport;
use spdmlib::{
    config::{
        MAX_SPDM_CERT_CHAIN_DATA_SIZE, MAX_SPDM_MEASUREMENT_RECORD_SIZE,
        MAX_SPDM_MEASUREMENT_VALUE_LEN, MAX_SPDM_MSG_SIZE, MAX_SPDM_PSK_CONTEXT_SIZE,
        MAX_SPDM_PSK_HINT_SIZE, RECEIVER_BUFFER_SIZE, SENDER_BUFFER_SIZE,
    },
    protocol::{
        SpdmCertChainBuffer, SpdmCertChainData, SpdmMeasurementRecordStructure,
        SPDM_MAX_SLOT_NUMBER,
    },
};
use std::net::TcpStream;

#[allow(non_snake_case)]
pub const fn MAX(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

const TRANSPORT_SIZE: usize = MAX(
    size_of::<PciDoeTransportEncap>(),
    size_of::<MctpTransportEncap>(),
);
const DEVICE_IO_SIZE: usize = size_of::<SocketIoTransport>();
const SPDMLIB_SIZE: usize = size_of::<spdmlib::common::SpdmContext>() +
                            size_of::<SpdmCertChainData>() * (SPDM_MAX_SLOT_NUMBER + 1) + size_of::<SpdmCertChainBuffer>() * SPDM_MAX_SLOT_NUMBER + // SpdmProvisionInfo
                            size_of::<SpdmCertChainData>() * (SPDM_MAX_SLOT_NUMBER + 1) + // SpdmPeerInfo
                            (MAX_SPDM_MSG_SIZE + SENDER_BUFFER_SIZE + RECEIVER_BUFFER_SIZE) * 5 + // send/receive + encode/decode
                            MAX_SPDM_CERT_CHAIN_DATA_SIZE * 8 + // worst case: 8 slots
                            (MAX_SPDM_MEASUREMENT_RECORD_SIZE + MAX_SPDM_MEASUREMENT_VALUE_LEN) * 255 + // worst case: 255 index
                            MAX_SPDM_PSK_CONTEXT_SIZE + // for PSK
                            MAX_SPDM_PSK_HINT_SIZE + // for PSK
                            size_of::<usize>() * 256; // for general stack case

const EMU_FUNCTION_STACK: usize = SENDER_BUFFER_SIZE
    + RECEIVER_BUFFER_SIZE
    + size_of::<TcpStream>()
    + size_of::<PciDoeTransportEncap>()
    + size_of::<MctpTransportEncap>()
    + size_of::<SpdmMeasurementRecordStructure>() * 255
    + size_of::<SpdmCertChainData>() * (SPDM_MAX_SLOT_NUMBER + 1)
    + size_of::<SpdmCertChainBuffer>() * SPDM_MAX_SLOT_NUMBER
    + size_of::<usize>() * 256; // for general stack case

pub const EMU_STACK_SIZE: usize =
    TRANSPORT_SIZE + DEVICE_IO_SIZE + SPDMLIB_SIZE + EMU_FUNCTION_STACK;
