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

use mctp_transport::{MctpTransportEncap, MCTP_TRANSPORT_STACK_SIZE};
use pcidoe_transport::{PciDoeTransportEncap, PCIDOE_TRANSPORT_STACK_SIZE};
use socket_io_transport::DEVICE_IO_STACK_SIZE;
use spdmlib::{
    config::{RECEIVER_BUFFER_SIZE, SENDER_BUFFER_SIZE},
    protocol::{
        SpdmCertChainBuffer, SpdmCertChainData, SpdmMeasurementRecordStructure,
        SPDM_MAX_SLOT_NUMBER,
    },
    SPDM_STACK_SIZE,
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

const TRANSPORT_STACK_SIZE: usize = MAX(PCIDOE_TRANSPORT_STACK_SIZE, MCTP_TRANSPORT_STACK_SIZE);

const EMU_FUNCTION_STACK_SIZE: usize = SENDER_BUFFER_SIZE
    + RECEIVER_BUFFER_SIZE
    + size_of::<TcpStream>()
    + size_of::<PciDoeTransportEncap>()
    + size_of::<MctpTransportEncap>()
    + size_of::<SpdmMeasurementRecordStructure>() * 255
    + size_of::<SpdmCertChainData>() * (SPDM_MAX_SLOT_NUMBER + 1)
    + size_of::<SpdmCertChainBuffer>() * SPDM_MAX_SLOT_NUMBER
    + size_of::<usize>() * 256; // for general stack case

pub const EMU_STACK_SIZE: usize =
    TRANSPORT_STACK_SIZE + DEVICE_IO_STACK_SIZE + SPDM_STACK_SIZE + EMU_FUNCTION_STACK_SIZE;
