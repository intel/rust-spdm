// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![no_std]

mod header;
pub use header::*;

extern crate codec;

pub const MCTP_TRANSPORT_STACK_SIZE: usize =
    core::mem::size_of::<MctpTransportEncap>() + core::mem::size_of::<usize>() * 256; // for general stack case;
