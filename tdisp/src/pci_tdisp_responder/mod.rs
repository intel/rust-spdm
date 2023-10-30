// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

pub const MAX_TDISP_VERSION_COUNT: usize = u8::MAX as usize;

pub mod pci_tdisp_rsp_dispatcher;
pub use pci_tdisp_rsp_dispatcher::*;

pub mod pci_tdisp_rsp_version;

pub mod pci_tdisp_rsp_capabilities;

pub mod pci_tdisp_rsp_lock_interface;

pub mod pci_tdisp_rsp_interface_report;

pub mod pci_tdisp_rsp_interface_state;

pub mod pci_tdisp_rsp_start_interface;

pub mod pci_tdisp_rsp_stop_interface;

pub mod pci_tdisp_rsp_error;
pub use pci_tdisp_rsp_error::*;
