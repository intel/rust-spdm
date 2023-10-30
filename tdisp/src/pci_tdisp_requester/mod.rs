// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::pci_tdisp::{InterfaceId, TdispVersion};

pub mod pci_tdisp_req_get_version;
pub use pci_tdisp_req_get_version::*;

pub mod pci_tdisp_req_get_capabilities;
pub use pci_tdisp_req_get_capabilities::*;

pub mod pci_tdisp_req_lock_interface;
pub use pci_tdisp_req_lock_interface::*;

pub mod pci_tdisp_req_get_interface_report;
pub use pci_tdisp_req_get_interface_report::*;

pub mod pci_tdisp_req_get_interface_state;
pub use pci_tdisp_req_get_interface_state::*;

pub mod pci_tdisp_req_start_interface;
pub use pci_tdisp_req_start_interface::*;

pub mod pci_tdisp_req_stop_interface;
pub use pci_tdisp_req_stop_interface::*;
