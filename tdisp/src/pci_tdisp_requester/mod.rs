// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::{
    context::{InterfaceId, TdispContext},
    device::TdispConfiguration,
};

pub struct TdispRequester<'a> {
    pub tdisp_requester_context: TdispContext<'a>,
}

impl<'a> TdispRequester<'a> {
    pub fn new(
        interface_id: InterfaceId,
        configuration: &'a mut dyn TdispConfiguration,
        spdm_session_id: u32,
    ) -> Self {
        TdispRequester {
            tdisp_requester_context: TdispContext::new(
                interface_id,
                configuration,
                spdm_session_id,
            ),
        }
    }
}

pub mod pci_tdisp_req_bind_p2p_stream_request;
pub mod pci_tdisp_req_get_device_interface_report;
pub mod pci_tdisp_req_get_device_interface_state;
pub mod pci_tdisp_req_get_tdisp_capabilities;
pub mod pci_tdisp_req_get_tdisp_version;
pub mod pci_tdisp_req_lock_interface_request;
pub mod pci_tdisp_req_set_mmio_attribute_request;
pub mod pci_tdisp_req_start_interface_request;
pub mod pci_tdisp_req_stop_interface_request;
pub mod pci_tdisp_req_unbind_p2p_stream_request;
pub mod pci_tdisp_req_vdm_request;
