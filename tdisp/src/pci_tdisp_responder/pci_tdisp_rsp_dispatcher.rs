// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use core::convert::TryFrom;
use spdmlib::{
    error::{SpdmResult, SPDM_STATUS_INVALID_MSG_FIELD},
    message::{
        VendorDefinedReqPayloadStruct, VendorDefinedRspPayloadStruct, VendorIDStruct,
        MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE,
    },
};

use crate::pci_tdisp::{pci_sig_vendor_id, TdispErrorCode, TdispRequestResponseCode};

use super::{
    pci_tdisp_rsp_capabilities::pci_tdisp_rsp_capabilities,
    pci_tdisp_rsp_interface_report::pci_tdisp_rsp_interface_report,
    pci_tdisp_rsp_interface_state::pci_tdisp_rsp_interface_state,
    pci_tdisp_rsp_lock_interface::pci_tdisp_rsp_lock_interface,
    pci_tdisp_rsp_start_interface::pci_tdisp_rsp_start_interface,
    pci_tdisp_rsp_stop_interface::pci_tdisp_rsp_stop_interface,
    pci_tdisp_rsp_version::pci_tdisp_rsp_version, write_error,
};

pub fn pci_tdisp_rsp_dispatcher(
    vendor_context: usize,
    vendor_id: &VendorIDStruct,
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    if vendor_defined_req_payload_struct.req_length < 3 || *vendor_id != pci_sig_vendor_id() {
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }

    if let Ok(request_response_code) = TdispRequestResponseCode::try_from(
        vendor_defined_req_payload_struct.vendor_defined_req_payload[2],
    ) {
        match request_response_code {
            TdispRequestResponseCode::GET_TDISP_VERSION => {
                pci_tdisp_rsp_version(vendor_context, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::GET_TDISP_CAPABILITIES => {
                pci_tdisp_rsp_capabilities(vendor_context, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::LOCK_INTERFACE_REQUEST => {
                pci_tdisp_rsp_lock_interface(vendor_context, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::GET_DEVICE_INTERFACE_REPORT => {
                pci_tdisp_rsp_interface_report(vendor_context, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::GET_DEVICE_INTERFACE_STATE => {
                pci_tdisp_rsp_interface_state(vendor_context, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::START_INTERFACE_REQUEST => {
                pci_tdisp_rsp_start_interface(vendor_context, vendor_defined_req_payload_struct)
            }
            TdispRequestResponseCode::STOP_INTERFACE_REQUEST => {
                pci_tdisp_rsp_stop_interface(vendor_context, vendor_defined_req_payload_struct)
            }
            _ => {
                let mut vendor_defined_rsp_payload_struct = VendorDefinedRspPayloadStruct {
                    rsp_length: 0,
                    vendor_defined_rsp_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
                };

                let len = write_error(
                    vendor_context,
                    TdispErrorCode::UNSUPPORTED_REQUEST,
                    0,
                    &[],
                    &mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload,
                )?;
                vendor_defined_rsp_payload_struct.rsp_length = len as u16;
                Ok(vendor_defined_rsp_payload_struct)
            }
        }
    } else {
        Err(SPDM_STATUS_INVALID_MSG_FIELD)
    }
}
