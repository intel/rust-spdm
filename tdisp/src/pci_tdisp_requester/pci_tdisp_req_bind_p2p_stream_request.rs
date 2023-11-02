// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Writer;
use core::convert::TryInto;
use spdmlib::{
    message::{
        RegistryOrStandardsBodyID, VendorDefinedReqPayloadStruct, VendorDefinedRspPayloadStruct,
    },
    requester::RequesterContext,
};

use crate::{
    common::{InternalError, TdispResult, PCI_VENDOR_ID_STRUCT},
    context::{MessagePayloadRequestBindP2pStream, TdispMessage, TdispRequestResponseCode},
    tdisp_codec::TdispCodec,
};

use super::*;

impl<'a> TdispRequester<'a> {
    pub fn pci_tdisp_req_bind_p2p_stream_request(
        &mut self,
        spdm_requester: &mut RequesterContext,
    ) -> TdispResult {
        let mut tdisp_message = TdispMessage::<MessagePayloadRequestBindP2pStream>::default();
        tdisp_message.tdisp_message_header.interface_id = self.tdisp_requester_context.tdi;
        tdisp_message.tdisp_message_header.tdisp_version = self.tdisp_requester_context.version_sel;
        let mut vendor_defined_req_payload =
            [0u8; spdmlib::config::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
        let mut writer = Writer::init(&mut vendor_defined_req_payload);
        tdisp_message.tdisp_encode(&mut self.tdisp_requester_context, &mut writer);
        let req_length: u16 = writer.used().try_into().unwrap();

        let vdrp = VendorDefinedReqPayloadStruct {
            req_length,
            vendor_defined_req_payload,
        };

        self.tdisp_requester_context
            .request_message
            .copy_from_slice(&vendor_defined_req_payload);
        self.tdisp_requester_context.request_code =
            TdispRequestResponseCode::RequestBindP2pStreamRequest;

        match spdm_requester.send_spdm_vendor_defined_request(
            self.tdisp_requester_context.spdm_session_id,
            RegistryOrStandardsBodyID::PCISIG,
            PCI_VENDOR_ID_STRUCT,
            vdrp,
        ) {
            Ok(vdrp) => {
                let VendorDefinedRspPayloadStruct {
                    rsp_length: _,
                    vendor_defined_rsp_payload,
                } = vdrp;

                self.tdisp_requester_context.response_code =
                    TdispRequestResponseCode::ResponseBindP2pStreamResponse;
                self.tdisp_requester_context
                    .response_message
                    .copy_from_slice(&vendor_defined_rsp_payload);

                self.handle_bind_p2p_stream_response(spdm_requester)
            }
            Err(_) => Err(InternalError::Unrecoverable),
        }
    }

    fn handle_bind_p2p_stream_response(
        &mut self,
        _spdm_requester: &mut RequesterContext,
    ) -> TdispResult {
        Ok(())
    }
}
