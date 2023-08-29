// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

use async_trait::async_trait;
use spdmlib::common::{SpdmDeviceIo, ST1};
use spdmlib::config::RECEIVER_BUFFER_SIZE;
use spdmlib::error::{SpdmResult, SPDM_STATUS_ERROR_PEER};
use spdmlib::responder;
use std::cell::RefCell;
use std::collections::VecDeque;

use spin::Mutex;
extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::borrow::BorrowMut;
use core::ops::DerefMut;

pub struct MySpdmDeviceIo;

#[async_trait]
impl SpdmDeviceIo for MySpdmDeviceIo {
    async fn send(&mut self, _buffer: Arc<&[u8]>) -> SpdmResult {
        todo!()
    }

    async fn receive(
        &mut self,
        _buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        todo!()
    }

    async fn flush_all(&mut self) -> SpdmResult {
        todo!()
    }
}

pub struct FakeSpdmDeviceIo {
    pub data: Arc<SharedBuffer>,
    pub responder: Arc<Mutex<responder::ResponderContext>>,
}

impl FakeSpdmDeviceIo {
    pub fn new(
        data: Arc<SharedBuffer>,
        responder: Arc<Mutex<responder::ResponderContext>>,
    ) -> Self {
        FakeSpdmDeviceIo { data, responder }
    }
}

#[async_trait]
impl SpdmDeviceIo for FakeSpdmDeviceIo {
    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let mut responder = self.responder.lock();
        let mut responder = responder.deref_mut();

        let len = {
            let mut device_io = responder.common.device_io.lock();
            let device_io = device_io.deref_mut();
            device_io.receive(read_buffer.clone(), 0).await.unwrap()
        };
        let mut read_buffer = read_buffer.lock();
        let mut read_buffer = read_buffer.to_vec();
        let read_buffer = Arc::new(read_buffer.as_slice());
        self.data.set_buffer_ref(read_buffer.clone());
        println!("requester receive RAW - {:02x?}\n", &read_buffer[0..len]);

        Ok(len)
    }

    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        self.data.set_buffer_ref(buffer.clone());
        log::info!("requester send    RAW - {:02x?}\n", &buffer);

        let mut responder = self.responder.lock();
        let mut responder = responder.deref_mut();

        {
            let mut device_io = responder.common.device_io.lock();
            let device_io = device_io.deref_mut();
            log::info!("0:{:?}", buffer);
            device_io.send(buffer).await;
        }

        let mut raw_packet = [0u8; RECEIVER_BUFFER_SIZE];

        if responder
            .process_message(false, &[0], &mut raw_packet)
            .await
            .is_err()
        {
            return Err(SPDM_STATUS_ERROR_PEER);
        }
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct SpdmDeviceIoReceve {
    data: Arc<SharedBuffer>,
    fuzzdata: Arc<[u8]>,
}

impl SpdmDeviceIoReceve {
    pub fn new(data: Arc<SharedBuffer>, fuzzdata: Arc<[u8]>) -> Self {
        SpdmDeviceIoReceve { data, fuzzdata }
    }
}

#[async_trait]
impl SpdmDeviceIo for SpdmDeviceIoReceve {
    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer.clone());
        let mut read_buffer = read_buffer.lock();
        let read_buffer = read_buffer.deref_mut();
        log::info!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        self.data.set_buffer(self.fuzzdata.clone());
        log::info!("responder send    RAW - {:02x?}\n", buffer);
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct FakeSpdmDeviceIoReceve {
    pub data: Arc<SharedBuffer>,
}

impl FakeSpdmDeviceIoReceve {
    pub fn new(data: Arc<SharedBuffer>) -> Self {
        FakeSpdmDeviceIoReceve { data }
    }
}

#[async_trait]
impl SpdmDeviceIo for FakeSpdmDeviceIoReceve {
    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer.clone());
        let mut read_buffer = read_buffer.lock();
        let read_buffer = read_buffer.deref_mut();
        println!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        self.data.set_buffer_ref(buffer.clone());
        println!("responder send    RAW - {:02x?}\n", &buffer);
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct SharedBuffer {
    queue: Arc<Mutex<VecDeque<u8>>>,
}

impl SharedBuffer {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        SharedBuffer {
            queue: Arc::new(Mutex::new(VecDeque::<u8>::new())),
        }
    }

    pub fn set_buffer_ref(&self, b: Arc<&[u8]>) {
        log::info!("send    {:02x?}\n", b);
        let mut queue = self.queue.lock();
        let queue = queue.deref_mut();
        for i in *b {
            queue.push_back(*i);
        }
    }

    pub fn set_buffer(&self, b: Arc<[u8]>) {
        log::info!("send    {:02x?}\n", b);
        let mut queue = self.queue.lock();
        let queue = queue.deref_mut();
        for i in &*b {
            queue.push_back(*i);
        }
    }

    pub fn get_buffer(&self, b: Arc<Mutex<&mut [u8]>>) -> usize {
        let mut queue = self.queue.lock();
        let queue = queue.deref_mut();
        let mut len = 0usize;
        let mut b = b.lock();
        let b = b.deref_mut();
        for i in b.iter_mut() {
            if queue.is_empty() {
                break;
            }
            *i = queue.pop_front().unwrap();
            len += 1;
        }
        log::info!("recieve {:02x?}\n", &b[..len]);
        len
    }
}

#[test]
fn test_fake_device_io() {
    let future = async {
        let buffer = SharedBuffer::new();
        let buffer = Arc::new(buffer);
        let mut server = FakeSpdmDeviceIoReceve::new(buffer.clone());
        let mut client = FakeSpdmDeviceIoReceve::new(buffer.clone());
        const SEND_DATA: &[u8] = &[1, 2];
        client.send(Arc::new(SEND_DATA)).await.unwrap();
        let mut rev = [0u8, 64];
        server
            .receive(Arc::new(Mutex::new(&mut rev)), ST1)
            .await
            .unwrap();
        assert_eq!(rev[..=1], *SEND_DATA)
    };
    executor::block_on(future);
}
