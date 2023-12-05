// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
#![no_std]

pub use async_or_impl::async_impl_or;
pub use async_or_impl::async_or;
pub use async_or_impl::async_trait_or;

#[cfg(feature = "async")]
#[macro_export]
macro_rules! await_or {
    ($e:expr) => {
        $e.await
    };
}

#[cfg(not(feature = "async"))]
#[macro_export]
macro_rules! await_or {
    ($e:expr) => {
        $e
    };
}
