// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use async_or::await_or;
use async_or_impl::*;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[async_or]
fn test_to_panic() {
    panic!("This test function is set to panic!");
}

#[async_or]
pub fn test() {
    await_or!(test_to_panic());
}

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let msg = catch_unwind(AssertUnwindSafe(|| {
        rt.block_on(test());
    }));

    assert_eq!(
        "This test function is set to panic!",
        *msg.unwrap_err().downcast_ref::<&str>().unwrap()
    );
}
