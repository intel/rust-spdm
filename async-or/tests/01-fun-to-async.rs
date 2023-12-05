// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use async_or_impl::*;

#[async_or]
pub fn test() {
    panic!("This test function should be async-able, So this panic should be not called w/out async runtime!");
}

#[allow(unused_must_use)]
fn main() {
    test();
}
