// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[test]
fn tests() {
    let t = trybuild::TestCases::new();
    t.pass("tests/01-fun-to-async.rs");
    t.pass("tests/02-fun-call-to-await.rs");
}
