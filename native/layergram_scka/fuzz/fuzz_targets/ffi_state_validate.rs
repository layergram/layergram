// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#![no_main]

mod support;

use layergram_scka::lg_scka_v1_state_validate;
use libfuzzer_sys::fuzz_target;
use support::{assert_candidate_status, fixture, state_candidate};

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let (role, revision, state) = state_candidate(data, &fixture.initiator_state);
    let first = unsafe {
        lg_scka_v1_state_validate(
            role,
            fixture.session.as_ptr(),
            fixture.session.len() as u64,
            fixture.state_key.as_ptr(),
            fixture.state_key.len() as u64,
            revision,
            state.as_ptr(),
            state.len() as u64,
        )
    };
    assert_candidate_status(first);
    let second = unsafe {
        lg_scka_v1_state_validate(
            role,
            fixture.session.as_ptr(),
            fixture.session.len() as u64,
            fixture.state_key.as_ptr(),
            fixture.state_key.len() as u64,
            revision,
            state.as_ptr(),
            state.len() as u64,
        )
    };
    assert_eq!(first, second, "state validation must be deterministic");
});
