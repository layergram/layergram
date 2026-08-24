// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#![no_main]

mod support;

use layergram_scka::{
    lg_scka_v1_receive, lg_scka_v1_state_validate, EPOCH_SECRET_BYTES, MAX_STATE_BYTES,
    MIN_STATE_BYTES, STATUS_OK,
};
use libfuzzer_sys::fuzz_target;
use support::{assert_candidate_status, fixture, message_candidate, ROLE_RESPONDER};

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let message = message_candidate(data, &fixture.first_message);
    let mut state_out = vec![0xa5_u8; MAX_STATE_BYTES as usize];
    let mut epoch_secret = [0xa5_u8; EPOCH_SECRET_BYTES as usize];
    let mut state_out_len = u64::MAX;
    let mut receiving_epoch = u64::MAX;
    let mut has_epoch_secret = u32::MAX;
    let mut epoch_secret_epoch = u64::MAX;
    let status = unsafe {
        lg_scka_v1_receive(
            ROLE_RESPONDER,
            fixture.session.as_ptr(),
            fixture.session.len() as u64,
            fixture.state_key.as_ptr(),
            fixture.state_key.len() as u64,
            0,
            fixture.responder_state.as_ptr(),
            fixture.responder_state.len() as u64,
            message.as_ptr(),
            message.len() as u64,
            state_out.as_mut_ptr(),
            state_out.len() as u64,
            &mut state_out_len,
            &mut receiving_epoch,
            &mut has_epoch_secret,
            &mut epoch_secret_epoch,
            epoch_secret.as_mut_ptr(),
            epoch_secret.len() as u64,
        )
    };
    assert_candidate_status(status);
    if status == STATUS_OK {
        assert!((MIN_STATE_BYTES..=MAX_STATE_BYTES).contains(&state_out_len));
        assert!(state_out[state_out_len as usize..]
            .iter()
            .all(|byte| *byte == 0));
        assert!(has_epoch_secret <= 1);
        if has_epoch_secret == 0 {
            assert_eq!(epoch_secret_epoch, 0);
            assert!(epoch_secret.iter().all(|byte| *byte == 0));
        }
        let validation = unsafe {
            lg_scka_v1_state_validate(
                ROLE_RESPONDER,
                fixture.session.as_ptr(),
                fixture.session.len() as u64,
                fixture.state_key.as_ptr(),
                fixture.state_key.len() as u64,
                1,
                state_out.as_ptr(),
                state_out_len,
            )
        };
        assert_eq!(
            validation, STATUS_OK,
            "accepted message produced invalid state"
        );
    } else {
        assert_eq!(
            (
                state_out_len,
                receiving_epoch,
                has_epoch_secret,
                epoch_secret_epoch
            ),
            (0, 0, 0, 0)
        );
        assert!(state_out.iter().all(|byte| *byte == 0));
        assert!(epoch_secret.iter().all(|byte| *byte == 0));
    }
});
