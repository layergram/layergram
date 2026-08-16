// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "candidate-ffi")]

use layergram_scka::{
    lg_scka_v1_initialize, lg_scka_v1_receive, lg_scka_v1_send, lg_scka_v1_state_validate,
    EPOCH_SECRET_BYTES, MAX_COUNTER, MAX_MESSAGE_BYTES, MAX_STATE_BYTES, MIN_STATE_BYTES,
    SESSION_ID_BYTES, SHARED_SECRET_BYTES, STATE_KEY_BYTES, STATUS_AUTHENTICATION, STATUS_BACKEND,
    STATUS_ENTROPY, STATUS_INVALID_ARGUMENT, STATUS_OK, STATUS_STATE_FORMAT, STATUS_STATE_REVISION,
};
use std::mem::align_of;
use std::ptr;

const ROLE_INITIATOR: u32 = 1;
const ROLE_RESPONDER: u32 = 2;
const GUARD_BYTES: usize = 32;
const GUARD_VALUE: u8 = 0x6d;
const DIRTY_VALUE: u8 = 0xa5;

struct GuardedBytes {
    storage: Vec<u8>,
    payload_len: usize,
}

impl GuardedBytes {
    fn new(payload_len: usize) -> Self {
        let mut value = Self {
            storage: vec![GUARD_VALUE; payload_len + (2 * GUARD_BYTES)],
            payload_len,
        };
        value.prime();
        value
    }

    fn prime(&mut self) {
        self.storage[..GUARD_BYTES].fill(GUARD_VALUE);
        self.storage[GUARD_BYTES..GUARD_BYTES + self.payload_len].fill(DIRTY_VALUE);
        self.storage[GUARD_BYTES + self.payload_len..].fill(GUARD_VALUE);
    }

    fn payload(&self) -> &[u8] {
        &self.storage[GUARD_BYTES..GUARD_BYTES + self.payload_len]
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.storage[GUARD_BYTES..GUARD_BYTES + self.payload_len]
    }

    fn payload_ptr(&self) -> *const u8 {
        self.payload().as_ptr()
    }

    fn payload_mut_ptr(&mut self) -> *mut u8 {
        self.payload_mut().as_mut_ptr()
    }

    fn assert_guards(&self) {
        assert!(self.storage[..GUARD_BYTES]
            .iter()
            .all(|byte| *byte == GUARD_VALUE));
        assert!(self.storage[GUARD_BYTES + self.payload_len..]
            .iter()
            .all(|byte| *byte == GUARD_VALUE));
    }

    fn assert_scrubbed(&self) {
        self.assert_guards();
        assert!(self.payload().iter().all(|byte| *byte == 0));
    }
}

struct SendOutputs {
    state: GuardedBytes,
    message: GuardedBytes,
    secret: GuardedBytes,
    state_len: u64,
    message_len: u64,
    epoch: u64,
    has_secret: u32,
    secret_epoch: u64,
}

impl SendOutputs {
    fn new() -> Self {
        Self {
            state: GuardedBytes::new(MAX_STATE_BYTES as usize),
            message: GuardedBytes::new(MAX_MESSAGE_BYTES as usize),
            secret: GuardedBytes::new(EPOCH_SECRET_BYTES as usize),
            state_len: u64::MAX,
            message_len: u64::MAX,
            epoch: u64::MAX,
            has_secret: u32::MAX,
            secret_epoch: u64::MAX,
        }
    }

    fn prime(&mut self) {
        self.state.prime();
        self.message.prime();
        self.secret.prime();
        self.state_len = u64::MAX;
        self.message_len = u64::MAX;
        self.epoch = u64::MAX;
        self.has_secret = u32::MAX;
        self.secret_epoch = u64::MAX;
    }

    fn assert_scrubbed(&self) {
        self.state.assert_scrubbed();
        self.message.assert_scrubbed();
        self.secret.assert_scrubbed();
        assert_eq!(
            (
                self.state_len,
                self.message_len,
                self.epoch,
                self.has_secret,
                self.secret_epoch,
            ),
            (0, 0, 0, 0, 0)
        );
    }
}

struct ReceiveOutputs {
    state: GuardedBytes,
    secret: GuardedBytes,
    state_len: u64,
    epoch: u64,
    has_secret: u32,
    secret_epoch: u64,
}

impl ReceiveOutputs {
    fn new() -> Self {
        Self {
            state: GuardedBytes::new(MAX_STATE_BYTES as usize),
            secret: GuardedBytes::new(EPOCH_SECRET_BYTES as usize),
            state_len: u64::MAX,
            epoch: u64::MAX,
            has_secret: u32::MAX,
            secret_epoch: u64::MAX,
        }
    }

    fn prime(&mut self) {
        self.state.prime();
        self.secret.prime();
        self.state_len = u64::MAX;
        self.epoch = u64::MAX;
        self.has_secret = u32::MAX;
        self.secret_epoch = u64::MAX;
    }

    fn assert_scrubbed(&self) {
        self.state.assert_scrubbed();
        self.secret.assert_scrubbed();
        assert_eq!(
            (
                self.state_len,
                self.epoch,
                self.has_secret,
                self.secret_epoch,
            ),
            (0, 0, 0, 0)
        );
    }
}

fn initialize_state(
    role: u32,
    session: &[u8; SESSION_ID_BYTES as usize],
    state_key: &[u8; STATE_KEY_BYTES as usize],
    shared_secret: &[u8; SHARED_SECRET_BYTES as usize],
) -> Vec<u8> {
    let mut output = GuardedBytes::new(MAX_STATE_BYTES as usize);
    let mut output_len = 0_u64;
    let status = unsafe {
        lg_scka_v1_initialize(
            role,
            session.as_ptr(),
            session.len() as u64,
            state_key.as_ptr(),
            state_key.len() as u64,
            shared_secret.as_ptr(),
            shared_secret.len() as u64,
            output.payload_mut_ptr(),
            MAX_STATE_BYTES,
            &mut output_len,
        )
    };
    assert_eq!(status, STATUS_OK);
    assert!((MIN_STATE_BYTES..=MAX_STATE_BYTES).contains(&output_len));
    output.assert_guards();
    output.payload()[..output_len as usize].to_vec()
}

fn assert_candidate_status(status: i32) {
    assert!(matches!(
        status,
        STATUS_OK
            | STATUS_INVALID_ARGUMENT
            | STATUS_AUTHENTICATION
            | STATUS_STATE_FORMAT
            | STATUS_STATE_REVISION
            | STATUS_BACKEND
            | STATUS_ENTROPY
    ));
}

fn next_u64(state: &mut u64) -> u64 {
    let mut value = *state;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *state = value;
    value
}

fn fill_deterministic(bytes: &mut [u8], state: &mut u64) {
    for byte in bytes {
        *byte = next_u64(state) as u8;
    }
}

#[test]
fn candidate_abi_rejects_overlapping_outputs_inputs_and_unaligned_scalars() {
    let session = [0x11_u8; SESSION_ID_BYTES as usize];
    let state_key = [0x22_u8; STATE_KEY_BYTES as usize];
    let shared_secret = [0x33_u8; SHARED_SECRET_BYTES as usize];

    let mut overlapping_output = GuardedBytes::new(MAX_STATE_BYTES as usize);
    let overlapping_len = unsafe { overlapping_output.payload_mut_ptr().add(8).cast::<u64>() };
    let status = unsafe {
        lg_scka_v1_initialize(
            ROLE_INITIATOR,
            session.as_ptr(),
            session.len() as u64,
            state_key.as_ptr(),
            state_key.len() as u64,
            shared_secret.as_ptr(),
            shared_secret.len() as u64,
            overlapping_output.payload_mut_ptr(),
            MAX_STATE_BYTES,
            overlapping_len,
        )
    };
    assert_eq!(status, STATUS_INVALID_ARGUMENT);
    overlapping_output.assert_guards();
    assert!(overlapping_output
        .payload()
        .iter()
        .all(|byte| *byte == DIRTY_VALUE));

    let mut scalar_storage = [0_u8; 32];
    let unaligned_offset = (0..align_of::<u64>())
        .find(|offset| unsafe { scalar_storage.as_mut_ptr().add(*offset) } as usize % align_of::<u64>() != 0)
        .expect("an unaligned offset exists");
    let unaligned_len = unsafe {
        scalar_storage
            .as_mut_ptr()
            .add(unaligned_offset)
            .cast::<u64>()
    };
    let mut output = GuardedBytes::new(MAX_STATE_BYTES as usize);
    let status = unsafe {
        lg_scka_v1_initialize(
            ROLE_INITIATOR,
            session.as_ptr(),
            session.len() as u64,
            state_key.as_ptr(),
            state_key.len() as u64,
            shared_secret.as_ptr(),
            shared_secret.len() as u64,
            output.payload_mut_ptr(),
            MAX_STATE_BYTES,
            unaligned_len,
        )
    };
    assert_eq!(status, STATUS_INVALID_ARGUMENT);
    output.assert_guards();
    assert!(output.payload().iter().all(|byte| *byte == DIRTY_VALUE));

    let alice = initialize_state(ROLE_INITIATOR, &session, &state_key, &shared_secret);
    let mut aliased_state = GuardedBytes::new(MAX_STATE_BYTES as usize);
    aliased_state.payload_mut()[..alice.len()].copy_from_slice(&alice);
    let mut send = SendOutputs::new();
    let status = unsafe {
        lg_scka_v1_send(
            ROLE_INITIATOR,
            session.as_ptr(),
            session.len() as u64,
            state_key.as_ptr(),
            state_key.len() as u64,
            0,
            aliased_state.payload_ptr(),
            alice.len() as u64,
            aliased_state.payload_mut_ptr(),
            MAX_STATE_BYTES,
            &mut send.state_len,
            send.message.payload_mut_ptr(),
            MAX_MESSAGE_BYTES,
            &mut send.message_len,
            &mut send.epoch,
            &mut send.has_secret,
            &mut send.secret_epoch,
            send.secret.payload_mut_ptr(),
            EPOCH_SECRET_BYTES,
        )
    };
    assert_eq!(status, STATUS_INVALID_ARGUMENT);
    aliased_state.assert_scrubbed();
    send.message.assert_scrubbed();
    send.secret.assert_scrubbed();
    assert_eq!(
        (
            send.state_len,
            send.message_len,
            send.epoch,
            send.has_secret,
            send.secret_epoch,
        ),
        (0, 0, 0, 0, 0)
    );

    let mut one_byte_message = [0x44_u8];
    let bob = initialize_state(ROLE_RESPONDER, &session, &state_key, &shared_secret);
    let mut receive = ReceiveOutputs::new();
    let status = unsafe {
        lg_scka_v1_receive(
            ROLE_RESPONDER,
            session.as_ptr(),
            session.len() as u64,
            state_key.as_ptr(),
            state_key.len() as u64,
            0,
            bob.as_ptr(),
            bob.len() as u64,
            one_byte_message.as_mut_ptr(),
            MAX_MESSAGE_BYTES + 1,
            receive.state.payload_mut_ptr(),
            MAX_STATE_BYTES,
            &mut receive.state_len,
            &mut receive.epoch,
            &mut receive.has_secret,
            &mut receive.secret_epoch,
            receive.secret.payload_mut_ptr(),
            EPOCH_SECRET_BYTES,
        )
    };
    assert_eq!(status, STATUS_INVALID_ARGUMENT);
    receive.assert_scrubbed();
}

#[test]
fn candidate_authenticated_states_reject_deterministic_hostile_mutations() {
    let session = [0x41_u8; SESSION_ID_BYTES as usize];
    let state_key = [0x52_u8; STATE_KEY_BYTES as usize];
    let shared_secret = [0x63_u8; SHARED_SECRET_BYTES as usize];
    let alice = initialize_state(ROLE_INITIATOR, &session, &state_key, &shared_secret);
    let mut mutated = alice.clone();

    for index in 0..mutated.len() {
        mutated[index] ^= 1_u8 << (index % 8);
        let status = unsafe {
            lg_scka_v1_state_validate(
                ROLE_INITIATOR,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                0,
                mutated.as_ptr(),
                mutated.len() as u64,
            )
        };
        assert_candidate_status(status);
        assert_ne!(status, STATUS_OK, "mutation at byte {index} was accepted");
        mutated[index] = alice[index];
    }

    let mut random = 0x4c41_5945_5247_5241_u64;
    for case_index in 0..512_usize {
        let length = MIN_STATE_BYTES as usize + (next_u64(&mut random) as usize % 4096);
        let mut state = vec![0_u8; length];
        fill_deterministic(&mut state, &mut random);
        let status = unsafe {
            lg_scka_v1_state_validate(
                ROLE_INITIATOR,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                case_index as u64 & MAX_COUNTER,
                state.as_ptr(),
                state.len() as u64,
            )
        };
        assert_candidate_status(status);
        assert_ne!(
            status, STATUS_OK,
            "random state case {case_index} was accepted"
        );
    }
}

#[test]
fn candidate_message_corpus_is_bounded_and_every_failure_scrubs_outputs() {
    let session = [0x71_u8; SESSION_ID_BYTES as usize];
    let state_key = [0x82_u8; STATE_KEY_BYTES as usize];
    let shared_secret = [0x93_u8; SHARED_SECRET_BYTES as usize];
    let bob = initialize_state(ROLE_RESPONDER, &session, &state_key, &shared_secret);
    let mut output = ReceiveOutputs::new();
    let mut random = 0x5352_564c_4553_534c_u64;

    for case_index in 0..512_usize {
        let length = 1 + (next_u64(&mut random) as usize % MAX_MESSAGE_BYTES as usize);
        let mut message = vec![0_u8; length];
        fill_deterministic(&mut message, &mut random);
        output.prime();
        let status = unsafe {
            lg_scka_v1_receive(
                ROLE_RESPONDER,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                0,
                bob.as_ptr(),
                bob.len() as u64,
                message.as_ptr(),
                message.len() as u64,
                output.state.payload_mut_ptr(),
                MAX_STATE_BYTES,
                &mut output.state_len,
                &mut output.epoch,
                &mut output.has_secret,
                &mut output.secret_epoch,
                output.secret.payload_mut_ptr(),
                EPOCH_SECRET_BYTES,
            )
        };
        assert_candidate_status(status);
        if status == STATUS_OK {
            assert!((MIN_STATE_BYTES..=MAX_STATE_BYTES).contains(&output.state_len));
            output.state.assert_guards();
            output.secret.assert_guards();
            assert_eq!(
                unsafe {
                    lg_scka_v1_state_validate(
                        ROLE_RESPONDER,
                        session.as_ptr(),
                        session.len() as u64,
                        state_key.as_ptr(),
                        state_key.len() as u64,
                        1,
                        output.state.payload_ptr(),
                        output.state_len,
                    )
                },
                STATUS_OK,
                "accepted message case {case_index} produced an invalid state"
            );
        } else {
            output.assert_scrubbed();
        }
    }

    output.prime();
    let status = unsafe {
        lg_scka_v1_receive(
            ROLE_RESPONDER,
            session.as_ptr(),
            session.len() as u64,
            state_key.as_ptr(),
            state_key.len() as u64,
            MAX_COUNTER + 1,
            bob.as_ptr(),
            bob.len() as u64,
            ptr::null(),
            0,
            output.state.payload_mut_ptr(),
            MAX_STATE_BYTES,
            &mut output.state_len,
            &mut output.epoch,
            &mut output.has_secret,
            &mut output.secret_epoch,
            output.secret.payload_mut_ptr(),
            EPOCH_SECRET_BYTES,
        )
    };
    assert_eq!(status, STATUS_INVALID_ARGUMENT);
    output.assert_scrubbed();
}

#[test]
fn candidate_send_failures_scrub_guarded_outputs() {
    let session = [0x24_u8; SESSION_ID_BYTES as usize];
    let state_key = [0x35_u8; STATE_KEY_BYTES as usize];
    let shared_secret = [0x46_u8; SHARED_SECRET_BYTES as usize];
    let alice = initialize_state(ROLE_INITIATOR, &session, &state_key, &shared_secret);
    let mut mutated = alice.clone();
    let mut output = SendOutputs::new();
    let stride = (mutated.len() / 64).max(1);

    for index in (0..mutated.len()).step_by(stride) {
        mutated[index] ^= 0x80;
        output.prime();
        let status = unsafe {
            lg_scka_v1_send(
                ROLE_INITIATOR,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                0,
                mutated.as_ptr(),
                mutated.len() as u64,
                output.state.payload_mut_ptr(),
                MAX_STATE_BYTES,
                &mut output.state_len,
                output.message.payload_mut_ptr(),
                MAX_MESSAGE_BYTES,
                &mut output.message_len,
                &mut output.epoch,
                &mut output.has_secret,
                &mut output.secret_epoch,
                output.secret.payload_mut_ptr(),
                EPOCH_SECRET_BYTES,
            )
        };
        assert_candidate_status(status);
        assert_ne!(status, STATUS_OK, "mutation at byte {index} was accepted");
        output.assert_scrubbed();
        mutated[index] = alice[index];
    }
}
