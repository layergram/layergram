// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "candidate-ffi")]

use layergram_scka::{
    lg_scka_v1_initialize, lg_scka_v1_receive, lg_scka_v1_send, lg_scka_v1_state_validate,
    EPOCH_SECRET_BYTES, MAX_COUNTER, MAX_MESSAGE_BYTES, MAX_STATE_BYTES, MIN_STATE_BYTES,
    SESSION_ID_BYTES, SHARED_SECRET_BYTES, STATE_KEY_BYTES, STATUS_AUTHENTICATION, STATUS_BACKEND,
    STATUS_ENTROPY, STATUS_INVALID_ARGUMENT, STATUS_OK, STATUS_STATE_FORMAT, STATUS_STATE_REVISION,
};
use std::collections::{BTreeMap, VecDeque};
use std::mem::align_of;
use std::ptr;
use std::thread;

const ROLE_INITIATOR: u32 = 1;
const ROLE_RESPONDER: u32 = 2;
const GUARD_BYTES: usize = 32;
const GUARD_VALUE: u8 = 0x6d;
const DIRTY_VALUE: u8 = 0xa5;

struct GuardedBytes {
    storage: Vec<u8>,
    payload_len: usize,
}

impl Drop for GuardedBytes {
    fn drop(&mut self) {
        self.storage.fill(0);
    }
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

#[derive(Clone)]
struct QueuedMessage {
    bytes: Vec<u8>,
}

struct Participant {
    role: u32,
    state: Vec<u8>,
    revision: u64,
    sending_epoch: u64,
    receiving_epoch: u64,
    epoch_secrets: BTreeMap<u64, [u8; EPOCH_SECRET_BYTES as usize]>,
}

impl Participant {
    fn new(
        role: u32,
        session: &[u8; SESSION_ID_BYTES as usize],
        state_key: &[u8; STATE_KEY_BYTES as usize],
        shared_secret: &[u8; SHARED_SECRET_BYTES as usize],
    ) -> Self {
        Self {
            role,
            state: initialize_state(role, session, state_key, shared_secret),
            revision: 0,
            sending_epoch: 0,
            receiving_epoch: 0,
            epoch_secrets: BTreeMap::new(),
        }
    }

    fn validate_current(
        &self,
        session: &[u8; SESSION_ID_BYTES as usize],
        state_key: &[u8; STATE_KEY_BYTES as usize],
    ) {
        let status = unsafe {
            lg_scka_v1_state_validate(
                self.role,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                self.revision,
                self.state.as_ptr(),
                self.state.len() as u64,
            )
        };
        assert_eq!(status, STATUS_OK);
    }

    fn record_secret(&mut self, epoch: u64, secret: [u8; EPOCH_SECRET_BYTES as usize]) {
        if let Some(existing) = self.epoch_secrets.insert(epoch, secret) {
            if existing != secret {
                panic!("epoch {epoch} produced divergent secrets");
            }
        }
    }

    fn send(
        &mut self,
        session: &[u8; SESSION_ID_BYTES as usize],
        state_key: &[u8; STATE_KEY_BYTES as usize],
    ) -> QueuedMessage {
        let prior_state = self.state.clone();
        let prior_revision = self.revision;
        let mut output = SendOutputs::new();
        let status = unsafe {
            lg_scka_v1_send(
                self.role,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                prior_revision,
                prior_state.as_ptr(),
                prior_state.len() as u64,
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
        assert_eq!(status, STATUS_OK);
        assert!((MIN_STATE_BYTES..=MAX_STATE_BYTES).contains(&output.state_len));
        assert!((1..=MAX_MESSAGE_BYTES).contains(&output.message_len));
        assert!(output.epoch >= self.sending_epoch);
        output.state.assert_guards();
        output.message.assert_guards();
        output.secret.assert_guards();

        self.state = output.state.payload()[..output.state_len as usize].to_vec();
        self.revision = prior_revision + 1;
        self.sending_epoch = output.epoch;
        if output.has_secret == 1 {
            assert!((1..=MAX_COUNTER).contains(&output.secret_epoch));
            let mut secret = [0_u8; EPOCH_SECRET_BYTES as usize];
            secret.copy_from_slice(output.secret.payload());
            output.secret.payload_mut().fill(0);
            self.record_secret(output.secret_epoch, secret);
        } else {
            assert_eq!(output.has_secret, 0);
            assert_eq!(output.secret_epoch, 0);
            assert!(output.secret.payload().iter().all(|byte| *byte == 0));
        }
        self.validate_current(session, state_key);

        let stale_status = unsafe {
            lg_scka_v1_state_validate(
                self.role,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                self.revision,
                prior_state.as_ptr(),
                prior_state.len() as u64,
            )
        };
        assert_eq!(stale_status, STATUS_STATE_REVISION);

        QueuedMessage {
            bytes: output.message.payload()[..output.message_len as usize].to_vec(),
        }
    }

    fn receive(
        &mut self,
        session: &[u8; SESSION_ID_BYTES as usize],
        state_key: &[u8; STATE_KEY_BYTES as usize],
        message: &QueuedMessage,
    ) {
        let prior_state = self.state.clone();
        let prior_revision = self.revision;
        let mut output = ReceiveOutputs::new();
        let status = unsafe {
            lg_scka_v1_receive(
                self.role,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                prior_revision,
                prior_state.as_ptr(),
                prior_state.len() as u64,
                message.bytes.as_ptr(),
                message.bytes.len() as u64,
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
        assert_eq!(status, STATUS_OK);
        assert!((MIN_STATE_BYTES..=MAX_STATE_BYTES).contains(&output.state_len));
        assert!(output.epoch >= self.receiving_epoch);
        output.state.assert_guards();
        output.secret.assert_guards();

        self.state = output.state.payload()[..output.state_len as usize].to_vec();
        self.revision = prior_revision + 1;
        self.receiving_epoch = output.epoch;
        if output.has_secret == 1 {
            assert!((1..=MAX_COUNTER).contains(&output.secret_epoch));
            let mut secret = [0_u8; EPOCH_SECRET_BYTES as usize];
            secret.copy_from_slice(output.secret.payload());
            output.secret.payload_mut().fill(0);
            self.record_secret(output.secret_epoch, secret);
        } else {
            assert_eq!(output.has_secret, 0);
            assert_eq!(output.secret_epoch, 0);
            assert!(output.secret.payload().iter().all(|byte| *byte == 0));
        }
        self.validate_current(session, state_key);

        let stale_status = unsafe {
            lg_scka_v1_state_validate(
                self.role,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                self.revision,
                prior_state.as_ptr(),
                prior_state.len() as u64,
            )
        };
        assert_eq!(stale_status, STATUS_STATE_REVISION);
    }

    fn wipe(&mut self) {
        self.state.fill(0);
        for secret in self.epoch_secrets.values_mut() {
            secret.fill(0);
        }
        self.epoch_secrets.clear();
    }
}

fn pop_scheduled(queue: &mut VecDeque<QueuedMessage>, newest_first: bool) -> Option<QueuedMessage> {
    if newest_first {
        queue.pop_back()
    } else {
        queue.pop_front()
    }
}

fn run_stateful_session(session_index: u8) {
    let session = [0x10_u8.wrapping_add(session_index); SESSION_ID_BYTES as usize];
    let state_key = [0x40_u8.wrapping_add(session_index); STATE_KEY_BYTES as usize];
    let shared_secret = [0x70_u8.wrapping_add(session_index); SHARED_SECRET_BYTES as usize];
    let mut alice = Participant::new(ROLE_INITIATOR, &session, &state_key, &shared_secret);
    let mut bob = Participant::new(ROLE_RESPONDER, &session, &state_key, &shared_secret);
    let mut alice_to_bob = VecDeque::<QueuedMessage>::new();
    let mut bob_to_alice = VecDeque::<QueuedMessage>::new();
    let mut schedule = 0x4c41_5945_5247_0000_u64 | u64::from(session_index);
    let mut delivered = 0_usize;
    let mut replayed = 0_usize;
    let mut dropped = 0_usize;

    for round in 0..128_usize {
        let alice_message = alice.send(&session, &state_key);
        if next_u64(&mut schedule) % 11 == 0 {
            dropped += 1;
        } else {
            alice_to_bob.push_back(alice_message);
        }

        let bob_message = bob.send(&session, &state_key);
        if next_u64(&mut schedule) % 13 == 0 {
            dropped += 1;
        } else {
            bob_to_alice.push_back(bob_message);
        }

        if round % 3 != 0 || alice_to_bob.len() > 8 {
            if let Some(message) =
                pop_scheduled(&mut alice_to_bob, next_u64(&mut schedule) & 1 == 1)
            {
                bob.receive(&session, &state_key, &message);
                delivered += 1;
                if round % 17 == 0 {
                    bob.receive(&session, &state_key, &message);
                    replayed += 1;
                }
            }
        }
        if round % 4 != 0 || bob_to_alice.len() > 8 {
            if let Some(message) =
                pop_scheduled(&mut bob_to_alice, next_u64(&mut schedule) & 1 == 1)
            {
                alice.receive(&session, &state_key, &message);
                delivered += 1;
                if round % 19 == 0 {
                    alice.receive(&session, &state_key, &message);
                    replayed += 1;
                }
            }
        }
        assert!(alice_to_bob.len() <= 9);
        assert!(bob_to_alice.len() <= 9);
    }

    while let Some(message) = pop_scheduled(&mut alice_to_bob, schedule & 1 == 1) {
        bob.receive(&session, &state_key, &message);
        delivered += 1;
        schedule = next_u64(&mut schedule);
    }
    while let Some(message) = pop_scheduled(&mut bob_to_alice, schedule & 1 == 1) {
        alice.receive(&session, &state_key, &message);
        delivered += 1;
        schedule = next_u64(&mut schedule);
    }

    let mut matching_secrets = 0_usize;
    for (epoch, alice_secret) in &alice.epoch_secrets {
        if let Some(bob_secret) = bob.epoch_secrets.get(epoch) {
            if alice_secret != bob_secret {
                panic!("session {session_index}, epoch {epoch}");
            }
            matching_secrets += 1;
        }
    }
    assert!(
        matching_secrets > 0,
        "session {session_index} made no shared-key progress"
    );
    assert!(delivered > 128);
    assert!(replayed > 0);
    assert!(dropped > 0);
    alice.wipe();
    bob.wipe();
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

#[test]
fn candidate_stateful_sessions_survive_loss_reorder_replay_restart_and_concurrency() {
    let workers = (0_u8..4)
        .map(|session_index| thread::spawn(move || run_stateful_session(session_index)))
        .collect::<Vec<_>>();

    for worker in workers {
        worker.join().expect("stateful SCKA campaign worker");
    }
}
