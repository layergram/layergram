// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use layergram_scka::{
    lg_scka_v1_initialize, lg_scka_v1_send, EPOCH_SECRET_BYTES, MAX_COUNTER, MAX_MESSAGE_BYTES,
    MAX_STATE_BYTES, MIN_STATE_BYTES, SESSION_ID_BYTES, SHARED_SECRET_BYTES, STATE_KEY_BYTES,
    STATUS_ALLOCATION, STATUS_AUTHENTICATION, STATUS_BACKEND, STATUS_ENTROPY,
    STATUS_INVALID_ARGUMENT, STATUS_OK, STATUS_STATE_FORMAT, STATUS_STATE_REVISION,
};
use std::sync::OnceLock;

pub const ROLE_INITIATOR: u32 = 1;
pub const ROLE_RESPONDER: u32 = 2;

pub struct Fixture {
    pub session: [u8; SESSION_ID_BYTES as usize],
    pub state_key: [u8; STATE_KEY_BYTES as usize],
    pub initiator_state: Vec<u8>,
    pub responder_state: Vec<u8>,
    pub first_message: Vec<u8>,
}

pub fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(Fixture::new)
}

impl Fixture {
    fn new() -> Self {
        let session = [0x51_u8; SESSION_ID_BYTES as usize];
        let state_key = [0x62_u8; STATE_KEY_BYTES as usize];
        let shared_secret = [0x73_u8; SHARED_SECRET_BYTES as usize];
        let initiator_state =
            initialize_state(ROLE_INITIATOR, &session, &state_key, &shared_secret);
        let responder_state =
            initialize_state(ROLE_RESPONDER, &session, &state_key, &shared_secret);
        let first_message = first_message(&session, &state_key, &initiator_state);
        Self {
            session,
            state_key,
            initiator_state,
            responder_state,
            first_message,
        }
    }
}

fn initialize_state(
    role: u32,
    session: &[u8; SESSION_ID_BYTES as usize],
    state_key: &[u8; STATE_KEY_BYTES as usize],
    shared_secret: &[u8; SHARED_SECRET_BYTES as usize],
) -> Vec<u8> {
    let mut state = vec![0_u8; MAX_STATE_BYTES as usize];
    let mut state_len = 0_u64;
    let status = unsafe {
        lg_scka_v1_initialize(
            role,
            session.as_ptr(),
            session.len() as u64,
            state_key.as_ptr(),
            state_key.len() as u64,
            shared_secret.as_ptr(),
            shared_secret.len() as u64,
            state.as_mut_ptr(),
            state.len() as u64,
            &mut state_len,
        )
    };
    assert_eq!(status, STATUS_OK, "fuzz fixture initialization failed");
    assert!((MIN_STATE_BYTES..=MAX_STATE_BYTES).contains(&state_len));
    state.truncate(state_len as usize);
    state
}

fn first_message(
    session: &[u8; SESSION_ID_BYTES as usize],
    state_key: &[u8; STATE_KEY_BYTES as usize],
    initiator_state: &[u8],
) -> Vec<u8> {
    let mut state_out = vec![0_u8; MAX_STATE_BYTES as usize];
    let mut message_out = vec![0_u8; MAX_MESSAGE_BYTES as usize];
    let mut epoch_secret = [0_u8; EPOCH_SECRET_BYTES as usize];
    let mut state_out_len = 0_u64;
    let mut message_out_len = 0_u64;
    let mut sending_epoch = 0_u64;
    let mut has_epoch_secret = 0_u32;
    let mut epoch_secret_epoch = 0_u64;
    let status = unsafe {
        lg_scka_v1_send(
            ROLE_INITIATOR,
            session.as_ptr(),
            session.len() as u64,
            state_key.as_ptr(),
            state_key.len() as u64,
            0,
            initiator_state.as_ptr(),
            initiator_state.len() as u64,
            state_out.as_mut_ptr(),
            state_out.len() as u64,
            &mut state_out_len,
            message_out.as_mut_ptr(),
            message_out.len() as u64,
            &mut message_out_len,
            &mut sending_epoch,
            &mut has_epoch_secret,
            &mut epoch_secret_epoch,
            epoch_secret.as_mut_ptr(),
            epoch_secret.len() as u64,
        )
    };
    epoch_secret.fill(0);
    state_out.fill(0);
    assert_eq!(status, STATUS_OK, "fuzz fixture first send failed");
    assert!((1..=MAX_MESSAGE_BYTES).contains(&message_out_len));
    message_out.truncate(message_out_len as usize);
    message_out
}

pub fn assert_candidate_status(status: i32) {
    assert!(matches!(
        status,
        STATUS_OK
            | STATUS_INVALID_ARGUMENT
            | STATUS_AUTHENTICATION
            | STATUS_STATE_FORMAT
            | STATUS_STATE_REVISION
            | STATUS_BACKEND
            | STATUS_ENTROPY
            | STATUS_ALLOCATION
    ));
}

pub fn state_candidate(data: &[u8], valid: &[u8]) -> (u32, u64, Vec<u8>) {
    if data.is_empty() {
        return (ROLE_INITIATOR, 0, valid.to_vec());
    }
    let payload = &data[1..];
    match data[0] % 6 {
        0 => (ROLE_INITIATOR, 0, payload.to_vec()),
        1 => (ROLE_INITIATOR, 0, valid.to_vec()),
        2 => {
            let mut candidate = valid.to_vec();
            for pair in payload.chunks(2) {
                let first = pair[0] as usize;
                let second = pair.get(1).copied().unwrap_or(0) as usize;
                let index = ((first << 8) | second) % candidate.len();
                candidate[index] ^= 1_u8 << (second & 7);
            }
            (ROLE_INITIATOR, 0, candidate)
        }
        3 => {
            let length = payload.iter().take(8).fold(0_usize, |value, byte| {
                value.wrapping_mul(257).wrapping_add(*byte as usize)
            }) % (valid.len() + 1);
            (ROLE_INITIATOR, 0, valid[..length].to_vec())
        }
        4 => {
            let mut candidate = valid.to_vec();
            let available = MAX_STATE_BYTES as usize - candidate.len();
            candidate.extend_from_slice(&payload[..payload.len().min(available)]);
            (ROLE_INITIATOR, 0, candidate)
        }
        _ => {
            let role = if payload.first().copied().unwrap_or(0) & 1 == 0 {
                ROLE_INITIATOR
            } else {
                ROLE_RESPONDER
            };
            let revision = payload
                .iter()
                .take(8)
                .enumerate()
                .fold(0_u64, |value, (index, byte)| {
                    value | ((*byte as u64) << (index * 8))
                })
                & MAX_COUNTER;
            (role, revision, valid.to_vec())
        }
    }
}

pub fn message_candidate(data: &[u8], valid: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return valid.to_vec();
    }
    let payload = &data[1..];
    match data[0] % 6 {
        0 => payload[..payload.len().min(MAX_MESSAGE_BYTES as usize)].to_vec(),
        1 => valid.to_vec(),
        2 => {
            let mut candidate = valid.to_vec();
            for pair in payload.chunks(2) {
                let first = pair[0] as usize;
                let second = pair.get(1).copied().unwrap_or(0) as usize;
                let index = ((first << 8) | second) % candidate.len();
                candidate[index] ^= 1_u8 << (second & 7);
            }
            candidate
        }
        3 => {
            let length = payload.iter().take(8).fold(0_usize, |value, byte| {
                value.wrapping_mul(257).wrapping_add(*byte as usize)
            }) % (valid.len() + 1);
            valid[..length].to_vec()
        }
        4 => {
            let mut candidate = valid.to_vec();
            let available = MAX_MESSAGE_BYTES as usize - candidate.len();
            candidate.extend_from_slice(&payload[..payload.len().min(available)]);
            candidate
        }
        _ => {
            let mut candidate = valid.to_vec();
            for (index, byte) in payload.iter().copied().enumerate() {
                let destination = index % candidate.len();
                candidate[destination] = byte;
            }
            candidate
        }
    }
}
