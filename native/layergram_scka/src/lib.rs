// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_char;
use core::ptr;

#[cfg(feature = "candidate-ffi")]
use crate::state_envelope::StateRole;

#[allow(dead_code)]
mod authenticated_braid;
#[allow(dead_code)]
mod braid_authenticator;
#[allow(dead_code)]
mod braid_message;
#[allow(dead_code)]
mod braid_state_payload;
#[allow(dead_code)]
mod braid_transition;
#[allow(dead_code)]
mod entropy;
#[allow(dead_code)]
mod erasure;
#[allow(dead_code)]
mod incremental_mlkem;
#[allow(dead_code)]
mod state_envelope;

pub const ABI_VERSION: u32 = 1;
pub const PROTOCOL_REVISION: u32 = 1;
pub const STATE_FORMAT_VERSION: u32 = 2;
pub const SESSION_ID_BYTES: u64 = 16;
pub const STATE_KEY_BYTES: u64 = 32;
pub const SHARED_SECRET_BYTES: u64 = 32;
pub const EPOCH_SECRET_BYTES: u64 = 32;
pub const STATE_HEADER_BYTES: u64 = 80;
pub const STATE_TAG_BYTES: u64 = 16;
pub const MIN_STATE_BYTES: u64 = 97;
pub const MAX_STATE_BYTES: u64 = 196_608;
pub const MAX_MESSAGE_BYTES: u64 = 512;
pub const MAX_COUNTER: u64 = 0x7fff_ffff_ffff_ffff;

pub const STATUS_OK: i32 = 0;
pub const STATUS_INVALID_ARGUMENT: i32 = -1;
pub const STATUS_NOT_READY: i32 = -2;
pub const STATUS_AUTHENTICATION: i32 = -3;
pub const STATUS_STATE_FORMAT: i32 = -4;
pub const STATUS_STATE_REVISION: i32 = -5;
pub const STATUS_BACKEND: i32 = -6;
pub const STATUS_ENTROPY: i32 = -7;
pub const STATUS_SELF_TEST: i32 = -8;
pub const STATUS_ALLOCATION: i32 = -9;

const ROLE_INITIATOR: u32 = 1;
const ROLE_RESPONDER: u32 = 2;
#[cfg(not(feature = "candidate-ffi"))]
const IMPLEMENTATION_ID: &[u8] = b"layergram-scka-scaffold-r1-abi1\0";
#[cfg(feature = "candidate-ffi")]
const IMPLEMENTATION_ID: &[u8] = b"layergram-scka-private-r1-abi1-state2-build1\0";

fn valid_role(role: u32) -> bool {
    role == ROLE_INITIATOR || role == ROLE_RESPONDER
}

fn valid_exact_input(pointer: *const u8, length: u64, expected: u64) -> bool {
    !pointer.is_null() && length == expected
}

fn valid_optional_input(pointer: *const u8, length: u64, maximum: u64) -> bool {
    length <= maximum && ((length == 0 && pointer.is_null()) || !pointer.is_null())
}

fn valid_state_input(pointer: *const u8, length: u64) -> bool {
    !pointer.is_null() && (MIN_STATE_BYTES..=MAX_STATE_BYTES).contains(&length)
}

fn valid_revision(revision: u64) -> bool {
    revision <= MAX_COUNTER
}

#[cfg(feature = "candidate-ffi")]
fn state_role(role: u32) -> Option<StateRole> {
    match role {
        ROLE_INITIATOR => Some(StateRole::Initiator),
        ROLE_RESPONDER => Some(StateRole::Responder),
        _ => None,
    }
}

#[cfg(feature = "candidate-ffi")]
fn candidate_status(error: authenticated_braid::AuthenticatedBraidError) -> i32 {
    use authenticated_braid::AuthenticatedBraidError;
    match error {
        AuthenticatedBraidError::Authentication => STATUS_AUTHENTICATION,
        AuthenticatedBraidError::StateRevision => STATUS_STATE_REVISION,
        AuthenticatedBraidError::StateFormat => STATUS_STATE_FORMAT,
        AuthenticatedBraidError::MessageFormat => STATUS_INVALID_ARGUMENT,
        AuthenticatedBraidError::Entropy => STATUS_ENTROPY,
        AuthenticatedBraidError::Transition(_) | AuthenticatedBraidError::Primitive => {
            STATUS_BACKEND
        }
    }
}

#[cfg(feature = "candidate-ffi")]
unsafe fn input_bytes<'a>(pointer: *const u8, length: u64) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(pointer, length as usize) }
}

#[cfg(feature = "candidate-ffi")]
unsafe fn output_bytes<'a>(pointer: *mut u8, length: u64) -> &'a mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(pointer, length as usize) }
}

#[cfg(feature = "candidate-ffi")]
fn copy_candidate_output(destination: &mut [u8], value: &[u8]) -> Result<u64, i32> {
    if value.is_empty() || value.len() > destination.len() {
        return Err(STATUS_BACKEND);
    }
    destination[..value.len()].copy_from_slice(value);
    Ok(value.len() as u64)
}

#[cfg(feature = "candidate-ffi")]
struct SelfTestEntropy {
    call: usize,
}

#[cfg(feature = "candidate-ffi")]
impl entropy::EntropySource for SelfTestEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), entropy::EntropyError> {
        self.call += 1;
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = ((self.call * 37 + index * 13 + 7) & 0xff) as u8;
        }
        Ok(())
    }
}

#[cfg(feature = "candidate-ffi")]
fn candidate_self_test() -> bool {
    const SESSION: [u8; SESSION_ID_BYTES as usize] = [0x31; SESSION_ID_BYTES as usize];
    const SHARED_SECRET: [u8; SHARED_SECRET_BYTES as usize] = [0x42; SHARED_SECRET_BYTES as usize];
    const STATE_KEY: [u8; STATE_KEY_BYTES as usize] = [0x53; STATE_KEY_BYTES as usize];

    let result = (|| {
        let initiator = authenticated_braid::initialize_authenticated(
            StateRole::Initiator,
            SESSION,
            &SHARED_SECRET,
            &STATE_KEY,
        )?;
        let responder = authenticated_braid::initialize_authenticated(
            StateRole::Responder,
            SESSION,
            &SHARED_SECRET,
            &STATE_KEY,
        )?;
        authenticated_braid::validate_authenticated_state(
            StateRole::Initiator,
            &SESSION,
            &STATE_KEY,
            0,
            &initiator,
        )?;
        let sent = authenticated_braid::send_with_entropy(
            StateRole::Initiator,
            &SESSION,
            &STATE_KEY,
            0,
            &initiator,
            &mut SelfTestEntropy { call: 0 },
        )?;
        if sent.state_revision() != 1 || sent.message().is_empty() {
            return Ok::<bool, authenticated_braid::AuthenticatedBraidError>(false);
        }
        authenticated_braid::validate_authenticated_state(
            StateRole::Initiator,
            &SESSION,
            &STATE_KEY,
            1,
            sent.sealed_state(),
        )?;
        let received = authenticated_braid::receive_authenticated(
            StateRole::Responder,
            &SESSION,
            &STATE_KEY,
            0,
            &responder,
            sent.message(),
        )?;
        if received.state_revision() != 1 || received.receiving_epoch() != sent.sending_epoch() {
            return Ok(false);
        }
        authenticated_braid::validate_authenticated_state(
            StateRole::Responder,
            &SESSION,
            &STATE_KEY,
            1,
            received.sealed_state(),
        )?;
        Ok(true)
    })();
    result.unwrap_or(false)
}

fn valid_exact_output(pointer: *mut u8, capacity: u64, expected: u64) -> bool {
    !pointer.is_null() && capacity == expected
}

unsafe fn reset_bytes(pointer: *mut u8, length: u64) {
    unsafe {
        ptr::write_bytes(pointer, 0, length as usize);
    }
}

unsafe fn reset_u64(pointer: *mut u64) {
    unsafe {
        ptr::write(pointer, 0);
    }
}

unsafe fn reset_u32(pointer: *mut u32) {
    unsafe {
        ptr::write(pointer, 0);
    }
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_protocol_revision() -> u32 {
    PROTOCOL_REVISION
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_state_format_version() -> u32 {
    STATE_FORMAT_VERSION
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_implementation_id() -> *const c_char {
    IMPLEMENTATION_ID.as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_session_id_bytes() -> u32 {
    SESSION_ID_BYTES as u32
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_state_key_bytes() -> u32 {
    STATE_KEY_BYTES as u32
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_epoch_secret_bytes() -> u32 {
    EPOCH_SECRET_BYTES as u32
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_state_header_bytes() -> u32 {
    STATE_HEADER_BYTES as u32
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_state_tag_bytes() -> u32 {
    STATE_TAG_BYTES as u32
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_min_state_bytes() -> u32 {
    MIN_STATE_BYTES as u32
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_max_state_bytes() -> u32 {
    MAX_STATE_BYTES as u32
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_max_message_bytes() -> u32 {
    MAX_MESSAGE_BYTES as u32
}

#[no_mangle]
pub extern "C" fn lg_scka_v1_self_test() -> i32 {
    #[cfg(feature = "candidate-ffi")]
    {
        if candidate_self_test() {
            STATUS_OK
        } else {
            STATUS_SELF_TEST
        }
    }
    #[cfg(not(feature = "candidate-ffi"))]
    {
        STATUS_NOT_READY
    }
}

/// # Safety
///
/// Every non-null pointer must reference readable memory for its declared
/// length. The scaffold does not dereference inputs, but the contract is frozen
/// for the future implementation that will.
#[no_mangle]
pub unsafe extern "C" fn lg_scka_v1_state_validate(
    role: u32,
    session_id: *const u8,
    session_id_len: u64,
    state_key: *const u8,
    state_key_len: u64,
    expected_state_revision: u64,
    state_in: *const u8,
    state_in_len: u64,
) -> i32 {
    if !valid_role(role)
        || !valid_exact_input(session_id, session_id_len, SESSION_ID_BYTES)
        || !valid_exact_input(state_key, state_key_len, STATE_KEY_BYTES)
        || !valid_revision(expected_state_revision)
        || !valid_state_input(state_in, state_in_len)
    {
        return STATUS_INVALID_ARGUMENT;
    }
    #[cfg(feature = "candidate-ffi")]
    {
        let role = state_role(role).expect("validated role");
        let session = unsafe { input_bytes(session_id, session_id_len) };
        let key = unsafe { input_bytes(state_key, state_key_len) };
        let state = unsafe { input_bytes(state_in, state_in_len) };
        match authenticated_braid::validate_authenticated_state(
            role,
            session,
            key,
            expected_state_revision,
            state,
        ) {
            Ok(()) => STATUS_OK,
            Err(error) => candidate_status(error),
        }
    }
    #[cfg(not(feature = "candidate-ffi"))]
    {
        STATUS_NOT_READY
    }
}

/// # Safety
///
/// Input pointers must be readable for their declared lengths. Output pointers
/// must be writable for the exact capacities required by the public header.
#[no_mangle]
pub unsafe extern "C" fn lg_scka_v1_initialize(
    role: u32,
    session_id: *const u8,
    session_id_len: u64,
    state_key: *const u8,
    state_key_len: u64,
    shared_secret: *const u8,
    shared_secret_len: u64,
    state_out: *mut u8,
    state_out_capacity: u64,
    state_out_len: *mut u64,
) -> i32 {
    if !valid_exact_output(state_out, state_out_capacity, MAX_STATE_BYTES)
        || state_out_len.is_null()
    {
        return STATUS_INVALID_ARGUMENT;
    }
    unsafe {
        reset_bytes(state_out, state_out_capacity);
        reset_u64(state_out_len);
    }
    if !valid_role(role)
        || !valid_exact_input(session_id, session_id_len, SESSION_ID_BYTES)
        || !valid_exact_input(state_key, state_key_len, STATE_KEY_BYTES)
        || !valid_exact_input(shared_secret, shared_secret_len, SHARED_SECRET_BYTES)
    {
        return STATUS_INVALID_ARGUMENT;
    }
    #[cfg(feature = "candidate-ffi")]
    {
        let role = state_role(role).expect("validated role");
        let session_slice = unsafe { input_bytes(session_id, session_id_len) };
        let session: [u8; SESSION_ID_BYTES as usize] =
            session_slice.try_into().expect("validated session length");
        let key = unsafe { input_bytes(state_key, state_key_len) };
        let shared = unsafe { input_bytes(shared_secret, shared_secret_len) };
        let destination = unsafe { output_bytes(state_out, state_out_capacity) };
        match authenticated_braid::initialize_authenticated(role, session, shared, key) {
            Ok(state) => match copy_candidate_output(destination, &state) {
                Ok(length) => {
                    unsafe { ptr::write(state_out_len, length) };
                    STATUS_OK
                }
                Err(status) => status,
            },
            Err(error) => candidate_status(error),
        }
    }
    #[cfg(not(feature = "candidate-ffi"))]
    {
        STATUS_NOT_READY
    }
}

/// # Safety
///
/// Input pointers must be readable for their declared lengths. Output pointers
/// must be writable for the exact capacities required by the public header.
#[no_mangle]
pub unsafe extern "C" fn lg_scka_v1_send(
    role: u32,
    session_id: *const u8,
    session_id_len: u64,
    state_key: *const u8,
    state_key_len: u64,
    expected_state_revision: u64,
    state_in: *const u8,
    state_in_len: u64,
    state_out: *mut u8,
    state_out_capacity: u64,
    state_out_len: *mut u64,
    message_out: *mut u8,
    message_out_capacity: u64,
    message_out_len: *mut u64,
    sending_epoch_out: *mut u64,
    has_epoch_secret_out: *mut u32,
    epoch_secret_epoch_out: *mut u64,
    epoch_secret_out: *mut u8,
    epoch_secret_out_len: u64,
) -> i32 {
    if !valid_exact_output(state_out, state_out_capacity, MAX_STATE_BYTES)
        || !valid_exact_output(message_out, message_out_capacity, MAX_MESSAGE_BYTES)
        || !valid_exact_output(epoch_secret_out, epoch_secret_out_len, EPOCH_SECRET_BYTES)
        || state_out_len.is_null()
        || message_out_len.is_null()
        || sending_epoch_out.is_null()
        || has_epoch_secret_out.is_null()
        || epoch_secret_epoch_out.is_null()
    {
        return STATUS_INVALID_ARGUMENT;
    }
    unsafe {
        reset_bytes(state_out, state_out_capacity);
        reset_u64(state_out_len);
        reset_bytes(message_out, message_out_capacity);
        reset_u64(message_out_len);
        reset_u64(sending_epoch_out);
        reset_u32(has_epoch_secret_out);
        reset_u64(epoch_secret_epoch_out);
        reset_bytes(epoch_secret_out, epoch_secret_out_len);
    }
    if !valid_role(role)
        || !valid_exact_input(session_id, session_id_len, SESSION_ID_BYTES)
        || !valid_exact_input(state_key, state_key_len, STATE_KEY_BYTES)
        || !valid_revision(expected_state_revision)
        || !valid_state_input(state_in, state_in_len)
    {
        return STATUS_INVALID_ARGUMENT;
    }
    #[cfg(feature = "candidate-ffi")]
    {
        let role = state_role(role).expect("validated role");
        let session = unsafe { input_bytes(session_id, session_id_len) };
        let key = unsafe { input_bytes(state_key, state_key_len) };
        let state = unsafe { input_bytes(state_in, state_in_len) };
        let state_destination = unsafe { output_bytes(state_out, state_out_capacity) };
        let message_destination = unsafe { output_bytes(message_out, message_out_capacity) };
        match authenticated_braid::send_authenticated(
            role,
            session,
            key,
            expected_state_revision,
            state,
        ) {
            Ok(candidate) => {
                let (sealed, message, revision, sending_epoch, output) = candidate.into_parts();
                if revision != expected_state_revision + 1 {
                    return STATUS_STATE_REVISION;
                }
                let state_length = match copy_candidate_output(state_destination, &sealed) {
                    Ok(length) => length,
                    Err(status) => return status,
                };
                let message_length = match copy_candidate_output(message_destination, &message) {
                    Ok(length) => length,
                    Err(status) => {
                        state_destination.fill(0);
                        return status;
                    }
                };
                unsafe {
                    ptr::write(state_out_len, state_length);
                    ptr::write(message_out_len, message_length);
                    ptr::write(sending_epoch_out, sending_epoch);
                }
                if let Some(output) = output.as_ref() {
                    if output.key_bytes().len() != EPOCH_SECRET_BYTES as usize {
                        state_destination.fill(0);
                        message_destination.fill(0);
                        unsafe {
                            reset_u64(state_out_len);
                            reset_u64(message_out_len);
                            reset_u64(sending_epoch_out);
                        }
                        return STATUS_BACKEND;
                    }
                    let secret_destination =
                        unsafe { output_bytes(epoch_secret_out, epoch_secret_out_len) };
                    secret_destination.copy_from_slice(output.key_bytes());
                    unsafe {
                        ptr::write(has_epoch_secret_out, 1);
                        ptr::write(epoch_secret_epoch_out, output.epoch());
                    }
                }
                STATUS_OK
            }
            Err(error) => candidate_status(error),
        }
    }
    #[cfg(not(feature = "candidate-ffi"))]
    {
        STATUS_NOT_READY
    }
}

/// # Safety
///
/// Input pointers must be readable for their declared lengths. Output pointers
/// must be writable for the exact capacities required by the public header.
#[no_mangle]
pub unsafe extern "C" fn lg_scka_v1_receive(
    role: u32,
    session_id: *const u8,
    session_id_len: u64,
    state_key: *const u8,
    state_key_len: u64,
    expected_state_revision: u64,
    state_in: *const u8,
    state_in_len: u64,
    message_in: *const u8,
    message_in_len: u64,
    state_out: *mut u8,
    state_out_capacity: u64,
    state_out_len: *mut u64,
    receiving_epoch_out: *mut u64,
    has_epoch_secret_out: *mut u32,
    epoch_secret_epoch_out: *mut u64,
    epoch_secret_out: *mut u8,
    epoch_secret_out_len: u64,
) -> i32 {
    if !valid_exact_output(state_out, state_out_capacity, MAX_STATE_BYTES)
        || !valid_exact_output(epoch_secret_out, epoch_secret_out_len, EPOCH_SECRET_BYTES)
        || state_out_len.is_null()
        || receiving_epoch_out.is_null()
        || has_epoch_secret_out.is_null()
        || epoch_secret_epoch_out.is_null()
    {
        return STATUS_INVALID_ARGUMENT;
    }
    unsafe {
        reset_bytes(state_out, state_out_capacity);
        reset_u64(state_out_len);
        reset_u64(receiving_epoch_out);
        reset_u32(has_epoch_secret_out);
        reset_u64(epoch_secret_epoch_out);
        reset_bytes(epoch_secret_out, epoch_secret_out_len);
    }
    if !valid_role(role)
        || !valid_exact_input(session_id, session_id_len, SESSION_ID_BYTES)
        || !valid_exact_input(state_key, state_key_len, STATE_KEY_BYTES)
        || !valid_revision(expected_state_revision)
        || !valid_state_input(state_in, state_in_len)
        || !valid_optional_input(message_in, message_in_len, MAX_MESSAGE_BYTES)
    {
        return STATUS_INVALID_ARGUMENT;
    }
    #[cfg(feature = "candidate-ffi")]
    {
        if message_in_len == 0 {
            return STATUS_INVALID_ARGUMENT;
        }
        let role = state_role(role).expect("validated role");
        let session = unsafe { input_bytes(session_id, session_id_len) };
        let key = unsafe { input_bytes(state_key, state_key_len) };
        let state = unsafe { input_bytes(state_in, state_in_len) };
        let message = unsafe { input_bytes(message_in, message_in_len) };
        let state_destination = unsafe { output_bytes(state_out, state_out_capacity) };
        match authenticated_braid::receive_authenticated(
            role,
            session,
            key,
            expected_state_revision,
            state,
            message,
        ) {
            Ok(candidate) => {
                let (sealed, revision, receiving_epoch, output) = candidate.into_parts();
                if revision != expected_state_revision + 1 {
                    return STATUS_STATE_REVISION;
                }
                let state_length = match copy_candidate_output(state_destination, &sealed) {
                    Ok(length) => length,
                    Err(status) => return status,
                };
                unsafe {
                    ptr::write(state_out_len, state_length);
                    ptr::write(receiving_epoch_out, receiving_epoch);
                }
                if let Some(output) = output.as_ref() {
                    if output.key_bytes().len() != EPOCH_SECRET_BYTES as usize {
                        state_destination.fill(0);
                        unsafe {
                            reset_u64(state_out_len);
                            reset_u64(receiving_epoch_out);
                        }
                        return STATUS_BACKEND;
                    }
                    let secret_destination =
                        unsafe { output_bytes(epoch_secret_out, epoch_secret_out_len) };
                    secret_destination.copy_from_slice(output.key_bytes());
                    unsafe {
                        ptr::write(has_epoch_secret_out, 1);
                        ptr::write(epoch_secret_epoch_out, output.epoch());
                    }
                }
                STATUS_OK
            }
            Err(error) => candidate_status(error),
        }
    }
    #[cfg(not(feature = "candidate-ffi"))]
    {
        STATUS_NOT_READY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[cfg(not(feature = "candidate-ffi"))]
    #[test]
    fn metadata_is_frozen_and_scaffold_cannot_activate() {
        assert_eq!(lg_scka_v1_abi_version(), 1);
        assert_eq!(lg_scka_v1_protocol_revision(), 1);
        assert_eq!(lg_scka_v1_state_format_version(), 2);
        assert_eq!(lg_scka_v1_session_id_bytes(), 16);
        assert_eq!(lg_scka_v1_state_key_bytes(), 32);
        assert_eq!(lg_scka_v1_epoch_secret_bytes(), 32);
        assert_eq!(lg_scka_v1_state_header_bytes(), 80);
        assert_eq!(lg_scka_v1_state_tag_bytes(), 16);
        assert_eq!(lg_scka_v1_min_state_bytes(), 97);
        assert_eq!(lg_scka_v1_max_state_bytes(), 196_608);
        assert_eq!(lg_scka_v1_max_message_bytes(), 512);
        let implementation = unsafe { CStr::from_ptr(lg_scka_v1_implementation_id()) };
        assert_eq!(
            implementation.to_bytes(),
            b"layergram-scka-scaffold-r1-abi1"
        );
        assert_eq!(lg_scka_v1_self_test(), STATUS_NOT_READY);
    }

    #[cfg(not(feature = "candidate-ffi"))]
    #[test]
    fn initialize_is_fail_closed_and_scrubs_outputs() {
        let session = [0x11_u8; SESSION_ID_BYTES as usize];
        let state_key = [0x22_u8; STATE_KEY_BYTES as usize];
        let shared = [0x33_u8; SHARED_SECRET_BYTES as usize];
        let mut state = vec![0xa5_u8; MAX_STATE_BYTES as usize];
        let mut state_len = u64::MAX;
        let status = unsafe {
            lg_scka_v1_initialize(
                ROLE_INITIATOR,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                shared.as_ptr(),
                shared.len() as u64,
                state.as_mut_ptr(),
                state.len() as u64,
                &mut state_len,
            )
        };
        assert_eq!(status, STATUS_NOT_READY);
        assert_eq!(state_len, 0);
        assert!(state.iter().all(|byte| *byte == 0));
    }

    #[cfg(not(feature = "candidate-ffi"))]
    #[test]
    fn transition_entrypoints_are_fail_closed_and_revision_bounded() {
        let session = [0x11_u8; SESSION_ID_BYTES as usize];
        let state_key = [0x22_u8; STATE_KEY_BYTES as usize];
        let state_in = vec![0x44_u8; MIN_STATE_BYTES as usize];
        let mut state_out = vec![0xa5_u8; MAX_STATE_BYTES as usize];
        let mut message_out = vec![0xa5_u8; MAX_MESSAGE_BYTES as usize];
        let mut secret = [0xa5_u8; EPOCH_SECRET_BYTES as usize];
        let mut state_len = u64::MAX;
        let mut message_len = u64::MAX;
        let mut epoch = u64::MAX;
        let mut has_secret = u32::MAX;
        let mut secret_epoch = u64::MAX;

        assert_eq!(
            unsafe {
                lg_scka_v1_state_validate(
                    ROLE_INITIATOR,
                    session.as_ptr(),
                    session.len() as u64,
                    state_key.as_ptr(),
                    state_key.len() as u64,
                    0,
                    state_in.as_ptr(),
                    state_in.len() as u64,
                )
            },
            STATUS_NOT_READY
        );
        assert_eq!(
            unsafe {
                lg_scka_v1_state_validate(
                    ROLE_INITIATOR,
                    session.as_ptr(),
                    session.len() as u64,
                    state_key.as_ptr(),
                    state_key.len() as u64,
                    MAX_COUNTER + 1,
                    state_in.as_ptr(),
                    state_in.len() as u64,
                )
            },
            STATUS_INVALID_ARGUMENT
        );

        let send_status = unsafe {
            lg_scka_v1_send(
                ROLE_INITIATOR,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                0,
                state_in.as_ptr(),
                state_in.len() as u64,
                state_out.as_mut_ptr(),
                state_out.len() as u64,
                &mut state_len,
                message_out.as_mut_ptr(),
                message_out.len() as u64,
                &mut message_len,
                &mut epoch,
                &mut has_secret,
                &mut secret_epoch,
                secret.as_mut_ptr(),
                secret.len() as u64,
            )
        };
        assert_eq!(send_status, STATUS_NOT_READY);
        assert_eq!(
            (state_len, message_len, epoch, has_secret, secret_epoch),
            (0, 0, 0, 0, 0)
        );
        assert!(state_out.iter().all(|byte| *byte == 0));
        assert!(message_out.iter().all(|byte| *byte == 0));
        assert!(secret.iter().all(|byte| *byte == 0));

        state_out.fill(0xa5);
        secret.fill(0xa5);
        state_len = u64::MAX;
        epoch = u64::MAX;
        has_secret = u32::MAX;
        secret_epoch = u64::MAX;
        let receive_status = unsafe {
            lg_scka_v1_receive(
                ROLE_RESPONDER,
                session.as_ptr(),
                session.len() as u64,
                state_key.as_ptr(),
                state_key.len() as u64,
                0,
                state_in.as_ptr(),
                state_in.len() as u64,
                ptr::null(),
                0,
                state_out.as_mut_ptr(),
                state_out.len() as u64,
                &mut state_len,
                &mut epoch,
                &mut has_secret,
                &mut secret_epoch,
                secret.as_mut_ptr(),
                secret.len() as u64,
            )
        };
        assert_eq!(receive_status, STATUS_NOT_READY);
        assert_eq!((state_len, epoch, has_secret, secret_epoch), (0, 0, 0, 0));
        assert!(state_out.iter().all(|byte| *byte == 0));
        assert!(secret.iter().all(|byte| *byte == 0));
    }

    #[cfg(feature = "candidate-ffi")]
    #[test]
    fn candidate_feature_connects_authenticated_composition_without_packaging() {
        let implementation = unsafe { CStr::from_ptr(lg_scka_v1_implementation_id()) };
        assert_eq!(
            implementation.to_bytes(),
            b"layergram-scka-private-r1-abi1-state2-build1"
        );
        assert_eq!(lg_scka_v1_self_test(), STATUS_OK);

        let session = [0x11_u8; SESSION_ID_BYTES as usize];
        let state_key = [0x22_u8; STATE_KEY_BYTES as usize];
        let shared = [0x33_u8; SHARED_SECRET_BYTES as usize];
        let mut alice = vec![0_u8; MAX_STATE_BYTES as usize];
        let mut bob = vec![0_u8; MAX_STATE_BYTES as usize];
        let mut alice_len = 0_u64;
        let mut bob_len = 0_u64;
        for (role, output, output_len) in [
            (ROLE_INITIATOR, &mut alice, &mut alice_len),
            (ROLE_RESPONDER, &mut bob, &mut bob_len),
        ] {
            assert_eq!(
                unsafe {
                    lg_scka_v1_initialize(
                        role,
                        session.as_ptr(),
                        session.len() as u64,
                        state_key.as_ptr(),
                        state_key.len() as u64,
                        shared.as_ptr(),
                        shared.len() as u64,
                        output.as_mut_ptr(),
                        output.len() as u64,
                        output_len,
                    )
                },
                STATUS_OK
            );
            assert!((MIN_STATE_BYTES..=MAX_STATE_BYTES).contains(output_len));
        }

        let mut next_alice = vec![0_u8; MAX_STATE_BYTES as usize];
        let mut message = vec![0_u8; MAX_MESSAGE_BYTES as usize];
        let mut next_alice_len = 0_u64;
        let mut message_len = 0_u64;
        let mut sending_epoch = 0_u64;
        let mut has_secret = 0_u32;
        let mut secret_epoch = 0_u64;
        let mut secret = [0_u8; EPOCH_SECRET_BYTES as usize];
        assert_eq!(
            unsafe {
                lg_scka_v1_send(
                    ROLE_INITIATOR,
                    session.as_ptr(),
                    session.len() as u64,
                    state_key.as_ptr(),
                    state_key.len() as u64,
                    0,
                    alice.as_ptr(),
                    alice_len,
                    next_alice.as_mut_ptr(),
                    next_alice.len() as u64,
                    &mut next_alice_len,
                    message.as_mut_ptr(),
                    message.len() as u64,
                    &mut message_len,
                    &mut sending_epoch,
                    &mut has_secret,
                    &mut secret_epoch,
                    secret.as_mut_ptr(),
                    secret.len() as u64,
                )
            },
            STATUS_OK
        );
        assert!(message_len == 24 || message_len == 58);
        assert_eq!(
            unsafe {
                lg_scka_v1_state_validate(
                    ROLE_INITIATOR,
                    session.as_ptr(),
                    session.len() as u64,
                    state_key.as_ptr(),
                    state_key.len() as u64,
                    1,
                    next_alice.as_ptr(),
                    next_alice_len,
                )
            },
            STATUS_OK
        );

        let mut next_bob = vec![0_u8; MAX_STATE_BYTES as usize];
        let mut next_bob_len = 0_u64;
        let mut receiving_epoch = 0_u64;
        has_secret = 0;
        secret_epoch = 0;
        secret.fill(0);
        assert_eq!(
            unsafe {
                lg_scka_v1_receive(
                    ROLE_RESPONDER,
                    session.as_ptr(),
                    session.len() as u64,
                    state_key.as_ptr(),
                    state_key.len() as u64,
                    0,
                    bob.as_ptr(),
                    bob_len,
                    message.as_ptr(),
                    message_len,
                    next_bob.as_mut_ptr(),
                    next_bob.len() as u64,
                    &mut next_bob_len,
                    &mut receiving_epoch,
                    &mut has_secret,
                    &mut secret_epoch,
                    secret.as_mut_ptr(),
                    secret.len() as u64,
                )
            },
            STATUS_OK
        );
        assert_eq!(receiving_epoch, sending_epoch);
        assert_eq!(
            unsafe {
                lg_scka_v1_state_validate(
                    ROLE_RESPONDER,
                    session.as_ptr(),
                    session.len() as u64,
                    state_key.as_ptr(),
                    state_key.len() as u64,
                    1,
                    next_bob.as_ptr(),
                    next_bob_len,
                )
            },
            STATUS_OK
        );

        next_bob[80] ^= 1;
        assert_eq!(
            unsafe {
                lg_scka_v1_state_validate(
                    ROLE_RESPONDER,
                    session.as_ptr(),
                    session.len() as u64,
                    state_key.as_ptr(),
                    state_key.len() as u64,
                    1,
                    next_bob.as_ptr(),
                    next_bob_len,
                )
            },
            STATUS_AUTHENTICATION
        );
    }

    #[test]
    fn invalid_arguments_do_not_report_backend_readiness() {
        let mut state = vec![0xa5_u8; MAX_STATE_BYTES as usize];
        let mut state_len = u64::MAX;
        let status = unsafe {
            lg_scka_v1_initialize(
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                state.as_mut_ptr(),
                state.len() as u64,
                &mut state_len,
            )
        };
        assert_eq!(status, STATUS_INVALID_ARGUMENT);
        assert_eq!(state_len, 0);
        assert!(state.iter().all(|byte| *byte == 0));
    }
}
