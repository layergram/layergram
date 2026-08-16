// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_char;
use core::ptr;

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
pub const STATE_FORMAT_VERSION: u32 = 1;
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
const IMPLEMENTATION_ID: &[u8] = b"layergram-scka-scaffold-r1-abi1\0";

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
    STATUS_NOT_READY
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
    STATUS_NOT_READY
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
    STATUS_NOT_READY
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
    STATUS_NOT_READY
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
    STATUS_NOT_READY
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn metadata_is_frozen_and_scaffold_cannot_activate() {
        assert_eq!(lg_scka_v1_abi_version(), 1);
        assert_eq!(lg_scka_v1_protocol_revision(), 1);
        assert_eq!(lg_scka_v1_state_format_version(), 1);
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
