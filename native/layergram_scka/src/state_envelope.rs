// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

//! Inactive authenticated `LS3` state envelope.
//!
//! This module freezes and enforces the outer AES-256-GCM container described
//! in `specs/SCKA_NATIVE_ABI.md`. It deliberately does not define the inner
//! ML-KEM Braid state-machine payload and is not connected to the public C ABI.
//! Callers must supply a fresh 96-bit nonce from an approved OS CSPRNG, persist
//! the returned bytes exactly once, and semantically validate the decrypted
//! payload before accepting it as a candidate transition.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use zeroize::Zeroize;

use crate::{
    MAX_COUNTER, MAX_STATE_BYTES, MIN_STATE_BYTES, SESSION_ID_BYTES, STATE_HEADER_BYTES,
    STATE_KEY_BYTES, STATE_TAG_BYTES,
};

pub(crate) const STATE_NONCE_BYTES: usize = 12;
pub(crate) const MAX_PAYLOAD_BYTES: usize =
    MAX_STATE_BYTES as usize - STATE_HEADER_BYTES as usize - STATE_TAG_BYTES as usize;

const MAGIC: &[u8; 3] = b"LS3";
const STATE_FORMAT: u8 = 1;
const SUITE: u8 = 1;
const PROTOCOL_REVISION: u16 = 1;

const FORMAT_OFFSET: usize = 3;
const SUITE_OFFSET: usize = 4;
const ROLE_OFFSET: usize = 5;
const FLAGS_OFFSET: usize = 6;
const HEADER_LENGTH_OFFSET: usize = 8;
const PROTOCOL_REVISION_OFFSET: usize = 10;
const TOTAL_LENGTH_OFFSET: usize = 12;
const CIPHERTEXT_LENGTH_OFFSET: usize = 16;
const SESSION_ID_OFFSET: usize = 20;
const STATE_REVISION_OFFSET: usize = 36;
const SENDING_EPOCH_OFFSET: usize = 44;
const RECEIVING_EPOCH_OFFSET: usize = 52;
const NONCE_OFFSET: usize = 60;
const RESERVED_OFFSET: usize = 72;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StateEnvelopeError {
    InvalidLength,
    InvalidMetadata,
    Authentication,
    StateRevision,
    PrimitiveFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum StateRole {
    Initiator = 1,
    Responder = 2,
}

impl StateRole {
    fn decode(value: u8) -> Result<Self, StateEnvelopeError> {
        match value {
            1 => Ok(Self::Initiator),
            2 => Ok(Self::Responder),
            _ => Err(StateEnvelopeError::InvalidMetadata),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StateMetadata {
    role: StateRole,
    session_id: [u8; SESSION_ID_BYTES as usize],
    state_revision: u64,
    sending_epoch: u64,
    receiving_epoch: u64,
}

impl StateMetadata {
    pub(crate) fn new(
        role: StateRole,
        session_id: [u8; SESSION_ID_BYTES as usize],
        state_revision: u64,
        sending_epoch: u64,
        receiving_epoch: u64,
    ) -> Result<Self, StateEnvelopeError> {
        if session_id.iter().all(|byte| *byte == 0)
            || state_revision > MAX_COUNTER
            || sending_epoch > MAX_COUNTER
            || receiving_epoch > MAX_COUNTER
        {
            return Err(StateEnvelopeError::InvalidMetadata);
        }
        Ok(Self {
            role,
            session_id,
            state_revision,
            sending_epoch,
            receiving_epoch,
        })
    }

    pub(crate) fn role(&self) -> StateRole {
        self.role
    }

    pub(crate) fn session_id(&self) -> &[u8; SESSION_ID_BYTES as usize] {
        &self.session_id
    }

    pub(crate) fn state_revision(&self) -> u64 {
        self.state_revision
    }

    pub(crate) fn sending_epoch(&self) -> u64 {
        self.sending_epoch
    }

    pub(crate) fn receiving_epoch(&self) -> u64 {
        self.receiving_epoch
    }
}

pub(crate) struct OpenedState {
    metadata: StateMetadata,
    payload: Vec<u8>,
}

impl OpenedState {
    pub(crate) fn metadata(&self) -> StateMetadata {
        self.metadata
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl Drop for OpenedState {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

pub(crate) fn seal(
    metadata: StateMetadata,
    state_key: &[u8],
    nonce: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, StateEnvelopeError> {
    require_exact_length(state_key, STATE_KEY_BYTES as usize)?;
    require_exact_length(nonce, STATE_NONCE_BYTES)?;
    validate_payload_length(payload.len())?;

    let total_length = STATE_HEADER_BYTES as usize + payload.len() + STATE_TAG_BYTES as usize;
    let mut header = [0_u8; STATE_HEADER_BYTES as usize];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[FORMAT_OFFSET] = STATE_FORMAT;
    header[SUITE_OFFSET] = SUITE;
    header[ROLE_OFFSET] = metadata.role as u8;
    header[HEADER_LENGTH_OFFSET..PROTOCOL_REVISION_OFFSET]
        .copy_from_slice(&(STATE_HEADER_BYTES as u16).to_be_bytes());
    header[PROTOCOL_REVISION_OFFSET..TOTAL_LENGTH_OFFSET]
        .copy_from_slice(&PROTOCOL_REVISION.to_be_bytes());
    header[TOTAL_LENGTH_OFFSET..CIPHERTEXT_LENGTH_OFFSET]
        .copy_from_slice(&(total_length as u32).to_be_bytes());
    header[CIPHERTEXT_LENGTH_OFFSET..SESSION_ID_OFFSET]
        .copy_from_slice(&(payload.len() as u32).to_be_bytes());
    header[SESSION_ID_OFFSET..STATE_REVISION_OFFSET].copy_from_slice(&metadata.session_id);
    header[STATE_REVISION_OFFSET..SENDING_EPOCH_OFFSET]
        .copy_from_slice(&metadata.state_revision.to_be_bytes());
    header[SENDING_EPOCH_OFFSET..RECEIVING_EPOCH_OFFSET]
        .copy_from_slice(&metadata.sending_epoch.to_be_bytes());
    header[RECEIVING_EPOCH_OFFSET..NONCE_OFFSET]
        .copy_from_slice(&metadata.receiving_epoch.to_be_bytes());
    header[NONCE_OFFSET..RESERVED_OFFSET].copy_from_slice(nonce);

    let mut checked_key = exact_array::<{ STATE_KEY_BYTES as usize }>(state_key)?;
    let cipher_result = Aes256Gcm::new_from_slice(&checked_key);
    checked_key.zeroize();
    let cipher = cipher_result.map_err(|_| StateEnvelopeError::PrimitiveFailure)?;

    let mut ciphertext = payload.to_vec();
    let tag = match cipher.encrypt_in_place_detached(
        Nonce::from_slice(nonce),
        &header,
        &mut ciphertext,
    ) {
        Ok(tag) => tag,
        Err(_) => {
            ciphertext.zeroize();
            return Err(StateEnvelopeError::PrimitiveFailure);
        }
    };

    let mut encoded = Vec::with_capacity(total_length);
    encoded.extend_from_slice(&header);
    encoded.append(&mut ciphertext);
    encoded.extend_from_slice(&tag);
    Ok(encoded)
}

pub(crate) fn open(
    expected_role: StateRole,
    expected_session_id: &[u8],
    state_key: &[u8],
    expected_state_revision: u64,
    encoded: &[u8],
) -> Result<OpenedState, StateEnvelopeError> {
    require_exact_length(expected_session_id, SESSION_ID_BYTES as usize)?;
    require_exact_length(state_key, STATE_KEY_BYTES as usize)?;
    if expected_session_id.iter().all(|byte| *byte == 0) || expected_state_revision > MAX_COUNTER {
        return Err(StateEnvelopeError::InvalidMetadata);
    }
    if !(MIN_STATE_BYTES as usize..=MAX_STATE_BYTES as usize).contains(&encoded.len()) {
        return Err(StateEnvelopeError::InvalidLength);
    }

    let header = exact_array_ref::<{ STATE_HEADER_BYTES as usize }>(
        &encoded[..STATE_HEADER_BYTES as usize],
    )?;
    let parsed = parse_header(header, encoded.len())?;
    if parsed.role != expected_role || parsed.session_id.as_slice() != expected_session_id {
        return Err(StateEnvelopeError::Authentication);
    }
    if parsed.state_revision != expected_state_revision {
        return Err(StateEnvelopeError::StateRevision);
    }

    let ciphertext_end = STATE_HEADER_BYTES as usize + parsed.ciphertext_length;
    let mut payload = encoded[STATE_HEADER_BYTES as usize..ciphertext_end].to_vec();
    let tag = Tag::from_slice(&encoded[ciphertext_end..]);
    let nonce = Nonce::from_slice(&header[NONCE_OFFSET..RESERVED_OFFSET]);

    let mut checked_key = exact_array::<{ STATE_KEY_BYTES as usize }>(state_key)?;
    let cipher_result = Aes256Gcm::new_from_slice(&checked_key);
    checked_key.zeroize();
    let cipher = cipher_result.map_err(|_| StateEnvelopeError::PrimitiveFailure)?;
    if cipher
        .decrypt_in_place_detached(nonce, header, &mut payload, tag)
        .is_err()
    {
        payload.zeroize();
        return Err(StateEnvelopeError::Authentication);
    }

    Ok(OpenedState {
        metadata: parsed.metadata(),
        payload,
    })
}

struct ParsedHeader {
    role: StateRole,
    session_id: [u8; SESSION_ID_BYTES as usize],
    state_revision: u64,
    sending_epoch: u64,
    receiving_epoch: u64,
    ciphertext_length: usize,
}

impl ParsedHeader {
    fn metadata(&self) -> StateMetadata {
        StateMetadata {
            role: self.role,
            session_id: self.session_id,
            state_revision: self.state_revision,
            sending_epoch: self.sending_epoch,
            receiving_epoch: self.receiving_epoch,
        }
    }
}

fn parse_header(
    header: &[u8; STATE_HEADER_BYTES as usize],
    encoded_length: usize,
) -> Result<ParsedHeader, StateEnvelopeError> {
    if &header[..MAGIC.len()] != MAGIC
        || header[FORMAT_OFFSET] != STATE_FORMAT
        || header[SUITE_OFFSET] != SUITE
        || header[FLAGS_OFFSET..HEADER_LENGTH_OFFSET] != [0, 0]
        || read_u16(header, HEADER_LENGTH_OFFSET) != STATE_HEADER_BYTES as u16
        || read_u16(header, PROTOCOL_REVISION_OFFSET) != PROTOCOL_REVISION
        || header[RESERVED_OFFSET..].iter().any(|byte| *byte != 0)
    {
        return Err(StateEnvelopeError::InvalidMetadata);
    }

    let total_length = read_u32(header, TOTAL_LENGTH_OFFSET) as usize;
    let ciphertext_length = read_u32(header, CIPHERTEXT_LENGTH_OFFSET) as usize;
    if total_length != encoded_length
        || ciphertext_length + STATE_HEADER_BYTES as usize + STATE_TAG_BYTES as usize
            != total_length
    {
        return Err(StateEnvelopeError::InvalidLength);
    }
    validate_payload_length(ciphertext_length)?;

    let role = StateRole::decode(header[ROLE_OFFSET])?;
    let session_id = exact_array::<{ SESSION_ID_BYTES as usize }>(
        &header[SESSION_ID_OFFSET..STATE_REVISION_OFFSET],
    )?;
    let state_revision = read_u64(header, STATE_REVISION_OFFSET);
    let sending_epoch = read_u64(header, SENDING_EPOCH_OFFSET);
    let receiving_epoch = read_u64(header, RECEIVING_EPOCH_OFFSET);
    StateMetadata::new(
        role,
        session_id,
        state_revision,
        sending_epoch,
        receiving_epoch,
    )?;

    Ok(ParsedHeader {
        role,
        session_id,
        state_revision,
        sending_epoch,
        receiving_epoch,
        ciphertext_length,
    })
}

fn validate_payload_length(length: usize) -> Result<(), StateEnvelopeError> {
    if (1..=MAX_PAYLOAD_BYTES).contains(&length) {
        Ok(())
    } else {
        Err(StateEnvelopeError::InvalidLength)
    }
}

fn require_exact_length(bytes: &[u8], expected: usize) -> Result<(), StateEnvelopeError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(StateEnvelopeError::InvalidLength)
    }
}

fn exact_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StateEnvelopeError> {
    bytes
        .try_into()
        .map_err(|_| StateEnvelopeError::InvalidLength)
}

fn exact_array_ref<const N: usize>(bytes: &[u8]) -> Result<&[u8; N], StateEnvelopeError> {
    bytes
        .try_into()
        .map_err(|_| StateEnvelopeError::InvalidLength)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().expect("fixed header"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("fixed header"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().expect("fixed header"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; STATE_KEY_BYTES as usize] = [0x42; STATE_KEY_BYTES as usize];
    const NONCE: [u8; STATE_NONCE_BYTES] = [0x24; STATE_NONCE_BYTES];
    const SESSION: [u8; SESSION_ID_BYTES as usize] = [0x11; SESSION_ID_BYTES as usize];

    fn metadata(role: StateRole) -> StateMetadata {
        StateMetadata::new(role, SESSION, 7, 5, 6).unwrap()
    }

    #[test]
    fn envelope_round_trips_and_freezes_header() {
        let payload = b"canonical-state-machine-payload";
        for role in [StateRole::Initiator, StateRole::Responder] {
            let sealed = seal(metadata(role), &KEY, &NONCE, payload).unwrap();
            assert_eq!(
                sealed.len(),
                STATE_HEADER_BYTES as usize + payload.len() + 16
            );
            assert_eq!(&sealed[..3], b"LS3");
            assert_eq!(sealed[FORMAT_OFFSET], 1);
            assert_eq!(sealed[SUITE_OFFSET], 1);
            assert_eq!(sealed[ROLE_OFFSET], role as u8);
            assert_eq!(read_u16(&sealed, HEADER_LENGTH_OFFSET), 80);
            assert_eq!(read_u16(&sealed, PROTOCOL_REVISION_OFFSET), 1);
            assert_eq!(
                read_u32(&sealed, TOTAL_LENGTH_OFFSET) as usize,
                sealed.len()
            );
            assert_eq!(
                read_u32(&sealed, CIPHERTEXT_LENGTH_OFFSET),
                payload.len() as u32
            );
            assert_eq!(&sealed[SESSION_ID_OFFSET..STATE_REVISION_OFFSET], &SESSION);
            assert_eq!(read_u64(&sealed, STATE_REVISION_OFFSET), 7);
            assert_eq!(read_u64(&sealed, SENDING_EPOCH_OFFSET), 5);
            assert_eq!(read_u64(&sealed, RECEIVING_EPOCH_OFFSET), 6);
            assert_eq!(&sealed[NONCE_OFFSET..RESERVED_OFFSET], &NONCE);
            assert!(sealed[RESERVED_OFFSET..STATE_HEADER_BYTES as usize]
                .iter()
                .all(|byte| *byte == 0));
            assert_ne!(
                &sealed[STATE_HEADER_BYTES as usize..STATE_HEADER_BYTES as usize + payload.len()],
                payload
            );

            let opened = open(role, &SESSION, &KEY, 7, &sealed).unwrap();
            assert_eq!(opened.metadata(), metadata(role));
            assert_eq!(opened.payload(), payload);
        }
    }

    #[test]
    fn authentication_binds_key_session_role_and_revision() {
        let sealed = seal(metadata(StateRole::Initiator), &KEY, &NONCE, b"state").unwrap();
        let mut wrong_key = KEY;
        wrong_key[0] ^= 1;
        let mut wrong_session = SESSION;
        wrong_session[0] ^= 1;

        assert!(matches!(
            open(StateRole::Initiator, &SESSION, &wrong_key, 7, &sealed),
            Err(StateEnvelopeError::Authentication)
        ));
        assert!(matches!(
            open(StateRole::Initiator, &wrong_session, &KEY, 7, &sealed),
            Err(StateEnvelopeError::Authentication)
        ));
        assert!(matches!(
            open(StateRole::Responder, &SESSION, &KEY, 7, &sealed),
            Err(StateEnvelopeError::Authentication)
        ));
        assert!(matches!(
            open(StateRole::Initiator, &SESSION, &KEY, 6, &sealed),
            Err(StateEnvelopeError::StateRevision)
        ));
    }

    #[test]
    fn every_authenticated_region_rejects_tampering() {
        let sealed = seal(
            metadata(StateRole::Initiator),
            &KEY,
            &NONCE,
            b"authenticated payload with enough bytes",
        )
        .unwrap();
        for index in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert!(
                open(StateRole::Initiator, &SESSION, &KEY, 7, &tampered).is_err(),
                "tampered byte {index} was accepted"
            );
        }
    }

    #[test]
    fn exact_lengths_bounds_and_counters_fail_closed() {
        assert!(matches!(
            seal(metadata(StateRole::Initiator), &KEY[..31], &NONCE, b"x"),
            Err(StateEnvelopeError::InvalidLength)
        ));
        assert!(matches!(
            seal(metadata(StateRole::Initiator), &KEY, &NONCE[..11], b"x"),
            Err(StateEnvelopeError::InvalidLength)
        ));
        assert!(matches!(
            seal(metadata(StateRole::Initiator), &KEY, &NONCE, b""),
            Err(StateEnvelopeError::InvalidLength)
        ));
        assert!(matches!(
            seal(
                metadata(StateRole::Initiator),
                &KEY,
                &NONCE,
                &vec![0_u8; MAX_PAYLOAD_BYTES + 1]
            ),
            Err(StateEnvelopeError::InvalidLength)
        ));
        assert!(matches!(
            StateMetadata::new(StateRole::Initiator, [0_u8; 16], 0, 0, 0),
            Err(StateEnvelopeError::InvalidMetadata)
        ));
        assert!(matches!(
            StateMetadata::new(StateRole::Initiator, SESSION, MAX_COUNTER + 1, 0, 0),
            Err(StateEnvelopeError::InvalidMetadata)
        ));

        let maximum = vec![0xa5_u8; MAX_PAYLOAD_BYTES];
        let sealed = seal(
            StateMetadata::new(
                StateRole::Responder,
                SESSION,
                MAX_COUNTER,
                MAX_COUNTER,
                MAX_COUNTER,
            )
            .unwrap(),
            &KEY,
            &NONCE,
            &maximum,
        )
        .unwrap();
        assert_eq!(sealed.len(), MAX_STATE_BYTES as usize);
        let opened = open(StateRole::Responder, &SESSION, &KEY, MAX_COUNTER, &sealed).unwrap();
        assert_eq!(opened.payload(), maximum);
    }

    #[test]
    fn malformed_header_and_total_lengths_are_rejected_before_open() {
        let sealed = seal(metadata(StateRole::Initiator), &KEY, &NONCE, b"state").unwrap();
        assert!(matches!(
            open(
                StateRole::Initiator,
                &SESSION,
                &KEY,
                7,
                &sealed[..MIN_STATE_BYTES as usize - 1]
            ),
            Err(StateEnvelopeError::InvalidLength)
        ));

        let mut wrong_total = sealed.clone();
        wrong_total[TOTAL_LENGTH_OFFSET..CIPHERTEXT_LENGTH_OFFSET]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            open(StateRole::Initiator, &SESSION, &KEY, 7, &wrong_total),
            Err(StateEnvelopeError::InvalidLength)
        ));

        let mut reserved = sealed;
        reserved[RESERVED_OFFSET] = 1;
        assert!(matches!(
            open(StateRole::Initiator, &SESSION, &KEY, 7, &reserved),
            Err(StateEnvelopeError::InvalidMetadata)
        ));
    }

    #[test]
    fn aes_256_gcm_configuration_matches_nist_zero_vector() {
        let key = [0_u8; 32];
        let nonce = [0_u8; 12];
        let mut plaintext = [0_u8; 16];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut plaintext)
            .unwrap();
        assert_eq!(hex(&plaintext), "cea7403d4d606b6e074ec5d3baf39d18");
        assert_eq!(hex(&tag), "d0d1c8a799996bf0265b98b5d48ab919");
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(DIGITS[(byte >> 4) as usize] as char);
            output.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        output
    }
}
