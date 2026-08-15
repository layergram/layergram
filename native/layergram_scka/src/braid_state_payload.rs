// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

//! Canonical plaintext state payload for ML-KEM Braid revision 1.
//!
//! `LB3` is an internal, encrypted-at-rest representation. It is accepted only
//! after the outer `LS3` envelope has authenticated and supplied the expected
//! role, session, revision, and epoch high-water metadata. This codec remains
//! disconnected from the C ABI and from every production call path.

use zeroize::Zeroize;

use crate::erasure::{ENCODED_CHUNK_BYTES, MAX_ENCODING_INDEX};
use crate::incremental_mlkem::{
    key_pair_from_private_key, validate_public_key, CIPHERTEXT_PART_ONE_BYTES,
    CIPHERTEXT_PART_TWO_BYTES, ENCAPSULATION_STATE_BYTES, PRIVATE_KEY_BYTES,
    PUBLIC_KEY_HEADER_BYTES, PUBLIC_KEY_VECTOR_BYTES,
};
use crate::state_envelope::{StateMetadata, StateRole};
use crate::{MAX_COUNTER, SESSION_ID_BYTES};

pub(crate) const PAYLOAD_HEADER_BYTES: usize = 136;
pub(crate) const MIN_BRAID_PAYLOAD_BYTES: usize = PAYLOAD_HEADER_BYTES;
pub(crate) const MAX_BRAID_PAYLOAD_BYTES: usize = 4_434;

const MAGIC: &[u8; 3] = b"LB3";
const PAYLOAD_FORMAT: u8 = 1;
const SUITE: u8 = 1;
const PROTOCOL_REVISION: u16 = 1;
const AUTH_KEY_BYTES: usize = 32;
const MAC_BYTES: usize = 32;
const EXHAUSTED_ENCODER_INDEX: u16 = u16::MAX;

const FORMAT_OFFSET: usize = 3;
const SUITE_OFFSET: usize = 4;
const ROLE_OFFSET: usize = 5;
const VARIANT_OFFSET: usize = 6;
const FLAGS_OFFSET: usize = 7;
const HEADER_LENGTH_OFFSET: usize = 8;
const PROTOCOL_REVISION_OFFSET: usize = 10;
const TOTAL_LENGTH_OFFSET: usize = 12;
const SESSION_ID_OFFSET: usize = 16;
const STATE_REVISION_OFFSET: usize = 32;
const EPOCH_OFFSET: usize = 40;
const SENDING_EPOCH_OFFSET: usize = 48;
const RECEIVING_EPOCH_OFFSET: usize = 56;
const AUTH_ROOT_OFFSET: usize = 64;
const AUTH_MAC_OFFSET: usize = 96;
const BODY_LENGTH_OFFSET: usize = 128;
const RESERVED_OFFSET: usize = 132;

const PENDING_ENCAPSULATION_BYTES: usize =
    PUBLIC_KEY_HEADER_BYTES + ENCAPSULATION_STATE_BYTES + CIPHERTEXT_PART_ONE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum BraidStatePayloadError {
    InvalidLength,
    InvalidMetadata,
    InvalidVariant,
    InvalidBody,
    InvalidPrivateKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum BraidStateVariant {
    KeysUnsampled = 1,
    KeysSampled = 2,
    HeaderSent = 3,
    Ct1Received = 4,
    EkSentCt1Received = 5,
    NoHeaderReceived = 6,
    HeaderReceived = 7,
    Ct1Sampled = 8,
    EkReceivedCt1Sampled = 9,
    Ct1Acknowledged = 10,
    Ct2Sampled = 11,
}

impl BraidStateVariant {
    fn decode(value: u8) -> Result<Self, BraidStatePayloadError> {
        match value {
            1 => Ok(Self::KeysUnsampled),
            2 => Ok(Self::KeysSampled),
            3 => Ok(Self::HeaderSent),
            4 => Ok(Self::Ct1Received),
            5 => Ok(Self::EkSentCt1Received),
            6 => Ok(Self::NoHeaderReceived),
            7 => Ok(Self::HeaderReceived),
            8 => Ok(Self::Ct1Sampled),
            9 => Ok(Self::EkReceivedCt1Sampled),
            10 => Ok(Self::Ct1Acknowledged),
            11 => Ok(Self::Ct2Sampled),
            _ => Err(BraidStatePayloadError::InvalidVariant),
        }
    }

    fn is_key_sender(self) -> bool {
        matches!(
            self,
            Self::KeysUnsampled
                | Self::KeysSampled
                | Self::HeaderSent
                | Self::Ct1Received
                | Self::EkSentCt1Received
        )
    }
}

/// Owned canonical plaintext. The complete byte vector contains secret state
/// and is wiped on drop. It intentionally implements neither `Clone` nor
/// `Debug`.
pub(crate) struct BraidStatePayload {
    metadata: StateMetadata,
    epoch: u64,
    variant: BraidStateVariant,
    encoded: Vec<u8>,
}

impl BraidStatePayload {
    pub(crate) fn metadata(&self) -> StateMetadata {
        self.metadata
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn variant(&self) -> BraidStateVariant {
        self.variant
    }

    pub(crate) fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    fn wipe(&mut self) {
        self.encoded.zeroize();
    }
}

impl Drop for BraidStatePayload {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub(crate) fn encode(
    metadata: StateMetadata,
    epoch: u64,
    variant: BraidStateVariant,
    auth_root_key: &[u8],
    auth_mac_key: &[u8],
    body: &[u8],
) -> Result<BraidStatePayload, BraidStatePayloadError> {
    validate_common(metadata, epoch, variant)?;
    require_exact_length(auth_root_key, AUTH_KEY_BYTES)?;
    require_exact_length(auth_mac_key, AUTH_KEY_BYTES)?;
    validate_body(variant, body)?;

    let total_length = PAYLOAD_HEADER_BYTES
        .checked_add(body.len())
        .ok_or(BraidStatePayloadError::InvalidLength)?;
    if !(MIN_BRAID_PAYLOAD_BYTES..=MAX_BRAID_PAYLOAD_BYTES).contains(&total_length) {
        return Err(BraidStatePayloadError::InvalidLength);
    }

    let mut encoded = Vec::with_capacity(total_length);
    encoded.resize(PAYLOAD_HEADER_BYTES, 0);
    encoded[..MAGIC.len()].copy_from_slice(MAGIC);
    encoded[FORMAT_OFFSET] = PAYLOAD_FORMAT;
    encoded[SUITE_OFFSET] = SUITE;
    encoded[ROLE_OFFSET] = metadata.role() as u8;
    encoded[VARIANT_OFFSET] = variant as u8;
    encoded[HEADER_LENGTH_OFFSET..PROTOCOL_REVISION_OFFSET]
        .copy_from_slice(&(PAYLOAD_HEADER_BYTES as u16).to_be_bytes());
    encoded[PROTOCOL_REVISION_OFFSET..TOTAL_LENGTH_OFFSET]
        .copy_from_slice(&PROTOCOL_REVISION.to_be_bytes());
    encoded[TOTAL_LENGTH_OFFSET..SESSION_ID_OFFSET]
        .copy_from_slice(&(total_length as u32).to_be_bytes());
    encoded[SESSION_ID_OFFSET..STATE_REVISION_OFFSET].copy_from_slice(metadata.session_id());
    encoded[STATE_REVISION_OFFSET..EPOCH_OFFSET]
        .copy_from_slice(&metadata.state_revision().to_be_bytes());
    encoded[EPOCH_OFFSET..SENDING_EPOCH_OFFSET].copy_from_slice(&epoch.to_be_bytes());
    encoded[SENDING_EPOCH_OFFSET..RECEIVING_EPOCH_OFFSET]
        .copy_from_slice(&metadata.sending_epoch().to_be_bytes());
    encoded[RECEIVING_EPOCH_OFFSET..AUTH_ROOT_OFFSET]
        .copy_from_slice(&metadata.receiving_epoch().to_be_bytes());
    encoded[AUTH_ROOT_OFFSET..AUTH_MAC_OFFSET].copy_from_slice(auth_root_key);
    encoded[AUTH_MAC_OFFSET..BODY_LENGTH_OFFSET].copy_from_slice(auth_mac_key);
    encoded[BODY_LENGTH_OFFSET..RESERVED_OFFSET]
        .copy_from_slice(&(body.len() as u32).to_be_bytes());
    encoded.extend_from_slice(body);

    Ok(BraidStatePayload {
        metadata,
        epoch,
        variant,
        encoded,
    })
}

pub(crate) fn decode(
    expected_metadata: StateMetadata,
    encoded: &[u8],
) -> Result<BraidStatePayload, BraidStatePayloadError> {
    if !(MIN_BRAID_PAYLOAD_BYTES..=MAX_BRAID_PAYLOAD_BYTES).contains(&encoded.len()) {
        return Err(BraidStatePayloadError::InvalidLength);
    }
    let header = &encoded[..PAYLOAD_HEADER_BYTES];
    if &header[..MAGIC.len()] != MAGIC
        || header[FORMAT_OFFSET] != PAYLOAD_FORMAT
        || header[SUITE_OFFSET] != SUITE
        || header[FLAGS_OFFSET] != 0
        || read_u16(header, HEADER_LENGTH_OFFSET) != PAYLOAD_HEADER_BYTES as u16
        || read_u16(header, PROTOCOL_REVISION_OFFSET) != PROTOCOL_REVISION
        || header[RESERVED_OFFSET..].iter().any(|byte| *byte != 0)
    {
        return Err(BraidStatePayloadError::InvalidMetadata);
    }

    let total_length = read_u32(header, TOTAL_LENGTH_OFFSET) as usize;
    let body_length = read_u32(header, BODY_LENGTH_OFFSET) as usize;
    if total_length != encoded.len()
        || body_length
            .checked_add(PAYLOAD_HEADER_BYTES)
            .ok_or(BraidStatePayloadError::InvalidLength)?
            != total_length
    {
        return Err(BraidStatePayloadError::InvalidLength);
    }

    let role = StateRole::decode(header[ROLE_OFFSET])
        .map_err(|_| BraidStatePayloadError::InvalidMetadata)?;
    let session_id: [u8; SESSION_ID_BYTES as usize] = header
        [SESSION_ID_OFFSET..STATE_REVISION_OFFSET]
        .try_into()
        .map_err(|_| BraidStatePayloadError::InvalidLength)?;
    let metadata = StateMetadata::new(
        role,
        session_id,
        read_u64(header, STATE_REVISION_OFFSET),
        read_u64(header, SENDING_EPOCH_OFFSET),
        read_u64(header, RECEIVING_EPOCH_OFFSET),
    )
    .map_err(|_| BraidStatePayloadError::InvalidMetadata)?;
    if metadata != expected_metadata {
        return Err(BraidStatePayloadError::InvalidMetadata);
    }

    let epoch = read_u64(header, EPOCH_OFFSET);
    let variant = BraidStateVariant::decode(header[VARIANT_OFFSET])?;
    validate_common(metadata, epoch, variant)?;
    validate_body(variant, &encoded[PAYLOAD_HEADER_BYTES..])?;

    Ok(BraidStatePayload {
        metadata,
        epoch,
        variant,
        encoded: encoded.to_vec(),
    })
}

fn validate_common(
    metadata: StateMetadata,
    epoch: u64,
    variant: BraidStateVariant,
) -> Result<(), BraidStatePayloadError> {
    if epoch == 0 || epoch > MAX_COUNTER {
        return Err(BraidStatePayloadError::InvalidMetadata);
    }
    let high = epoch - 1;
    let low = epoch.saturating_sub(2);
    let valid_high_water = match variant {
        BraidStateVariant::KeysUnsampled => {
            metadata.sending_epoch() == low && metadata.receiving_epoch() == high
        }
        BraidStateVariant::NoHeaderReceived => {
            (low..=high).contains(&metadata.sending_epoch())
                && (low..=high).contains(&metadata.receiving_epoch())
        }
        BraidStateVariant::HeaderReceived => {
            (low..=high).contains(&metadata.sending_epoch()) && metadata.receiving_epoch() == high
        }
        _ => metadata.sending_epoch() == high && metadata.receiving_epoch() == high,
    };
    if !valid_high_water {
        return Err(BraidStatePayloadError::InvalidMetadata);
    }
    let initiator_is_sender = epoch & 1 == 1;
    let stable_role_is_initiator = metadata.role() == StateRole::Initiator;
    if variant.is_key_sender() != (initiator_is_sender == stable_role_is_initiator) {
        return Err(BraidStatePayloadError::InvalidVariant);
    }
    Ok(())
}

fn validate_body(variant: BraidStateVariant, body: &[u8]) -> Result<(), BraidStatePayloadError> {
    match variant {
        BraidStateVariant::KeysUnsampled => require_exact_length(body, 0),
        BraidStateVariant::KeysSampled => {
            require_exact_length(body, PRIVATE_KEY_BYTES + MAC_BYTES + 2)?;
            validate_private_key(&body[..PRIVATE_KEY_BYTES])?;
            validate_encoder_index(read_u16(body, PRIVATE_KEY_BYTES + MAC_BYTES), true)
        }
        BraidStateVariant::HeaderSent => {
            let decoder_offset = PRIVATE_KEY_BYTES + 2;
            require_minimum_length(body, decoder_offset + 2)?;
            validate_private_key(&body[..PRIVATE_KEY_BYTES])?;
            validate_encoder_index(read_u16(body, PRIVATE_KEY_BYTES), false)?;
            validate_decoder(body, decoder_offset, 30, 1)
        }
        BraidStateVariant::Ct1Received => {
            let next_index_offset = PRIVATE_KEY_BYTES + CIPHERTEXT_PART_ONE_BYTES;
            require_exact_length(body, next_index_offset + 2)?;
            validate_private_key(&body[..PRIVATE_KEY_BYTES])?;
            validate_encoder_index(read_u16(body, next_index_offset), false)
        }
        BraidStateVariant::EkSentCt1Received => {
            let decoder_offset = PRIVATE_KEY_BYTES + CIPHERTEXT_PART_ONE_BYTES;
            require_minimum_length(body, decoder_offset + 2)?;
            validate_private_key(&body[..PRIVATE_KEY_BYTES])?;
            validate_decoder(body, decoder_offset, 5, 1)
        }
        BraidStateVariant::NoHeaderReceived => validate_decoder(body, 0, 3, 0),
        BraidStateVariant::HeaderReceived => {
            require_minimum_length(body, PUBLIC_KEY_HEADER_BYTES + 2)?;
            validate_decoder(body, PUBLIC_KEY_HEADER_BYTES, 36, 0)?;
            if read_u16(body, PUBLIC_KEY_HEADER_BYTES) != 0 {
                return Err(BraidStatePayloadError::InvalidBody);
            }
            Ok(())
        }
        BraidStateVariant::Ct1Sampled => {
            let next_index_offset = PENDING_ENCAPSULATION_BYTES;
            let decoder_offset = next_index_offset + 2;
            require_minimum_length(body, decoder_offset + 2)?;
            validate_encoder_index(read_u16(body, next_index_offset), true)?;
            validate_decoder(body, decoder_offset, 36, 0)
        }
        BraidStateVariant::EkReceivedCt1Sampled => {
            let vector_offset = PENDING_ENCAPSULATION_BYTES;
            let next_index_offset = vector_offset + PUBLIC_KEY_VECTOR_BYTES;
            require_exact_length(body, next_index_offset + 2)?;
            validate_public_key(
                &body[..PUBLIC_KEY_HEADER_BYTES],
                &body[vector_offset..next_index_offset],
            )
            .map_err(|_| BraidStatePayloadError::InvalidBody)?;
            validate_encoder_index(read_u16(body, next_index_offset), true)
        }
        BraidStateVariant::Ct1Acknowledged => {
            require_minimum_length(body, PENDING_ENCAPSULATION_BYTES + 2)?;
            validate_decoder(body, PENDING_ENCAPSULATION_BYTES, 36, 1)
        }
        BraidStateVariant::Ct2Sampled => {
            let next_index_offset = CIPHERTEXT_PART_TWO_BYTES + MAC_BYTES;
            require_exact_length(body, next_index_offset + 2)?;
            validate_encoder_index(read_u16(body, next_index_offset), false)
        }
    }
}

fn validate_private_key(bytes: &[u8]) -> Result<(), BraidStatePayloadError> {
    key_pair_from_private_key(bytes)
        .map(|_| ())
        .map_err(|_| BraidStatePayloadError::InvalidPrivateKey)
}

fn validate_encoder_index(
    next_index: u16,
    must_have_emitted: bool,
) -> Result<(), BraidStatePayloadError> {
    if must_have_emitted && next_index == 0 {
        return Err(BraidStatePayloadError::InvalidBody);
    }
    // 65535 is never emitted on the wire. It is the sole canonical marker that
    // all 0..65534 symbols have already been emitted.
    let _exhausted = next_index == EXHAUSTED_ENCODER_INDEX;
    Ok(())
}

fn validate_decoder(
    body: &[u8],
    offset: usize,
    source_chunks: usize,
    minimum_count: usize,
) -> Result<(), BraidStatePayloadError> {
    let count_end = offset
        .checked_add(2)
        .ok_or(BraidStatePayloadError::InvalidLength)?;
    if count_end > body.len() {
        return Err(BraidStatePayloadError::InvalidLength);
    }
    let count = read_u16(body, offset) as usize;
    if count < minimum_count || count >= source_chunks {
        return Err(BraidStatePayloadError::InvalidBody);
    }
    let chunks_bytes = count
        .checked_mul(ENCODED_CHUNK_BYTES)
        .ok_or(BraidStatePayloadError::InvalidLength)?;
    let expected_end = count_end
        .checked_add(chunks_bytes)
        .ok_or(BraidStatePayloadError::InvalidLength)?;
    if expected_end != body.len() {
        return Err(BraidStatePayloadError::InvalidLength);
    }

    let mut previous_index = None;
    for chunk in body[count_end..].chunks_exact(ENCODED_CHUNK_BYTES) {
        let index = u16::from_be_bytes([chunk[0], chunk[1]]);
        if index > MAX_ENCODING_INDEX || previous_index.is_some_and(|previous| index <= previous) {
            return Err(BraidStatePayloadError::InvalidBody);
        }
        previous_index = Some(index);
    }
    Ok(())
}

fn require_exact_length(bytes: &[u8], expected: usize) -> Result<(), BraidStatePayloadError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(BraidStatePayloadError::InvalidLength)
    }
}

fn require_minimum_length(bytes: &[u8], minimum: usize) -> Result<(), BraidStatePayloadError> {
    if bytes.len() >= minimum {
        Ok(())
    } else {
        Err(BraidStatePayloadError::InvalidLength)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incremental_mlkem::key_pair_from_seed;
    use crate::state_envelope::{open as open_envelope, seal as seal_envelope, STATE_NONCE_BYTES};

    const AUTH_ROOT: [u8; AUTH_KEY_BYTES] = [0x31; AUTH_KEY_BYTES];
    const AUTH_MAC: [u8; AUTH_KEY_BYTES] = [0x72; AUTH_KEY_BYTES];

    fn metadata(role: StateRole, epoch: u64) -> StateMetadata {
        StateMetadata::new(
            role,
            [0x44; SESSION_ID_BYTES as usize],
            7,
            epoch - 1,
            epoch - 1,
        )
        .unwrap()
    }

    fn private_key() -> [u8; PRIVATE_KEY_BYTES] {
        *key_pair_from_seed(&[0x53; 64]).unwrap().private_key()
    }

    fn pending() -> Vec<u8> {
        let key_pair = key_pair_from_seed(&[0x53; 64]).unwrap();
        let mut body = Vec::with_capacity(PENDING_ENCAPSULATION_BYTES);
        body.extend_from_slice(key_pair.public_key_header());
        body.extend_from_slice(&[0xa6; ENCAPSULATION_STATE_BYTES]);
        body.extend_from_slice(&[0xb7; CIPHERTEXT_PART_ONE_BYTES]);
        body
    }

    fn decoder(count: usize) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(2 + count * ENCODED_CHUNK_BYTES);
        encoded.extend_from_slice(&(count as u16).to_be_bytes());
        for item in 0..count {
            encoded.extend_from_slice(&((item * 3 + 1) as u16).to_be_bytes());
            encoded.extend_from_slice(&[item as u8 + 1; ENCODED_CHUNK_BYTES - 2]);
        }
        encoded
    }

    fn body(variant: BraidStateVariant) -> Vec<u8> {
        let key_pair = key_pair_from_seed(&[0x53; 64]).unwrap();
        match variant {
            BraidStateVariant::KeysUnsampled => Vec::new(),
            BraidStateVariant::KeysSampled => {
                let mut body = private_key().to_vec();
                body.extend_from_slice(&[0x81; MAC_BYTES]);
                body.extend_from_slice(&1_u16.to_be_bytes());
                body
            }
            BraidStateVariant::HeaderSent => {
                let mut body = private_key().to_vec();
                body.extend_from_slice(&0_u16.to_be_bytes());
                body.extend_from_slice(&decoder(1));
                body
            }
            BraidStateVariant::Ct1Received => {
                let mut body = private_key().to_vec();
                body.extend_from_slice(&[0x42; CIPHERTEXT_PART_ONE_BYTES]);
                body.extend_from_slice(&9_u16.to_be_bytes());
                body
            }
            BraidStateVariant::EkSentCt1Received => {
                let mut body = private_key().to_vec();
                body.extend_from_slice(&[0x42; CIPHERTEXT_PART_ONE_BYTES]);
                body.extend_from_slice(&decoder(1));
                body
            }
            BraidStateVariant::NoHeaderReceived => decoder(0),
            BraidStateVariant::HeaderReceived => {
                let mut body = key_pair.public_key_header().to_vec();
                body.extend_from_slice(&decoder(0));
                body
            }
            BraidStateVariant::Ct1Sampled => {
                let mut body = pending();
                body.extend_from_slice(&1_u16.to_be_bytes());
                body.extend_from_slice(&decoder(2));
                body
            }
            BraidStateVariant::EkReceivedCt1Sampled => {
                let mut body = pending();
                body.extend_from_slice(key_pair.public_key_vector());
                body.extend_from_slice(&3_u16.to_be_bytes());
                body
            }
            BraidStateVariant::Ct1Acknowledged => {
                let mut body = pending();
                body.extend_from_slice(&decoder(1));
                body
            }
            BraidStateVariant::Ct2Sampled => {
                let mut body = vec![0x91; CIPHERTEXT_PART_TWO_BYTES + MAC_BYTES];
                body.extend_from_slice(&0_u16.to_be_bytes());
                body
            }
        }
    }

    fn role_for(variant: BraidStateVariant) -> StateRole {
        if variant.is_key_sender() {
            StateRole::Initiator
        } else {
            StateRole::Responder
        }
    }

    #[test]
    fn all_revision_one_variants_round_trip_canonically() {
        let variants = [
            BraidStateVariant::KeysUnsampled,
            BraidStateVariant::KeysSampled,
            BraidStateVariant::HeaderSent,
            BraidStateVariant::Ct1Received,
            BraidStateVariant::EkSentCt1Received,
            BraidStateVariant::NoHeaderReceived,
            BraidStateVariant::HeaderReceived,
            BraidStateVariant::Ct1Sampled,
            BraidStateVariant::EkReceivedCt1Sampled,
            BraidStateVariant::Ct1Acknowledged,
            BraidStateVariant::Ct2Sampled,
        ];
        for variant in variants {
            let metadata = metadata(role_for(variant), 1);
            let encoded =
                encode(metadata, 1, variant, &AUTH_ROOT, &AUTH_MAC, &body(variant)).unwrap();
            let decoded = decode(metadata, encoded.encoded()).unwrap();
            assert_eq!(decoded.metadata(), metadata);
            assert_eq!(decoded.epoch(), 1);
            assert_eq!(decoded.variant(), variant);
            assert_eq!(decoded.encoded(), encoded.encoded());
        }
    }

    #[test]
    fn stable_role_and_epoch_parity_select_the_state_machine_side() {
        let sender = BraidStateVariant::KeysUnsampled;
        let receiver = BraidStateVariant::NoHeaderReceived;
        assert!(encode(
            metadata(StateRole::Initiator, 1),
            1,
            sender,
            &AUTH_ROOT,
            &AUTH_MAC,
            &body(sender),
        )
        .is_ok());
        assert!(encode(
            metadata(StateRole::Initiator, 2),
            2,
            receiver,
            &AUTH_ROOT,
            &AUTH_MAC,
            &body(receiver),
        )
        .is_ok());
        assert_eq!(
            encode(
                metadata(StateRole::Initiator, 1),
                1,
                receiver,
                &AUTH_ROOT,
                &AUTH_MAC,
                &body(receiver),
            )
            .err(),
            Some(BraidStatePayloadError::InvalidVariant)
        );
    }

    #[test]
    fn variant_specific_high_water_values_match_revision_one_outputs() {
        let session = [0x44; SESSION_ID_BYTES as usize];
        let keys_unsampled = BraidStateVariant::KeysUnsampled;
        let after_ct2 = StateMetadata::new(StateRole::Responder, session, 7, 0, 1).unwrap();
        assert!(encode(
            after_ct2,
            2,
            keys_unsampled,
            &AUTH_ROOT,
            &AUTH_MAC,
            &body(keys_unsampled),
        )
        .is_ok());
        let impossible = StateMetadata::new(StateRole::Responder, session, 7, 1, 1).unwrap();
        assert!(encode(
            impossible,
            2,
            keys_unsampled,
            &AUTH_ROOT,
            &AUTH_MAC,
            &body(keys_unsampled),
        )
        .is_err());

        let no_header = BraidStateVariant::NoHeaderReceived;
        for sending in 0..=1 {
            for receiving in 0..=1 {
                let metadata =
                    StateMetadata::new(StateRole::Initiator, session, 7, sending, receiving)
                        .unwrap();
                assert!(encode(
                    metadata,
                    2,
                    no_header,
                    &AUTH_ROOT,
                    &AUTH_MAC,
                    &body(no_header),
                )
                .is_ok());
            }
        }

        let header_received = BraidStateVariant::HeaderReceived;
        let header_body = body(header_received);
        for sending in 0..=1 {
            let metadata =
                StateMetadata::new(StateRole::Initiator, session, 7, sending, 1).unwrap();
            assert!(encode(
                metadata,
                2,
                header_received,
                &AUTH_ROOT,
                &AUTH_MAC,
                &header_body,
            )
            .is_ok());
        }
    }

    #[test]
    fn outer_metadata_must_match_every_duplicated_inner_field() {
        let variant = BraidStateVariant::KeysUnsampled;
        let metadata = metadata(StateRole::Initiator, 1);
        let state = encode(metadata, 1, variant, &AUTH_ROOT, &AUTH_MAC, &[]).unwrap();
        let wrong = StateMetadata::new(
            StateRole::Initiator,
            [0x44; SESSION_ID_BYTES as usize],
            8,
            0,
            0,
        )
        .unwrap();
        assert_eq!(
            decode(wrong, state.encoded()).err(),
            Some(BraidStatePayloadError::InvalidMetadata)
        );

        let mut malformed = state.encoded().to_vec();
        malformed[SENDING_EPOCH_OFFSET..RECEIVING_EPOCH_OFFSET]
            .copy_from_slice(&1_u64.to_be_bytes());
        assert_eq!(
            decode(metadata, &malformed).err(),
            Some(BraidStatePayloadError::InvalidMetadata)
        );
    }

    #[test]
    fn fixed_header_rejects_alternate_encodings_and_bad_lengths() {
        let metadata = metadata(StateRole::Initiator, 1);
        let state = encode(
            metadata,
            1,
            BraidStateVariant::KeysUnsampled,
            &AUTH_ROOT,
            &AUTH_MAC,
            &[],
        )
        .unwrap();
        let canonical = state.encoded();

        for offset in [
            0,
            FORMAT_OFFSET,
            SUITE_OFFSET,
            FLAGS_OFFSET,
            RESERVED_OFFSET,
        ] {
            let mut malformed = canonical.to_vec();
            malformed[offset] ^= 1;
            assert!(decode(metadata, &malformed).is_err(), "offset {offset}");
        }
        for range in [
            HEADER_LENGTH_OFFSET..PROTOCOL_REVISION_OFFSET,
            PROTOCOL_REVISION_OFFSET..TOTAL_LENGTH_OFFSET,
            TOTAL_LENGTH_OFFSET..SESSION_ID_OFFSET,
            BODY_LENGTH_OFFSET..RESERVED_OFFSET,
        ] {
            let mut malformed = canonical.to_vec();
            malformed[range.start] ^= 1;
            assert!(decode(metadata, &malformed).is_err(), "range {range:?}");
        }
        assert!(decode(metadata, &canonical[..canonical.len() - 1]).is_err());
        let mut appended = canonical.to_vec();
        appended.push(0);
        assert!(decode(metadata, &appended).is_err());
    }

    #[test]
    fn private_key_and_public_key_relationships_are_validated() {
        let sender = BraidStateVariant::KeysSampled;
        let mut sender_body = body(sender);
        sender_body[PRIVATE_KEY_BYTES - 65] ^= 1;
        assert_eq!(
            encode(
                metadata(StateRole::Initiator, 1),
                1,
                sender,
                &AUTH_ROOT,
                &AUTH_MAC,
                &sender_body,
            )
            .err(),
            Some(BraidStatePayloadError::InvalidPrivateKey)
        );

        let responder = BraidStateVariant::EkReceivedCt1Sampled;
        let mut responder_body = body(responder);
        responder_body[PENDING_ENCAPSULATION_BYTES] ^= 1;
        assert_eq!(
            encode(
                metadata(StateRole::Responder, 1),
                1,
                responder,
                &AUTH_ROOT,
                &AUTH_MAC,
                &responder_body,
            )
            .err(),
            Some(BraidStatePayloadError::InvalidBody)
        );
    }

    #[test]
    fn decoder_state_is_sorted_unique_incomplete_and_bounded() {
        let variant = BraidStateVariant::NoHeaderReceived;
        let metadata = metadata(StateRole::Responder, 1);
        let mut unsorted = decoder(2);
        unsorted[2..4].copy_from_slice(&9_u16.to_be_bytes());
        unsorted[2 + ENCODED_CHUNK_BYTES..4 + ENCODED_CHUNK_BYTES]
            .copy_from_slice(&8_u16.to_be_bytes());
        assert!(encode(metadata, 1, variant, &AUTH_ROOT, &AUTH_MAC, &unsorted).is_err());

        let mut duplicate = decoder(2);
        let first = [duplicate[2], duplicate[3]];
        duplicate[2 + ENCODED_CHUNK_BYTES..4 + ENCODED_CHUNK_BYTES].copy_from_slice(&first);
        assert!(encode(metadata, 1, variant, &AUTH_ROOT, &AUTH_MAC, &duplicate).is_err());

        let mut reserved = decoder(1);
        reserved[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(encode(metadata, 1, variant, &AUTH_ROOT, &AUTH_MAC, &reserved).is_err());
        assert!(encode(metadata, 1, variant, &AUTH_ROOT, &AUTH_MAC, &decoder(3)).is_err());
    }

    #[test]
    fn state_specific_progress_invariants_reject_impossible_bodies() {
        let keys = BraidStateVariant::KeysSampled;
        let mut keys_body = body(keys);
        let keys_next = PRIVATE_KEY_BYTES + MAC_BYTES;
        keys_body[keys_next..keys_next + 2].copy_from_slice(&0_u16.to_be_bytes());
        assert!(encode(
            metadata(StateRole::Initiator, 1),
            1,
            keys,
            &AUTH_ROOT,
            &AUTH_MAC,
            &keys_body,
        )
        .is_err());

        let acknowledged = BraidStateVariant::Ct1Acknowledged;
        let mut empty = pending();
        empty.extend_from_slice(&decoder(0));
        assert!(encode(
            metadata(StateRole::Responder, 1),
            1,
            acknowledged,
            &AUTH_ROOT,
            &AUTH_MAC,
            &empty,
        )
        .is_err());
    }

    #[test]
    fn signed_63_epoch_boundary_is_canonical() {
        let epoch = MAX_COUNTER;
        let metadata = StateMetadata::new(
            StateRole::Initiator,
            [0x44; SESSION_ID_BYTES as usize],
            7,
            epoch - 2,
            epoch - 1,
        )
        .unwrap();
        let state = encode(
            metadata,
            epoch,
            BraidStateVariant::KeysUnsampled,
            &AUTH_ROOT,
            &AUTH_MAC,
            &[],
        )
        .unwrap();
        assert!(decode(metadata, state.encoded()).is_ok());

        let mut high_bit = state.encoded().to_vec();
        high_bit[EPOCH_OFFSET..SENDING_EPOCH_OFFSET]
            .copy_from_slice(&0x8000_0000_0000_0000_u64.to_be_bytes());
        assert!(decode(metadata, &high_bit).is_err());
    }

    #[test]
    fn owned_plaintext_is_zeroized_by_the_drop_path() {
        let metadata = metadata(StateRole::Initiator, 1);
        let mut state = encode(
            metadata,
            1,
            BraidStateVariant::KeysUnsampled,
            &AUTH_ROOT,
            &AUTH_MAC,
            &[],
        )
        .unwrap();
        state.wipe();
        assert!(state.encoded.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn maximum_canonical_payload_round_trips_inside_authenticated_ls3() {
        let variant = BraidStateVariant::Ct1Sampled;
        let metadata = metadata(StateRole::Responder, 1);
        let mut maximum_body = pending();
        maximum_body.extend_from_slice(&1_u16.to_be_bytes());
        maximum_body.extend_from_slice(&decoder(35));
        let payload = encode(metadata, 1, variant, &AUTH_ROOT, &AUTH_MAC, &maximum_body).unwrap();
        assert_eq!(payload.encoded().len(), MAX_BRAID_PAYLOAD_BYTES);

        let state_key = [0x19; 32];
        let nonce = [0x28; STATE_NONCE_BYTES];
        let sealed = seal_envelope(metadata, &state_key, &nonce, payload.encoded()).unwrap();
        let opened = open_envelope(
            metadata.role(),
            metadata.session_id(),
            &state_key,
            metadata.state_revision(),
            &sealed,
        )
        .unwrap();
        let decoded = decode(opened.metadata(), opened.payload()).unwrap();
        assert_eq!(decoded.variant(), variant);
        assert_eq!(decoded.encoded(), payload.encoded());
    }
}
