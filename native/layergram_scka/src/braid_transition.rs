// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

//! First immutable ML-KEM Braid revision-1 transitions.
//!
//! This private slice implements `InitAlice`, `InitBob`, transition 1
//! (`KeysUnsampled.Send`), and the `KeysUnsampled.Receive` no-op from the
//! public-domain specification. It does not mutate the authenticated prior.
//! A send result is an owned candidate containing the exact successor and BM3
//! record; a future durable coordinator must seal the plaintext successor and
//! atomically persist that exact LS3 state with the outbound record before the
//! record can be exported through another messaging application.

use zeroize::Zeroize;

use crate::braid_authenticator::{BraidAuthenticator, BraidAuthenticatorError, MAC_BYTES};
use crate::braid_message::{BraidMessageError, BraidMessageType, BraidPublicMessage};
use crate::braid_state_payload::{
    self, BraidStatePayload, BraidStatePayloadError, BraidStateVariant,
};
use crate::entropy::{EntropyError, EntropySource, OsEntropy};
use crate::erasure::{encode_chunks, ErasureError, ErasureMessageKind};
use crate::incremental_mlkem::{
    key_pair_from_seed, IncrementalMlKemError, KEY_GENERATION_SEED_BYTES, PRIVATE_KEY_BYTES,
    PUBLIC_KEY_HEADER_BYTES,
};
use crate::state_envelope::{StateEnvelopeError, StateMetadata, StateRole};
use crate::{MAX_COUNTER, SESSION_ID_BYTES};

const INITIAL_EPOCH: u64 = 1;
const INITIAL_HIGH_WATER: u64 = 0;
const FIRST_ENCODER_INDEX: u16 = 1;
const HEADER_AND_MAC_BYTES: usize = PUBLIC_KEY_HEADER_BYTES + MAC_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BraidTransitionError {
    InvalidState,
    RevisionExhausted,
    Entropy,
    Primitive,
    Encoding,
}

impl From<BraidAuthenticatorError> for BraidTransitionError {
    fn from(_: BraidAuthenticatorError) -> Self {
        Self::Primitive
    }
}

impl From<BraidStatePayloadError> for BraidTransitionError {
    fn from(_: BraidStatePayloadError) -> Self {
        Self::Encoding
    }
}

impl From<StateEnvelopeError> for BraidTransitionError {
    fn from(_: StateEnvelopeError) -> Self {
        Self::InvalidState
    }
}

impl From<IncrementalMlKemError> for BraidTransitionError {
    fn from(_: IncrementalMlKemError) -> Self {
        Self::Primitive
    }
}

impl From<ErasureError> for BraidTransitionError {
    fn from(_: ErasureError) -> Self {
        Self::Encoding
    }
}

impl From<BraidMessageError> for BraidTransitionError {
    fn from(_: BraidMessageError) -> Self {
        Self::Encoding
    }
}

impl From<EntropyError> for BraidTransitionError {
    fn from(_: EntropyError) -> Self {
        Self::Entropy
    }
}

/// Exact, detached result of one Braid send.
///
/// It intentionally implements neither `Clone` nor `Debug`. Re-export and
/// retry must reuse this exact candidate (or its future durable representation)
/// instead of invoking the randomized transition again.
pub(crate) struct BraidSendCandidate {
    successor: BraidStatePayload,
    message: BraidPublicMessage,
    sending_epoch: u64,
}

impl BraidSendCandidate {
    pub(crate) fn successor(&self) -> &BraidStatePayload {
        &self.successor
    }

    pub(crate) fn message(&self) -> &BraidPublicMessage {
        &self.message
    }

    pub(crate) fn sending_epoch(&self) -> u64 {
        self.sending_epoch
    }
}

/// Detached revision-plus-one candidate for a semantically ignored receive.
/// The Braid state is unchanged, but the Layergram durable revision records
/// that one canonical input was accepted by the serialized session authority.
pub(crate) struct BraidReceiveCandidate {
    successor: BraidStatePayload,
    receiving_epoch: u64,
}

impl BraidReceiveCandidate {
    pub(crate) fn successor(&self) -> &BraidStatePayload {
        &self.successor
    }

    pub(crate) fn into_successor(self) -> BraidStatePayload {
        self.successor
    }

    pub(crate) fn receiving_epoch(&self) -> u64 {
        self.receiving_epoch
    }
}

/// Implements revision-1 `InitAlice`/`InitBob` without sealing or activating
/// the public ABI.
pub(crate) fn initialize(
    role: StateRole,
    session_id: [u8; SESSION_ID_BYTES as usize],
    shared_secret: &[u8],
) -> Result<BraidStatePayload, BraidTransitionError> {
    let metadata = StateMetadata::new(role, session_id, 0, INITIAL_HIGH_WATER, INITIAL_HIGH_WATER)?;
    let auth = BraidAuthenticator::initialize(INITIAL_EPOCH, shared_secret)?;
    let (variant, body): (BraidStateVariant, &[u8]) = match role {
        StateRole::Initiator => (BraidStateVariant::KeysUnsampled, &[]),
        StateRole::Responder => (BraidStateVariant::NoHeaderReceived, &[0, 0]),
    };
    braid_state_payload::encode(
        metadata,
        INITIAL_EPOCH,
        variant,
        auth.root_key(),
        auth.mac_key(),
        body,
    )
    .map_err(Into::into)
}

/// Production entropy entry point for transition 1.
pub(crate) fn send(prior: &BraidStatePayload) -> Result<BraidSendCandidate, BraidTransitionError> {
    send_with_entropy(prior, &mut OsEntropy)
}

fn send_with_entropy(
    prior: &BraidStatePayload,
    entropy: &mut impl EntropySource,
) -> Result<BraidSendCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::KeysUnsampled || !prior.body().is_empty() {
        return Err(BraidTransitionError::InvalidState);
    }
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;
    let successor_metadata = StateMetadata::new(
        metadata.role(),
        *metadata.session_id(),
        successor_revision,
        prior.epoch() - 1,
        prior.epoch() - 1,
    )?;
    let auth = BraidAuthenticator::restore(prior.auth_root_key(), prior.auth_mac_key())?;

    let mut key_seed = [0_u8; KEY_GENERATION_SEED_BYTES];
    let result = (|| {
        entropy.fill(&mut key_seed)?;
        let key_pair = key_pair_from_seed(&key_seed)?;
        let header_mac = auth.mac_header(prior.epoch(), key_pair.public_key_header())?;

        let mut header_and_mac = [0_u8; HEADER_AND_MAC_BYTES];
        header_and_mac[..PUBLIC_KEY_HEADER_BYTES].copy_from_slice(key_pair.public_key_header());
        header_and_mac[PUBLIC_KEY_HEADER_BYTES..].copy_from_slice(&header_mac);
        let encoded_chunks = encode_chunks(ErasureMessageKind::HeaderAndMac, &header_and_mac, &[0]);
        header_and_mac.zeroize();
        let mut encoded_chunks = encoded_chunks?;
        let first_chunk = encoded_chunks.pop().ok_or(BraidTransitionError::Encoding)?;
        let message =
            BraidPublicMessage::with_chunk(prior.epoch(), BraidMessageType::Header, first_chunk)?;

        let mut body = Vec::with_capacity(PRIVATE_KEY_BYTES + MAC_BYTES + 2);
        body.extend_from_slice(key_pair.private_key());
        body.extend_from_slice(&header_mac);
        body.extend_from_slice(&FIRST_ENCODER_INDEX.to_be_bytes());
        let successor = braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::KeysSampled,
            auth.root_key(),
            auth.mac_key(),
            &body,
        );
        body.zeroize();

        Ok(BraidSendCandidate {
            successor: successor?,
            message,
            sending_epoch: prior.epoch() - 1,
        })
    })();
    key_seed.zeroize();
    result
}

/// Implements the revision-1 no-op receive behavior of `KeysUnsampled`.
/// Delayed, duplicated, and reordered canonical messages do not mutate the
/// prior or advance Braid semantics. The detached wrapper revision still
/// advances once, matching the frozen durable ABI contract.
pub(crate) fn receive_while_keys_unsampled(
    prior: &BraidStatePayload,
    _message: &BraidPublicMessage,
) -> Result<BraidReceiveCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::KeysUnsampled || !prior.body().is_empty() {
        return Err(BraidTransitionError::InvalidState);
    }
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;
    let successor_metadata = StateMetadata::new(
        metadata.role(),
        *metadata.session_id(),
        successor_revision,
        metadata.sending_epoch(),
        metadata.receiving_epoch(),
    )?;
    let successor = braid_state_payload::encode(
        successor_metadata,
        prior.epoch(),
        BraidStateVariant::KeysUnsampled,
        prior.auth_root_key(),
        prior.auth_mac_key(),
        &[],
    )?;
    Ok(BraidReceiveCandidate {
        successor,
        receiving_epoch: prior.epoch() - 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::braid_message::BraidMessageType;

    const SESSION: [u8; SESSION_ID_BYTES as usize] = [0x51; SESSION_ID_BYTES as usize];
    const SHARED_SECRET: [u8; 32] = [0x11; 32];
    const D: [u8; 32] = hex32("934d60b35624d740b30a7f227af2ae7c678e4e04e13c5f509eade2b79aea77e2");
    const Z: [u8; 32] = hex32("3e2a2ea6c9c476fc4937b013c993a793d6c0ab9960695ba838f649da539ca3d0");

    struct FixedEntropy {
        seed: [u8; KEY_GENERATION_SEED_BYTES],
        calls: usize,
    }

    impl FixedEntropy {
        fn vector() -> Self {
            let mut seed = [0_u8; KEY_GENERATION_SEED_BYTES];
            seed[..32].copy_from_slice(&D);
            seed[32..].copy_from_slice(&Z);
            Self { seed, calls: 0 }
        }
    }

    impl EntropySource for FixedEntropy {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            assert_eq!(output.len(), self.seed.len());
            self.calls += 1;
            output.copy_from_slice(&self.seed);
            Ok(())
        }
    }

    #[test]
    fn initialization_freezes_revision_zero_roles_without_emitting_a_message() {
        let alice = initialize(StateRole::Initiator, SESSION, &SHARED_SECRET).unwrap();
        let bob = initialize(StateRole::Responder, SESSION, &SHARED_SECRET).unwrap();

        assert_eq!(alice.variant(), BraidStateVariant::KeysUnsampled);
        assert_eq!(bob.variant(), BraidStateVariant::NoHeaderReceived);
        assert_eq!(alice.epoch(), INITIAL_EPOCH);
        assert_eq!(bob.epoch(), INITIAL_EPOCH);
        assert_eq!(alice.metadata().state_revision(), 0);
        assert_eq!(bob.metadata().state_revision(), 0);
        assert_eq!(alice.metadata().sending_epoch(), 0);
        assert_eq!(alice.metadata().receiving_epoch(), 0);
        assert_eq!(bob.body(), &[0, 0]);
        assert_eq!(alice.auth_root_key(), bob.auth_root_key());
        assert_eq!(alice.auth_mac_key(), bob.auth_mac_key());
    }

    #[test]
    fn transition_one_is_detached_and_matches_the_independent_mlkem_vector() {
        let prior = initialize(StateRole::Initiator, SESSION, &SHARED_SECRET).unwrap();
        let prior_bytes = prior.encoded().to_vec();
        let mut entropy = FixedEntropy::vector();
        let candidate = send_with_entropy(&prior, &mut entropy).unwrap();

        assert_eq!(entropy.calls, 1);
        assert_eq!(prior.encoded(), prior_bytes);
        assert_eq!(prior.metadata().state_revision(), 0);
        assert_eq!(candidate.successor().metadata().state_revision(), 1);
        assert_eq!(
            candidate.successor().variant(),
            BraidStateVariant::KeysSampled
        );
        assert_eq!(candidate.successor().epoch(), 1);
        assert_eq!(candidate.sending_epoch(), 0);
        assert_eq!(candidate.message().epoch(), 1);
        assert_eq!(candidate.message().message_type(), BraidMessageType::Header);
        assert_eq!(candidate.message().chunk().unwrap().index(), 0);
        // The first systematic symbol is `rho`, independently computed as
        // SHA3-512(d || 0x03)[0..32] for the frozen ML-KEM-768 FIPS vector.
        assert_eq!(
            hex(candidate.message().chunk().unwrap().symbol()),
            "8a177e9b906fc450387061085ba73e2f1b49e58bca05bda09173f856df8bc38c"
        );
        assert_eq!(
            hex(&candidate.message().encode()),
            "424d330101010018003a000100000000000000010000000000008a177e9b906fc450387061085ba73e2f1b49e58bca05bda09173f856df8bc38c"
        );
        assert_eq!(
            &candidate.successor().body()[PRIVATE_KEY_BYTES + MAC_BYTES..],
            &FIRST_ENCODER_INDEX.to_be_bytes()
        );
    }

    #[test]
    fn one_candidate_is_stable_for_reexport_loss_and_restart() {
        let prior = initialize(StateRole::Initiator, SESSION, &SHARED_SECRET).unwrap();
        let mut entropy = FixedEntropy::vector();
        let candidate = send_with_entropy(&prior, &mut entropy).unwrap();
        let first_export = candidate.message().encode();
        let retry_export = candidate.message().encode();
        assert_eq!(first_export, retry_export);

        // Losing or never sending the exported copy cannot mutate either the
        // durable candidate or its prior.
        drop(first_export);
        assert_eq!(candidate.message().encode(), retry_export);
        assert_eq!(prior.metadata().state_revision(), 0);

        let restored = braid_state_payload::decode(
            candidate.successor().metadata(),
            candidate.successor().encoded(),
        )
        .unwrap();
        assert_eq!(restored.encoded(), candidate.successor().encoded());
        assert_eq!(restored.variant(), BraidStateVariant::KeysSampled);
        assert_eq!(restored.metadata().state_revision(), 1);
    }

    #[test]
    fn duplicates_and_reordering_are_ignored_in_keys_unsampled() {
        let mut prior = initialize(StateRole::Initiator, SESSION, &SHARED_SECRET).unwrap();
        let late = BraidPublicMessage::without_data(1, BraidMessageType::None).unwrap();
        let future = BraidPublicMessage::without_data(2, BraidMessageType::Ciphertext1Ack).unwrap();

        for (expected_revision, message) in [1, 2, 3].into_iter().zip([&future, &late, &late]) {
            let prior_bytes = prior.encoded().to_vec();
            let outcome = receive_while_keys_unsampled(&prior, message).unwrap();
            assert_eq!(outcome.receiving_epoch(), 0);
            assert_eq!(prior.encoded(), prior_bytes);
            assert_eq!(
                outcome.successor().variant(),
                BraidStateVariant::KeysUnsampled
            );
            assert_eq!(
                outcome.successor().metadata().state_revision(),
                expected_revision
            );
            assert_eq!(outcome.successor().auth_root_key(), prior.auth_root_key());
            assert_eq!(outcome.successor().auth_mac_key(), prior.auth_mac_key());
            prior = outcome.into_successor();
        }
    }

    #[test]
    fn entropy_errors_fail_closed_before_a_candidate_is_returned() {
        struct FailingEntropy;
        impl EntropySource for FailingEntropy {
            fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
                output.fill(0xa5);
                Err(EntropyError::Unavailable)
            }
        }

        let prior = initialize(StateRole::Initiator, SESSION, &SHARED_SECRET).unwrap();
        assert_eq!(
            send_with_entropy(&prior, &mut FailingEntropy).err(),
            Some(BraidTransitionError::Entropy)
        );

        let responder = initialize(StateRole::Responder, SESSION, &SHARED_SECRET).unwrap();
        let mut unused = FixedEntropy::vector();
        assert_eq!(
            send_with_entropy(&responder, &mut unused).err(),
            Some(BraidTransitionError::InvalidState)
        );
        assert_eq!(unused.calls, 0);

        let exhausted_metadata = StateMetadata::new(
            StateRole::Initiator,
            SESSION,
            MAX_COUNTER,
            INITIAL_HIGH_WATER,
            INITIAL_HIGH_WATER,
        )
        .unwrap();
        let exhausted = braid_state_payload::encode(
            exhausted_metadata,
            INITIAL_EPOCH,
            BraidStateVariant::KeysUnsampled,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            &[],
        )
        .unwrap();
        assert_eq!(
            send_with_entropy(&exhausted, &mut unused).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
        let ignored = BraidPublicMessage::without_data(1, BraidMessageType::None).unwrap();
        assert_eq!(
            receive_while_keys_unsampled(&exhausted, &ignored).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
        assert_eq!(unused.calls, 0);
    }

    #[test]
    fn production_send_uses_operating_system_entropy() {
        let prior = initialize(StateRole::Initiator, SESSION, &SHARED_SECRET).unwrap();
        let candidate = send(&prior).unwrap();
        assert_eq!(candidate.successor().metadata().state_revision(), 1);
        assert_eq!(candidate.message().message_type(), BraidMessageType::Header);
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

    const fn hex32(value: &str) -> [u8; 32] {
        let bytes = value.as_bytes();
        let mut output = [0_u8; 32];
        let mut index = 0;
        while index < 32 {
            output[index] = (nibble(bytes[index * 2]) << 4) | nibble(bytes[index * 2 + 1]);
            index += 1;
        }
        output
    }

    const fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid hex"),
        }
    }
}
