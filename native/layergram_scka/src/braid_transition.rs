// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

//! Initial immutable ML-KEM Braid revision-1 transitions.
//!
//! This private slice implements `InitAlice`, `InitBob`, transition 1
//! (`KeysUnsampled.Send`), transition 2 (`KeysSampled.Receive`), and the
//! corresponding same-state send/receive behavior from the public-domain
//! specification. It does not mutate the authenticated prior.
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
use crate::erasure::{
    encode_chunks, ErasureError, ErasureMessageKind, ENCODED_CHUNK_BYTES, MAX_ENCODING_INDEX,
};
use crate::incremental_mlkem::{
    key_pair_from_private_key, key_pair_from_seed, IncrementalMlKemError,
    KEY_GENERATION_SEED_BYTES, PRIVATE_KEY_BYTES, PUBLIC_KEY_HEADER_BYTES,
};
use crate::state_envelope::{StateEnvelopeError, StateMetadata, StateRole};
use crate::{MAX_COUNTER, SESSION_ID_BYTES};

const INITIAL_EPOCH: u64 = 1;
const INITIAL_HIGH_WATER: u64 = 0;
const FIRST_ENCODER_INDEX: u16 = 1;
const HEADER_AND_MAC_BYTES: usize = PUBLIC_KEY_HEADER_BYTES + MAC_BYTES;
const KEYS_SAMPLED_MAC_OFFSET: usize = PRIVATE_KEY_BYTES;
const KEYS_SAMPLED_INDEX_OFFSET: usize = PRIVATE_KEY_BYTES + MAC_BYTES;
const KEYS_SAMPLED_BODY_BYTES: usize = KEYS_SAMPLED_INDEX_OFFSET + 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BraidTransitionError {
    InvalidState,
    RevisionExhausted,
    EncoderExhausted,
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

/// Detached revision-plus-one candidate for one canonical receive operation.
/// The semantic Braid state may remain unchanged, but the Layergram durable
/// revision always records that the serialized session authority accepted the
/// input.
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

/// Production state-machine send entry point for the implemented slice.
pub(crate) fn send(prior: &BraidStatePayload) -> Result<BraidSendCandidate, BraidTransitionError> {
    match prior.variant() {
        BraidStateVariant::KeysUnsampled => send_with_entropy(prior, &mut OsEntropy),
        BraidStateVariant::KeysSampled => send_while_keys_sampled(prior),
        _ => Err(BraidTransitionError::InvalidState),
    }
}

/// Production state-machine receive entry point for the implemented slice.
pub(crate) fn receive(
    prior: &BraidStatePayload,
    message: &BraidPublicMessage,
) -> Result<BraidReceiveCandidate, BraidTransitionError> {
    match prior.variant() {
        BraidStateVariant::KeysUnsampled => receive_while_keys_unsampled(prior, message),
        BraidStateVariant::KeysSampled => receive_while_keys_sampled(prior, message),
        _ => Err(BraidTransitionError::InvalidState),
    }
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

/// Emits the next authenticated header erasure symbol without requesting new
/// entropy. A lost exported symbol advances only the detached candidate; retry
/// must reuse that exact candidate, while a later committed send emits a fresh
/// erasure symbol from the persisted next index.
fn send_while_keys_sampled(
    prior: &BraidStatePayload,
) -> Result<BraidSendCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::KeysSampled
        || prior.body().len() != KEYS_SAMPLED_BODY_BYTES
    {
        return Err(BraidTransitionError::InvalidState);
    }
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;
    let next_index = u16::from_be_bytes(
        prior.body()[KEYS_SAMPLED_INDEX_OFFSET..KEYS_SAMPLED_BODY_BYTES]
            .try_into()
            .map_err(|_| BraidTransitionError::InvalidState)?,
    );
    if next_index > MAX_ENCODING_INDEX {
        return Err(BraidTransitionError::EncoderExhausted);
    }

    let key_pair = key_pair_from_private_key(&prior.body()[..PRIVATE_KEY_BYTES])?;
    let auth = BraidAuthenticator::restore(prior.auth_root_key(), prior.auth_mac_key())?;
    let header_mac = &prior.body()[KEYS_SAMPLED_MAC_OFFSET..KEYS_SAMPLED_INDEX_OFFSET];
    auth.verify_header(prior.epoch(), key_pair.public_key_header(), header_mac)
        .map_err(|_| BraidTransitionError::InvalidState)?;

    let mut header_and_mac = [0_u8; HEADER_AND_MAC_BYTES];
    header_and_mac[..PUBLIC_KEY_HEADER_BYTES].copy_from_slice(key_pair.public_key_header());
    header_and_mac[PUBLIC_KEY_HEADER_BYTES..].copy_from_slice(header_mac);
    let encoded_chunks = encode_chunks(
        ErasureMessageKind::HeaderAndMac,
        &header_and_mac,
        &[next_index],
    );
    header_and_mac.zeroize();
    let mut encoded_chunks = encoded_chunks?;
    let chunk = encoded_chunks.pop().ok_or(BraidTransitionError::Encoding)?;
    let message = BraidPublicMessage::with_chunk(prior.epoch(), BraidMessageType::Header, chunk)?;

    let successor_metadata = StateMetadata::new(
        metadata.role(),
        *metadata.session_id(),
        successor_revision,
        metadata.sending_epoch(),
        metadata.receiving_epoch(),
    )?;
    let successor_index = next_index + 1;
    let mut body = Vec::with_capacity(KEYS_SAMPLED_BODY_BYTES);
    body.extend_from_slice(key_pair.private_key());
    body.extend_from_slice(header_mac);
    body.extend_from_slice(&successor_index.to_be_bytes());
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
}

/// Implements `KeysSampled.Receive`, including transition 2 on a current-epoch
/// `Ct1` symbol. Other canonical messages are semantically ignored but still
/// produce a detached revision-plus-one Layergram candidate.
fn receive_while_keys_sampled(
    prior: &BraidStatePayload,
    message: &BraidPublicMessage,
) -> Result<BraidReceiveCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::KeysSampled
        || prior.body().len() != KEYS_SAMPLED_BODY_BYTES
    {
        return Err(BraidTransitionError::InvalidState);
    }
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;

    // Reconstruct and authenticate the persisted sender state before either
    // carrying it forward or consuming a remote transition trigger.
    let key_pair = key_pair_from_private_key(&prior.body()[..PRIVATE_KEY_BYTES])?;
    let auth = BraidAuthenticator::restore(prior.auth_root_key(), prior.auth_mac_key())?;
    let header_mac = &prior.body()[KEYS_SAMPLED_MAC_OFFSET..KEYS_SAMPLED_INDEX_OFFSET];
    auth.verify_header(prior.epoch(), key_pair.public_key_header(), header_mac)
        .map_err(|_| BraidTransitionError::InvalidState)?;

    let successor_metadata = StateMetadata::new(
        metadata.role(),
        *metadata.session_id(),
        successor_revision,
        metadata.sending_epoch(),
        metadata.receiving_epoch(),
    )?;
    let transitioning =
        message.epoch() == prior.epoch() && message.message_type() == BraidMessageType::Ciphertext1;
    let successor = if transitioning {
        let chunk = message.chunk().ok_or(BraidTransitionError::Encoding)?;
        let mut body = Vec::with_capacity(PRIVATE_KEY_BYTES + 2 + 2 + ENCODED_CHUNK_BYTES);
        body.extend_from_slice(key_pair.private_key());
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&1_u16.to_be_bytes());
        body.extend_from_slice(&chunk.encode());
        let successor = braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::HeaderSent,
            auth.root_key(),
            auth.mac_key(),
            &body,
        );
        body.zeroize();
        successor?
    } else {
        braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::KeysSampled,
            auth.root_key(),
            auth.mac_key(),
            prior.body(),
        )?
    };
    Ok(BraidReceiveCandidate {
        successor,
        receiving_epoch: prior.epoch() - 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::braid_message::BraidMessageType;
    use crate::erasure::decode_message;
    use sha2::{Digest, Sha256};

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
    fn keys_sampled_send_survives_loss_without_requesting_more_entropy() {
        let prior = initialize(StateRole::Initiator, SESSION, &SHARED_SECRET).unwrap();
        let mut entropy = FixedEntropy::vector();
        let first = send_with_entropy(&prior, &mut entropy).unwrap();
        let first_successor_bytes = first.successor().encoded().to_vec();

        let second = send(first.successor()).unwrap();
        assert_eq!(
            hex(&second.message().encode()),
            "424d330101010018003a00010000000000000001000000000001a97715c9af11ebb552f3043e4c58cabaa54341dd4c59f29f1c5b0e125c1959d5"
        );
        assert_eq!(
            hex(&Sha256::digest(second.successor().encoded())),
            "590a20aef8e687241eb6edd0df7da0a68ce99cd5f09356fff0b2a54204d55ce5"
        );
        let lost_export = second.message().encode();
        assert_eq!(second.message().chunk().unwrap().index(), 1);
        assert_eq!(second.successor().metadata().state_revision(), 2);
        assert_eq!(
            &second.successor().body()[KEYS_SAMPLED_INDEX_OFFSET..],
            &2_u16.to_be_bytes()
        );
        assert_eq!(first.successor().encoded(), first_successor_bytes);
        assert_eq!(second.message().encode(), lost_export);

        // The committed successor can continue after the carrier drops index
        // one. Later erasure symbols still reconstruct the exact header.
        drop(lost_export);
        let third = send(second.successor()).unwrap();
        let fourth = send(third.successor()).unwrap();
        assert_eq!(third.message().chunk().unwrap().index(), 2);
        assert_eq!(fourth.message().chunk().unwrap().index(), 3);
        let recovered = decode_message(
            ErasureMessageKind::HeaderAndMac,
            &[
                first.message().chunk().unwrap().clone(),
                third.message().chunk().unwrap().clone(),
                fourth.message().chunk().unwrap().clone(),
            ],
        )
        .unwrap();
        let key_pair =
            key_pair_from_private_key(&first.successor().body()[..PRIVATE_KEY_BYTES]).unwrap();
        assert_eq!(
            &recovered[..PUBLIC_KEY_HEADER_BYTES],
            key_pair.public_key_header()
        );
        assert_eq!(
            &recovered[PUBLIC_KEY_HEADER_BYTES..],
            &first.successor().body()[KEYS_SAMPLED_MAC_OFFSET..KEYS_SAMPLED_INDEX_OFFSET]
        );
        assert_eq!(entropy.calls, 1);
    }

    #[test]
    fn keys_sampled_receive_transitions_only_on_current_epoch_ciphertext_one() {
        let prior = initialize(StateRole::Initiator, SESSION, &SHARED_SECRET).unwrap();
        let mut entropy = FixedEntropy::vector();
        let first = send_with_entropy(&prior, &mut entropy).unwrap();
        let first_body = first.successor().body().to_vec();
        let chunk = encode_chunks(ErasureMessageKind::MlKem768Ciphertext1, &[0x6d; 960], &[7])
            .unwrap()
            .remove(0);

        let future =
            BraidPublicMessage::with_chunk(2, BraidMessageType::Ciphertext1, chunk.clone())
                .unwrap();
        let ignored = receive(first.successor(), &future).unwrap();
        assert_eq!(
            ignored.successor().variant(),
            BraidStateVariant::KeysSampled
        );
        assert_eq!(ignored.successor().body(), first_body);
        assert_eq!(ignored.successor().metadata().state_revision(), 2);

        let current =
            BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext1, chunk.clone())
                .unwrap();
        let transitioned = receive(ignored.successor(), &current).unwrap();
        assert_eq!(
            hex(&Sha256::digest(transitioned.successor().encoded())),
            "a72fba9760eaa352a96a8b704eef519b55ce98c7630af100f2fc66c8d012ad6b"
        );
        assert_eq!(transitioned.receiving_epoch(), 0);
        assert_eq!(
            transitioned.successor().variant(),
            BraidStateVariant::HeaderSent
        );
        assert_eq!(transitioned.successor().metadata().state_revision(), 3);
        assert_eq!(
            &transitioned.successor().body()[..PRIVATE_KEY_BYTES],
            &first_body[..PRIVATE_KEY_BYTES]
        );
        assert_eq!(
            &transitioned.successor().body()[PRIVATE_KEY_BYTES..PRIVATE_KEY_BYTES + 2],
            &0_u16.to_be_bytes()
        );
        assert_eq!(
            &transitioned.successor().body()[PRIVATE_KEY_BYTES + 2..PRIVATE_KEY_BYTES + 4],
            &1_u16.to_be_bytes()
        );
        assert_eq!(
            &transitioned.successor().body()[PRIVATE_KEY_BYTES + 4..],
            &chunk.encode()
        );
        assert_eq!(first.successor().body(), first_body);
    }

    #[test]
    fn keys_sampled_rejects_inconsistent_mac_and_exhausted_state() {
        let prior = initialize(StateRole::Initiator, SESSION, &SHARED_SECRET).unwrap();
        let mut entropy = FixedEntropy::vector();
        let first = send_with_entropy(&prior, &mut entropy).unwrap();
        let ignored = BraidPublicMessage::without_data(1, BraidMessageType::None).unwrap();

        let mut inconsistent_body = first.successor().body().to_vec();
        inconsistent_body[KEYS_SAMPLED_MAC_OFFSET] ^= 1;
        let inconsistent = braid_state_payload::encode(
            first.successor().metadata(),
            first.successor().epoch(),
            BraidStateVariant::KeysSampled,
            first.successor().auth_root_key(),
            first.successor().auth_mac_key(),
            &inconsistent_body,
        )
        .unwrap();
        inconsistent_body.zeroize();
        assert_eq!(
            send(&inconsistent).err(),
            Some(BraidTransitionError::InvalidState)
        );
        assert_eq!(
            receive(&inconsistent, &ignored).err(),
            Some(BraidTransitionError::InvalidState)
        );

        let mut exhausted_body = first.successor().body().to_vec();
        exhausted_body[KEYS_SAMPLED_INDEX_OFFSET..].copy_from_slice(&u16::MAX.to_be_bytes());
        let exhausted_encoder = braid_state_payload::encode(
            first.successor().metadata(),
            first.successor().epoch(),
            BraidStateVariant::KeysSampled,
            first.successor().auth_root_key(),
            first.successor().auth_mac_key(),
            &exhausted_body,
        )
        .unwrap();
        exhausted_body.zeroize();
        assert_eq!(
            send(&exhausted_encoder).err(),
            Some(BraidTransitionError::EncoderExhausted)
        );

        let exhausted_metadata =
            StateMetadata::new(StateRole::Initiator, SESSION, MAX_COUNTER, 0, 0).unwrap();
        let exhausted_revision = braid_state_payload::encode(
            exhausted_metadata,
            first.successor().epoch(),
            BraidStateVariant::KeysSampled,
            first.successor().auth_root_key(),
            first.successor().auth_mac_key(),
            first.successor().body(),
        )
        .unwrap();
        assert_eq!(
            send(&exhausted_revision).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
        assert_eq!(
            receive(&exhausted_revision, &ignored).err(),
            Some(BraidTransitionError::RevisionExhausted)
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
