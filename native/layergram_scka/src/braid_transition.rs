// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

//! Initial immutable ML-KEM Braid revision-1 transitions.
//!
//! This private slice implements `InitAlice`, `InitBob`, transition 1
//! (`KeysUnsampled.Send`), transition 2 (`KeysSampled.Receive`), transition 3
//! (`HeaderSent.Receive`), transition 4 (`Ct1Received.Receive`), transition 5
//! (`EkSentCt1Received.Receive`), transition 6
//! (`NoHeaderReceived.Receive`), transition 7 (`HeaderReceived.Send`), and the
//! corresponding same-state send/receive behavior from the public-domain
//! specification. It does not mutate the authenticated prior.
//! A send result is an owned candidate containing the exact successor and BM3
//! record; a future durable coordinator must seal the plaintext successor and
//! atomically persist that exact LS3 state with the outbound record before the
//! record can be exported through another messaging application.

use zeroize::Zeroize;

use crate::braid_authenticator::{
    derive_output_key, BraidAuthenticator, BraidAuthenticatorError, BraidOutputKey, MAC_BYTES,
};
use crate::braid_message::{BraidMessageError, BraidMessageType, BraidPublicMessage};
use crate::braid_state_payload::{
    self, BraidStatePayload, BraidStatePayloadError, BraidStateVariant,
};
use crate::entropy::{EntropyError, EntropySource, OsEntropy};
use crate::erasure::{
    decode_message, encode_chunks, EncodedChunk, ErasureError, ErasureMessageKind,
    ENCODED_CHUNK_BYTES, MAX_ENCODING_INDEX,
};
use crate::incremental_mlkem::{
    decapsulate, encapsulate_part_one_from_seed, key_pair_from_private_key, key_pair_from_seed,
    IncrementalMlKemError, CIPHERTEXT_PART_ONE_BYTES, CIPHERTEXT_PART_TWO_BYTES,
    ENCAPSULATION_SEED_BYTES, ENCAPSULATION_STATE_BYTES, KEY_GENERATION_SEED_BYTES,
    PRIVATE_KEY_BYTES, PUBLIC_KEY_HEADER_BYTES,
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
const HEADER_SENT_INDEX_OFFSET: usize = PRIVATE_KEY_BYTES;
const HEADER_SENT_DECODER_OFFSET: usize = HEADER_SENT_INDEX_OFFSET + 2;
const CT1_RECEIVED_INDEX_OFFSET: usize = PRIVATE_KEY_BYTES + CIPHERTEXT_PART_ONE_BYTES;
const CT1_RECEIVED_BODY_BYTES: usize = CT1_RECEIVED_INDEX_OFFSET + 2;
const EK_SENT_CT1_DECODER_OFFSET: usize = PRIVATE_KEY_BYTES + CIPHERTEXT_PART_ONE_BYTES;
const CT2_WITH_MAC_BYTES: usize = CIPHERTEXT_PART_TWO_BYTES + MAC_BYTES;
const CT1_SAMPLED_NEXT_INDEX_OFFSET: usize =
    PUBLIC_KEY_HEADER_BYTES + ENCAPSULATION_STATE_BYTES + CIPHERTEXT_PART_ONE_BYTES;
const CT1_SAMPLED_DECODER_OFFSET: usize = CT1_SAMPLED_NEXT_INDEX_OFFSET + 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BraidTransitionError {
    InvalidState,
    RevisionExhausted,
    EpochExhausted,
    EncoderExhausted,
    Entropy,
    Authentication,
    Primitive,
    Encoding,
}

impl From<BraidAuthenticatorError> for BraidTransitionError {
    fn from(error: BraidAuthenticatorError) -> Self {
        match error {
            BraidAuthenticatorError::Authentication => Self::Authentication,
            _ => Self::Primitive,
        }
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
    output: Option<BraidEpochOutput>,
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

    pub(crate) fn output(&self) -> Option<&BraidEpochOutput> {
        self.output.as_ref()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        BraidStatePayload,
        BraidPublicMessage,
        Option<BraidEpochOutput>,
    ) {
        (self.successor, self.message, self.output)
    }
}

/// Detached revision-plus-one candidate for one canonical receive operation.
/// The semantic Braid state may remain unchanged, but the Layergram durable
/// revision always records that the serialized session authority accepted the
/// input.
pub(crate) struct BraidReceiveCandidate {
    successor: BraidStatePayload,
    receiving_epoch: u64,
    output: Option<BraidEpochOutput>,
}

/// Zeroizing owner for an epoch key emitted by a completed send or receive
/// transition.
///
/// The raw key remains native and is borrowed only while this detached
/// candidate is alive. A future durable coordinator must consume the exact
/// state and key together; dropping an uncommitted candidate wipes the key.
pub(crate) struct BraidEpochOutput {
    epoch: u64,
    key: BraidOutputKey,
}

impl BraidEpochOutput {
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn key_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }
}

impl BraidReceiveCandidate {
    pub(crate) fn successor(&self) -> &BraidStatePayload {
        &self.successor
    }

    /// Extracts a successor only when the transition emitted no epoch key.
    /// This prevents state-only helpers from silently discarding a completed
    /// transition-5 key. Key-emitting callers must consume [`Self::into_parts`].
    pub(crate) fn into_state_only_successor(self) -> Option<BraidStatePayload> {
        if self.output.is_none() {
            Some(self.successor)
        } else {
            None
        }
    }

    pub(crate) fn receiving_epoch(&self) -> u64 {
        self.receiving_epoch
    }

    pub(crate) fn output(&self) -> Option<&BraidEpochOutput> {
        self.output.as_ref()
    }

    pub(crate) fn into_parts(self) -> (BraidStatePayload, Option<BraidEpochOutput>) {
        (self.successor, self.output)
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
        BraidStateVariant::HeaderSent => send_while_header_sent(prior),
        BraidStateVariant::Ct1Received => send_while_ct1_received(prior),
        BraidStateVariant::EkSentCt1Received => send_while_ek_sent_ct1_received(prior),
        BraidStateVariant::NoHeaderReceived => send_while_no_header_received(prior),
        BraidStateVariant::HeaderReceived => {
            send_while_header_received_with_entropy(prior, &mut OsEntropy)
        }
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
        BraidStateVariant::HeaderSent => receive_while_header_sent(prior, message),
        BraidStateVariant::Ct1Received => receive_while_ct1_received(prior, message),
        BraidStateVariant::EkSentCt1Received => receive_while_ek_sent_ct1_received(prior, message),
        BraidStateVariant::NoHeaderReceived => receive_while_no_header_received(prior, message),
        BraidStateVariant::HeaderReceived => receive_while_header_received(prior),
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
            output: None,
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
        output: None,
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
        output: None,
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
        output: None,
    })
}

/// Emits the next `ek_vector` erasure symbol while retaining the exact
/// partially received `ct1` decoder. The persisted encoder index, rather than
/// a carrier-delivery assumption, determines the next symbol.
fn send_while_header_sent(
    prior: &BraidStatePayload,
) -> Result<BraidSendCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::HeaderSent
        || prior.body().len() < HEADER_SENT_DECODER_OFFSET + 2
    {
        return Err(BraidTransitionError::InvalidState);
    }
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;
    let next_index = read_u16(prior.body(), HEADER_SENT_INDEX_OFFSET)?;
    if next_index > MAX_ENCODING_INDEX {
        return Err(BraidTransitionError::EncoderExhausted);
    }

    let key_pair = key_pair_from_private_key(&prior.body()[..PRIVATE_KEY_BYTES])?;
    let mut encoded_chunks = encode_chunks(
        ErasureMessageKind::MlKem768PublicKeyVector,
        key_pair.public_key_vector(),
        &[next_index],
    )?;
    let chunk = encoded_chunks.pop().ok_or(BraidTransitionError::Encoding)?;
    let message =
        BraidPublicMessage::with_chunk(prior.epoch(), BraidMessageType::EncapsulationKey, chunk)?;

    let successor_metadata = StateMetadata::new(
        metadata.role(),
        *metadata.session_id(),
        successor_revision,
        metadata.sending_epoch(),
        metadata.receiving_epoch(),
    )?;
    let successor_index = next_index + 1;
    let mut body = Vec::with_capacity(prior.body().len());
    body.extend_from_slice(key_pair.private_key());
    body.extend_from_slice(&successor_index.to_be_bytes());
    body.extend_from_slice(&prior.body()[HEADER_SENT_DECODER_OFFSET..]);
    let successor = braid_state_payload::encode(
        successor_metadata,
        prior.epoch(),
        BraidStateVariant::HeaderSent,
        prior.auth_root_key(),
        prior.auth_mac_key(),
        &body,
    );
    body.zeroize();

    Ok(BraidSendCandidate {
        successor: successor?,
        message,
        sending_epoch: prior.epoch() - 1,
        output: None,
    })
}

/// Implements `HeaderSent.Receive` and transition 3. Current-epoch `Ct1`
/// symbols are retained in canonical sorted order. Exact duplicates are
/// idempotent, conflicting duplicates fail before a candidate is produced,
/// and any complete set of 30 unique symbols reconstructs the exact `ct1`.
fn receive_while_header_sent(
    prior: &BraidStatePayload,
    message: &BraidPublicMessage,
) -> Result<BraidReceiveCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::HeaderSent
        || prior.body().len() < HEADER_SENT_DECODER_OFFSET + 2
    {
        return Err(BraidTransitionError::InvalidState);
    }
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;

    // Reconstruct the persisted keypair before carrying private state forward.
    let key_pair = key_pair_from_private_key(&prior.body()[..PRIVATE_KEY_BYTES])?;
    let next_index = read_u16(prior.body(), HEADER_SENT_INDEX_OFFSET)?;
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
        let incoming = message.chunk().ok_or(BraidTransitionError::Encoding)?;
        let mut chunks = decode_stored_chunks(prior.body(), HEADER_SENT_DECODER_OFFSET)?;
        match chunks.binary_search_by_key(&incoming.index(), EncodedChunk::index) {
            Ok(position) => {
                if chunks[position] != *incoming {
                    return Err(BraidTransitionError::Encoding);
                }
            }
            Err(position) => chunks.insert(position, incoming.clone()),
        }

        if chunks.len() == ErasureMessageKind::MlKem768Ciphertext1.source_chunks() {
            let mut ciphertext = decode_message(ErasureMessageKind::MlKem768Ciphertext1, &chunks)?;
            if ciphertext.len() != CIPHERTEXT_PART_ONE_BYTES {
                ciphertext.zeroize();
                return Err(BraidTransitionError::Encoding);
            }
            let mut body = Vec::with_capacity(CT1_RECEIVED_BODY_BYTES);
            body.extend_from_slice(key_pair.private_key());
            body.extend_from_slice(&ciphertext);
            body.extend_from_slice(&next_index.to_be_bytes());
            ciphertext.zeroize();
            let successor = braid_state_payload::encode(
                successor_metadata,
                prior.epoch(),
                BraidStateVariant::Ct1Received,
                prior.auth_root_key(),
                prior.auth_mac_key(),
                &body,
            );
            body.zeroize();
            successor?
        } else {
            let mut body = Vec::with_capacity(
                HEADER_SENT_DECODER_OFFSET + 2 + chunks.len() * ENCODED_CHUNK_BYTES,
            );
            body.extend_from_slice(key_pair.private_key());
            body.extend_from_slice(&next_index.to_be_bytes());
            append_stored_chunks(&mut body, &chunks)?;
            let successor = braid_state_payload::encode(
                successor_metadata,
                prior.epoch(),
                BraidStateVariant::HeaderSent,
                prior.auth_root_key(),
                prior.auth_mac_key(),
                &body,
            );
            body.zeroize();
            successor?
        }
    } else {
        braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::HeaderSent,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            prior.body(),
        )?
    };

    Ok(BraidReceiveCandidate {
        successor,
        receiving_epoch: prior.epoch() - 1,
        output: None,
    })
}

/// Continues the persisted `ek_vector` encoder after `ct1` reconstruction and
/// marks every emitted symbol as an acknowledgement of that exact transition.
fn send_while_ct1_received(
    prior: &BraidStatePayload,
) -> Result<BraidSendCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::Ct1Received
        || prior.body().len() != CT1_RECEIVED_BODY_BYTES
    {
        return Err(BraidTransitionError::InvalidState);
    }
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;
    let next_index = read_u16(prior.body(), CT1_RECEIVED_INDEX_OFFSET)?;
    if next_index > MAX_ENCODING_INDEX {
        return Err(BraidTransitionError::EncoderExhausted);
    }

    let key_pair = key_pair_from_private_key(&prior.body()[..PRIVATE_KEY_BYTES])?;
    let mut encoded_chunks = encode_chunks(
        ErasureMessageKind::MlKem768PublicKeyVector,
        key_pair.public_key_vector(),
        &[next_index],
    )?;
    let chunk = encoded_chunks.pop().ok_or(BraidTransitionError::Encoding)?;
    let message = BraidPublicMessage::with_chunk(
        prior.epoch(),
        BraidMessageType::EncapsulationKeyAndCiphertext1Ack,
        chunk,
    )?;

    let successor_metadata = StateMetadata::new(
        metadata.role(),
        *metadata.session_id(),
        successor_revision,
        metadata.sending_epoch(),
        metadata.receiving_epoch(),
    )?;
    let successor_index = next_index + 1;
    let mut body = Vec::with_capacity(CT1_RECEIVED_BODY_BYTES);
    body.extend_from_slice(key_pair.private_key());
    body.extend_from_slice(&prior.body()[PRIVATE_KEY_BYTES..CT1_RECEIVED_INDEX_OFFSET]);
    body.extend_from_slice(&successor_index.to_be_bytes());
    let successor = braid_state_payload::encode(
        successor_metadata,
        prior.epoch(),
        BraidStateVariant::Ct1Received,
        prior.auth_root_key(),
        prior.auth_mac_key(),
        &body,
    );
    body.zeroize();

    Ok(BraidSendCandidate {
        successor: successor?,
        message,
        sending_epoch: prior.epoch() - 1,
        output: None,
    })
}

/// Implements `Ct1Received.Receive` and transition 4. The first current-epoch
/// `Ct2` symbol proves that the peer reconstructed `ek_vector`, so the sender
/// drops its encoder and initializes the canonical `ct2 || mac` decoder with
/// that exact symbol. Other canonical messages are ignored semantically.
fn receive_while_ct1_received(
    prior: &BraidStatePayload,
    message: &BraidPublicMessage,
) -> Result<BraidReceiveCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::Ct1Received
        || prior.body().len() != CT1_RECEIVED_BODY_BYTES
    {
        return Err(BraidTransitionError::InvalidState);
    }
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;

    let key_pair = key_pair_from_private_key(&prior.body()[..PRIVATE_KEY_BYTES])?;
    let successor_metadata = StateMetadata::new(
        metadata.role(),
        *metadata.session_id(),
        successor_revision,
        metadata.sending_epoch(),
        metadata.receiving_epoch(),
    )?;
    let transitioning =
        message.epoch() == prior.epoch() && message.message_type() == BraidMessageType::Ciphertext2;

    let successor = if transitioning {
        let chunk = message.chunk().ok_or(BraidTransitionError::Encoding)?;
        let mut body = Vec::with_capacity(CT1_RECEIVED_INDEX_OFFSET + 2 + ENCODED_CHUNK_BYTES);
        body.extend_from_slice(key_pair.private_key());
        body.extend_from_slice(&prior.body()[PRIVATE_KEY_BYTES..CT1_RECEIVED_INDEX_OFFSET]);
        body.extend_from_slice(&1_u16.to_be_bytes());
        body.extend_from_slice(&chunk.encode());
        let successor = braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::EkSentCt1Received,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            &body,
        );
        body.zeroize();
        successor?
    } else {
        braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::Ct1Received,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            prior.body(),
        )?
    };

    Ok(BraidReceiveCandidate {
        successor,
        receiving_epoch: prior.epoch() - 1,
        output: None,
    })
}

/// Emits the revision-1 no-data message while the current-epoch `Ct2` decoder
/// remains incomplete. The detached wrapper revision advances, but no secret,
/// decoder progress, or epoch high-water changes.
fn send_while_ek_sent_ct1_received(
    prior: &BraidStatePayload,
) -> Result<BraidSendCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::EkSentCt1Received
        || prior.body().len() < EK_SENT_CT1_DECODER_OFFSET + 2
    {
        return Err(BraidTransitionError::InvalidState);
    }
    decode_stored_chunks(prior.body(), EK_SENT_CT1_DECODER_OFFSET)?;
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
        BraidStateVariant::EkSentCt1Received,
        prior.auth_root_key(),
        prior.auth_mac_key(),
        prior.body(),
    )?;
    let message = BraidPublicMessage::without_data(prior.epoch(), BraidMessageType::None)?;
    Ok(BraidSendCandidate {
        successor,
        message,
        sending_epoch: prior.epoch() - 1,
        output: None,
    })
}

/// Implements `EkSentCt1Received.Receive` and transition 5.
///
/// Current-epoch `Ct2` symbols are retained canonically until any five unique
/// symbols reconstruct `ct2 || mac`. Completion decapsulates the ML-KEM
/// secret, derives the epoch output key, ratchets the authenticator, verifies
/// the ciphertext MAC with that successor authenticator, and only then creates
/// the next-epoch `NoHeaderReceived` state. Authentication failure produces no
/// successor and is distinguished for the future durable session authority.
fn receive_while_ek_sent_ct1_received(
    prior: &BraidStatePayload,
    message: &BraidPublicMessage,
) -> Result<BraidReceiveCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::EkSentCt1Received
        || prior.body().len() < EK_SENT_CT1_DECODER_OFFSET + 2
    {
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
    let transitioning =
        message.epoch() == prior.epoch() && message.message_type() == BraidMessageType::Ciphertext2;

    if !transitioning {
        let successor = braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::EkSentCt1Received,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            prior.body(),
        )?;
        return Ok(BraidReceiveCandidate {
            successor,
            receiving_epoch: prior.epoch() - 1,
            output: None,
        });
    }

    let incoming = message.chunk().ok_or(BraidTransitionError::Encoding)?;
    let mut chunks = decode_stored_chunks(prior.body(), EK_SENT_CT1_DECODER_OFFSET)?;
    match chunks.binary_search_by_key(&incoming.index(), EncodedChunk::index) {
        Ok(position) => {
            if chunks[position] != *incoming {
                return Err(BraidTransitionError::Encoding);
            }
        }
        Err(position) => chunks.insert(position, incoming.clone()),
    }

    if chunks.len() < ErasureMessageKind::MlKem768Ciphertext2AndMac.source_chunks() {
        let mut body =
            Vec::with_capacity(EK_SENT_CT1_DECODER_OFFSET + 2 + chunks.len() * ENCODED_CHUNK_BYTES);
        body.extend_from_slice(&prior.body()[..EK_SENT_CT1_DECODER_OFFSET]);
        if let Err(error) = append_stored_chunks(&mut body, &chunks) {
            body.zeroize();
            return Err(error);
        }
        let successor = braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::EkSentCt1Received,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            &body,
        );
        body.zeroize();
        return Ok(BraidReceiveCandidate {
            successor: successor?,
            receiving_epoch: prior.epoch() - 1,
            output: None,
        });
    }

    let next_epoch = prior
        .epoch()
        .checked_add(1)
        .filter(|epoch| *epoch <= MAX_COUNTER)
        .ok_or(BraidTransitionError::EpochExhausted)?;
    let mut ct2_with_mac = decode_message(ErasureMessageKind::MlKem768Ciphertext2AndMac, &chunks)?;
    if ct2_with_mac.len() != CT2_WITH_MAC_BYTES {
        ct2_with_mac.zeroize();
        return Err(BraidTransitionError::Encoding);
    }

    let result = (|| {
        let ciphertext_part_one = &prior.body()[PRIVATE_KEY_BYTES..EK_SENT_CT1_DECODER_OFFSET];
        let ciphertext_part_two = &ct2_with_mac[..CIPHERTEXT_PART_TWO_BYTES];
        let expected_mac = &ct2_with_mac[CIPHERTEXT_PART_TWO_BYTES..];
        let key_pair = key_pair_from_private_key(&prior.body()[..PRIVATE_KEY_BYTES])?;
        let shared_secret = decapsulate(&key_pair, ciphertext_part_one, ciphertext_part_two)?;
        let output_key = derive_output_key(shared_secret.as_bytes(), prior.epoch())?;
        let authenticator =
            BraidAuthenticator::restore(prior.auth_root_key(), prior.auth_mac_key())?;
        let successor_auth = authenticator.ratchet(prior.epoch(), &output_key)?;
        successor_auth.verify_ciphertext(
            prior.epoch(),
            ciphertext_part_one,
            ciphertext_part_two,
            expected_mac,
        )?;

        let successor_metadata = StateMetadata::new(
            metadata.role(),
            *metadata.session_id(),
            successor_revision,
            metadata.sending_epoch(),
            prior.epoch(),
        )?;
        let successor = braid_state_payload::encode(
            successor_metadata,
            next_epoch,
            BraidStateVariant::NoHeaderReceived,
            successor_auth.root_key(),
            successor_auth.mac_key(),
            &[0, 0],
        )?;
        Ok(BraidReceiveCandidate {
            successor,
            receiving_epoch: prior.epoch() - 1,
            output: Some(BraidEpochOutput {
                epoch: prior.epoch(),
                key: output_key,
            }),
        })
    })();
    ct2_with_mac.zeroize();
    result
}

/// Emits the revision-1 no-data message while waiting for the current-epoch
/// authenticated header. The send high-water catches up to the current epoch,
/// while the exact incomplete header decoder and authenticator are preserved.
fn send_while_no_header_received(
    prior: &BraidStatePayload,
) -> Result<BraidSendCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::NoHeaderReceived || prior.body().len() < 2 {
        return Err(BraidTransitionError::InvalidState);
    }
    decode_stored_chunks(prior.body(), 0)?;
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;
    let sending_epoch = prior.epoch() - 1;
    let successor_metadata = StateMetadata::new(
        metadata.role(),
        *metadata.session_id(),
        successor_revision,
        sending_epoch,
        metadata.receiving_epoch(),
    )?;
    let successor = braid_state_payload::encode(
        successor_metadata,
        prior.epoch(),
        BraidStateVariant::NoHeaderReceived,
        prior.auth_root_key(),
        prior.auth_mac_key(),
        prior.body(),
    )?;
    let message = BraidPublicMessage::without_data(prior.epoch(), BraidMessageType::None)?;
    Ok(BraidSendCandidate {
        successor,
        message,
        sending_epoch,
        output: None,
    })
}

/// Implements NoHeaderReceived.Receive and transition 6.
///
/// Current-epoch Header symbols are retained canonically until any three
/// unique symbols reconstruct the exact 64-byte header and 32-byte MAC.
/// Authentication is verified against the current ratcheted authenticator
/// before a HeaderReceived successor containing the public pk1 and an empty
/// pk2 decoder can exist. Authentication failure returns no successor and
/// leaves the authenticated prior immutable.
fn receive_while_no_header_received(
    prior: &BraidStatePayload,
    message: &BraidPublicMessage,
) -> Result<BraidReceiveCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::NoHeaderReceived || prior.body().len() < 2 {
        return Err(BraidTransitionError::InvalidState);
    }
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;
    let receiving_epoch = prior.epoch() - 1;
    let successor_metadata = StateMetadata::new(
        metadata.role(),
        *metadata.session_id(),
        successor_revision,
        metadata.sending_epoch(),
        receiving_epoch,
    )?;
    let transitioning =
        message.epoch() == prior.epoch() && message.message_type() == BraidMessageType::Header;

    if !transitioning {
        let successor = braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::NoHeaderReceived,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            prior.body(),
        )?;
        return Ok(BraidReceiveCandidate {
            successor,
            receiving_epoch,
            output: None,
        });
    }

    let incoming = message.chunk().ok_or(BraidTransitionError::Encoding)?;
    let mut chunks = decode_stored_chunks(prior.body(), 0)?;
    match chunks.binary_search_by_key(&incoming.index(), EncodedChunk::index) {
        Ok(position) => {
            if chunks[position] != *incoming {
                return Err(BraidTransitionError::Encoding);
            }
        }
        Err(position) => chunks.insert(position, incoming.clone()),
    }

    if chunks.len() < ErasureMessageKind::HeaderAndMac.source_chunks() {
        let mut body = Vec::with_capacity(2 + chunks.len() * ENCODED_CHUNK_BYTES);
        if let Err(error) = append_stored_chunks(&mut body, &chunks) {
            body.zeroize();
            return Err(error);
        }
        let successor = braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::NoHeaderReceived,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            &body,
        );
        body.zeroize();
        return Ok(BraidReceiveCandidate {
            successor: successor?,
            receiving_epoch,
            output: None,
        });
    }

    let mut header_with_mac = decode_message(ErasureMessageKind::HeaderAndMac, &chunks)?;
    if header_with_mac.len() != HEADER_AND_MAC_BYTES {
        header_with_mac.zeroize();
        return Err(BraidTransitionError::Encoding);
    }
    let result = (|| {
        let header = &header_with_mac[..PUBLIC_KEY_HEADER_BYTES];
        let expected_mac = &header_with_mac[PUBLIC_KEY_HEADER_BYTES..];
        let authenticator =
            BraidAuthenticator::restore(prior.auth_root_key(), prior.auth_mac_key())?;
        authenticator.verify_header(prior.epoch(), header, expected_mac)?;

        let mut body = Vec::with_capacity(PUBLIC_KEY_HEADER_BYTES + 2);
        body.extend_from_slice(header);
        body.extend_from_slice(&0_u16.to_be_bytes());
        let successor = braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::HeaderReceived,
            authenticator.root_key(),
            authenticator.mac_key(),
            &body,
        );
        body.zeroize();
        Ok(BraidReceiveCandidate {
            successor: successor?,
            receiving_epoch,
            output: None,
        })
    })();
    header_with_mac.zeroize();
    result
}

/// Implements revision-1 transition 7 from an authenticated header.
///
/// One fresh 32-byte OS seed drives `Encaps1`. The raw ML-KEM shared secret is
/// immediately transformed through `KDF_OK`, consumed into the pending
/// encapsulation owner, and never serialized. The exact Ct1 first symbol,
/// ratcheted authenticator, pending continuation, and zeroizing epoch output
/// are returned as one detached candidate. A future durable coordinator must
/// commit the state and output atomically before exposing the BM3 record.
fn send_while_header_received_with_entropy(
    prior: &BraidStatePayload,
    entropy: &mut impl EntropySource,
) -> Result<BraidSendCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::HeaderReceived
        || prior.body().len() != PUBLIC_KEY_HEADER_BYTES + 2
    {
        return Err(BraidTransitionError::InvalidState);
    }
    let prepared_decoder = decode_stored_chunks(prior.body(), PUBLIC_KEY_HEADER_BYTES)?;
    if !prepared_decoder.is_empty() {
        return Err(BraidTransitionError::InvalidState);
    }
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;
    let sending_epoch = prior.epoch() - 1;
    let successor_metadata = StateMetadata::new(
        metadata.role(),
        *metadata.session_id(),
        successor_revision,
        sending_epoch,
        metadata.receiving_epoch(),
    )?;

    let mut encapsulation_seed = [0_u8; ENCAPSULATION_SEED_BYTES];
    let result = (|| {
        entropy.fill(&mut encapsulation_seed)?;
        let started = encapsulate_part_one_from_seed(
            &prior.body()[..PUBLIC_KEY_HEADER_BYTES],
            &encapsulation_seed,
        )?;
        let output_key = derive_output_key(started.shared_secret(), prior.epoch())?;
        let pending = started.into_pending();
        let authenticator =
            BraidAuthenticator::restore(prior.auth_root_key(), prior.auth_mac_key())?;
        let successor_auth = authenticator.ratchet(prior.epoch(), &output_key)?;

        let mut encoded_chunks = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext1,
            pending.ciphertext(),
            &[0],
        )?;
        let first_chunk = encoded_chunks.pop().ok_or(BraidTransitionError::Encoding)?;
        let message = BraidPublicMessage::with_chunk(
            prior.epoch(),
            BraidMessageType::Ciphertext1,
            first_chunk,
        )?;

        let mut body = Vec::with_capacity(CT1_SAMPLED_DECODER_OFFSET + 2);
        body.extend_from_slice(pending.public_key_header());
        body.extend_from_slice(pending.state());
        body.extend_from_slice(pending.ciphertext());
        body.extend_from_slice(&FIRST_ENCODER_INDEX.to_be_bytes());
        body.extend_from_slice(&0_u16.to_be_bytes());
        let successor = braid_state_payload::encode(
            successor_metadata,
            prior.epoch(),
            BraidStateVariant::Ct1Sampled,
            successor_auth.root_key(),
            successor_auth.mac_key(),
            &body,
        );
        body.zeroize();

        Ok(BraidSendCandidate {
            successor: successor?,
            message,
            sending_epoch,
            output: Some(BraidEpochOutput {
                epoch: prior.epoch(),
                key: output_key,
            }),
        })
    })();
    encapsulation_seed.zeroize();
    result
}

/// Implements the revision-1 no-op receive behavior of `HeaderReceived`.
/// Every canonical input is ignored semantically, while the detached wrapper
/// revision records that the serialized session authority accepted it.
fn receive_while_header_received(
    prior: &BraidStatePayload,
) -> Result<BraidReceiveCandidate, BraidTransitionError> {
    if prior.variant() != BraidStateVariant::HeaderReceived
        || prior.body().len() != PUBLIC_KEY_HEADER_BYTES + 2
    {
        return Err(BraidTransitionError::InvalidState);
    }
    let prepared_decoder = decode_stored_chunks(prior.body(), PUBLIC_KEY_HEADER_BYTES)?;
    if !prepared_decoder.is_empty() {
        return Err(BraidTransitionError::InvalidState);
    }
    let metadata = prior.metadata();
    let successor_revision = metadata
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(BraidTransitionError::RevisionExhausted)?;
    let receiving_epoch = prior.epoch() - 1;
    let successor_metadata = StateMetadata::new(
        metadata.role(),
        *metadata.session_id(),
        successor_revision,
        metadata.sending_epoch(),
        receiving_epoch,
    )?;
    let successor = braid_state_payload::encode(
        successor_metadata,
        prior.epoch(),
        BraidStateVariant::HeaderReceived,
        prior.auth_root_key(),
        prior.auth_mac_key(),
        prior.body(),
    )?;
    Ok(BraidReceiveCandidate {
        successor,
        receiving_epoch,
        output: None,
    })
}

fn decode_stored_chunks(
    body: &[u8],
    offset: usize,
) -> Result<Vec<EncodedChunk>, BraidTransitionError> {
    let count = read_u16(body, offset)? as usize;
    let chunks_offset = offset
        .checked_add(2)
        .ok_or(BraidTransitionError::InvalidState)?;
    let encoded_bytes = count
        .checked_mul(ENCODED_CHUNK_BYTES)
        .ok_or(BraidTransitionError::InvalidState)?;
    let expected_length = chunks_offset
        .checked_add(encoded_bytes)
        .ok_or(BraidTransitionError::InvalidState)?;
    if expected_length != body.len() {
        return Err(BraidTransitionError::InvalidState);
    }

    let mut chunks = Vec::with_capacity(count);
    for encoded in body[chunks_offset..].chunks_exact(ENCODED_CHUNK_BYTES) {
        chunks.push(EncodedChunk::decode(encoded)?);
    }
    if chunks
        .windows(2)
        .any(|pair| pair[0].index() >= pair[1].index())
    {
        return Err(BraidTransitionError::InvalidState);
    }
    Ok(chunks)
}

fn append_stored_chunks(
    output: &mut Vec<u8>,
    chunks: &[EncodedChunk],
) -> Result<(), BraidTransitionError> {
    let count = u16::try_from(chunks.len()).map_err(|_| BraidTransitionError::Encoding)?;
    output.extend_from_slice(&count.to_be_bytes());
    for chunk in chunks {
        output.extend_from_slice(&chunk.encode());
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BraidTransitionError> {
    let end = offset
        .checked_add(2)
        .ok_or(BraidTransitionError::InvalidState)?;
    let encoded = bytes
        .get(offset..end)
        .ok_or(BraidTransitionError::InvalidState)?;
    Ok(u16::from_be_bytes(
        encoded
            .try_into()
            .map_err(|_| BraidTransitionError::InvalidState)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::braid_message::BraidMessageType;
    use crate::erasure::decode_message;
    use crate::incremental_mlkem::{
        encapsulate_part_one_from_seed, encapsulate_part_two, ENCAPSULATION_SEED_BYTES,
    };
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

    struct FixedEncapsulationEntropy {
        seed: [u8; ENCAPSULATION_SEED_BYTES],
        calls: usize,
    }

    impl FixedEncapsulationEntropy {
        fn vector() -> Self {
            Self {
                seed: [0x37; ENCAPSULATION_SEED_BYTES],
                calls: 0,
            }
        }
    }

    impl EntropySource for FixedEncapsulationEntropy {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            assert_eq!(output.len(), ENCAPSULATION_SEED_BYTES);
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
    fn header_sent_send_continues_the_public_key_vector_after_a_lost_export() {
        let ciphertext = patterned_ciphertext_one();
        let prior = header_sent_state(&ciphertext, 7);
        let prior_bytes = prior.encoded().to_vec();
        let key_pair = key_pair_from_private_key(&prior.body()[..PRIVATE_KEY_BYTES]).unwrap();

        let first = send(&prior).unwrap();
        assert_eq!(prior.encoded(), prior_bytes);
        assert_eq!(first.successor().variant(), BraidStateVariant::HeaderSent);
        assert_eq!(first.successor().metadata().state_revision(), 3);
        assert_eq!(first.sending_epoch(), 0);
        assert_eq!(
            first.message().message_type(),
            BraidMessageType::EncapsulationKey
        );
        assert_eq!(first.message().chunk().unwrap().index(), 0);
        assert_eq!(
            first.message().chunk().unwrap().symbol(),
            &key_pair.public_key_vector()[..32]
        );
        assert_eq!(
            &first.successor().body()[HEADER_SENT_INDEX_OFFSET..HEADER_SENT_DECODER_OFFSET],
            &1_u16.to_be_bytes()
        );
        assert_eq!(
            &first.successor().body()[HEADER_SENT_DECODER_OFFSET..],
            &prior.body()[HEADER_SENT_DECODER_OFFSET..]
        );

        // The carrier can drop index zero. Committing its successor means the
        // next send continues at index one instead of rolling back state.
        let lost_export = first.message().encode();
        drop(lost_export);
        let second = send(first.successor()).unwrap();
        assert_eq!(second.message().chunk().unwrap().index(), 1);
        assert_eq!(second.successor().metadata().state_revision(), 4);
        assert_eq!(
            &second.successor().body()[HEADER_SENT_INDEX_OFFSET..HEADER_SENT_DECODER_OFFSET],
            &2_u16.to_be_bytes()
        );
        assert_eq!(
            hex(&Sha256::digest(second.successor().encoded())),
            "2249ad60c118b804384c25eda611c08b3010f5800db4eadc68d71d81b1d1386f"
        );
    }

    #[test]
    fn transition_three_recovers_ct1_after_loss_reordering_duplicate_and_restart() {
        let ciphertext = patterned_ciphertext_one();
        let initial_index = 7_u16;
        let prior = header_sent_state(&ciphertext, initial_index);
        let initial_chunk = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext1,
            &ciphertext,
            &[initial_index],
        )
        .unwrap()
        .remove(0);

        // Wrong-epoch and exact-duplicate inputs advance only the Layergram
        // wrapper revision while preserving the canonical decoder bytes.
        let prior_body = prior.body().to_vec();
        let future =
            BraidPublicMessage::with_chunk(2, BraidMessageType::Ciphertext1, initial_chunk.clone())
                .unwrap();
        let ignored = receive(&prior, &future).unwrap();
        assert_eq!(ignored.successor().body(), prior_body);
        let duplicate =
            BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext1, initial_chunk)
                .unwrap();
        let duplicate_outcome = receive(ignored.successor(), &duplicate).unwrap();
        assert_eq!(duplicate_outcome.successor().body(), prior_body);

        // Index five is permanently lost. Index thirty supplies the parity
        // symbol needed for recovery, and delivery order is reversed.
        let mut indexes: Vec<u16> = (0_u16..=30)
            .filter(|index| *index != initial_index && *index != 5)
            .collect();
        indexes.reverse();
        assert_eq!(indexes.len(), 29);
        let chunks = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext1,
            &ciphertext,
            &indexes,
        )
        .unwrap();

        let mut state = duplicate_outcome.into_state_only_successor().unwrap();
        for (position, chunk) in chunks.into_iter().enumerate() {
            let message =
                BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext1, chunk).unwrap();
            state = receive(&state, &message)
                .unwrap()
                .into_state_only_successor()
                .unwrap();
            if position == 11 {
                state = braid_state_payload::decode(state.metadata(), state.encoded()).unwrap();
            }
        }

        assert_eq!(state.variant(), BraidStateVariant::Ct1Received);
        assert_eq!(state.body().len(), CT1_RECEIVED_BODY_BYTES);
        assert_eq!(
            &state.body()[PRIVATE_KEY_BYTES..CT1_RECEIVED_INDEX_OFFSET],
            &ciphertext
        );
        assert_eq!(
            &state.body()[CT1_RECEIVED_INDEX_OFFSET..],
            &0_u16.to_be_bytes()
        );
        assert_eq!(state.auth_root_key(), prior.auth_root_key());
        assert_eq!(state.auth_mac_key(), prior.auth_mac_key());
        assert_eq!(
            hex(&Sha256::digest(state.encoded())),
            "5a5d233cdf7d8af7c888186c74916f6874613624737e1c585e30072c64546d06"
        );
    }

    #[test]
    fn ct1_received_send_continues_the_public_key_vector_with_ack_after_loss() {
        let ciphertext = patterned_ciphertext_one();
        let prior = ct1_received_state(&ciphertext, 0);
        let prior_bytes = prior.encoded().to_vec();
        let key_pair = key_pair_from_private_key(&prior.body()[..PRIVATE_KEY_BYTES]).unwrap();

        let first = send(&prior).unwrap();
        assert_eq!(prior.encoded(), prior_bytes);
        assert_eq!(first.successor().variant(), BraidStateVariant::Ct1Received);
        assert_eq!(first.sending_epoch(), 0);
        assert_eq!(
            first.message().message_type(),
            BraidMessageType::EncapsulationKeyAndCiphertext1Ack
        );
        assert_eq!(first.message().chunk().unwrap().index(), 0);
        assert_eq!(
            first.message().chunk().unwrap().symbol(),
            &key_pair.public_key_vector()[..32]
        );
        assert_eq!(
            &first.successor().body()[PRIVATE_KEY_BYTES..CT1_RECEIVED_INDEX_OFFSET],
            &ciphertext
        );
        assert_eq!(
            &first.successor().body()[CT1_RECEIVED_INDEX_OFFSET..],
            &1_u16.to_be_bytes()
        );

        // Committing the first candidate remains final even when its carrier
        // export is lost. The next send advances to a distinct erasure symbol.
        let lost_export = first.message().encode();
        drop(lost_export);
        let second = send(first.successor()).unwrap();
        assert_eq!(second.message().chunk().unwrap().index(), 1);
        assert_eq!(
            &second.successor().body()[CT1_RECEIVED_INDEX_OFFSET..],
            &2_u16.to_be_bytes()
        );
        assert_eq!(
            hex(&Sha256::digest(second.successor().encoded())),
            "284bbac4a19ee99feded8555225cb2fa58554b056e08aa50218ff67039aa0e74"
        );
    }

    #[test]
    fn transition_four_initializes_ct2_decoder_only_for_the_current_epoch() {
        let ciphertext = patterned_ciphertext_one();
        let prior = ct1_received_state(&ciphertext, 2);
        let prior_bytes = prior.encoded().to_vec();
        let prior_body = prior.body().to_vec();
        let chunk = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext2AndMac,
            &[0x6a; 160],
            &[9],
        )
        .unwrap()
        .remove(0);

        let future =
            BraidPublicMessage::with_chunk(2, BraidMessageType::Ciphertext2, chunk.clone())
                .unwrap();
        let ignored = receive(&prior, &future).unwrap();
        assert_eq!(prior.encoded(), prior_bytes);
        assert_eq!(
            ignored.successor().variant(),
            BraidStateVariant::Ct1Received
        );
        assert_eq!(ignored.successor().body(), prior_body);

        let current =
            BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext2, chunk.clone())
                .unwrap();
        let transitioned = receive(ignored.successor(), &current).unwrap();
        assert_eq!(transitioned.receiving_epoch(), 0);
        assert_eq!(
            transitioned.successor().variant(),
            BraidStateVariant::EkSentCt1Received
        );
        assert_eq!(
            &transitioned.successor().body()[..PRIVATE_KEY_BYTES],
            &prior_body[..PRIVATE_KEY_BYTES]
        );
        assert_eq!(
            &transitioned.successor().body()[PRIVATE_KEY_BYTES..CT1_RECEIVED_INDEX_OFFSET],
            &ciphertext
        );
        assert_eq!(
            &transitioned.successor().body()
                [CT1_RECEIVED_INDEX_OFFSET..CT1_RECEIVED_INDEX_OFFSET + 2],
            &1_u16.to_be_bytes()
        );
        assert_eq!(
            &transitioned.successor().body()[CT1_RECEIVED_INDEX_OFFSET + 2..],
            &chunk.encode()
        );

        let restored = braid_state_payload::decode(
            transitioned.successor().metadata(),
            transitioned.successor().encoded(),
        )
        .unwrap();
        assert_eq!(restored.encoded(), transitioned.successor().encoded());
        assert_eq!(
            hex(&Sha256::digest(restored.encoded())),
            "2fd8dbc4896b9801b05de6313bb7ccc0ecbba97e26b6da2d9f6e1d7f1518ab2b"
        );
    }

    #[test]
    fn ct1_received_rejects_encoder_and_revision_exhaustion() {
        let ciphertext = patterned_ciphertext_one();
        let prior = ct1_received_state(&ciphertext, 0);
        let mut exhausted_body = prior.body().to_vec();
        exhausted_body[CT1_RECEIVED_INDEX_OFFSET..].copy_from_slice(&u16::MAX.to_be_bytes());
        let exhausted_encoder = braid_state_payload::encode(
            prior.metadata(),
            prior.epoch(),
            BraidStateVariant::Ct1Received,
            prior.auth_root_key(),
            prior.auth_mac_key(),
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
            prior.epoch(),
            BraidStateVariant::Ct1Received,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            prior.body(),
        )
        .unwrap();
        let ct2 = BraidPublicMessage::with_chunk(
            1,
            BraidMessageType::Ciphertext2,
            encode_chunks(
                ErasureMessageKind::MlKem768Ciphertext2AndMac,
                &[0x6a; 160],
                &[0],
            )
            .unwrap()
            .remove(0),
        )
        .unwrap();
        assert_eq!(
            send(&exhausted_revision).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
        assert_eq!(
            receive(&exhausted_revision, &ct2).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
    }

    #[test]
    fn ek_sent_ct1_received_send_is_detached_no_data_and_preserves_decoder() {
        let fixture = valid_ct2_fixture();
        let prior = ek_sent_ct1_received_state(&fixture, 7);
        let prior_bytes = prior.encoded().to_vec();
        let candidate = send(&prior).unwrap();

        assert_eq!(prior.encoded(), prior_bytes);
        assert_eq!(candidate.message().message_type(), BraidMessageType::None);
        assert!(candidate.message().chunk().is_none());
        assert_eq!(candidate.message().epoch(), prior.epoch());
        assert_eq!(candidate.sending_epoch(), 0);
        assert_eq!(candidate.successor().body(), prior.body());
        assert_eq!(
            candidate.successor().metadata().state_revision(),
            prior.metadata().state_revision() + 1
        );
        assert_eq!(
            candidate.successor().variant(),
            BraidStateVariant::EkSentCt1Received
        );
    }

    #[test]
    fn transition_five_recovers_after_loss_reordering_duplicate_and_restart() {
        let fixture = valid_ct2_fixture();
        let mut state = ek_sent_ct1_received_state(&fixture, 7);
        let initial_body = state.body().to_vec();
        let initial = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext2AndMac,
            &fixture.ct2_with_mac,
            &[7],
        )
        .unwrap()
        .remove(0);

        // Exact duplicate and wrong-epoch inputs advance only the detached
        // wrapper revision and do not duplicate decoder progress.
        let duplicate =
            BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext2, initial).unwrap();
        let duplicate_outcome = receive(&state, &duplicate).unwrap();
        assert!(duplicate_outcome.output().is_none());
        assert_eq!(duplicate_outcome.successor().body(), initial_body);
        state = duplicate_outcome.into_state_only_successor().unwrap();
        let future = BraidPublicMessage::with_chunk(
            2,
            BraidMessageType::Ciphertext2,
            encode_chunks(
                ErasureMessageKind::MlKem768Ciphertext2AndMac,
                &fixture.ct2_with_mac,
                &[6],
            )
            .unwrap()
            .remove(0),
        )
        .unwrap();
        let ignored = receive(&state, &future).unwrap();
        assert!(ignored.output().is_none());
        assert_eq!(ignored.successor().body(), state.body());
        state = ignored.into_state_only_successor().unwrap();

        // Systematic index zero is permanently lost. Four reversed symbols,
        // combined with parity index seven, still recover the exact payload.
        let chunks = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext2AndMac,
            &fixture.ct2_with_mac,
            &[4, 3, 2, 1],
        )
        .unwrap();
        let mut final_candidate = None;
        for (position, chunk) in chunks.into_iter().enumerate() {
            let message =
                BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext2, chunk).unwrap();
            let outcome = receive(&state, &message).unwrap();
            if position == 3 {
                final_candidate = Some(outcome);
                break;
            }
            assert!(outcome.output().is_none());
            state = outcome.into_state_only_successor().unwrap();
            if position == 1 {
                state = braid_state_payload::decode(state.metadata(), state.encoded()).unwrap();
            }
        }

        let completed = final_candidate.unwrap();
        let output = completed.output().unwrap();
        assert_eq!(completed.receiving_epoch(), 0);
        assert_eq!(output.epoch(), 1);
        assert_eq!(output.key_bytes(), &fixture.output_key);
        assert_eq!(completed.successor().epoch(), 2);
        assert_eq!(
            completed.successor().variant(),
            BraidStateVariant::NoHeaderReceived
        );
        assert_eq!(completed.successor().body(), &[0, 0]);
        assert_eq!(completed.successor().metadata().sending_epoch(), 0);
        assert_eq!(completed.successor().metadata().receiving_epoch(), 1);
        assert_eq!(completed.successor().auth_root_key(), &fixture.auth_root);
        assert_eq!(completed.successor().auth_mac_key(), &fixture.auth_mac);
        assert_eq!(
            hex(&Sha256::digest(completed.successor().encoded())),
            "aa26f1d65441e3d20b7e06056fd71e3b598f8dd55649fa9dd7832248101021c4"
        );
    }

    #[test]
    fn transition_five_rejects_conflict_bad_mac_and_exhausted_counters() {
        let fixture = valid_ct2_fixture();
        let prior = ek_sent_ct1_received_state(&fixture, 7);
        let prior_bytes = prior.encoded().to_vec();
        let initial = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext2AndMac,
            &fixture.ct2_with_mac,
            &[7],
        )
        .unwrap()
        .remove(0);
        let mut conflicting_bytes = initial.encode();
        conflicting_bytes[2] ^= 1;
        let conflicting = BraidPublicMessage::with_chunk(
            1,
            BraidMessageType::Ciphertext2,
            EncodedChunk::decode(&conflicting_bytes).unwrap(),
        )
        .unwrap();
        assert_eq!(
            receive(&prior, &conflicting).err(),
            Some(BraidTransitionError::Encoding)
        );
        assert_eq!(prior.encoded(), prior_bytes);

        let mut bad_fixture = valid_ct2_fixture();
        bad_fixture.ct2_with_mac[CIPHERTEXT_PART_TWO_BYTES] ^= 1;
        let mut bad_state = ek_sent_ct1_received_state(&bad_fixture, 7);
        let bad_chunks = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext2AndMac,
            &bad_fixture.ct2_with_mac,
            &[4, 3, 2, 1],
        )
        .unwrap();
        for (position, chunk) in bad_chunks.into_iter().enumerate() {
            let message =
                BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext2, chunk).unwrap();
            if position == 3 {
                let before = bad_state.encoded().to_vec();
                assert_eq!(
                    receive(&bad_state, &message).err(),
                    Some(BraidTransitionError::Authentication)
                );
                assert_eq!(bad_state.encoded(), before);
                break;
            }
            bad_state = receive(&bad_state, &message)
                .unwrap()
                .into_state_only_successor()
                .unwrap();
        }

        let exhausted_revision_metadata = StateMetadata::new(
            StateRole::Initiator,
            SESSION,
            MAX_COUNTER,
            prior.metadata().sending_epoch(),
            prior.metadata().receiving_epoch(),
        )
        .unwrap();
        let exhausted_revision = braid_state_payload::encode(
            exhausted_revision_metadata,
            prior.epoch(),
            BraidStateVariant::EkSentCt1Received,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            prior.body(),
        )
        .unwrap();
        assert_eq!(
            send(&exhausted_revision).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
        assert_eq!(
            receive(&exhausted_revision, &conflicting).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );

        let almost_complete = ek_sent_ct1_received_with_indexes(&fixture, &[7, 4, 3, 2]);
        let exhausted_epoch_metadata = StateMetadata::new(
            StateRole::Initiator,
            SESSION,
            almost_complete.metadata().state_revision(),
            MAX_COUNTER - 1,
            MAX_COUNTER - 1,
        )
        .unwrap();
        let exhausted_epoch = braid_state_payload::encode(
            exhausted_epoch_metadata,
            MAX_COUNTER,
            BraidStateVariant::EkSentCt1Received,
            almost_complete.auth_root_key(),
            almost_complete.auth_mac_key(),
            almost_complete.body(),
        )
        .unwrap();
        let final_chunk = BraidPublicMessage::with_chunk(
            MAX_COUNTER,
            BraidMessageType::Ciphertext2,
            encode_chunks(
                ErasureMessageKind::MlKem768Ciphertext2AndMac,
                &fixture.ct2_with_mac,
                &[1],
            )
            .unwrap()
            .remove(0),
        )
        .unwrap();
        assert_eq!(
            receive(&exhausted_epoch, &final_chunk).err(),
            Some(BraidTransitionError::EpochExhausted)
        );
    }

    #[test]
    fn no_header_received_send_is_no_data_and_catches_up_sending_epoch() {
        let prior = no_header_received_epoch_two_state();
        let prior_bytes = prior.encoded().to_vec();
        assert_eq!(prior.metadata().sending_epoch(), 0);
        assert_eq!(prior.metadata().receiving_epoch(), 1);

        let candidate = send(&prior).unwrap();
        assert_eq!(prior.encoded(), prior_bytes);
        assert_eq!(candidate.message().message_type(), BraidMessageType::None);
        assert!(candidate.message().chunk().is_none());
        assert_eq!(candidate.message().epoch(), 2);
        assert_eq!(candidate.sending_epoch(), 1);
        assert_eq!(
            candidate.successor().variant(),
            BraidStateVariant::NoHeaderReceived
        );
        assert_eq!(candidate.successor().body(), prior.body());
        assert_eq!(candidate.successor().auth_root_key(), prior.auth_root_key());
        assert_eq!(candidate.successor().auth_mac_key(), prior.auth_mac_key());
        assert_eq!(candidate.successor().metadata().sending_epoch(), 1);
        assert_eq!(candidate.successor().metadata().receiving_epoch(), 1);
        assert_eq!(
            candidate.successor().metadata().state_revision(),
            prior.metadata().state_revision() + 1
        );
    }

    #[test]
    fn transition_six_recovers_header_after_loss_reordering_duplicate_and_restart() {
        let mut state = no_header_received_epoch_two_state();
        let header_with_mac = valid_header_with_mac(&state);
        let expected_header = &header_with_mac[..PUBLIC_KEY_HEADER_BYTES];
        let initial = encode_chunks(ErasureMessageKind::HeaderAndMac, &header_with_mac, &[7])
            .unwrap()
            .remove(0);
        let initial_message =
            BraidPublicMessage::with_chunk(2, BraidMessageType::Header, initial.clone()).unwrap();
        let first = receive(&state, &initial_message).unwrap();
        assert!(first.output().is_none());
        state = first.into_state_only_successor().unwrap();
        let partial_body = state.body().to_vec();

        let duplicate =
            BraidPublicMessage::with_chunk(2, BraidMessageType::Header, initial).unwrap();
        let duplicate_outcome = receive(&state, &duplicate).unwrap();
        assert_eq!(duplicate_outcome.successor().body(), partial_body);
        state = duplicate_outcome.into_state_only_successor().unwrap();

        let future = BraidPublicMessage::with_chunk(
            3,
            BraidMessageType::Header,
            encode_chunks(ErasureMessageKind::HeaderAndMac, &header_with_mac, &[2])
                .unwrap()
                .remove(0),
        )
        .unwrap();
        let ignored = receive(&state, &future).unwrap();
        assert_eq!(ignored.successor().body(), partial_body);
        state = ignored.into_state_only_successor().unwrap();

        // Systematic index zero is lost. Index seven plus reversed indexes two
        // and one reconstruct the exact header, including across a restart.
        let chunks =
            encode_chunks(ErasureMessageKind::HeaderAndMac, &header_with_mac, &[2, 1]).unwrap();
        let second =
            BraidPublicMessage::with_chunk(2, BraidMessageType::Header, chunks[0].clone()).unwrap();
        state = receive(&state, &second)
            .unwrap()
            .into_state_only_successor()
            .unwrap();
        state = braid_state_payload::decode(state.metadata(), state.encoded()).unwrap();
        let final_message =
            BraidPublicMessage::with_chunk(2, BraidMessageType::Header, chunks[1].clone()).unwrap();
        let completed = receive(&state, &final_message).unwrap();

        assert!(completed.output().is_none());
        assert_eq!(completed.receiving_epoch(), 1);
        assert_eq!(completed.successor().epoch(), 2);
        assert_eq!(
            completed.successor().variant(),
            BraidStateVariant::HeaderReceived
        );
        assert_eq!(
            &completed.successor().body()[..PUBLIC_KEY_HEADER_BYTES],
            expected_header
        );
        assert_eq!(
            &completed.successor().body()[PUBLIC_KEY_HEADER_BYTES..],
            &0_u16.to_be_bytes()
        );
        assert_eq!(completed.successor().auth_root_key(), state.auth_root_key());
        assert_eq!(completed.successor().auth_mac_key(), state.auth_mac_key());
        assert_eq!(completed.successor().metadata().sending_epoch(), 0);
        assert_eq!(completed.successor().metadata().receiving_epoch(), 1);
        assert_eq!(
            hex(&Sha256::digest(completed.successor().encoded())),
            "a14e9d8ea3af8c0412748d59bdb3fb715c142ee9018070f518d6472965ed843c"
        );
    }

    #[test]
    fn transition_six_rejects_conflict_bad_mac_and_revision_exhaustion() {
        let prior = no_header_received_epoch_two_state();
        let prior_bytes = prior.encoded().to_vec();
        let header_with_mac = valid_header_with_mac(&prior);
        let initial = encode_chunks(ErasureMessageKind::HeaderAndMac, &header_with_mac, &[7])
            .unwrap()
            .remove(0);
        let initial_message =
            BraidPublicMessage::with_chunk(2, BraidMessageType::Header, initial.clone()).unwrap();
        let partial = receive(&prior, &initial_message)
            .unwrap()
            .into_state_only_successor()
            .unwrap();

        let mut conflicting_bytes = initial.encode();
        conflicting_bytes[2] ^= 1;
        let conflicting = BraidPublicMessage::with_chunk(
            2,
            BraidMessageType::Header,
            EncodedChunk::decode(&conflicting_bytes).unwrap(),
        )
        .unwrap();
        assert_eq!(
            receive(&partial, &conflicting).err(),
            Some(BraidTransitionError::Encoding)
        );
        assert_eq!(prior.encoded(), prior_bytes);

        let mut bad_header_with_mac = header_with_mac;
        bad_header_with_mac[PUBLIC_KEY_HEADER_BYTES] ^= 1;
        let bad_chunks = encode_chunks(
            ErasureMessageKind::HeaderAndMac,
            &bad_header_with_mac,
            &[7, 2, 1],
        )
        .unwrap();
        let mut bad_state = no_header_received_epoch_two_state();
        for (position, chunk) in bad_chunks.into_iter().enumerate() {
            let message =
                BraidPublicMessage::with_chunk(2, BraidMessageType::Header, chunk).unwrap();
            if position == 2 {
                let before = bad_state.encoded().to_vec();
                assert_eq!(
                    receive(&bad_state, &message).err(),
                    Some(BraidTransitionError::Authentication)
                );
                assert_eq!(bad_state.encoded(), before);
                break;
            }
            bad_state = receive(&bad_state, &message)
                .unwrap()
                .into_state_only_successor()
                .unwrap();
        }

        let exhausted_metadata = StateMetadata::new(
            prior.metadata().role(),
            *prior.metadata().session_id(),
            MAX_COUNTER,
            prior.metadata().sending_epoch(),
            prior.metadata().receiving_epoch(),
        )
        .unwrap();
        let exhausted = braid_state_payload::encode(
            exhausted_metadata,
            prior.epoch(),
            BraidStateVariant::NoHeaderReceived,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            prior.body(),
        )
        .unwrap();
        assert_eq!(
            send(&exhausted).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
        assert_eq!(
            receive(&exhausted, &initial_message).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
    }

    #[test]
    fn transition_seven_emits_ct1_epoch_key_and_exact_detached_candidate() {
        let prior = header_received_epoch_two_state();
        let prior_bytes = prior.encoded().to_vec();
        let mut entropy = FixedEncapsulationEntropy::vector();

        let expected_started =
            encapsulate_part_one_from_seed(&prior.body()[..PUBLIC_KEY_HEADER_BYTES], &entropy.seed)
                .unwrap();
        let expected_output =
            derive_output_key(expected_started.shared_secret(), prior.epoch()).unwrap();
        let expected_pending = expected_started.into_pending();
        let expected_auth =
            BraidAuthenticator::restore(prior.auth_root_key(), prior.auth_mac_key())
                .unwrap()
                .ratchet(prior.epoch(), &expected_output)
                .unwrap();

        let candidate = send_while_header_received_with_entropy(&prior, &mut entropy).unwrap();
        assert_eq!(entropy.calls, 1);
        assert_eq!(prior.encoded(), prior_bytes);
        assert_eq!(candidate.sending_epoch(), 1);
        assert_eq!(candidate.message().epoch(), 2);
        assert_eq!(
            candidate.message().message_type(),
            BraidMessageType::Ciphertext1
        );
        assert_eq!(candidate.message().chunk().unwrap().index(), 0);
        assert_eq!(
            candidate.message().chunk().unwrap().symbol(),
            &expected_pending.ciphertext()[..32]
        );
        assert_eq!(candidate.message().encode(), candidate.message().encode());

        let output = candidate.output().expect("transition seven output");
        assert_eq!(output.epoch(), prior.epoch());
        assert_eq!(output.key_bytes(), expected_output.as_bytes());
        assert_eq!(
            candidate.successor().variant(),
            BraidStateVariant::Ct1Sampled
        );
        assert_eq!(
            candidate.successor().metadata().state_revision(),
            prior.metadata().state_revision() + 1
        );
        assert_eq!(candidate.successor().metadata().sending_epoch(), 1);
        assert_eq!(candidate.successor().metadata().receiving_epoch(), 1);
        assert_eq!(
            candidate.successor().auth_root_key(),
            expected_auth.root_key()
        );
        assert_eq!(
            candidate.successor().auth_mac_key(),
            expected_auth.mac_key()
        );
        assert_eq!(
            &candidate.successor().body()[..PUBLIC_KEY_HEADER_BYTES],
            expected_pending.public_key_header()
        );
        assert_eq!(
            &candidate.successor().body()
                [PUBLIC_KEY_HEADER_BYTES..PUBLIC_KEY_HEADER_BYTES + ENCAPSULATION_STATE_BYTES],
            expected_pending.state()
        );
        assert_eq!(
            &candidate.successor().body()[PUBLIC_KEY_HEADER_BYTES + ENCAPSULATION_STATE_BYTES
                ..CT1_SAMPLED_NEXT_INDEX_OFFSET],
            expected_pending.ciphertext()
        );
        assert_eq!(
            &candidate.successor().body()
                [CT1_SAMPLED_NEXT_INDEX_OFFSET..CT1_SAMPLED_DECODER_OFFSET],
            &FIRST_ENCODER_INDEX.to_be_bytes()
        );
        assert_eq!(
            &candidate.successor().body()[CT1_SAMPLED_DECODER_OFFSET..],
            &0_u16.to_be_bytes()
        );
        assert_eq!(
            hex(&Sha256::digest(candidate.successor().encoded())),
            "7fd1e87653e91e2e307dc01320134c373ecf9802f52bcffd69d4312fb390f290"
        );

        let restored = braid_state_payload::decode(
            candidate.successor().metadata(),
            candidate.successor().encoded(),
        )
        .unwrap();
        assert_eq!(restored.encoded(), candidate.successor().encoded());
        let (successor, message, output) = candidate.into_parts();
        assert_eq!(successor.encoded(), restored.encoded());
        assert_eq!(message.message_type(), BraidMessageType::Ciphertext1);
        assert_eq!(output.unwrap().key_bytes(), expected_output.as_bytes());
    }

    #[test]
    fn header_received_receive_is_noop_and_transition_seven_failures_are_closed() {
        struct FailingEntropy {
            calls: usize,
        }

        impl EntropySource for FailingEntropy {
            fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
                self.calls += 1;
                output.fill(0xa5);
                Err(EntropyError::Unavailable)
            }
        }

        let prior = header_received_epoch_two_state();
        let prior_bytes = prior.encoded().to_vec();
        let ignored = BraidPublicMessage::without_data(2, BraidMessageType::None).unwrap();
        let received = receive(&prior, &ignored).unwrap();
        assert!(received.output().is_none());
        assert_eq!(received.receiving_epoch(), 1);
        assert_eq!(
            received.successor().variant(),
            BraidStateVariant::HeaderReceived
        );
        assert_eq!(received.successor().body(), prior.body());
        assert_eq!(received.successor().auth_root_key(), prior.auth_root_key());
        assert_eq!(received.successor().auth_mac_key(), prior.auth_mac_key());
        assert_eq!(received.successor().metadata().sending_epoch(), 0);
        assert_eq!(received.successor().metadata().receiving_epoch(), 1);
        assert_eq!(prior.encoded(), prior_bytes);

        let mut failing = FailingEntropy { calls: 0 };
        assert_eq!(
            send_while_header_received_with_entropy(&prior, &mut failing).err(),
            Some(BraidTransitionError::Entropy)
        );
        assert_eq!(failing.calls, 1);
        assert_eq!(prior.encoded(), prior_bytes);

        let exhausted_metadata = StateMetadata::new(
            prior.metadata().role(),
            *prior.metadata().session_id(),
            MAX_COUNTER,
            prior.metadata().sending_epoch(),
            prior.metadata().receiving_epoch(),
        )
        .unwrap();
        let exhausted = braid_state_payload::encode(
            exhausted_metadata,
            prior.epoch(),
            BraidStateVariant::HeaderReceived,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            prior.body(),
        )
        .unwrap();
        let mut unused = FixedEncapsulationEntropy::vector();
        assert_eq!(
            send_while_header_received_with_entropy(&exhausted, &mut unused).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
        assert_eq!(unused.calls, 0);
        assert_eq!(
            receive(&exhausted, &ignored).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
    }

    #[test]
    fn header_sent_rejects_conflicting_duplicates_and_exhaustion() {
        let ciphertext = patterned_ciphertext_one();
        let initial_index = 7_u16;
        let prior = header_sent_state(&ciphertext, initial_index);
        let prior_bytes = prior.encoded().to_vec();
        let initial = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext1,
            &ciphertext,
            &[initial_index],
        )
        .unwrap()
        .remove(0);
        let mut conflicting_bytes = initial.encode();
        conflicting_bytes[2] ^= 1;
        let conflicting = BraidPublicMessage::with_chunk(
            1,
            BraidMessageType::Ciphertext1,
            EncodedChunk::decode(&conflicting_bytes).unwrap(),
        )
        .unwrap();
        assert_eq!(
            receive(&prior, &conflicting).err(),
            Some(BraidTransitionError::Encoding)
        );
        assert_eq!(prior.encoded(), prior_bytes);

        let mut exhausted_body = prior.body().to_vec();
        exhausted_body[HEADER_SENT_INDEX_OFFSET..HEADER_SENT_DECODER_OFFSET]
            .copy_from_slice(&u16::MAX.to_be_bytes());
        let exhausted_encoder = braid_state_payload::encode(
            prior.metadata(),
            prior.epoch(),
            BraidStateVariant::HeaderSent,
            prior.auth_root_key(),
            prior.auth_mac_key(),
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
            prior.epoch(),
            BraidStateVariant::HeaderSent,
            prior.auth_root_key(),
            prior.auth_mac_key(),
            prior.body(),
        )
        .unwrap();
        assert_eq!(
            send(&exhausted_revision).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
        assert_eq!(
            receive(&exhausted_revision, &conflicting).err(),
            Some(BraidTransitionError::RevisionExhausted)
        );
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
            prior = outcome.into_state_only_successor().unwrap();
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

        let header_received = header_received_epoch_two_state();
        let transition_seven = send(&header_received).unwrap();
        assert_eq!(
            transition_seven.successor().variant(),
            BraidStateVariant::Ct1Sampled
        );
        assert!(transition_seven.output().is_some());
        assert_eq!(
            transition_seven.message().message_type(),
            BraidMessageType::Ciphertext1
        );
    }

    fn header_sent_state(
        ciphertext: &[u8; CIPHERTEXT_PART_ONE_BYTES],
        initial_index: u16,
    ) -> BraidStatePayload {
        let prior = initialize(StateRole::Initiator, SESSION, &SHARED_SECRET).unwrap();
        let mut entropy = FixedEntropy::vector();
        let sampled = send_with_entropy(&prior, &mut entropy).unwrap();
        let chunk = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext1,
            ciphertext,
            &[initial_index],
        )
        .unwrap()
        .remove(0);
        let message =
            BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext1, chunk).unwrap();
        let result = receive(sampled.successor(), &message).unwrap();
        assert_eq!(entropy.calls, 1);
        result.into_state_only_successor().unwrap()
    }

    fn ct1_received_state(
        ciphertext: &[u8; CIPHERTEXT_PART_ONE_BYTES],
        emitted_ek_chunks: usize,
    ) -> BraidStatePayload {
        let initial_index = 7_u16;
        let mut state = header_sent_state(ciphertext, initial_index);
        for _ in 0..emitted_ek_chunks {
            let candidate = send(&state).unwrap();
            state = braid_state_payload::decode(
                candidate.successor().metadata(),
                candidate.successor().encoded(),
            )
            .unwrap();
        }
        let indexes: Vec<u16> = (0_u16..30)
            .filter(|index| *index != initial_index)
            .collect();
        let chunks = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext1,
            ciphertext,
            &indexes,
        )
        .unwrap();
        for chunk in chunks {
            let message =
                BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext1, chunk).unwrap();
            state = receive(&state, &message)
                .unwrap()
                .into_state_only_successor()
                .unwrap();
        }
        assert_eq!(state.variant(), BraidStateVariant::Ct1Received);
        state
    }

    struct Ct2Fixture {
        ciphertext_part_one: [u8; CIPHERTEXT_PART_ONE_BYTES],
        ct2_with_mac: [u8; CT2_WITH_MAC_BYTES],
        output_key: [u8; 32],
        auth_root: [u8; 32],
        auth_mac: [u8; 32],
    }

    fn valid_ct2_fixture() -> Ct2Fixture {
        let entropy = FixedEntropy::vector();
        let key_pair = key_pair_from_seed(&entropy.seed).unwrap();
        let started = encapsulate_part_one_from_seed(
            key_pair.public_key_header(),
            &[0x37; ENCAPSULATION_SEED_BYTES],
        )
        .unwrap();
        let ciphertext_part_one = *started.ciphertext();
        let output = derive_output_key(started.shared_secret(), 1).unwrap();
        let pending = started.into_pending();
        let part_two = encapsulate_part_two(pending, key_pair.public_key_vector()).unwrap();
        let authenticator = BraidAuthenticator::initialize(1, &SHARED_SECRET).unwrap();
        let successor_auth = authenticator.ratchet(1, &output).unwrap();
        let mac = successor_auth
            .mac_ciphertext(1, &ciphertext_part_one, part_two.ciphertext())
            .unwrap();
        let mut ct2_with_mac = [0_u8; CT2_WITH_MAC_BYTES];
        ct2_with_mac[..CIPHERTEXT_PART_TWO_BYTES].copy_from_slice(part_two.ciphertext());
        ct2_with_mac[CIPHERTEXT_PART_TWO_BYTES..].copy_from_slice(&mac);
        Ct2Fixture {
            ciphertext_part_one,
            ct2_with_mac,
            output_key: *output.as_bytes(),
            auth_root: *successor_auth.root_key(),
            auth_mac: *successor_auth.mac_key(),
        }
    }

    fn no_header_received_epoch_two_state() -> BraidStatePayload {
        let fixture = valid_ct2_fixture();
        let mut state = ek_sent_ct1_received_state(&fixture, 7);
        let chunks = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext2AndMac,
            &fixture.ct2_with_mac,
            &[4, 3, 2, 1],
        )
        .unwrap();
        for chunk in chunks {
            let message =
                BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext2, chunk).unwrap();
            let outcome = receive(&state, &message).unwrap();
            if outcome.output().is_some() {
                let (successor, output) = outcome.into_parts();
                let output = output.expect("transition five output");
                assert_eq!(output.epoch(), 1);
                assert_eq!(output.key_bytes(), &fixture.output_key);
                drop(output);
                return successor;
            }
            state = outcome.into_state_only_successor().unwrap();
        }
        panic!("transition five did not complete");
    }

    fn header_received_epoch_two_state() -> BraidStatePayload {
        let mut state = no_header_received_epoch_two_state();
        let header_with_mac = valid_header_with_mac(&state);
        let chunks = encode_chunks(
            ErasureMessageKind::HeaderAndMac,
            &header_with_mac,
            &[7, 2, 1],
        )
        .unwrap();
        for chunk in chunks {
            let message =
                BraidPublicMessage::with_chunk(2, BraidMessageType::Header, chunk).unwrap();
            state = receive(&state, &message)
                .unwrap()
                .into_state_only_successor()
                .unwrap();
        }
        assert_eq!(state.variant(), BraidStateVariant::HeaderReceived);
        state
    }

    fn valid_header_with_mac(state: &BraidStatePayload) -> [u8; HEADER_AND_MAC_BYTES] {
        let key_pair = key_pair_from_seed(&[0x62; KEY_GENERATION_SEED_BYTES]).unwrap();
        let authenticator =
            BraidAuthenticator::restore(state.auth_root_key(), state.auth_mac_key()).unwrap();
        let mac = authenticator
            .mac_header(state.epoch(), key_pair.public_key_header())
            .unwrap();
        let mut header_with_mac = [0_u8; HEADER_AND_MAC_BYTES];
        header_with_mac[..PUBLIC_KEY_HEADER_BYTES].copy_from_slice(key_pair.public_key_header());
        header_with_mac[PUBLIC_KEY_HEADER_BYTES..].copy_from_slice(&mac);
        header_with_mac
    }

    fn ek_sent_ct1_received_state(fixture: &Ct2Fixture, initial_index: u16) -> BraidStatePayload {
        let prior = ct1_received_state(&fixture.ciphertext_part_one, 2);
        let chunk = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext2AndMac,
            &fixture.ct2_with_mac,
            &[initial_index],
        )
        .unwrap()
        .remove(0);
        let message =
            BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext2, chunk).unwrap();
        let outcome = receive(&prior, &message).unwrap();
        assert!(outcome.output().is_none());
        outcome.into_state_only_successor().unwrap()
    }

    fn ek_sent_ct1_received_with_indexes(
        fixture: &Ct2Fixture,
        indexes: &[u16],
    ) -> BraidStatePayload {
        let mut state = ek_sent_ct1_received_state(fixture, indexes[0]);
        let chunks = encode_chunks(
            ErasureMessageKind::MlKem768Ciphertext2AndMac,
            &fixture.ct2_with_mac,
            &indexes[1..],
        )
        .unwrap();
        for chunk in chunks {
            let message =
                BraidPublicMessage::with_chunk(1, BraidMessageType::Ciphertext2, chunk).unwrap();
            state = receive(&state, &message)
                .unwrap()
                .into_state_only_successor()
                .unwrap();
        }
        state
    }

    fn patterned_ciphertext_one() -> [u8; CIPHERTEXT_PART_ONE_BYTES] {
        core::array::from_fn(|index| ((index * 17 + 3) & 0xff) as u8)
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
