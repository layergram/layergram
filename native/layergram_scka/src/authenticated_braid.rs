// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

//! Inactive authenticated composition for the complete ML-KEM Braid engine.
//!
//! This private module is the only Rust path that composes canonical `LS3`
//! authenticated state, canonical `LB3` plaintext, canonical `BM3` public
//! messages, operating-system entropy, and the revision-1 transition graph.
//! It deliberately remains disconnected from the public C ABI and application
//! packaging. A future session authority must durably commit the exact returned
//! sealed state, public message, optional epoch output, and matching TR3
//! revision before any carrier export is exposed.

use crate::braid_message::{BraidMessageError, BraidPublicMessage};
use crate::braid_state_payload::{self, BraidStatePayload, BraidStatePayloadError};
use crate::braid_transition::{self, BraidEpochOutput, BraidTransitionError};
use crate::entropy::{EntropySource, OsEntropy};
use crate::state_envelope::{
    self, StateEnvelopeError, StateMetadata, StateRole, STATE_NONCE_BYTES,
};
use crate::{MAX_COUNTER, SESSION_ID_BYTES};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthenticatedBraidError {
    StateFormat,
    Authentication,
    StateRevision,
    MessageFormat,
    Entropy,
    Transition(BraidTransitionError),
    Primitive,
}

impl From<StateEnvelopeError> for AuthenticatedBraidError {
    fn from(error: StateEnvelopeError) -> Self {
        match error {
            StateEnvelopeError::InvalidLength | StateEnvelopeError::InvalidMetadata => {
                Self::StateFormat
            }
            StateEnvelopeError::Authentication => Self::Authentication,
            StateEnvelopeError::StateRevision => Self::StateRevision,
            StateEnvelopeError::PrimitiveFailure => Self::Primitive,
        }
    }
}

impl From<BraidStatePayloadError> for AuthenticatedBraidError {
    fn from(_: BraidStatePayloadError) -> Self {
        Self::StateFormat
    }
}

impl From<BraidMessageError> for AuthenticatedBraidError {
    fn from(_: BraidMessageError) -> Self {
        Self::MessageFormat
    }
}

impl From<BraidTransitionError> for AuthenticatedBraidError {
    fn from(error: BraidTransitionError) -> Self {
        match error {
            BraidTransitionError::Entropy => Self::Entropy,
            BraidTransitionError::Authentication => Self::Authentication,
            BraidTransitionError::RevisionExhausted => Self::StateRevision,
            BraidTransitionError::InvalidState
            | BraidTransitionError::KeyIntegrity
            | BraidTransitionError::Encoding => Self::StateFormat,
            BraidTransitionError::Primitive => Self::Primitive,
            _ => Self::Transition(error),
        }
    }
}

/// Exact detached result of one authenticated native send candidate.
///
/// This type intentionally implements neither `Clone` nor `Debug`. Re-export
/// borrows the same exact bytes; it never re-runs a transition or reseals state.
pub(crate) struct AuthenticatedBraidSendCandidate {
    sealed_state: Vec<u8>,
    message: Vec<u8>,
    state_revision: u64,
    sending_epoch: u64,
    output: Option<BraidEpochOutput>,
}

impl AuthenticatedBraidSendCandidate {
    pub(crate) fn sealed_state(&self) -> &[u8] {
        &self.sealed_state
    }

    pub(crate) fn message(&self) -> &[u8] {
        &self.message
    }

    pub(crate) fn state_revision(&self) -> u64 {
        self.state_revision
    }

    pub(crate) fn sending_epoch(&self) -> u64 {
        self.sending_epoch
    }

    pub(crate) fn output(&self) -> Option<&BraidEpochOutput> {
        self.output.as_ref()
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, Vec<u8>, u64, u64, Option<BraidEpochOutput>) {
        (
            self.sealed_state,
            self.message,
            self.state_revision,
            self.sending_epoch,
            self.output,
        )
    }
}

/// Exact detached result of one authenticated native receive candidate.
pub(crate) struct AuthenticatedBraidReceiveCandidate {
    sealed_state: Vec<u8>,
    state_revision: u64,
    receiving_epoch: u64,
    output: Option<BraidEpochOutput>,
}

impl AuthenticatedBraidReceiveCandidate {
    pub(crate) fn sealed_state(&self) -> &[u8] {
        &self.sealed_state
    }

    pub(crate) fn state_revision(&self) -> u64 {
        self.state_revision
    }

    pub(crate) fn receiving_epoch(&self) -> u64 {
        self.receiving_epoch
    }

    pub(crate) fn output(&self) -> Option<&BraidEpochOutput> {
        self.output.as_ref()
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, u64, u64, Option<BraidEpochOutput>) {
        (
            self.sealed_state,
            self.state_revision,
            self.receiving_epoch,
            self.output,
        )
    }
}

pub(crate) fn initialize_authenticated(
    role: StateRole,
    session_id: [u8; SESSION_ID_BYTES as usize],
    shared_secret: &[u8],
    state_key: &[u8],
) -> Result<Vec<u8>, AuthenticatedBraidError> {
    let initial = braid_transition::initialize(role, session_id, shared_secret)?;
    seal_state(initial.metadata(), state_key, initial.encoded())
}

pub(crate) fn validate_authenticated_state(
    role: StateRole,
    session_id: &[u8],
    state_key: &[u8],
    expected_state_revision: u64,
    sealed_state: &[u8],
) -> Result<(), AuthenticatedBraidError> {
    let _state = open_state(
        role,
        session_id,
        state_key,
        expected_state_revision,
        sealed_state,
    )?;
    Ok(())
}

pub(crate) fn send_authenticated(
    role: StateRole,
    session_id: &[u8],
    state_key: &[u8],
    expected_state_revision: u64,
    sealed_state: &[u8],
) -> Result<AuthenticatedBraidSendCandidate, AuthenticatedBraidError> {
    send_with_entropy(
        role,
        session_id,
        state_key,
        expected_state_revision,
        sealed_state,
        &mut OsEntropy,
    )
}

fn send_with_entropy(
    role: StateRole,
    session_id: &[u8],
    state_key: &[u8],
    expected_state_revision: u64,
    sealed_state: &[u8],
    entropy: &mut impl EntropySource,
) -> Result<AuthenticatedBraidSendCandidate, AuthenticatedBraidError> {
    let prior = open_state(
        role,
        session_id,
        state_key,
        expected_state_revision,
        sealed_state,
    )?;
    let prior_metadata = prior.metadata();
    let candidate = braid_transition::send_with_entropy_source(&prior, entropy)?;
    let sending_epoch = candidate.sending_epoch();
    let successor_metadata = candidate.successor().metadata();
    validate_successor(prior_metadata, successor_metadata)?;
    let message = candidate.message().encode();
    let (successor, _message, output) = candidate.into_parts();
    let sealed_state = seal_state(successor_metadata, state_key, successor.encoded())?;
    Ok(AuthenticatedBraidSendCandidate {
        sealed_state,
        message,
        state_revision: successor_metadata.state_revision(),
        sending_epoch,
        output,
    })
}

/// Consumes a canonical BM3 only after the future outer Layergram framing has
/// authenticated and session-bound it. Raw BM3 bytes are not an authentication
/// boundary by themselves; this private function is intentionally unreachable
/// from the public ABI until that caller contract is enforced.
pub(crate) fn receive_authenticated(
    role: StateRole,
    session_id: &[u8],
    state_key: &[u8],
    expected_state_revision: u64,
    sealed_state: &[u8],
    authenticated_message: &[u8],
) -> Result<AuthenticatedBraidReceiveCandidate, AuthenticatedBraidError> {
    receive_candidate(
        role,
        session_id,
        state_key,
        expected_state_revision,
        sealed_state,
        authenticated_message,
    )
}

fn receive_candidate(
    role: StateRole,
    session_id: &[u8],
    state_key: &[u8],
    expected_state_revision: u64,
    sealed_state: &[u8],
    authenticated_message: &[u8],
) -> Result<AuthenticatedBraidReceiveCandidate, AuthenticatedBraidError> {
    let message = BraidPublicMessage::decode(authenticated_message)?;
    let prior = open_state(
        role,
        session_id,
        state_key,
        expected_state_revision,
        sealed_state,
    )?;
    let prior_metadata = prior.metadata();
    let candidate = braid_transition::receive(&prior, &message)?;
    let receiving_epoch = candidate.receiving_epoch();
    let successor_metadata = candidate.successor().metadata();
    validate_successor(prior_metadata, successor_metadata)?;
    let (successor, output) = candidate.into_parts();
    let sealed_state = seal_state(successor_metadata, state_key, successor.encoded())?;
    Ok(AuthenticatedBraidReceiveCandidate {
        sealed_state,
        state_revision: successor_metadata.state_revision(),
        receiving_epoch,
        output,
    })
}

fn open_state(
    role: StateRole,
    session_id: &[u8],
    state_key: &[u8],
    expected_state_revision: u64,
    sealed_state: &[u8],
) -> Result<BraidStatePayload, AuthenticatedBraidError> {
    let opened = state_envelope::open(
        role,
        session_id,
        state_key,
        expected_state_revision,
        sealed_state,
    )?;
    let decoded = braid_state_payload::decode(opened.metadata(), opened.payload())?;
    Ok(decoded)
}

fn validate_successor(
    prior: StateMetadata,
    successor: StateMetadata,
) -> Result<(), AuthenticatedBraidError> {
    let expected_revision = prior
        .state_revision()
        .checked_add(1)
        .filter(|revision| *revision <= MAX_COUNTER)
        .ok_or(AuthenticatedBraidError::StateRevision)?;
    if successor.role() != prior.role()
        || successor.session_id() != prior.session_id()
        || successor.state_revision() != expected_revision
    {
        return Err(AuthenticatedBraidError::StateRevision);
    }
    Ok(())
}

fn seal_state(
    metadata: StateMetadata,
    state_key: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, AuthenticatedBraidError> {
    let nonce = state_nonce(metadata);
    state_envelope::seal(metadata, state_key, &nonce, payload).map_err(Into::into)
}

/// Injective LS3 nonce for one role and one signed-63 state revision.
///
/// Both participants share the session state-sealing key, so the role byte is
/// part of the nonce domain. A future durable coordinator must still commit a
/// candidate before allowing another transition from the same prior revision;
/// exact retry reuses the already sealed candidate bytes.
fn state_nonce(metadata: StateMetadata) -> [u8; STATE_NONCE_BYTES] {
    let mut nonce = [0_u8; STATE_NONCE_BYTES];
    nonce[..3].copy_from_slice(b"LN3");
    nonce[3] = metadata.role() as u8;
    nonce[4..].copy_from_slice(&metadata.state_revision().to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::EntropyError;
    use std::collections::BTreeMap;
    use zeroize::Zeroize;

    const SESSION: [u8; SESSION_ID_BYTES as usize] = [0x31; SESSION_ID_BYTES as usize];
    const SHARED_SECRET: [u8; 32] = [0x42; 32];
    const STATE_KEY: [u8; 32] = [0x53; 32];

    struct PatternEntropy {
        calls: usize,
        fail_on_call: Option<usize>,
    }

    impl PatternEntropy {
        fn new() -> Self {
            Self {
                calls: 0,
                fail_on_call: None,
            }
        }

        fn failing(call: usize) -> Self {
            Self {
                calls: 0,
                fail_on_call: Some(call),
            }
        }
    }

    impl EntropySource for PatternEntropy {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            self.calls += 1;
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = ((self.calls * 37 + index * 13 + 7) & 0xff) as u8;
            }
            if self.fail_on_call == Some(self.calls) {
                Err(EntropyError::Unavailable)
            } else {
                Ok(())
            }
        }
    }

    fn initialize(role: StateRole) -> Vec<u8> {
        initialize_authenticated(role, SESSION, &SHARED_SECRET, &STATE_KEY).unwrap()
    }

    #[test]
    fn initialization_seals_and_cross_checks_ls3_and_lb3() {
        let state = initialize(StateRole::Initiator);
        validate_authenticated_state(StateRole::Initiator, &SESSION, &STATE_KEY, 0, &state)
            .unwrap();

        let mut wrong_key = STATE_KEY;
        wrong_key[0] ^= 1;
        let mut wrong_session = SESSION;
        wrong_session[0] ^= 1;
        assert_eq!(
            validate_authenticated_state(StateRole::Initiator, &SESSION, &wrong_key, 0, &state),
            Err(AuthenticatedBraidError::Authentication)
        );
        assert_eq!(
            validate_authenticated_state(
                StateRole::Initiator,
                &wrong_session,
                &STATE_KEY,
                0,
                &state,
            ),
            Err(AuthenticatedBraidError::Authentication)
        );
        assert_eq!(
            validate_authenticated_state(StateRole::Responder, &SESSION, &STATE_KEY, 0, &state),
            Err(AuthenticatedBraidError::Authentication)
        );
        assert_eq!(
            validate_authenticated_state(StateRole::Initiator, &SESSION, &STATE_KEY, 1, &state),
            Err(AuthenticatedBraidError::StateRevision)
        );

        let mut tampered = state;
        let middle = tampered.len() / 2;
        tampered[middle] ^= 1;
        assert_eq!(
            validate_authenticated_state(StateRole::Initiator, &SESSION, &STATE_KEY, 0, &tampered,),
            Err(AuthenticatedBraidError::Authentication)
        );

        // A valid outer tag cannot authorize an inner payload whose duplicated
        // metadata or canonical encoding disagrees with LS3.
        let opened = state_envelope::open(
            StateRole::Initiator,
            &SESSION,
            &STATE_KEY,
            0,
            &initialize(StateRole::Initiator),
        )
        .unwrap();
        let mut malformed_payload = opened.payload().to_vec();
        malformed_payload[5] = StateRole::Responder as u8;
        let semantically_invalid = state_envelope::seal(
            opened.metadata(),
            &STATE_KEY,
            &[0x91; STATE_NONCE_BYTES],
            &malformed_payload,
        )
        .unwrap();
        malformed_payload.zeroize();
        assert_eq!(
            validate_authenticated_state(
                StateRole::Initiator,
                &SESSION,
                &STATE_KEY,
                0,
                &semantically_invalid,
            ),
            Err(AuthenticatedBraidError::StateFormat)
        );
    }

    #[test]
    fn state_nonce_is_deterministic_and_injective_for_role_and_revision() {
        const NONCE_OFFSET: usize = 60;
        const NONCE_END: usize = NONCE_OFFSET + STATE_NONCE_BYTES;

        let initiator_zero =
            initialize_authenticated(StateRole::Initiator, SESSION, &SHARED_SECRET, &STATE_KEY)
                .unwrap();
        let initiator_zero_again =
            initialize_authenticated(StateRole::Initiator, SESSION, &SHARED_SECRET, &STATE_KEY)
                .unwrap();
        let responder_zero =
            initialize_authenticated(StateRole::Responder, SESSION, &SHARED_SECRET, &STATE_KEY)
                .unwrap();

        assert_eq!(
            &initiator_zero[NONCE_OFFSET..NONCE_END],
            &[
                b'L',
                b'N',
                b'3',
                StateRole::Initiator as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ],
        );
        assert_eq!(
            &initiator_zero_again[NONCE_OFFSET..NONCE_END],
            &initiator_zero[NONCE_OFFSET..NONCE_END],
        );
        assert_eq!(
            &responder_zero[NONCE_OFFSET..NONCE_END],
            &[
                b'L',
                b'N',
                b'3',
                StateRole::Responder as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ],
        );

        let revision_one = send_with_entropy(
            StateRole::Initiator,
            &SESSION,
            &STATE_KEY,
            0,
            &initiator_zero,
            &mut PatternEntropy::new(),
        )
        .unwrap();
        assert_eq!(
            &revision_one.sealed_state()[NONCE_OFFSET..NONCE_END],
            &[
                b'L',
                b'N',
                b'3',
                StateRole::Initiator as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1
            ],
        );

        let maximum = StateMetadata::new(
            StateRole::Responder,
            SESSION,
            MAX_COUNTER,
            MAX_COUNTER,
            MAX_COUNTER,
        )
        .unwrap();
        assert_eq!(
            state_nonce(maximum),
            [
                b'L',
                b'N',
                b'3',
                StateRole::Responder as u8,
                0x7f,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
            ],
        );
    }

    #[test]
    fn send_candidate_is_exact_and_restartable_without_resealing() {
        let prior = initialize(StateRole::Initiator);
        let mut entropy = PatternEntropy::new();
        let candidate = send_with_entropy(
            StateRole::Initiator,
            &SESSION,
            &STATE_KEY,
            0,
            &prior,
            &mut entropy,
        )
        .unwrap();
        assert_eq!(entropy.calls, 1);
        assert_eq!(candidate.state_revision(), 1);
        assert_eq!(candidate.sending_epoch(), 0);
        assert!(candidate.output().is_none());
        assert_eq!(candidate.message(), candidate.message());
        assert_eq!(candidate.sealed_state(), candidate.sealed_state());
        assert_eq!(
            BraidPublicMessage::decode(candidate.message())
                .unwrap()
                .epoch(),
            1
        );
        validate_authenticated_state(
            StateRole::Initiator,
            &SESSION,
            &STATE_KEY,
            1,
            candidate.sealed_state(),
        )
        .unwrap();

        let restored = send_with_entropy(
            StateRole::Initiator,
            &SESSION,
            &STATE_KEY,
            0,
            &prior,
            &mut PatternEntropy::new(),
        )
        .unwrap();
        assert_eq!(restored.message(), candidate.message());
        assert_eq!(restored.sealed_state(), candidate.sealed_state());
        assert_eq!(
            validate_authenticated_state(
                StateRole::Initiator,
                &SESSION,
                &STATE_KEY,
                0,
                candidate.sealed_state(),
            ),
            Err(AuthenticatedBraidError::StateRevision)
        );
    }

    #[test]
    fn authenticated_receive_binds_bm3_and_advances_exactly_one_revision() {
        let alice = initialize(StateRole::Initiator);
        let bob = initialize(StateRole::Responder);
        let sent = send_with_entropy(
            StateRole::Initiator,
            &SESSION,
            &STATE_KEY,
            0,
            &alice,
            &mut PatternEntropy::new(),
        )
        .unwrap();
        let received = receive_candidate(
            StateRole::Responder,
            &SESSION,
            &STATE_KEY,
            0,
            &bob,
            sent.message(),
        )
        .unwrap();
        assert_eq!(received.state_revision(), 1);
        assert_eq!(received.receiving_epoch(), sent.sending_epoch());
        assert!(received.output().is_none());
        validate_authenticated_state(
            StateRole::Responder,
            &SESSION,
            &STATE_KEY,
            1,
            received.sealed_state(),
        )
        .unwrap();

        let mut malformed = sent.message().to_vec();
        malformed[0] ^= 1;
        assert_eq!(
            receive_candidate(
                StateRole::Responder,
                &SESSION,
                &STATE_KEY,
                0,
                &bob,
                &malformed,
            )
            .err(),
            Some(AuthenticatedBraidError::MessageFormat)
        );
    }

    #[test]
    fn transition_entropy_failure_returns_no_candidate_and_sealing_needs_none() {
        let prior = initialize(StateRole::Initiator);
        assert_eq!(
            send_with_entropy(
                StateRole::Initiator,
                &SESSION,
                &STATE_KEY,
                0,
                &prior,
                &mut PatternEntropy::failing(1),
            )
            .err(),
            Some(AuthenticatedBraidError::Entropy)
        );
        let mut fails_only_if_state_sealing_requests_entropy = PatternEntropy::failing(2);
        let candidate = send_with_entropy(
            StateRole::Initiator,
            &SESSION,
            &STATE_KEY,
            0,
            &prior,
            &mut fails_only_if_state_sealing_requests_entropy,
        )
        .unwrap();
        assert_eq!(fails_only_if_state_sealing_requests_entropy.calls, 1);
        assert_eq!(candidate.state_revision(), 1);

        let bob = initialize(StateRole::Responder);
        let message =
            BraidPublicMessage::without_data(1, crate::braid_message::BraidMessageType::None)
                .unwrap()
                .encode();
        let received = receive_candidate(
            StateRole::Responder,
            &SESSION,
            &STATE_KEY,
            0,
            &bob,
            &message,
        )
        .unwrap();
        assert_eq!(received.state_revision(), 1);
    }

    #[test]
    fn production_entrypoints_use_os_transition_entropy_and_remain_private() {
        let state =
            initialize_authenticated(StateRole::Initiator, SESSION, &SHARED_SECRET, &STATE_KEY)
                .unwrap();
        let sent =
            send_authenticated(StateRole::Initiator, &SESSION, &STATE_KEY, 0, &state).unwrap();
        let bob =
            initialize_authenticated(StateRole::Responder, SESSION, &SHARED_SECRET, &STATE_KEY)
                .unwrap();
        let received = receive_authenticated(
            StateRole::Responder,
            &SESSION,
            &STATE_KEY,
            0,
            &bob,
            sent.message(),
        )
        .unwrap();
        assert_eq!(received.receiving_epoch(), sent.sending_epoch());
    }

    #[test]
    fn two_participants_advance_through_sealed_states_and_agree_on_epoch_keys() {
        let mut alice_state = initialize(StateRole::Initiator);
        let mut bob_state = initialize(StateRole::Responder);
        let mut alice_revision = 0_u64;
        let mut bob_revision = 0_u64;
        let mut alice_entropy = PatternEntropy::new();
        let mut bob_entropy = PatternEntropy::new();
        let mut alice_outputs = BTreeMap::<u64, [u8; 32]>::new();
        let mut bob_outputs = BTreeMap::<u64, [u8; 32]>::new();

        for round in 0..160 {
            let sent = send_with_entropy(
                StateRole::Initiator,
                &SESSION,
                &STATE_KEY,
                alice_revision,
                &alice_state,
                &mut alice_entropy,
            )
            .unwrap_or_else(|error| panic!("alice send round {round}: {error:?}"));
            let (next_alice, message, next_alice_revision, sending_epoch, output) =
                sent.into_parts();
            if let Some(output) = output {
                alice_outputs.insert(output.epoch(), output.key_bytes().try_into().unwrap());
            }
            let received = receive_candidate(
                StateRole::Responder,
                &SESSION,
                &STATE_KEY,
                bob_revision,
                &bob_state,
                &message,
            )
            .unwrap_or_else(|error| panic!("bob receive round {round}: {error:?}"));
            assert_eq!(received.receiving_epoch(), sending_epoch);
            let (next_bob, next_bob_revision, _, output) = received.into_parts();
            if let Some(output) = output {
                bob_outputs.insert(output.epoch(), output.key_bytes().try_into().unwrap());
            }
            alice_state = next_alice;
            alice_revision = next_alice_revision;
            bob_state = next_bob;
            bob_revision = next_bob_revision;

            let sent = send_with_entropy(
                StateRole::Responder,
                &SESSION,
                &STATE_KEY,
                bob_revision,
                &bob_state,
                &mut bob_entropy,
            )
            .unwrap_or_else(|error| {
                let state = open_state(
                    StateRole::Responder,
                    &SESSION,
                    &STATE_KEY,
                    bob_revision,
                    &bob_state,
                )
                .unwrap();
                panic!(
                    "bob send round {round}, variant {:?}, metadata {:?}: {error:?}",
                    state.variant(),
                    state.metadata(),
                )
            });
            let (next_bob, message, next_bob_revision, sending_epoch, output) = sent.into_parts();
            if let Some(output) = output {
                bob_outputs.insert(output.epoch(), output.key_bytes().try_into().unwrap());
            }
            let received = receive_candidate(
                StateRole::Initiator,
                &SESSION,
                &STATE_KEY,
                alice_revision,
                &alice_state,
                &message,
            )
            .unwrap_or_else(|error| {
                let state = open_state(
                    StateRole::Initiator,
                    &SESSION,
                    &STATE_KEY,
                    alice_revision,
                    &alice_state,
                )
                .unwrap();
                let message = BraidPublicMessage::decode(&message).unwrap();
                let direct = braid_transition::receive(&state, &message).unwrap();
                panic!(
                    "alice receive round {round}, variant {:?}, metadata {:?}, message {:?}, receiving {}, successor {:?}: {error:?}",
                    state.variant(),
                    state.metadata(),
                    message.message_type(),
                    direct.receiving_epoch(),
                    direct.successor().metadata(),
                )
            });
            assert_eq!(received.receiving_epoch(), sending_epoch);
            let (next_alice, next_alice_revision, _, output) = received.into_parts();
            if let Some(output) = output {
                alice_outputs.insert(output.epoch(), output.key_bytes().try_into().unwrap());
            }
            bob_state = next_bob;
            bob_revision = next_bob_revision;
            alice_state = next_alice;
            alice_revision = next_alice_revision;

            if alice_outputs.contains_key(&1) && bob_outputs.contains_key(&1) {
                break;
            }
        }

        assert_eq!(alice_outputs.get(&1), bob_outputs.get(&1));
        assert!(alice_outputs.contains_key(&1));
        validate_authenticated_state(
            StateRole::Initiator,
            &SESSION,
            &STATE_KEY,
            alice_revision,
            &alice_state,
        )
        .unwrap();
        validate_authenticated_state(
            StateRole::Responder,
            &SESSION,
            &STATE_KEY,
            bob_revision,
            &bob_state,
        )
        .unwrap();
    }
}
