// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:typed_data';

import 'fs_handshake.dart';

/// All possible states of a Forward Secrecy session.
///
/// States advance monotonically (no downgrade once [fsActive] or [fsConfirmed]
/// is reached). Transitions are atomic — the state is never partially updated.
///
/// Spec reference: §9 — Session State Machine.
enum FsSessionState {
  /// No FS negotiation in progress. Legacy encryption only.
  legacyOnly,

  /// This device sent an FS_INIT message; waiting for FS_REPLY.
  fsInitSent,

  /// An FS_INIT was received from the remote; waiting to send FS_REPLY.
  fsInitSeen,

  /// This device sent FS_REPLY in response to a received FS_INIT;
  /// waiting for FS_CONFIRM.
  fsReplySent,

  /// FS_REPLY received; waiting for local FS_CONFIRM to be sent.
  fsReplySeen,

  /// This device sent FS_CONFIRM; session is being confirmed.
  fsConfirmSent,

  /// FS_CONFIRM received and verified; handshake complete.
  fsConfirmed,

  /// Double Ratchet session is active.  Messages are FS-encrypted.
  fsActive,

  /// Session suspended (e.g., partner key changed, ratchet exhausted).
  fsSuspended,

  /// Remote requested Strict FS mode; waiting for local consent.
  strictRequested,

  /// Strict FS is fully active (no legacy fallback allowed).
  strictFsActive,

  /// Session is broken and cannot be recovered without re-keying.
  fsBroken,
}

// ---------------------------------------------------------------------------
// Clock interface (injectable for testing)
// ---------------------------------------------------------------------------

/// Monotonic clock interface.  Can be replaced with a test fake.
abstract class FsClock {
  int nowSeconds();
}

class _WallClock implements FsClock {
  const _WallClock();

  @override
  int nowSeconds() => DateTime.now().millisecondsSinceEpoch ~/ 1000;
}

// ---------------------------------------------------------------------------
// Session manager
// ---------------------------------------------------------------------------

/// In-memory Forward Secrecy state machine for a single contact pair.
///
/// This class is **not** persisted — the caller must serialise [state],
/// [pendingInitId], [pendingReplyId] etc. into aux records after each
/// transition (spec §10.2).
///
/// Design invariants:
/// - State only advances; never regresses once [FsSessionState.fsConfirmed]
///   is reached (except to [FsSessionState.fsBroken] on auth failure).
/// - Simultaneous FS_INIT tie-break: uses the full canonical form
///   `EncodeKey(IK) || EncodeKey(DK) || initId` (spec §8.3.4).
///   The lexicographically *smaller* canonical value becomes the initiator.
/// - Stale messages (createdAt too old or too far in the future) are ignored.
/// - Duplicate messages have no effect.
/// - Monotonic-time TTL for pending handshake state (default 7 days).
///
/// Spec reference: §9, §10.2, §8.3.
class FsSessionManager {
  FsSessionManager({
    FsClock? clock,
    this.maxHandshakeTtlSeconds = 7 * 24 * 60 * 60, // 7 days
    this.maxCreatedAtSkewSeconds = 5 * 60,           // 5 min tolerance
    this.maxCreatedAtAgeSeconds = 7 * 24 * 60 * 60,  // 7 days
  }) : _clock = clock ?? const _WallClock();

  final FsClock _clock;
  final int maxHandshakeTtlSeconds;
  final int maxCreatedAtSkewSeconds;
  final int maxCreatedAtAgeSeconds;

  // ---------------------------------------------------------------------------
  // Mutable session state
  // ---------------------------------------------------------------------------

  FsSessionState _state = FsSessionState.legacyOnly;

  /// The initId of the pending handshake (set when FS_INIT is sent/received).
  String? pendingInitId;

  /// The replyId of the pending handshake (set when FS_REPLY is sent/received).
  String? pendingReplyId;

  /// Monotonic timestamp when the current handshake was started.
  int? handshakeStartedAt;

  /// The session ID of the active ratchet session (set after [FsSessionState.fsActive]).
  String? activeSessionId;

  /// The FS_INIT message received from remote (needed to generate FS_REPLY).
  FsInitMessage? _storedInitMessage;

  /// The FS_INIT message we sent (needed to generate FS_CONFIRM).
  FsInitMessage? _storedSentInitMessage;

  /// The FS_REPLY message received from remote (needed to generate FS_CONFIRM).
  FsReplyMessage? _storedReplyMessage;

  /// The ephemeral private key generated when sending FS_INIT (needed for confirm).
  Uint8List? _pendingInitEphemeralPriv;

  /// The ephemeral private key generated when sending FS_REPLY (needed for ratchet).
  Uint8List? _pendingReplyEphemeralPriv;

  /// The raw root secret stored by responder to verify FS_CONFIRM (wiped after verification).
  Uint8List? _pendingRawRootSecret;

  /// The transcript hash stored by responder to verify FS_CONFIRM.
  Uint8List? _pendingTranscriptHash;

  /// Partial handshake state for initiator (stored when generating FS_CONFIRM, used for ratchet init).
  FsHandshakePartialState? _initiatorPartialState;

  /// Partial handshake state for responder (stored when generating FS_REPLY, used for ratchet init).
  FsHandshakePartialState? _responderPartialState;

  /// Whether strict mode was requested before handshake completed.
  bool _strictRequestedBeforeHandshake = false;

  FsSessionState get state => _state;

  /// Returns the stored FS_INIT message received from remote (for generating FS_REPLY).
  FsInitMessage? get storedInitMessage => _storedInitMessage;

  /// Returns the FS_INIT message we sent (for generating FS_CONFIRM).
  FsInitMessage? get storedSentInitMessage => _storedSentInitMessage;

  /// Returns the stored FS_REPLY message received from remote (for generating FS_CONFIRM).
  FsReplyMessage? get storedReplyMessage => _storedReplyMessage;

  /// Returns the ephemeral private key from our sent FS_INIT (for completing handshake).
  Uint8List? get pendingInitEphemeralPriv => _pendingInitEphemeralPriv;

  /// Returns the ephemeral private key from our sent FS_REPLY (for ratchet initialization).
  Uint8List? get pendingReplyEphemeralPriv => _pendingReplyEphemeralPriv;

  /// Returns the initiator's partial handshake state (for ratchet initialization after confirm sent).
  FsHandshakePartialState? get initiatorPartialState => _initiatorPartialState;

  /// Returns the responder's partial handshake state (for ratchet initialization after confirm verified).
  FsHandshakePartialState? get responderPartialState => _responderPartialState;

  /// Returns the raw root secret for FS_CONFIRM verification (responder only).
  Uint8List? get pendingRawRootSecret => _pendingRawRootSecret;

  /// Returns the transcript hash for FS_CONFIRM verification (responder only).
  Uint8List? get pendingTranscriptHash => _pendingTranscriptHash;

  /// Sets the ephemeral private key used for FS_INIT (must be called after generating init).
  void setPendingInitEphemeralPriv(Uint8List key) {
    _pendingInitEphemeralPriv = key;
  }

  /// Sets the ephemeral private key used for FS_REPLY (must be called after generating reply).
  void setPendingReplyEphemeralPriv(Uint8List key) {
    _pendingReplyEphemeralPriv = key;
  }

  /// Sets the raw root secret for FS_CONFIRM verification (responder only).
  void setPendingRawRootSecret(Uint8List secret) {
    _pendingRawRootSecret = secret;
  }

  /// Sets the transcript hash for FS_CONFIRM verification (responder only).
  void setPendingTranscriptHash(Uint8List hash) {
    _pendingTranscriptHash = hash;
  }

  // ---------------------------------------------------------------------------
  // Outgoing: this device initiates
  // ---------------------------------------------------------------------------

  /// Records that this device has sent an FS_INIT message.
  ///
  /// Returns the [FsInitPayload] that should be embedded in `x.fs`.
  /// Returns null if the current state does not allow sending FS_INIT
  /// (e.g., already in [FsSessionState.fsActive]).
  FsSessionTransitionResult<FsInitPayload> recordFsInitSent(
    FsInitPayload payload,
  ) {
    if (!_canSendFsInit()) {
      return FsSessionTransitionResult.rejected(
        _state,
        'Cannot send FS_INIT in state $_state',
      );
    }

    pendingInitId = payload.initId;
    _storedSentInitMessage = payload.toMessage();
    handshakeStartedAt = _clock.nowSeconds();
    _state = FsSessionState.fsInitSent;

    return FsSessionTransitionResult.ok(_state, payload);
  }

  /// Records that this device has sent an FS_REPLY to a received FS_INIT.
  FsSessionTransitionResult<FsReplyPayload> recordFsReplySent(
    FsReplyPayload payload,
  ) {
    if (_state != FsSessionState.fsInitSeen) {
      return FsSessionTransitionResult.rejected(
        _state,
        'Cannot send FS_REPLY in state $_state (expected fsInitSeen)',
      );
    }
    if (pendingInitId != payload.initId) {
      return FsSessionTransitionResult.rejected(
        _state,
        'FS_REPLY initId mismatch',
      );
    }

    pendingReplyId = payload.replyId;
    _responderPartialState = payload.partialState;
    _pendingRawRootSecret = payload.partialState.rawRootSecret;
    _pendingTranscriptHash = payload.partialState.transcriptHash;
    _state = FsSessionState.fsReplySent;

    return FsSessionTransitionResult.ok(_state, payload);
  }

  /// Records that this device has sent an FS_CONFIRM.
  FsSessionTransitionResult<FsConfirmPayload> recordFsConfirmSent(
    FsConfirmPayload payload,
  ) {
    if (_state != FsSessionState.fsReplySeen) {
      return FsSessionTransitionResult.rejected(
        _state,
        'Cannot send FS_CONFIRM in state $_state (expected fsReplySeen)',
      );
    }
    if (pendingInitId != payload.initId || pendingReplyId != payload.replyId) {
      return FsSessionTransitionResult.rejected(
        _state,
        'FS_CONFIRM initId/replyId mismatch',
      );
    }

    _initiatorPartialState = payload.partialState;
    _state = FsSessionState.fsConfirmSent;

    return FsSessionTransitionResult.ok(_state, payload);
  }

  // ---------------------------------------------------------------------------
  // Incoming: messages received from remote
  // ---------------------------------------------------------------------------

  /// Processes a received FS_INIT message.
  ///
  /// Handles:
  /// - Normal case: transitions to [FsSessionState.fsInitSeen].
  /// - Simultaneous FS_INIT (both parties sent FS_INIT): tie-break uses
  ///   the full canonical form `EncodeKey(IK) || EncodeKey(DK) || initId`
  ///   (spec §8.3.4). The lexicographically smaller canonical value becomes
  ///   the authoritative initiator.  The loser drops its own pending FS_INIT
  ///   and transitions to [FsSessionState.fsInitSeen].
  ///
  /// [localCanonical] and [remoteCanonical] are the full canonical tie-break
  /// strings per §8.3.4. When provided, they are used instead of bare initId.
  FsSessionTransitionResult<FsInitMessage> processFsInitReceived({
    required FsInitMessage message,
    required String localInitId,   // non-empty only if state == fsInitSent
    String? localCanonical,
    String? remoteCanonical,
  }) {
    if (_isStale(message.createdAt)) {
      return FsSessionTransitionResult.rejected(
        _state,
        'FS_INIT rejected: stale createdAt ${message.createdAt}',
      );
    }

    // If already confirmed/active, ignore — no downgrade.
    if (_isTerminal()) {
      return FsSessionTransitionResult.rejected(
        _state,
        'FS_INIT ignored: session already in terminal state $_state',
      );
    }

    if (_state == FsSessionState.fsInitSent) {
      // Simultaneous FS_INIT: tie-break using canonical form (§8.3.4).
      final localCmp = localCanonical ?? localInitId;
      final remoteCmp = remoteCanonical ?? message.initId;
      final localWins = _tieBreak(localCmp, remoteCmp) == localCmp;
      if (localWins) {
        // We win the tie-break → we remain the initiator, ignore the incoming.
        return FsSessionTransitionResult.rejected(
          _state,
          'FS_INIT tie-break: local canonical wins, ignoring remote FS_INIT',
        );
      } else {
        // Remote wins → we become the responder.
        pendingInitId = message.initId;
        _storedInitMessage = message;
        _state = FsSessionState.fsInitSeen;
        return FsSessionTransitionResult.ok(_state, message);
      }
    }

    if (_state != FsSessionState.legacyOnly) {
      // Already in mid-handshake from our side; ignore duplicate.
      return FsSessionTransitionResult.rejected(
        _state,
        'FS_INIT duplicate/unexpected in state $_state',
      );
    }

    pendingInitId = message.initId;
    _storedInitMessage = message;
    handshakeStartedAt = _clock.nowSeconds();
    _state = FsSessionState.fsInitSeen;

    return FsSessionTransitionResult.ok(_state, message);
  }

  /// Processes a received FS_REPLY message.
  FsSessionTransitionResult<FsReplyMessage> processFsReplyReceived(
    FsReplyMessage message,
  ) {
    if (_state != FsSessionState.fsInitSent) {
      return FsSessionTransitionResult.rejected(
        _state,
        'FS_REPLY unexpected in state $_state',
      );
    }
    if (message.initId != pendingInitId) {
      return FsSessionTransitionResult.rejected(
        _state,
        'FS_REPLY initId mismatch (expected $pendingInitId, got ${message.initId})',
      );
    }
    if (_isStale(message.createdAt)) {
      return FsSessionTransitionResult.rejected(
        _state,
        'FS_REPLY rejected: stale createdAt ${message.createdAt}',
      );
    }
    if (_isHandshakeExpired()) {
      _resetHandshake();
      return FsSessionTransitionResult.rejected(
        FsSessionState.legacyOnly,
        'FS_REPLY rejected: local handshake TTL expired',
      );
    }

    pendingReplyId = message.replyId;
    _storedReplyMessage = message;
    _state = FsSessionState.fsReplySeen;

    return FsSessionTransitionResult.ok(_state, message);
  }

  /// Processes a received FS_CONFIRM message.
  ///
  /// [verified] must be true only if [FsHandshake.verifyFsConfirmAsResponder]
  /// returned true for this confirm.
  FsSessionTransitionResult<FsConfirmMessage> processFsConfirmReceived({
    required FsConfirmMessage message,
    required bool verified,
  }) {
    if (_state != FsSessionState.fsReplySent) {
      return FsSessionTransitionResult.rejected(
        _state,
        'FS_CONFIRM unexpected in state $_state',
      );
    }
    if (message.initId != pendingInitId || message.replyId != pendingReplyId) {
      return FsSessionTransitionResult.rejected(
        _state,
        'FS_CONFIRM id mismatch',
      );
    }
    if (!verified) {
      _state = FsSessionState.fsBroken;
      return FsSessionTransitionResult.rejected(
        _state,
        'FS_CONFIRM: MAC verification failed — session broken',
      );
    }

    _state = FsSessionState.fsConfirmed;

    return FsSessionTransitionResult.ok(_state, message);
  }

  /// Records that the Double Ratchet session is now active.
  ///
  /// Called after [FsSessionState.fsConfirmed] on the responder side,
  /// or after [FsSessionState.fsConfirmSent] is acknowledged by the initiator.
  FsSessionTransitionResult<void> activateSession(String sessionId) {
    if (_state != FsSessionState.fsConfirmed &&
        _state != FsSessionState.fsConfirmSent) {
      return FsSessionTransitionResult.rejected(
        _state,
        'activateSession: invalid state $_state',
      );
    }

    activeSessionId = sessionId;
    // If strict was requested before handshake, activate strict mode
    if (_strictRequestedBeforeHandshake) {
      _state = FsSessionState.strictFsActive;
      _strictRequestedBeforeHandshake = false;
    } else {
      _state = FsSessionState.fsActive;
    }
    _clearHandshakeMaterial();

    return FsSessionTransitionResult.ok(_state, null);
  }

  // ---------------------------------------------------------------------------
  // Downgrade / error paths
  // ---------------------------------------------------------------------------

  /// Marks the session as broken.  Called when a MAC verification fails
  /// or an unrecoverable error is encountered.
  void markBroken() {
    _state = FsSessionState.fsBroken;
    _clearHandshakeMaterial();
  }

  /// Suspends the session (e.g., partner key rotation detected).
  void suspend() {
    if (_state == FsSessionState.fsActive ||
        _state == FsSessionState.strictFsActive) {
      _state = FsSessionState.fsSuspended;
    }
  }

  /// Resets the entire session to [FsSessionState.legacyOnly].
  ///
  /// Only safe to call as part of "reset keys" user action.
  void reset() {
    _state = FsSessionState.legacyOnly;
    _clearHandshakeMaterial();
    activeSessionId = null;
  }

  // ---------------------------------------------------------------------------
  // Testing support
  // ---------------------------------------------------------------------------

  /// Sets the session state directly.  **For use in tests only.**
  ///
  /// Allows tests to drive the FSM to a specific state without executing
  /// the full handshake.  Must not be called in production code.
  // ignore: invalid_use_of_visible_for_testing_member
  void setStateForTesting(FsSessionState state, {String? sessionId}) {
    _state = state;
    if (sessionId != null) activeSessionId = sessionId;
  }

  // ---------------------------------------------------------------------------
  // Strict / Maximum FS mode
  // ---------------------------------------------------------------------------

  /// Records that the user has requested Maximum FS for this contact.
  ///
  /// Transitions from [FsSessionState.fsActive] to
  /// [FsSessionState.strictRequested]. If called before handshake completes,
  /// sets a flag so that activateSession will transition to strictFsActive.
  void requestStrict() {
    if (_state == FsSessionState.fsActive) {
      _state = FsSessionState.strictRequested;
    } else if (_state == FsSessionState.legacyOnly ||
               _state == FsSessionState.fsInitSent ||
               _state == FsSessionState.fsInitSeen ||
               _state == FsSessionState.fsReplySent ||
               _state == FsSessionState.fsReplySeen) {
      // Set flag to activate strict mode after handshake completes
      _strictRequestedBeforeHandshake = true;
    }
  }

  /// Activates Strict FS mode after a confirmed handshake under a strict
  /// request.
  ///
  /// Transitions from [FsSessionState.strictRequested] to
  /// [FsSessionState.strictFsActive].  Does nothing otherwise.
  void activateStrictSession(String sessionId) {
    if (_state == FsSessionState.strictRequested) {
      activeSessionId = sessionId;
      _state = FsSessionState.strictFsActive;
    }
  }

  /// Disables Maximum FS and reverts to [FsSessionState.fsActive].
  ///
  /// Called when the user explicitly disables Maximum FS, allowing legacy
  /// fallback again.
  void disableStrict() {
    if (_state == FsSessionState.strictFsActive ||
        _state == FsSessionState.strictRequested) {
      _state = FsSessionState.fsActive;
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  bool _canSendFsInit() {
    // Can send FS_INIT from legacy or suspended (to resume).
    // Cannot send from fsBroken - requires manual reset/re-key.
    return _state == FsSessionState.legacyOnly ||
        _state == FsSessionState.fsSuspended;
  }

  bool _isTerminal() {
    return _state == FsSessionState.fsConfirmed ||
        _state == FsSessionState.fsActive ||
        _state == FsSessionState.strictFsActive ||
        _state == FsSessionState.fsBroken ||
        _state == FsSessionState.fsSuspended;
  }

  bool _isStale(int createdAt) {
    final now = _clock.nowSeconds();
    if (createdAt > now + maxCreatedAtSkewSeconds) return true;
    if (now - createdAt > maxCreatedAtAgeSeconds) return true;
    return false;
  }

  bool _isHandshakeExpired() {
    final start = handshakeStartedAt;
    if (start == null) return false;
    return _clock.nowSeconds() - start > maxHandshakeTtlSeconds;
  }

  void _resetHandshake() {
    _state = FsSessionState.legacyOnly;
    pendingInitId = null;
    pendingReplyId = null;
    handshakeStartedAt = null;
    _storedInitMessage = null;
    _storedSentInitMessage = null;
    _storedReplyMessage = null;
    _pendingInitEphemeralPriv = null;
    _pendingReplyEphemeralPriv = null;
    _pendingRawRootSecret = null;
    _pendingTranscriptHash = null;
    _initiatorPartialState = null;
    _responderPartialState = null;
    _strictRequestedBeforeHandshake = false;
  }

  void _clearHandshakeMaterial() {
    pendingInitId = null;
    pendingReplyId = null;
    handshakeStartedAt = null;
    _storedInitMessage = null;
    _storedSentInitMessage = null;
    _storedReplyMessage = null;
    _pendingInitEphemeralPriv = null;
    _pendingReplyEphemeralPriv = null;
    _pendingRawRootSecret = null;
    _pendingTranscriptHash = null;
    _initiatorPartialState = null;
    _responderPartialState = null;
    // Note: _strictRequestedBeforeHandshake is preserved here because
    // it should survive until session activation
  }

  /// Tie-break: returns the canonical value that wins
  /// (lexicographically smaller per §8.3.4).
  static String _tieBreak(String canonicalA, String canonicalB) {
    return canonicalA.compareTo(canonicalB) <= 0 ? canonicalA : canonicalB;
  }

  /// Builds the canonical tie-break string per spec §8.3.4:
  /// `EncodeKey(identityPublicKey) || EncodeKey(devicePublicKey) || initId`
  ///
  /// All keys are base64url-encoded (no padding).
  static String buildCanonical({
    required String identityPublicKey,
    required String devicePublicKey,
    required String initId,
  }) {
    return '$identityPublicKey$devicePublicKey$initId';
  }
}

// ---------------------------------------------------------------------------
// Transition result
// ---------------------------------------------------------------------------

/// The result of a state machine transition.
///
/// [accepted] indicates whether the transition succeeded.
/// [newState] is always the current state after the attempt.
/// [value] carries the payload (e.g., the message or key material) on success.
/// [reason] carries an explanation string on rejection.
class FsSessionTransitionResult<T> {
  const FsSessionTransitionResult._({
    required this.accepted,
    required this.newState,
    this.value,
    this.reason,
  });

  factory FsSessionTransitionResult.ok(FsSessionState newState, T? value) =>
      FsSessionTransitionResult._(accepted: true, newState: newState, value: value);

  factory FsSessionTransitionResult.rejected(FsSessionState newState, String reason) =>
      FsSessionTransitionResult._(accepted: false, newState: newState, reason: reason);

  final bool accepted;
  final FsSessionState newState;
  final T? value;
  final String? reason;

  @override
  String toString() => accepted
      ? 'FsSessionTransitionResult.ok($newState)'
      : 'FsSessionTransitionResult.rejected($newState, $reason)';
}
