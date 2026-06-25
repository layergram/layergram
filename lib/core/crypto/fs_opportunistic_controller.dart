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

import 'fs_contact_security_state.dart';
import 'fs_control_messages.dart';
import 'fs_device_session_router.dart';
import 'fs_dos_resistance.dart';
import 'fs_double_ratchet.dart';
import 'fs_downgrade_detector.dart';
import 'fs_handshake.dart';
import 'fs_key_codec.dart';
import 'fs_message_classification.dart';
import 'fs_payload_budget.dart';
import 'fs_plaintext_cache.dart';
import 'fs_ratchet_persistence_service.dart';
import 'fs_replay_cache.dart';
import 'fs_security_mode.dart';
import 'fs_session_manager.dart';
import 'fs_state_mutex.dart';
import 'fs_state_persistence_service.dart';
import 'lmf_v2_decoder.dart';

/// Orchestrates Opportunistic Forward Secrecy between two parties.
///
/// This controller sits between the LMF encode/decode layer and the
/// [FsSessionManager] state machine.  It processes incoming `x.fs` extensions
/// and decides what (if any) `x.fs` extension to attach to outgoing messages.
///
/// **Key design rules (spec §10):**
/// - Opportunistic FS is the default mode.  Old clients that do not include
///   `x.fs` remain fully compatible — they continue on legacy encryption.
/// - FS activates only after a full FS_INIT → FS_REPLY → FS_CONFIRM handshake.
/// - Fallback messages are not described as Forward Secrecy.
/// - No global "FS enabled" flag is used.
/// - Contact card state is updated through [FsContactSecurityRegistry].
///
/// Spec reference: §10 — Opportunistic FS Beta.
class FsOpportunisticController {
  FsOpportunisticController({
    required String localContactId,
    required String identityContext,
    required FsSessionManager sessionManager,
    required FsContactSecurityRegistry registry,
    FsClock? clock,
    FsStatePersistenceService? persistenceService,
    FsRatchetPersistenceService? ratchetPersistenceService,
    void Function(RatchetState)? onRatchetInitialized,
    String? localIdentityPublicKey,
    String? localDevicePublicKey,
    FsReplayCache? replayCache,
    FsDoSGuard? dosGuard,
    FsStateMutex? stateMutex,
    FsDowngradeDetector? downgradeDetector,
    FsPlaintextCache? plaintextCache,
  })  : _localContactId = localContactId,
        _identityContext = identityContext,
        _sessionManager = sessionManager,
        _deviceRouter =
            FsDeviceSessionRouter(clock: clock, initialSession: sessionManager),
        _registry = registry,
        _persistenceService = persistenceService,
        _ratchetPersistenceService = ratchetPersistenceService,
        _onRatchetInitialized = onRatchetInitialized,
        _localIdentityPublicKey = localIdentityPublicKey,
        _localDevicePublicKey = localDevicePublicKey,
        _replayCache = replayCache,
        _dosGuard = dosGuard,
        _stateMutex = stateMutex,
        _downgradeDetector = downgradeDetector,
        _plaintextCache = plaintextCache;

  final String _localContactId;
  final String _identityContext;
  String get identityContext => _identityContext;
  FsSessionManager _sessionManager;
  final FsDeviceSessionRouter _deviceRouter;
  final FsContactSecurityRegistry _registry;
  final FsStatePersistenceService? _persistenceService;
  final FsRatchetPersistenceService? _ratchetPersistenceService;
  final void Function(RatchetState)? _onRatchetInitialized;
  final String? _localIdentityPublicKey;
  final String? _localDevicePublicKey;
  final FsReplayCache? _replayCache;
  final FsDoSGuard? _dosGuard;
  final FsStateMutex? _stateMutex;
  final FsDowngradeDetector? _downgradeDetector;
  final FsPlaintextCache? _plaintextCache;

  /// Per-contact security mode (§14.3).
  ///
  /// Defaults to [FsSecurityMode.advanced]. The caller (provider layer) sets
  /// this after reading from [FsSecurityModeService].
  FsSecurityMode securityMode = FsSecurityMode.advanced;

  // ---------------------------------------------------------------------------
  // Outgoing message handling
  // ---------------------------------------------------------------------------

  /// Returns the `x.fs` JSON extension to attach to an outgoing message,
  /// or `null` if no FS extension should be sent.
  ///
  /// Policy:
  /// - [FsSessionState.legacyOnly]: try to start handshake → attach fs_init.
  /// - Handshake in progress: attach the next expected handshake message.
  /// - [FsSessionState.fsActive] / [FsSessionState.strictFsActive]: no
  ///   handshake message needed; FS is already established.
  /// - Any other state: no attachment.
  ///
  /// The caller must check [FsPayloadBudget.fitsInOpportunisticBudget] before
  /// embedding.  If the payload is too large the caller may omit `x.fs` and
  /// retry on a future message.
  ///
  /// [pendingInit] must be provided when [FsSessionState.legacyOnly] so the
  /// controller knows which `FsInitPayload` was prepared for this message.
  ///
  /// [pendingReply] must be provided when [FsSessionState.fsInitSeen] so the
  /// responder can include the `fs_reply` extension.
  ///
  /// [pendingConfirm] must be provided when [FsSessionState.fsReplySeen] so
  /// the initiator can include the `fs_confirm` extension.
  Future<FsOutgoingExtension?> buildOutgoingExtension({
    FsInitPayload? pendingInit,
    FsReplyPayload? pendingReply,
    FsConfirmPayload? pendingConfirm,
  }) async {
    final state = _sessionManager.state;

    switch (state) {
      case FsSessionState.legacyOnly:
        // §6.1 Base mode: suppress FS negotiation entirely.
        if (securityMode == FsSecurityMode.base) return null;
        if (pendingInit == null) return null;
        // DoS guard: check rate limits before initiating handshake (§20.3)
        if (_dosGuard != null) {
          final dosCheck = _dosGuard.canInitiateHandshake(_localContactId);
          if (!dosCheck.allowed) {
            return FsOutgoingExtension._(
              json: null,
              droppedReason: FsExtensionDropReason.dosRateLimited,
            );
          }
          _dosGuard.recordHandshakeInitiation(
            contactId: _localContactId,
            initId: pendingInit.initId,
          );
        }
        final msg = pendingInit.toMessage();
        final json = msg.toJson();
        if (!FsPayloadBudget.fitsInOpportunisticBudget(json)) {
          return FsOutgoingExtension._(
            json: null,
            droppedReason: FsExtensionDropReason.payloadTooLarge,
          );
        }
        final result = _sessionManager.recordFsInitSent(pendingInit);
        if (!result.accepted) {
          return FsOutgoingExtension._(
            json: null,
            droppedReason: FsExtensionDropReason.payloadTooLarge,
          );
        }
        await _updateRegistry(
          sessionId: pendingInit.initId,
          state: FsSessionState.fsInitSent,
        );
        return FsOutgoingExtension._(json: json);

      case FsSessionState.fsInitSeen:
        if (pendingReply == null) return null;
        final msg = pendingReply.toMessage();
        final json = msg.toJson();
        if (!FsPayloadBudget.fitsInOpportunisticBudget(json)) {
          return FsOutgoingExtension._(
            json: null,
            droppedReason: FsExtensionDropReason.payloadTooLarge,
          );
        }
        final replyResult = _sessionManager.recordFsReplySent(pendingReply);
        if (!replyResult.accepted) {
          return FsOutgoingExtension._(
            json: null,
            droppedReason: FsExtensionDropReason.payloadTooLarge,
          );
        }
        await _updateRegistry(
          sessionId: pendingReply.replyId,
          state: FsSessionState.fsReplySent,
        );
        return FsOutgoingExtension._(json: json);

      case FsSessionState.fsReplySeen:
        // Generate FS_CONFIRM in response to received FS_REPLY
        // pendingConfirm is passed as parameter to buildOutgoingExtension
        if (pendingConfirm == null) {
          return const FsOutgoingExtension._(json: null);
        }

        // Build FS_CONFIRM extension with the confirm payload
        final json = pendingConfirm.toMessage().toJson();

        // Record that we are sending FS_CONFIRM
        final confirmResult =
            _sessionManager.recordFsConfirmSent(pendingConfirm);
        if (!confirmResult.accepted) {
          return const FsOutgoingExtension._(json: null);
        }

        // Initialize the double ratchet for initiator FIRST
        // Get responder's ratchet pub from the stored FS_REPLY message
        final storedReply = _sessionManager.storedReplyMessage;
        bool ratchetInitialized = false;
        if (storedReply != null) {
          ratchetInitialized = await _initializeRatchetForInitiator(
            sessionId: pendingConfirm.replyId,
            confirmPayload: pendingConfirm,
            responderRatchetPub: storedReply.responderInitialRatchetPub,
          );
        }

        // CRITICAL: Only activate session if ratchet was successfully initialized
        // If ratchet initialization failed (e.g., after identity reset), mark broken
        if (ratchetInitialized) {
          _sessionManager.activateSession(pendingConfirm.replyId);
        } else {
          _sessionManager.markBroken();
        }

        await _updateRegistry(
          sessionId: pendingConfirm.replyId,
          state: _sessionManager.state,
        );

        return FsOutgoingExtension._(json: json);

      case FsSessionState.fsActive:
      case FsSessionState.strictFsActive:
      case FsSessionState.fsConfirmSent:
      case FsSessionState.fsConfirmed:
      case FsSessionState.fsInitSent:
      case FsSessionState.fsReplySent:
      case FsSessionState.fsSuspended:
      case FsSessionState.strictRequested:
      case FsSessionState.fsBroken:
        return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Incoming message handling
  // ---------------------------------------------------------------------------

  /// Processes the `x.fs` extension from a decoded LMF v2 envelope.
  ///
  /// Returns a [FsIncomingResult] indicating what action was taken.
  ///
  /// If the envelope contains no `x.fs` field the remote is assumed to be a
  /// legacy client; the contact state remains [FsSessionState.legacyOnly].
  ///
  /// [remoteContactId] is the `senderId` from the decoded envelope.
  Future<FsIncomingResult> processIncomingEnvelope(
    Map<String, dynamic> envelope, {
    required String remoteContactId,
    String? remoteIdentityPublicKey,
  }) async {
    final contactKey = '$remoteContactId|$_identityContext';

    // Atomic state transitions: serialize per-contact processing (§20.1)
    if (_stateMutex != null) {
      return _stateMutex.withLock(contactKey, () async {
        return _processIncomingEnvelopeInner(envelope,
            remoteContactId: remoteContactId,
            remoteIdentityPublicKey: remoteIdentityPublicKey);
      });
    }
    return _processIncomingEnvelopeInner(envelope,
        remoteContactId: remoteContactId,
        remoteIdentityPublicKey: remoteIdentityPublicKey);
  }

  Future<FsIncomingResult> _processIncomingEnvelopeInner(
    Map<String, dynamic> envelope, {
    required String remoteContactId,
    String? remoteIdentityPublicKey,
  }) async {
    final fs = LmfV2Decoder.extractFsExtension(envelope);
    if (fs == null) {
      // No FS extension: record as legacy for downgrade detection (§7.6)
      _downgradeDetector?.recordSecurityLevel(
        contactId: remoteContactId,
        identityContext: _identityContext,
        level: FsMessageSecurity.legacy,
      );
      return const FsIncomingResult._(type: FsIncomingType.noExtension);
    }

    // §6.1 Base mode: ignore all incoming FS extensions.
    if (securityMode == FsSecurityMode.base) {
      return const FsIncomingResult._(type: FsIncomingType.noExtension);
    }

    final type = LmfV2Decoder.fsMsgType(envelope);
    switch (type) {
      case 'fs_init':
        return await _handleFsInit(
          fs,
          remoteContactId: remoteContactId,
          remoteIdentityPublicKey: remoteIdentityPublicKey,
        );
      case 'fs_reply':
        return await _handleFsReply(fs, remoteContactId: remoteContactId);
      case 'fs_confirm':
        return await _handleFsConfirm(fs, remoteContactId: remoteContactId);
      case 'fs_ack':
        return _handleFsAck(fs);
      case 'fs_suspend':
        return await _handleFsSuspend(fs, remoteContactId: remoteContactId);
      case 'fs_reset':
        return await _handleFsReset(fs, remoteContactId: remoteContactId);
      case 'fs_downgrade_notice':
        return _handleFsDowngradeNotice(fs, remoteContactId: remoteContactId);
      case 'fs_simultaneous_notice':
        return _handleFsSimultaneousNotice(fs);
      default:
        return FsIncomingResult._(
          type: FsIncomingType.unknownType,
          rawType: type,
        );
    }
  }

  // ---------------------------------------------------------------------------
  // Private handlers
  // ---------------------------------------------------------------------------

  Future<FsIncomingResult> _handleFsInit(
    Map<String, dynamic> fs, {
    required String remoteContactId,
    String? remoteIdentityPublicKey,
  }) async {
    late FsInitMessage msg;
    try {
      msg = FsInitMessage.fromJson(fs);
    } catch (_) {
      return const FsIncomingResult._(type: FsIncomingType.malformed);
    }

    // Replay cache: reject already-seen initIds (§8.7)
    if (_replayCache != null && _replayCache.isHandshakeIdReplay(msg.initId)) {
      return const FsIncomingResult._(type: FsIncomingType.fsInitRejected);
    }

    // §7.3/§7.9: Per-device session routing.
    // If the current session is in a terminal state (active/broken/suspended),
    // a new fs_init from the same identity means a new device or restored
    // device. Instead of resetting the current session (which would destroy
    // the old ratchet and break in-flight messages from the old device),
    // we archive the current session and create a fresh one.
    final currentState = _sessionManager.state;
    final isTerminal = currentState == FsSessionState.fsActive ||
        currentState == FsSessionState.strictFsActive ||
        currentState == FsSessionState.fsBroken ||
        currentState == FsSessionState.fsSuspended;
    final replacingPendingResponder =
        (currentState == FsSessionState.fsInitSeen ||
                currentState == FsSessionState.fsReplySent) &&
            _sessionManager.pendingInitId != null &&
            _sessionManager.pendingInitId != msg.initId;
    final replacedInitId =
        replacingPendingResponder ? _sessionManager.pendingInitId : null;

    // DoS guard: check pending handshake limits for remote contact (§20.3).
    // A fresh init replacing the current responder-side pending handshake is
    // recovery from lossy manual transport, not another parallel handshake.
    if (_dosGuard != null && !replacingPendingResponder) {
      final dosCheck = _dosGuard.canInitiateHandshake(remoteContactId);
      if (!dosCheck.allowed) {
        return FsIncomingResult._(
          type: FsIncomingType.fsInitRejected,
          rejectionReason: 'DoS: ${dosCheck.detail}',
        );
      }
    }

    bool newDeviceDetected = false;
    if (isTerminal) {
      _sessionManager = _deviceRouter.rotateForNewDevice();
      newDeviceDetected = true;
    }

    // Build canonical tie-break strings per §8.3.4 when keys are available.
    String? localCanonical;
    String? remoteCanonical;
    final localInit = _sessionManager.pendingInitId ?? '';
    if (_localIdentityPublicKey != null && _localDevicePublicKey != null) {
      localCanonical = FsSessionManager.buildCanonical(
        identityPublicKey: _localIdentityPublicKey,
        devicePublicKey: _localDevicePublicKey,
        initId: localInit,
      );
      final remoteIK = remoteIdentityPublicKey ?? msg.initiatorDevicePub;
      remoteCanonical = FsSessionManager.buildCanonical(
        identityPublicKey: remoteIK,
        devicePublicKey: msg.initiatorDevicePub,
        initId: msg.initId,
      );
    }

    final result = _sessionManager.processFsInitReceived(
      message: msg,
      localInitId: localInit,
      localCanonical: localCanonical,
      remoteCanonical: remoteCanonical,
    );
    if (result.accepted) {
      if (replacedInitId != null) {
        _dosGuard?.completeHandshake(
          contactId: remoteContactId,
          initId: replacedInitId,
        );
      }
      _replayCache?.recordHandshakeId(msg.initId);
      _dosGuard?.recordHandshakeInitiation(
        contactId: remoteContactId,
        initId: msg.initId,
      );
      await _updateRegistry(
        sessionId: msg.initId,
        state: _sessionManager.state,
        remoteDeviceId: msg.initiatorDevicePub,
      );
    }
    return FsIncomingResult._(
      type: result.accepted
          ? FsIncomingType.fsInitAccepted
          : FsIncomingType.fsInitRejected,
      rejectionReason: result.reason,
      newDeviceDetected: newDeviceDetected && result.accepted,
    );
  }

  Future<FsIncomingResult> _handleFsReply(
    Map<String, dynamic> fs, {
    required String remoteContactId,
  }) async {
    late FsReplyMessage msg;
    try {
      msg = FsReplyMessage.fromJson(fs);
    } catch (_) {
      return const FsIncomingResult._(type: FsIncomingType.malformed);
    }

    // Replay cache: reject already-seen replyIds (§8.7)
    if (_replayCache != null && _replayCache.isHandshakeIdReplay(msg.replyId)) {
      return const FsIncomingResult._(type: FsIncomingType.fsReplyRejected);
    }

    final result = _sessionManager.processFsReplyReceived(msg);
    if (result.accepted) {
      _replayCache?.recordHandshakeId(msg.replyId);
      await _updateRegistry(
        sessionId: msg.replyId,
        state: _sessionManager.state,
      );
    }
    return FsIncomingResult._(
      type: result.accepted
          ? FsIncomingType.fsReplyAccepted
          : FsIncomingType.fsReplyRejected,
      rejectionReason: result.reason,
    );
  }

  Future<FsIncomingResult> _handleFsConfirm(
    Map<String, dynamic> fs, {
    required String remoteContactId,
  }) async {
    late FsConfirmMessage msg;
    try {
      msg = FsConfirmMessage.fromJson(fs);
    } catch (_) {
      return const FsIncomingResult._(type: FsIncomingType.malformed);
    }

    // Verify FS_CONFIRM using stored responder state (if available)
    bool verified = false;
    final rawRootSecret = _sessionManager.pendingRawRootSecret;
    final transcriptHash = _sessionManager.pendingTranscriptHash;

    if (rawRootSecret != null && transcriptHash != null) {
      // Create minimal partial state for verification
      final partialState = FsHandshakePartialState(
        transcriptHash: transcriptHash,
        rootKey0: Uint8List(0), // dummy, not used for verification
        sendingChainKey0: Uint8List(0), // dummy
        receivingChainKey0: Uint8List(0), // dummy
        isInitiator: false,
        rawRootSecret: rawRootSecret,
      );

      // Get remote identity public key (if needed for verification)
      // Note: ikAPub is not actually used in verifyFsConfirmAsResponder,
      // but we pass an empty list since it's required by the API
      verified = await FsHandshake.verifyFsConfirmAsResponder(
        confirm: msg,
        bState: partialState,
        ikAPub: Uint8List(0), // not used for cryptographic verification
      );
    }

    final result = _sessionManager.processFsConfirmReceived(
      message: msg,
      verified: verified,
    );

    if (result.accepted) {
      // Handshake complete: clear pending handshake from DoS guard
      _dosGuard?.completeHandshake(
        contactId: remoteContactId,
        initId: msg.initId,
      );
      await _updateRegistry(
        sessionId: msg.replyId,
        state: _sessionManager.state,
      );

      // Activate the session after successful confirm
      if (verified) {
        // Initialize the double ratchet FIRST (before activating session)
        final ratchetInitialized = await _initializeRatchetAfterHandshake(
          sessionId: msg.replyId,
          isInitiator: false,
          remoteRatchetPub: msg.initiatorInitialRatchetPub,
        );

        // CRITICAL: Only activate session if ratchet was successfully initialized
        if (ratchetInitialized) {
          _sessionManager.activateSession(msg.replyId);
        } else {
          _sessionManager.markBroken();
        }
        await _updateRegistry(
          sessionId: msg.replyId,
          state: _sessionManager.state,
        );
      }
    }

    return FsIncomingResult._(
      type: result.accepted
          ? FsIncomingType.fsConfirmAccepted
          : FsIncomingType.fsConfirmRejected,
      rejectionReason: result.reason,
    );
  }

  // ---------------------------------------------------------------------------
  // Control message handlers (§9.2)
  // ---------------------------------------------------------------------------

  FsIncomingResult _handleFsAck(Map<String, dynamic> fs) {
    try {
      FsAckMessage.fromJson(fs);
    } catch (_) {
      return const FsIncomingResult._(type: FsIncomingType.malformed);
    }
    // fs_ack is informational — no state change needed.
    // The initiator can use it as extra confirmation that B verified.
    return const FsIncomingResult._(type: FsIncomingType.fsAckReceived);
  }

  Future<FsIncomingResult> _handleFsSuspend(
    Map<String, dynamic> fs, {
    required String remoteContactId,
  }) async {
    try {
      final msg = FsSuspendMessage.fromJson(fs);
      final currentState = _sessionManager.state;
      if (currentState == FsSessionState.fsActive ||
          currentState == FsSessionState.strictFsActive) {
        _sessionManager.suspend();
        await _updateRegistry(
          sessionId: msg.sessionId,
          state: _sessionManager.state,
        );
      }
      return const FsIncomingResult._(type: FsIncomingType.fsSuspendReceived);
    } catch (_) {
      return const FsIncomingResult._(type: FsIncomingType.malformed);
    }
  }

  Future<FsIncomingResult> _handleFsReset(
    Map<String, dynamic> fs, {
    required String remoteContactId,
  }) async {
    try {
      final msg = FsResetMessage.fromJson(fs);
      // Reset all sessions (current + previous devices) — explicit reset
      // from the remote means all device sessions are invalidated.
      _deviceRouter.resetAll();
      _sessionManager = _deviceRouter.currentSession;
      _dosGuard?.completeHandshake(
        contactId: remoteContactId,
        initId: msg.previousSessionId,
      );
      await _updateRegistry(
        sessionId: null,
        state: _sessionManager.state,
      );
      return const FsIncomingResult._(type: FsIncomingType.fsResetReceived);
    } catch (_) {
      return const FsIncomingResult._(type: FsIncomingType.malformed);
    }
  }

  FsIncomingResult _handleFsDowngradeNotice(
    Map<String, dynamic> fs, {
    required String remoteContactId,
  }) {
    try {
      FsDowngradeNoticeMessage.fromJson(fs);
      // The remote is informing us that they detected a downgrade.
      // Evaluate locally and record the warning.
      _downgradeDetector?.evaluate(
        contactId: remoteContactId,
        identityContext: _identityContext,
        incomingLevel: FsMessageSecurity.legacy,
        sessionState: _sessionManager.state,
      );
      return const FsIncomingResult._(
          type: FsIncomingType.fsDowngradeNoticeReceived);
    } catch (_) {
      return const FsIncomingResult._(type: FsIncomingType.malformed);
    }
  }

  FsIncomingResult _handleFsSimultaneousNotice(Map<String, dynamic> fs) {
    try {
      FsSimultaneousNoticeMessage.fromJson(fs);
      // Informational: the remote is notifying us that a tie-break occurred.
      return const FsIncomingResult._(
          type: FsIncomingType.fsSimultaneousNoticeReceived);
    } catch (_) {
      return const FsIncomingResult._(type: FsIncomingType.malformed);
    }
  }

  // ---------------------------------------------------------------------------
  // Downgrade detection (§7.6)
  // ---------------------------------------------------------------------------

  /// Evaluates the security level of a received message and checks for
  /// downgrades from the highest confirmed level.
  FsDowngradeResult? evaluateDowngrade({
    required String contactId,
    required FsMessageSecurity incomingLevel,
  }) {
    if (_downgradeDetector == null) return null;
    return _downgradeDetector.evaluate(
      contactId: contactId,
      identityContext: _identityContext,
      incomingLevel: incomingLevel,
      sessionState: _sessionManager.state,
    );
  }

  /// Records a successfully processed message's security level.
  void recordSecurityLevel({
    required String contactId,
    required FsMessageSecurity level,
  }) {
    _downgradeDetector?.recordSecurityLevel(
      contactId: contactId,
      identityContext: _identityContext,
      level: level,
    );
  }

  // ---------------------------------------------------------------------------
  // Plaintext cache (§12.3)
  // ---------------------------------------------------------------------------

  /// Returns cached FS-decrypted plaintext for the given message key, or null.
  String? getCachedPlaintext(String messageKey) {
    return _plaintextCache?.get(messageKey);
  }

  /// Caches FS-decrypted plaintext for the given message key.
  void cachePlaintext(String messageKey, String plaintext) {
    _plaintextCache?.put(messageKey, plaintext);
  }

  /// Wipes all cached plaintext (e.g., on identity reset or app background).
  void wipePlaintextCache() {
    _plaintextCache?.wipe();
  }

  // ---------------------------------------------------------------------------
  // Replay cache (§8.7)
  // ---------------------------------------------------------------------------

  /// Checks whether a message counter has been seen before.
  bool isMessageReplay({required String sessionId, required int counter}) {
    return _replayCache?.isMessageReplay(
          sessionId: sessionId,
          counter: counter,
        ) ??
        false;
  }

  /// Records a successfully processed message counter.
  void recordMessageProcessed(
      {required String sessionId, required int counter}) {
    _replayCache?.recordMessage(sessionId: sessionId, counter: counter);
  }

  Future<void> _updateRegistry({
    required String? sessionId,
    required FsSessionState state,
    String? remoteDeviceId,
  }) async {
    final stateEntry = FsContactSecurityState(
      contactId: _localContactId,
      identityContext: _identityContext,
      sessionId: sessionId,
      fsState: state,
      remoteDeviceId: remoteDeviceId,
    );
    _registry.upsert(stateEntry);
    // Persist to storage (only for primary context)
    await _persistenceService?.saveState(stateEntry);
  }

  // ---------------------------------------------------------------------------
  // Ratchet initialization after handshake
  // ---------------------------------------------------------------------------

  /// Initializes the double ratchet for the responder after FS_CONFIRM verification.
  /// Returns true if initialization succeeded, false otherwise.
  Future<bool> _initializeRatchetAfterHandshake({
    required String sessionId,
    required bool isInitiator,
    required String? remoteRatchetPub,
  }) async {
    try {
      // Get the stored handshake state with initial keys
      final partialState = isInitiator
          ? _sessionManager.initiatorPartialState
          : _sessionManager.responderPartialState;
      if (partialState == null) {
        return false;
      }

      // Decode remote ratchet public key if provided
      Uint8List? lastRemoteRatchetPub;
      if (remoteRatchetPub != null) {
        lastRemoteRatchetPub = FsKeyCodec.decodeKey(remoteRatchetPub);
      }

      // Initialize the ratchet with the handshake keys
      final ratchetState = await FsDoubleRatchet.initRatchet(
        sessionId: sessionId,
        rootKey0: partialState.rootKey0,
        sendingChainKey0: partialState.sendingChainKey0,
        receivingChainKey0: partialState.receivingChainKey0,
        localRatchetPriv: partialState.localRatchetPriv!,
        localRatchetPub: partialState.localRatchetPub!,
        lastRemoteRatchetPub: lastRemoteRatchetPub,
      );

      // Notify callback (used by HomeController to cache and persist)
      _onRatchetInitialized?.call(ratchetState);

      // Also persist via service if available
      await _ratchetPersistenceService?.saveRatchetState(ratchetState);

      return true;
    } catch (_) {
      return false;
    }
  }

  /// Initializes the double ratchet for the initiator after sending FS_CONFIRM.
  /// Returns true if initialization succeeded, false otherwise.
  Future<bool> _initializeRatchetForInitiator({
    required String sessionId,
    required FsConfirmPayload confirmPayload,
    required String? responderRatchetPub,
  }) async {
    try {
      final partialState = confirmPayload.partialState;

      // Decode responder's ratchet public key
      Uint8List? lastRemoteRatchetPub;
      if (responderRatchetPub != null) {
        lastRemoteRatchetPub = FsKeyCodec.decodeKey(responderRatchetPub);
      }

      // initiatorInitialRatchetPriv is already Uint8List (not encoded)
      final localRatchetPriv = confirmPayload.initiatorInitialRatchetPriv;

      // Decode initiator's ratchet public key (it's encoded as string)
      final localRatchetPub = FsKeyCodec.decodeKey(
        confirmPayload.initiatorInitialRatchetPub,
      );

      // Initialize the ratchet
      final ratchetState = await FsDoubleRatchet.initRatchet(
        sessionId: sessionId,
        rootKey0: partialState.rootKey0,
        sendingChainKey0: partialState.sendingChainKey0,
        receivingChainKey0: partialState.receivingChainKey0,
        localRatchetPriv: localRatchetPriv,
        localRatchetPub: localRatchetPub,
        lastRemoteRatchetPub: lastRemoteRatchetPub,
      );

      // Notify callback and persist
      _onRatchetInitialized?.call(ratchetState);
      await _ratchetPersistenceService?.saveRatchetState(ratchetState);
      return true;
    } catch (_) {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // State access
  // ---------------------------------------------------------------------------

  /// Current FS session state (from the most recently active device session).
  FsSessionState get state => _sessionManager.state;

  /// The best FS state across all device sessions.
  ///
  /// Returns the highest-priority state: if the current device session is in
  /// handshake but a previous device session is still active, returns fsActive.
  FsSessionState get bestState => _deviceRouter.bestState;

  /// The session manager for direct access (ensures consistency with controller state).
  ///
  /// Returns the current (most recently active) device's session manager.
  FsSessionManager get sessionManager => _sessionManager;

  /// The per-device session router.
  ///
  /// Used by the home controller to look up ratchets for specific session IDs
  /// (e.g., when decrypting a message whose `fs_session` points to a previous
  /// device's ratchet).
  FsDeviceSessionRouter get deviceRouter => _deviceRouter;

  /// Returns all active session IDs across all device sessions.
  List<String> get allActiveSessionIds => _deviceRouter.allActiveSessionIds;

  /// Restores an active session from persisted registry + ratchet state.
  void restorePersistedActiveSession({
    required String sessionId,
    required FsSessionState state,
  }) {
    if (allActiveSessionIds.contains(sessionId)) return;
    if (_sessionManager.state == FsSessionState.legacyOnly &&
        _sessionManager.activeSessionId == null) {
      _sessionManager.restorePersistedActiveSession(
        state,
        sessionId: sessionId,
      );
      return;
    }

    final restored = FsSessionManager();
    restored.restorePersistedActiveSession(state, sessionId: sessionId);
    _deviceRouter.restorePreviousSession(sessionId, restored);
  }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Describes the outcome of attaching an outgoing `x.fs` extension.
class FsOutgoingExtension {
  const FsOutgoingExtension._({this.json, this.droppedReason});

  /// The JSON map to attach as `x.fs`, or null if no extension is attached.
  final Map<String, dynamic>? json;

  /// If non-null, explains why the extension was dropped.
  final FsExtensionDropReason? droppedReason;

  /// Whether an extension will be attached.
  bool get hasExtension => json != null;
}

/// Reason an outgoing FS extension was dropped.
enum FsExtensionDropReason {
  /// The serialised extension exceeds [FsPayloadBudget.kMaxFsControlPayloadBytes].
  payloadTooLarge,

  /// DoS guard rejected the handshake initiation (§20.3).
  dosRateLimited,
}

/// Describes the outcome of processing an incoming `x.fs` extension.
class FsIncomingResult {
  const FsIncomingResult._({
    required this.type,
    this.rejectionReason,
    this.rawType,
    this.newDeviceDetected = false,
  });

  final FsIncomingType type;

  /// Human-readable rejection reason from [FsSessionManager], if any.
  final String? rejectionReason;

  /// The raw `type` string if [type] is [FsIncomingType.unknownType].
  final String? rawType;

  /// True if this `fs_init` was accepted because a new device/session was
  /// detected for the same identity (§7.9). The previous device's session
  /// has been archived (its ratchet is preserved for in-flight decryption).
  final bool newDeviceDetected;

  bool get accepted =>
      type == FsIncomingType.fsInitAccepted ||
      type == FsIncomingType.fsReplyAccepted ||
      type == FsIncomingType.fsConfirmAccepted;
}

enum FsIncomingType {
  /// Envelope contained no `x.fs` extension (legacy client).
  noExtension,

  /// `x.fs` type field was not recognised.
  unknownType,

  /// `x.fs` JSON could not be parsed.
  malformed,

  fsInitAccepted,
  fsInitRejected,
  fsReplyAccepted,
  fsReplyRejected,
  fsConfirmAccepted,
  fsConfirmRejected,

  /// Control message types (§9.2)
  fsAckReceived,
  fsSuspendReceived,
  fsResetReceived,
  fsDowngradeNoticeReceived,
  fsSimultaneousNoticeReceived,
}
