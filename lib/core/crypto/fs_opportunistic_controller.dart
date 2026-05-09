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
import 'fs_handshake.dart';
import 'fs_payload_budget.dart';
import 'fs_session_manager.dart';
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
  })  : _localContactId = localContactId,
        _identityContext = identityContext,
        _sessionManager = sessionManager,
        _registry = registry;

  final String _localContactId;
  final String _identityContext;
  final FsSessionManager _sessionManager;
  final FsContactSecurityRegistry _registry;

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
  FsOutgoingExtension? buildOutgoingExtension({
    FsInitPayload? pendingInit,
    FsReplyPayload? pendingReply,
    FsConfirmPayload? pendingConfirm,
  }) {
    final state = _sessionManager.state;

    switch (state) {
      case FsSessionState.legacyOnly:
        if (pendingInit == null) return null;
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
        _updateRegistry(
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
        _updateRegistry(
          sessionId: pendingReply.replyId,
          state: FsSessionState.fsReplySent,
        );
        return FsOutgoingExtension._(json: json);

      case FsSessionState.fsReplySeen:
        if (pendingConfirm == null) return null;
        final msg = pendingConfirm.toMessage();
        final json = msg.toJson();
        if (!FsPayloadBudget.fitsInOpportunisticBudget(json)) {
          return FsOutgoingExtension._(
            json: null,
            droppedReason: FsExtensionDropReason.payloadTooLarge,
          );
        }
        final confirmResult = _sessionManager.recordFsConfirmSent(pendingConfirm);
        if (!confirmResult.accepted) {
          return FsOutgoingExtension._(
            json: null,
            droppedReason: FsExtensionDropReason.payloadTooLarge,
          );
        }
        _updateRegistry(
          sessionId: pendingConfirm.replyId,
          state: FsSessionState.fsConfirmSent,
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
  }) async {
    final fs = LmfV2Decoder.extractFsExtension(envelope);
    if (fs == null) {
      return const FsIncomingResult._(type: FsIncomingType.noExtension);
    }

    final type = LmfV2Decoder.fsMsgType(envelope);
    switch (type) {
      case 'fs_init':
        return _handleFsInit(fs, remoteContactId: remoteContactId);
      case 'fs_reply':
        return _handleFsReply(fs, remoteContactId: remoteContactId);
      case 'fs_confirm':
        return await _handleFsConfirm(fs, remoteContactId: remoteContactId);
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

  FsIncomingResult _handleFsInit(
    Map<String, dynamic> fs, {
    required String remoteContactId,
  }) {
    late FsInitMessage msg;
    try {
      msg = FsInitMessage.fromJson(fs);
    } catch (_) {
      return const FsIncomingResult._(type: FsIncomingType.malformed);
    }

    final result = _sessionManager.processFsInitReceived(
      message: msg,
      localInitId: _sessionManager.pendingInitId ?? '',
    );
    if (result.accepted) {
      _updateRegistry(sessionId: msg.initId, state: _sessionManager.state);
    }
    return FsIncomingResult._(
      type: result.accepted
          ? FsIncomingType.fsInitAccepted
          : FsIncomingType.fsInitRejected,
      rejectionReason: result.reason,
    );
  }

  FsIncomingResult _handleFsReply(
    Map<String, dynamic> fs, {
    required String remoteContactId,
  }) {
    late FsReplyMessage msg;
    try {
      msg = FsReplyMessage.fromJson(fs);
    } catch (_) {
      return const FsIncomingResult._(type: FsIncomingType.malformed);
    }

    final result = _sessionManager.processFsReplyReceived(msg);
    if (result.accepted) {
      _updateRegistry(sessionId: msg.replyId, state: _sessionManager.state);
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
      _updateRegistry(sessionId: msg.replyId, state: _sessionManager.state);

      // Activate the session after successful confirm
      if (verified) {
        _sessionManager.activateSession(msg.replyId);
        _updateRegistry(sessionId: msg.replyId, state: _sessionManager.state);
      }
    }

    return FsIncomingResult._(
      type: result.accepted
          ? FsIncomingType.fsConfirmAccepted
          : FsIncomingType.fsConfirmRejected,
      rejectionReason: result.reason,
    );
  }

  void _updateRegistry({
    required String? sessionId,
    required FsSessionState state,
  }) {
    _registry.upsert(FsContactSecurityState(
      contactId: _localContactId,
      identityContext: _identityContext,
      sessionId: sessionId,
      fsState: state,
    ));
  }

  // ---------------------------------------------------------------------------
  // State access
  // ---------------------------------------------------------------------------

  /// Current FS session state.
  FsSessionState get state => _sessionManager.state;
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
}

/// Describes the outcome of processing an incoming `x.fs` extension.
class FsIncomingResult {
  const FsIncomingResult._({
    required this.type,
    this.rejectionReason,
    this.rawType,
  });

  final FsIncomingType type;

  /// Human-readable rejection reason from [FsSessionManager], if any.
  final String? rejectionReason;

  /// The raw `type` string if [type] is [FsIncomingType.unknownType].
  final String? rawType;

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
}
