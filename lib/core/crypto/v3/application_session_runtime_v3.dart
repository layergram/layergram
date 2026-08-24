// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

import '../../storage/aux_record_repository.dart';
import '../../storage/messages_repository_core.dart';
import '../fs_message_classification.dart';
import '../fs_security_mode.dart';
import 'application_payload_v3.dart';
import 'application_projection_v3.dart';
import 'application_runtime_owner_v3.dart';
import 'application_send_group_v3.dart';
import 'application_transport_v3.dart';
import 'device_key_repository_v3.dart';
import 'handshake_frame_inbox_v3.dart';
import 'handshake_persistence_v3.dart';
import 'handshake_session_handoff_v3.dart';
import 'handshake_transport_v3.dart';
import 'key_schedule_v3.dart';
import 'lmf_v3.dart';
import 'lmf_v3_outbox.dart';
import 'lmf_v3_persistence.dart';
import 'local_identity_v3.dart';
import 'public_identity_v3.dart';
import 'retention_policy_v3.dart';
import 'session_commit_controller_v3.dart';
import 'session_persistence_scope_v3.dart';
import 'sparse_pq_ratchet_v3.dart';
import 'triple_ratchet_state_v3.dart';

/// Public, already-durable handshake data ready for carrier export.
///
/// Frames contain public handshake records protected by deterministic LMF
/// framing. They can be copied freely; HP3 secrets remain inside the encrypted
/// persistence scope.
final class V3ApplicationHandshakeExport {
  V3ApplicationHandshakeExport({
    required this.handshakeId,
    required this.kind,
    required Iterable<V3LmfFrame> frames,
    required this.restored,
    this.session,
  }) : frames = List<V3LmfFrame>.unmodifiable(frames);

  final String handshakeId;
  final V3HandshakeRecordKind kind;
  final List<V3LmfFrame> frames;
  final bool restored;
  final V3ApplicationSessionBinding? session;

  String get text => V3HandshakeTransport.encodeText(frames);
  String get links => V3HandshakeTransport.encodeLinks(frames);

  List<String> stego(List<String> coverTexts) =>
      V3HandshakeTransport.encodeStego(
        frames: frames,
        coverTexts: coverTexts,
      );
}

/// Non-secret binding returned once HP3 has become a durable TR3 session.
final class V3ApplicationSessionBinding {
  V3ApplicationSessionBinding({
    required this.handshakeId,
    required this.sessionId,
    required this.checkpointDigest,
    required this.role,
    required this.recovered,
  });

  final String handshakeId;
  final String sessionId;
  final String checkpointDigest;
  final V3SessionRole role;
  final bool recovered;

  Uint8List get sessionIdBytes => _decodeCanonicalId(sessionId, 16);
}

final class V3ApplicationHandshakeInboundResult {
  const V3ApplicationHandshakeInboundResult({
    required this.status,
    required this.assemblyId,
    this.outbound,
    this.session,
  });

  final V3HandshakeFrameInboxStatus status;
  final String? assemblyId;
  final V3ApplicationHandshakeExport? outbound;
  final V3ApplicationSessionBinding? session;

  bool get isComplete => outbound != null || session != null;
}

final class V3ApplicationMessageTargetExport {
  V3ApplicationMessageTargetExport({
    required this.sessionId,
    required this.assemblyId,
    required this.ratchetRevision,
    required Iterable<V3LmfFrame> frames,
  }) : frames = List<V3LmfFrame>.unmodifiable(frames);

  final String sessionId;
  final String assemblyId;
  final int ratchetRevision;
  final List<V3LmfFrame> frames;
}

/// One logical message, atomically prepared for every selected device session.
final class V3ApplicationMessageExport {
  V3ApplicationMessageExport({
    required this.groupId,
    required Iterable<V3ApplicationMessageTargetExport> targets,
  }) : targets = List<V3ApplicationMessageTargetExport>.unmodifiable(targets);

  final String groupId;
  final List<V3ApplicationMessageTargetExport> targets;

  List<V3LmfFrame> get frames => List<V3LmfFrame>.unmodifiable(
        targets.expand((target) => target.frames),
      );

  /// Each part is independently below the conservative 4,000-character
  /// portable carrier limit used for WhatsApp, Telegram, Signal and iMessage.
  List<String> get textParts =>
      frames.map(V3ApplicationTransport.encodeText).toList(growable: false);

  List<String> get linkParts =>
      frames.map(V3ApplicationTransport.encodeLink).toList(growable: false);

  List<String> stegoParts(List<String> coverTexts) {
    final sealed = frames;
    if (sealed.length != coverTexts.length) {
      throw ArgumentError('one cover text is required for each v3 frame');
    }
    return List<String>.generate(
      sealed.length,
      (index) => V3ApplicationTransport.encodeStego(
        frame: sealed[index],
        coverText: coverTexts[index],
      ),
      growable: false,
    );
  }
}

/// Aggregate outcome of one scope-local retention maintenance pass.
final class V3ApplicationRetentionMaintenanceResult {
  const V3ApplicationRetentionMaintenanceResult({
    required this.compactedSessions,
    required this.collectedIncomingEffects,
    required this.collectedOutgoingEffects,
    required this.replayWindowEntries,
    required this.examinedReceipts,
    required this.retiredReceipts,
    required this.collectedDeletedApplicationRecords,
  });

  final int compactedSessions;
  final int collectedIncomingEffects;
  final int collectedOutgoingEffects;
  final int replayWindowEntries;
  final int examinedReceipts;
  final int retiredReceipts;
  final int collectedDeletedApplicationRecords;
}

enum V3ApplicationInboundStatus {
  notForThisInstallation,
  pending,
  delivered,
  expired,
  invalidPayload,
  identityMismatch,
  committedReplay,
  acknowledgementApplied,
}

final class V3ApplicationMessageInboundResult {
  const V3ApplicationMessageInboundResult({
    required this.status,
    this.inboxStatus,
    this.payload,
    this.acknowledgementFrame,
    this.sendAcknowledgementStatus,
  });

  final V3ApplicationInboundStatus status;
  final V3LmfInboxStatus? inboxStatus;
  final V3ApplicationPayload? payload;
  final V3LmfFrame? acknowledgementFrame;
  final V3LmfOutboxAckStatus? sendAcknowledgementStatus;

  bool get shouldExportAcknowledgement => acknowledgementFrame != null;

  String? get acknowledgementText => acknowledgementFrame == null
      ? null
      : V3ApplicationTransport.encodeText(acknowledgementFrame!);

  String? get acknowledgementLink => acknowledgementFrame == null
      ? null
      : V3ApplicationTransport.encodeLink(acknowledgementFrame!);

  String acknowledgementStego(String coverText) {
    final frame = acknowledgementFrame;
    if (frame == null) {
      throw StateError('Layergram v3 result has no acknowledgement');
    }
    return V3ApplicationTransport.encodeStego(
      frame: frame,
      coverText: coverText,
    );
  }
}

/// Application-facing owner of one protocol-v3 identity/passphrase scope.
///
/// This is the only layer allowed to combine the installation device key,
/// durable HP3 controller, HP3-to-TR3 handoff and session inbox/outbox. It
/// deliberately does not own [localIdentity]; the process-level identity
/// runtime closes that handle only after this runtime has drained.
final class V3ApplicationSessionRuntime implements V3ApplicationRuntimeSession {
  static const int maxNormalDeviceTargetsPerMessage = 16;

  V3ApplicationSessionRuntime._({
    required this.localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3SessionPersistenceScope scope,
    required AuxRecordRepository contactPolicyRepository,
    required SecretKeyData contactPolicyStorageKey,
    required FsSecurityModeService contactPolicyService,
    required this.restoreResult,
  })  : _localDevice = localDevice,
        _scope = scope,
        _contactPolicyRepository = contactPolicyRepository,
        _contactPolicyStorageKey = contactPolicyStorageKey,
        _contactPolicyService = contactPolicyService;

  /// Opens the real encrypted Aux scope and restores all durable state.
  ///
  /// On a fresh installation [bootstrapCheckpoints] is normally empty and the
  /// first handshake registers revision zero. On restart the encrypted
  /// checkpoint repository is authoritative, so an empty iterable restores
  /// every existing session. The optional iterable is retained for controlled
  /// migration/import tests only.
  static Future<V3ApplicationSessionRuntime> open({
    required V3LocalIdentityHandle localIdentity,
    required String scopeToken,
    required V3SckaBackend sckaBackend,
    Iterable<V3TripleRatchetState> bootstrapCheckpoints = const [],
    V3SessionSnapshotValidator? snapshotValidator,
    int maxSessions = 4096,
    int maxAcknowledgementEntries = 4096,
    int maxAcknowledgementTotalBytes = 4 * 1024 * 1024,
  }) =>
      _open(
        localIdentity: localIdentity,
        scopeToken: scopeToken,
        sckaBackend: sckaBackend,
        bootstrapCheckpoints: bootstrapCheckpoints,
        snapshotValidator: snapshotValidator,
        maxSessions: maxSessions,
        maxAcknowledgementEntries: maxAcknowledgementEntries,
        maxAcknowledgementTotalBytes: maxAcknowledgementTotalBytes,
      );

  /// Opens the runtime with the signed candidate library embedded by the
  /// platform packaging scripts.
  ///
  /// Merely compiling this method does not load the library. The application
  /// lifecycle calls it only after the single fail-closed activation policy is
  /// true.
  static Future<V3ApplicationSessionRuntime> openPackagedScka({
    required V3LocalIdentityHandle localIdentity,
    required String scopeToken,
    Iterable<V3TripleRatchetState> bootstrapCheckpoints = const [],
    V3SessionSnapshotValidator? snapshotValidator,
    int maxSessions = 4096,
    int maxAcknowledgementEntries = 4096,
    int maxAcknowledgementTotalBytes = 4 * 1024 * 1024,
  }) =>
      _open(
        localIdentity: localIdentity,
        scopeToken: scopeToken,
        bootstrapCheckpoints: bootstrapCheckpoints,
        snapshotValidator: snapshotValidator,
        maxSessions: maxSessions,
        maxAcknowledgementEntries: maxAcknowledgementEntries,
        maxAcknowledgementTotalBytes: maxAcknowledgementTotalBytes,
      );

  static Future<V3ApplicationSessionRuntime> _open({
    required V3LocalIdentityHandle localIdentity,
    required String scopeToken,
    V3SckaBackend? sckaBackend,
    required Iterable<V3TripleRatchetState> bootstrapCheckpoints,
    V3SessionSnapshotValidator? snapshotValidator,
    required int maxSessions,
    required int maxAcknowledgementEntries,
    required int maxAcknowledgementTotalBytes,
  }) async {
    if (localIdentity.isClosed) {
      throw StateError('Layergram v3 local identity is closed');
    }

    final derivedKey = await localIdentity.deriveAuxStorageKey();
    final extractedKey = await derivedKey.extract();
    final deviceRepository = AuxRecordRepository();
    V3LocalDeviceHandle? device;
    V3SessionPersistenceScope? scope;
    AuxRecordRepository? contactPolicyRepository;
    SecretKeyData? contactPolicyStorageKey;
    try {
      deviceRepository.setActiveContext(
        scopeToken: scopeToken,
        auxStorageKey: extractedKey,
      );
      device = await V3DeviceKeyRepository(
        store: V3LmfAuxRecordStore(deviceRepository),
      ).loadOrCreate();
      scope = sckaBackend == null
          ? await V3SessionPersistenceScope.openPackagedScka(
              scopeToken: scopeToken,
              auxStorageKey: extractedKey,
              snapshotValidator: snapshotValidator,
              maxSessions: maxSessions,
              maxAcknowledgementEntries: maxAcknowledgementEntries,
              maxAcknowledgementTotalBytes: maxAcknowledgementTotalBytes,
            )
          : await V3SessionPersistenceScope.open(
              scopeToken: scopeToken,
              auxStorageKey: extractedKey,
              sckaBackend: sckaBackend,
              snapshotValidator: snapshotValidator,
              maxSessions: maxSessions,
              maxAcknowledgementEntries: maxAcknowledgementEntries,
              maxAcknowledgementTotalBytes: maxAcknowledgementTotalBytes,
            );
      final restored = await scope.restore(
        checkpoints: bootstrapCheckpoints,
      );
      contactPolicyStorageKey = extractedKey.copy();
      contactPolicyRepository = AuxRecordRepository()
        ..setActiveContext(
          scopeToken: scopeToken,
          auxStorageKey: contactPolicyStorageKey,
        );
      final contactPolicyService = FsSecurityModeService(
        auxRepository: contactPolicyRepository,
      );
      await contactPolicyService.rebuildIndex();
      return V3ApplicationSessionRuntime._(
        localIdentity: localIdentity,
        localDevice: device,
        scope: scope,
        contactPolicyRepository: contactPolicyRepository,
        contactPolicyStorageKey: contactPolicyStorageKey,
        contactPolicyService: contactPolicyService,
        restoreResult: restored,
      );
    } catch (_) {
      contactPolicyRepository?.setActiveContext(
        scopeToken: null,
        auxStorageKey: null,
      );
      contactPolicyStorageKey?.destroy();
      await scope?.close();
      device?.close();
      rethrow;
    } finally {
      deviceRepository.setActiveContext(
        scopeToken: null,
        auxStorageKey: null,
      );
      extractedKey.destroy();
      if (derivedKey is SecretKeyData && !identical(derivedKey, extractedKey)) {
        derivedKey.destroy();
      }
    }
  }

  final V3LocalIdentityHandle localIdentity;
  final V3LocalDeviceHandle _localDevice;
  final V3SessionPersistenceScope _scope;
  final AuxRecordRepository _contactPolicyRepository;
  final SecretKeyData _contactPolicyStorageKey;
  final FsSecurityModeService _contactPolicyService;
  final V3SessionPersistenceRestoreResult restoreResult;

  Future<void> _operationTail = Future<void>.value();
  final Set<String> _locallyExcludedHandshakeIds = <String>{};
  bool _closed = false;

  bool get requiresRecovery => _scope.requiresRecovery;

  Uint8List get localDeviceId => _localDevice.deviceId;

  /// Starts or durably retries an offer before returning exportable frames.
  Future<V3ApplicationHandshakeExport> createOffer({
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode mode,
    Set<String> excludedHandshakeIds = const <String>{},
    DateTime? createdAt,
  }) {
    return _serialized(() async {
      final excluded = _effectiveExcludedHandshakeIds(excludedHandshakeIds);
      final outbound = await _scope.handshakes.createOffer(
        localIdentity: localIdentity,
        localDevice: _localDevice,
        remoteIdentity: remoteIdentity,
        mode: mode,
        excludedHandshakeIds: excluded,
        createdAt: createdAt,
      );
      return _sealOutbound(
        outbound,
        initiatorIdentity: localIdentity.publicIdentity,
        responderIdentity: remoteIdentity,
      );
    });
  }

  /// Accepts an offer and durably stores the exact reply record before export.
  Future<V3ApplicationHandshakeExport> receiveOffer({
    required Iterable<V3LmfFrame> frames,
    required V3PublicIdentity initiatorIdentity,
    required V3HandshakeMode expectedMode,
    Set<String> excludedHandshakeIds = const <String>{},
    DateTime? createdAt,
  }) {
    return _serialized(() async {
      final opened = await V3HandshakeTransport.open(
        frames: frames,
        initiatorIdentity: initiatorIdentity,
        responderIdentity: localIdentity.publicIdentity,
      );
      try {
        final offer = opened.decodeOffer();
        final outbound = await _scope.handshakes.createReply(
          localIdentity: localIdentity,
          localDevice: _localDevice,
          initiatorIdentity: initiatorIdentity,
          offer: offer,
          expectedMode: expectedMode,
          excludedHandshakeIds:
              _effectiveExcludedHandshakeIds(excludedHandshakeIds),
          createdAt: createdAt,
        );
        return _sealOutbound(
          outbound,
          initiatorIdentity: initiatorIdentity,
          responderIdentity: localIdentity.publicIdentity,
        );
      } finally {
        opened.close();
      }
    });
  }

  /// Accepts a reply, commits revision-zero TR3, then returns the durable
  /// confirmation. If the carrier loses it, [retryHandshake] reproduces the
  /// same LMF bytes from the committed completion tombstone.
  Future<V3ApplicationHandshakeExport> receiveReply({
    required Iterable<V3LmfFrame> frames,
    required V3PublicIdentity responderIdentity,
    DateTime? preparedAt,
    DateTime? completedAt,
  }) {
    return _serialized(() async {
      final opened = await V3HandshakeTransport.open(
        frames: frames,
        initiatorIdentity: localIdentity.publicIdentity,
        responderIdentity: responderIdentity,
      );
      try {
        final reply = opened.decodeReply();
        final handshakeId = _id(reply.handshakeId);
        final stateDigest =
            await _scope.handshakes.stateDigestForId(handshakeId);
        if (stateDigest == null) {
          throw StateError(
              'Layergram v3 initiator pending state was not found');
        }
        final handoff = await _scope.handoffs.completeInitiator(
          handshakeId: handshakeId,
          expectedStateDigest: stateDigest,
          localIdentity: localIdentity,
          localDevice: _localDevice,
          responderIdentity: responderIdentity,
          reply: reply,
          preparedAt: preparedAt,
          completedAt: completedAt,
        );
        final confirmationRecord = handoff.confirmationRecord;
        try {
          final outbound = V3DurableHandshakeOutbound(
            handshakeId: handoff.handshakeId,
            kind: V3HandshakeRecordKind.confirmation,
            messageId: _confirmationMessageId(confirmationRecord),
            stateDigest: stateDigest,
            outboundRecord: confirmationRecord,
            restored: handoff.recovered,
          );
          return _sealOutbound(
            outbound,
            initiatorIdentity: localIdentity.publicIdentity,
            responderIdentity: responderIdentity,
            session: _binding(handoff),
          );
        } finally {
          _wipe(confirmationRecord);
        }
      } finally {
        opened.close();
      }
    });
  }

  /// Accepts the initiator confirmation and atomically registers responder
  /// revision-zero TR3. Duplicate/lost carrier deliveries are idempotent.
  Future<V3ApplicationSessionBinding> receiveConfirmation({
    required Iterable<V3LmfFrame> frames,
    required V3PublicIdentity initiatorIdentity,
    DateTime? preparedAt,
    DateTime? completedAt,
  }) {
    return _serialized(() async {
      final opened = await V3HandshakeTransport.open(
        frames: frames,
        initiatorIdentity: initiatorIdentity,
        responderIdentity: localIdentity.publicIdentity,
      );
      try {
        final confirmation = opened.decodeConfirmation();
        final handshakeId = _id(confirmation.handshakeId);
        final stateDigest =
            await _scope.handshakes.stateDigestForId(handshakeId);
        if (stateDigest == null) {
          throw StateError(
              'Layergram v3 responder pending state was not found');
        }
        final handoff = await _scope.handoffs.completeResponder(
          handshakeId: handshakeId,
          expectedStateDigest: stateDigest,
          initiatorIdentity: initiatorIdentity,
          responderIdentity: localIdentity.publicIdentity,
          confirmation: confirmation,
          preparedAt: preparedAt,
          completedAt: completedAt,
        );
        return _binding(handoff);
      } finally {
        opened.close();
      }
    });
  }

  /// Persists one carrier fragment before attempting HP3 authentication.
  ///
  /// The complete assembly remains durable until the matching reply or
  /// revision-zero TR3 handoff is independently committed. This allows
  /// fragments to arrive out of order and across process restarts.
  Future<V3ApplicationHandshakeInboundResult> receiveHandshakeFrame({
    required V3LmfFrame frame,
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode expectedMode,
    Set<String> excludedHandshakeIds = const <String>{},
    String? maximumRemoteDeviceId,
    String? Function()? maximumRemoteDeviceIdResolver,
    Future<void> Function(V3CompletedHandshakeSession session)?
        onSessionEstablished,
    DateTime? receivedAt,
  }) {
    return _serialized(() async {
      final excluded = _effectiveExcludedHandshakeIds(excludedHandshakeIds);
      final pinnedDeviceId =
          maximumRemoteDeviceIdResolver?.call() ?? maximumRemoteDeviceId;
      final handshakeId = _id(frame.metadata.sessionId);
      if (excluded.contains(handshakeId)) {
        throw const FormatException('Layergram v3 handshake was reset');
      }
      final outcome = await _scope.handshakeInbox.receive(
        frame: frame,
        receivedAt: receivedAt,
      );
      final assembly = outcome.assembly;
      if (assembly == null) {
        return V3ApplicationHandshakeInboundResult(
          status: outcome.status,
          assemblyId: null,
        );
      }

      late final ({
        V3ApplicationHandshakeExport? outbound,
        V3ApplicationSessionBinding? session,
      }) processed;
      try {
        processed = await _processHandshakeAssembly(
          assembly: assembly,
          remoteIdentity: remoteIdentity,
          expectedMode: expectedMode,
          excludedHandshakeIds: excluded,
          maximumRemoteDeviceId: pinnedDeviceId,
          receivedAt: receivedAt,
        );
      } catch (error) {
        if (_isTerminalHandshakeCandidateFailure(error)) {
          await _scope.handshakeInbox.discard(assembly.assemblyId);
        }
        rethrow;
      }
      final established = processed.session;
      if (established != null && onSessionEstablished != null) {
        final sessionId = established.sessionIdBytes;
        try {
          await onSessionEstablished(await _completedSessionForId(sessionId));
        } finally {
          _wipe(sessionId);
        }
      }
      await _scope.handshakeInbox.commit(
        assembly.assemblyId,
        committedAt: receivedAt,
      );
      return V3ApplicationHandshakeInboundResult(
        status: outcome.status,
        assemblyId: assembly.assemblyId,
        outbound: processed.outbound,
        session: processed.session,
      );
    });
  }

  /// Rebuilds the deterministic outer frames from a durable pending outbound
  /// or initiator completion tombstone. No handshake or ratchet crypto reruns.
  Future<V3ApplicationHandshakeExport?> retryHandshake({
    required String handshakeId,
    required V3PublicIdentity remoteIdentity,
  }) {
    return _serialized(() async {
      var outbound = await _scope.handshakes.pendingOutboundForId(handshakeId);
      outbound ??=
          await _scope.handshakes.completedConfirmationForId(handshakeId);
      if (outbound == null) return null;
      final localIsResponder = outbound.kind == V3HandshakeRecordKind.reply;
      return _sealOutbound(
        outbound,
        initiatorIdentity:
            localIsResponder ? remoteIdentity : localIdentity.publicIdentity,
        responderIdentity:
            localIsResponder ? localIdentity.publicIdentity : remoteIdentity,
      );
    });
  }

  /// Returns the newest exact pending setup export for this installation and
  /// peer, or null when a new offer is required.
  Future<V3ApplicationHandshakeExport?> pendingHandshakeForRemoteIdentity({
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode mode,
    Set<String> excludedHandshakeIds = const <String>{},
  }) {
    return _serialized(() async {
      var outbound = await _scope.handshakes.latestPendingOutboundForPeer(
        localIdentity: localIdentity,
        localDevice: _localDevice,
        remoteIdentity: remoteIdentity,
        mode: mode,
        excludedHandshakeIds:
            _effectiveExcludedHandshakeIds(excludedHandshakeIds),
      );
      outbound ??= await _scope.handshakes.latestCompletedConfirmationForPeer(
        localIdentity: localIdentity,
        localDevice: _localDevice,
        remoteIdentity: remoteIdentity,
        mode: mode,
        excludedHandshakeIds:
            _effectiveExcludedHandshakeIds(excludedHandshakeIds),
      );
      if (outbound == null) return null;
      final localIsResponder = outbound.kind == V3HandshakeRecordKind.reply;
      return _sealOutbound(
        outbound,
        initiatorIdentity:
            localIsResponder ? remoteIdentity : localIdentity.publicIdentity,
        responderIdentity:
            localIsResponder ? localIdentity.publicIdentity : remoteIdentity,
      );
    });
  }

  /// Returns every completed device session bound to [remoteIdentity].
  /// Normal mode may return multiple device IDs; Maximum mode is enforced as
  /// an exclusive pair by the durable handshake controller.
  Future<List<V3CompletedHandshakeSession>> sessionsForRemoteIdentity(
    V3PublicIdentity remoteIdentity,
  ) {
    return _serialized(() => _sessionsForRemoteIdentity(remoteIdentity));
  }

  /// Captures every pending and completed handshake for one contact and
  /// persists the new policy while this runtime's transition authority is
  /// held. IDs are also denied locally before persistence, so an ambiguous
  /// write cannot reopen them in the current process.
  Future<T> commitContactPolicyBoundary<T>({
    required V3PublicIdentity remoteIdentity,
    required Future<T> Function(Set<String> handshakeIds) persist,
  }) {
    return _serialized(() async {
      final ids = await _handshakeIdsForRemoteIdentity(remoteIdentity);
      _locallyExcludedHandshakeIds.addAll(ids);
      return persist(Set<String>.unmodifiable(ids));
    });
  }

  /// Persists the first empty policy only if this contact has no durable
  /// setup or completed session. Missing policy beside existing state is a
  /// recovery condition, never an implicit default generation.
  Future<T> initializeContactPolicy<T>({
    required V3PublicIdentity remoteIdentity,
    required Future<T> Function() persist,
  }) {
    return _serialized(() async {
      if ((await _handshakeIdsForRemoteIdentity(remoteIdentity)).isNotEmpty) {
        throw StateError('Layergram v3 contact policy requires recovery');
      }
      return persist();
    });
  }

  FsSecurityMode protocolV3ModeForIdentity(V3PublicIdentity remoteIdentity) {
    return _contactPolicyService.getModeSync(
      contactId: remoteIdentity.identityId,
      identityContext: localIdentity.publicIdentity.identityId,
    );
  }

  V3SessionEligibilityPolicy? protocolV3EligibilityForIdentity(
    V3PublicIdentity remoteIdentity,
  ) {
    return protocolV3EligibilityForIdentityId(remoteIdentity.identityId);
  }

  V3SessionEligibilityPolicy? protocolV3EligibilityForIdentityId(
    String remoteIdentityId,
  ) {
    return _contactPolicyService.getV3SessionEligibilitySync(
      contactId: remoteIdentityId,
      identityContext: localIdentity.publicIdentity.identityId,
    );
  }

  Future<V3SessionEligibilityPolicy> ensureProtocolV3ContactPolicy({
    required V3PublicIdentity remoteIdentity,
    required FsSecurityMode mode,
  }) {
    return initializeContactPolicy(
      remoteIdentity: remoteIdentity,
      persist: () => _contactPolicyService.ensureProtocolV3Policy(
        contactId: remoteIdentity.identityId,
        identityContext: localIdentity.publicIdentity.identityId,
        mode: mode,
      ),
    );
  }

  Future<void> setProtocolV3ContactMode({
    required V3PublicIdentity remoteIdentity,
    required FsSecurityMode mode,
  }) {
    return commitContactPolicyBoundary<void>(
      remoteIdentity: remoteIdentity,
      persist: (handshakeIds) => _contactPolicyService.setProtocolV3Mode(
        contactId: remoteIdentity.identityId,
        identityContext: localIdentity.publicIdentity.identityId,
        mode: mode,
        existingHandshakeIds: handshakeIds,
      ),
    );
  }

  Future<V3SessionEligibilityPolicy> pinProtocolV3MaximumDevice({
    required V3PublicIdentity remoteIdentity,
    required String remoteDeviceId,
  }) {
    return _contactPolicyService.pinProtocolV3MaximumDevice(
      contactId: remoteIdentity.identityId,
      identityContext: localIdentity.publicIdentity.identityId,
      remoteDeviceId: remoteDeviceId,
    );
  }

  /// Resolves only non-secret handshake routing metadata for a session frame.
  /// Application routing bindings are session-specific, so the UI must not
  /// guess a contact from the public identity routing used by HP3 frames.
  Future<V3CompletedHandshakeSession?> completedSessionForFrame(
    V3LmfFrame frame,
  ) {
    return _serialized(() async {
      final sessionId = frame.metadata.sessionId;
      try {
        if (!await _scope.hasSession(sessionId)) return null;
        return _completedSessionForId(sessionId);
      } finally {
        _wipe(sessionId);
      }
    });
  }

  Future<V3ApplicationMessageExport> sendMessageToIdentity({
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode expectedMode,
    required Uint8List plaintext,
    V3LmfFrameKind kind = V3LmfFrameKind.application,
    int expiresAtUnixSeconds = 0,
    DateTime? persistedAt,
    Set<String>? excludedHandshakeIds,
    String? maximumRemoteDeviceId,
    String? Function()? maximumRemoteDeviceIdResolver,
  }) {
    return _serialized(
      () => _sendMessageToIdentity(
        remoteIdentity: remoteIdentity,
        expectedMode: expectedMode,
        plaintext: plaintext,
        kind: kind,
        expiresAtUnixSeconds: expiresAtUnixSeconds,
        persistedAt: persistedAt,
        excludedHandshakeIds: excludedHandshakeIds,
        maximumRemoteDeviceId:
            maximumRemoteDeviceIdResolver?.call() ?? maximumRemoteDeviceId,
      ),
    );
  }

  /// Encodes one canonical AP3 user message and commits the same logical
  /// payload independently to every selected remote-device ratchet.
  Future<V3ApplicationMessageExport> sendApplicationMessageToIdentity({
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode expectedMode,
    required String text,
    String? senderDisplayName,
    int? timestampUnixSeconds,
    int? expireAfterUnixSeconds,
    bool deleteAfterRead = false,
    bool backupExcluded = false,
    DateTime? persistedAt,
    Set<String>? excludedHandshakeIds,
    String? maximumRemoteDeviceId,
    String? Function()? maximumRemoteDeviceIdResolver,
  }) {
    return _serialized(() async {
      final messageId = _newRandomId(V3ApplicationPayloadCodec.messageIdBytes);
      final senderDigest = _identityDigestBytes(localIdentity.publicIdentity);
      final recipientDigest = _identityDigestBytes(remoteIdentity);
      Uint8List? encoded;
      try {
        final payload = V3ApplicationPayload(
          messageId: messageId,
          senderIdentityDigest: senderDigest,
          recipientIdentityDigest: recipientDigest,
          text: text,
          timestampUnixSeconds: timestampUnixSeconds ??
              DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000,
          senderDisplayName:
              senderDisplayName ?? localIdentity.publicIdentity.displayName,
          expireAfterUnixSeconds: expireAfterUnixSeconds,
          deleteAfterRead: deleteAfterRead,
          backupExcluded: backupExcluded,
        );
        encoded = V3ApplicationPayloadCodec.encode(payload);
        return await _sendMessageToIdentity(
          remoteIdentity: remoteIdentity,
          expectedMode: expectedMode,
          plaintext: encoded,
          kind: V3LmfFrameKind.application,
          expiresAtUnixSeconds: expireAfterUnixSeconds ?? 0,
          persistedAt: persistedAt,
          excludedHandshakeIds: excludedHandshakeIds,
          maximumRemoteDeviceId:
              maximumRemoteDeviceIdResolver?.call() ?? maximumRemoteDeviceId,
        );
      } finally {
        _wipe(messageId);
        _wipe(senderDigest);
        _wipe(recipientDigest);
        if (encoded != null) _wipe(encoded);
      }
    });
  }

  /// Completes any group interrupted before all per-device ratchets committed,
  /// then returns only exact frames that still await authenticated ACKs.
  Future<List<V3ApplicationMessageExport>> pendingMessageExports() {
    return _serialized(() async {
      final exports = <V3ApplicationMessageExport>[];
      for (final group in await _scope.pendingSendGroups()) {
        final export = await _resumeSendGroup(group);
        if (export.frames.isEmpty) {
          if (await _isSendGroupFullyAcknowledged(group)) {
            await _scope.deleteReadySendGroup(group.groupId);
          }
        } else {
          exports.add(export);
        }
      }
      return List.unmodifiable(exports);
    });
  }

  /// Imports one decoded carrier frame for this installation.
  ///
  /// Frames for another device in the same Normal-mode carrier are ignored
  /// before persistence. A complete authenticated message is committed to AR3
  /// and TR3 before its AP3 payload or durable exact-byte ACK is returned.
  Future<V3ApplicationMessageInboundResult> receiveApplicationFrame({
    required V3LmfFrame frame,
    DateTime? receivedAt,
    int? nowUnixSeconds,
    V3HandshakeMode? expectedMode,
    Set<String>? excludedHandshakeIds,
    String? maximumRemoteDeviceId,
    String? Function()? maximumRemoteDeviceIdResolver,
  }) {
    return _serialized(() async {
      final sessionId = frame.metadata.sessionId;
      try {
        if (!await _scope.hasSession(sessionId)) {
          return const V3ApplicationMessageInboundResult(
            status: V3ApplicationInboundStatus.notForThisInstallation,
          );
        }
      } finally {
        _wipe(sessionId);
      }

      if (frame.metadata.kind == V3LmfFrameKind.acknowledgement) {
        final status = await _scope.applySendAcknowledgement(
          acknowledgementFrame: frame,
          receivedAt: receivedAt,
        );
        await _collectAcknowledgedSendGroups();
        return V3ApplicationMessageInboundResult(
          status: V3ApplicationInboundStatus.acknowledgementApplied,
          sendAcknowledgementStatus: status,
        );
      }
      if (frame.metadata.kind != V3LmfFrameKind.application) {
        throw const FormatException(
          'Layergram v3 frame is not an application message or ACK',
        );
      }

      if (expectedMode != null) {
        final targetSessionId = frame.metadata.sessionId;
        try {
          final target = await _completedSessionForId(targetSessionId);
          final samePeer = (await _scope.handshakes.completedSessions())
              .where(
                (session) =>
                    session.remoteIdentityDigest == target.remoteIdentityDigest,
              )
              .toList(growable: false);
          if (!_isInboundSessionEligible(
            target,
            samePeer,
            expectedMode: expectedMode,
            excludedHandshakeIds:
                _effectiveExcludedHandshakeIds(excludedHandshakeIds),
            maximumRemoteDeviceId:
                maximumRemoteDeviceIdResolver?.call() ?? maximumRemoteDeviceId,
          )) {
            return const V3ApplicationMessageInboundResult(
              status: V3ApplicationInboundStatus.notForThisInstallation,
            );
          }
        } on StateError {
          return const V3ApplicationMessageInboundResult(
            status: V3ApplicationInboundStatus.notForThisInstallation,
          );
        } finally {
          _wipe(targetSessionId);
        }
      }

      final accepted = await _scope.receiveFrame(
        frame: frame,
        receivedAt: receivedAt,
        nowUnixSeconds: nowUnixSeconds,
      );
      var delivery = accepted.delivery;
      var inboxStatus = accepted.status;
      if (delivery == null &&
          accepted.status != V3LmfInboxStatus.committedReplay) {
        final assemblyId = V3LmfFrameCodec.assemblyId(frame);
        // After a restart, persisted continuations can sort before the sealed
        // fragment zero that recreates their in-memory ratchet candidate. The
        // first pass restores that candidate; the second accepts any earlier
        // continuations. Scope the retries to this carrier assembly so an
        // unrelated delayed message is never surfaced by the wrong GUI action.
        for (var pass = 0; pass < 2 && delivery == null; pass++) {
          final resumed = await _scope.resumeDeferred(
            nowUnixSeconds: nowUnixSeconds,
            onlyAssemblyId: assemblyId,
          );
          for (final candidate in resumed.deliveries) {
            if (candidate.assemblyId == assemblyId) {
              delivery = candidate;
              inboxStatus = V3LmfInboxStatus.complete;
              break;
            }
          }
          if (resumed.deferredFrames == 0) break;
        }
      }
      if (delivery == null) {
        V3LmfFrame? acknowledgementFrame;
        if (accepted.status == V3LmfInboxStatus.committedReplay &&
            accepted.acknowledgement != null) {
          acknowledgementFrame = await _scope.acknowledgementFor(
            targetFrame: frame,
            acknowledgement: accepted.acknowledgement!,
            createdAt: receivedAt,
          );
        }
        return V3ApplicationMessageInboundResult(
          status: accepted.status == V3LmfInboxStatus.committedReplay
              ? V3ApplicationInboundStatus.committedReplay
              : V3ApplicationInboundStatus.pending,
          inboxStatus: inboxStatus,
          acknowledgementFrame: acknowledgementFrame,
        );
      }

      V3ApplicationPayload? payload;
      var payloadDecoded = false;
      var payloadIsValid = false;
      final plaintext = delivery.plaintext;
      try {
        try {
          payload = V3ApplicationPayloadCodec.decode(plaintext);
          payloadDecoded = true;
          final session = await _completedSessionForId(
            delivery.frames.first.metadata.sessionId,
          );
          final sender = payload.senderIdentityDigest;
          final recipient = payload.recipientIdentityDigest;
          try {
            payloadIsValid = _id(sender) == session.remoteIdentityDigest &&
                _id(recipient) == session.localIdentityDigest;
          } finally {
            _wipe(sender);
            _wipe(recipient);
          }
        } on FormatException {
          payload = null;
        } on ArgumentError {
          payload = null;
        }
      } finally {
        _wipe(plaintext);
      }

      await _scope.preflightAcknowledgementFor(delivery.frames.first);
      await _scope.commitDelivery(
        delivery: delivery,
        persistedAt: receivedAt,
      );
      final acknowledgementFrame = await _scope.acknowledgementFor(
        targetFrame: delivery.frames.first,
        acknowledgement: delivery.completeAcknowledgement,
        createdAt: receivedAt,
      );
      if (!payloadIsValid || payload == null) {
        return V3ApplicationMessageInboundResult(
          status: payloadDecoded
              ? V3ApplicationInboundStatus.identityMismatch
              : V3ApplicationInboundStatus.invalidPayload,
          inboxStatus: inboxStatus,
          acknowledgementFrame: acknowledgementFrame,
        );
      }
      final now = nowUnixSeconds ??
          DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
      final expired = payload.expireAfterUnixSeconds != null &&
          payload.expireAfterUnixSeconds! < now;
      return V3ApplicationMessageInboundResult(
        status: expired
            ? V3ApplicationInboundStatus.expired
            : V3ApplicationInboundStatus.delivered,
        inboxStatus: inboxStatus,
        payload: expired ? null : payload,
        acknowledgementFrame: acknowledgementFrame,
      );
    });
  }

  Future<V3ApplicationMessageInboundResult> receiveApplicationCarrier({
    required String carrier,
    DateTime? receivedAt,
    int? nowUnixSeconds,
  }) {
    final decoded = V3ApplicationTransport.decode(carrier);
    return receiveApplicationFrame(
      frame: decoded.frame,
      receivedAt: receivedAt,
      nowUnixSeconds: nowUnixSeconds,
    );
  }

  Future<List<V3LmfFrame>> pendingAcknowledgementFrames() =>
      _serialized(_scope.pendingAcknowledgementFrames);

  /// Reconciles the encrypted canonical AR3 source into active chat metadata.
  ///
  /// The repository receives no v3 plaintext. Repeating this after a crash is
  /// idempotent because AP3 supplies one stable logical message ID shared by
  /// every independently encrypted Normal-mode device copy.
  Future<V3ApplicationProjectionResult> reconcileMessageRepository({
    required MessagesRepositoryCore messagesRepository,
    required String? keyTag,
    int? nowUnixSeconds,
  }) {
    return _serialized(() async {
      final projector = await _applicationProjector(
        messagesRepository: messagesRepository,
        keyTag: keyTag,
      );
      try {
        return await projector.reconcile(nowUnixSeconds: nowUnixSeconds);
      } finally {
        projector.close();
      }
    });
  }

  /// Loads one v3 message body on demand from encrypted canonical AR3 state.
  Future<String?> loadProjectedPlaintext({
    required MessagesRepositoryCore messagesRepository,
    required String messageRecordId,
    required String? keyTag,
  }) {
    return _serialized(() async {
      final projector = await _applicationProjector(
        messagesRepository: messagesRepository,
        keyTag: keyTag,
      );
      try {
        return await projector.loadPlaintext(messageRecordId);
      } finally {
        projector.close();
      }
    });
  }

  /// Durably marks a v3 projection read before updating chat metadata.
  Future<V3ApplicationProjectionResult> markProjectedMessageRead({
    required MessagesRepositoryCore messagesRepository,
    required String messageRecordId,
    required String? keyTag,
    DateTime? readAt,
  }) {
    return _serialized(() async {
      await _scope.markProjectedMessageRead(
        messageRecordId: messageRecordId,
        readAt: readAt,
      );
      final projector = await _applicationProjector(
        messagesRepository: messagesRepository,
        keyTag: keyTag,
      );
      try {
        return await projector.reconcile();
      } finally {
        projector.close();
      }
    });
  }

  /// Durably tombstones a v3 projection before removing chat metadata.
  Future<V3ApplicationProjectionResult> deleteProjectedMessage({
    required MessagesRepositoryCore messagesRepository,
    required String messageRecordId,
    required String? keyTag,
    DateTime? deletedAt,
  }) {
    return _serialized(() async {
      await _scope.markProjectedMessageDeleted(
        messageRecordId: messageRecordId,
        deletedAt: deletedAt,
      );
      final projector = await _applicationProjector(
        messagesRepository: messagesRepository,
        keyTag: keyTag,
      );
      try {
        final result = await projector.reconcile();
        await _scope.collectDeletedApplicationRecords();
        return result;
      } finally {
        projector.close();
      }
    });
  }

  Future<void> deleteAcknowledgementsOlderThan(DateTime cutoff) => _serialized(
        () => _scope.deleteAcknowledgementsOlderThan(cutoff),
      );

  Future<V3ApplicationMessageProjector> _applicationProjector({
    required MessagesRepositoryCore messagesRepository,
    required String? keyTag,
  }) async {
    final presentationStates = await _scope.presentationStates();
    final classificationsBySessionId = <String, FsMessageClassification>{};
    for (final session in await _scope.handshakes.completedSessions()) {
      classificationsBySessionId[session.sessionId] =
          session.mode == V3HandshakeMode.maximum
              ? FsMessageClassification.strictFs
              : FsMessageClassification.fsOnly;
    }
    return V3ApplicationMessageProjector(
      messagesRepository: messagesRepository,
      localIdentity: localIdentity.publicIdentity,
      recordLoader: _scope.applicationRecordBytesForProjection,
      keyTag: keyTag,
      presentationStates: presentationStates,
      classificationsBySessionId: classificationsBySessionId,
    );
  }

  Future<void> markMessageExported(
    V3ApplicationMessageExport export, {
    DateTime? exportedAt,
  }) {
    return _serialized(() async {
      for (final target in export.targets) {
        if (target.frames.isEmpty) continue;
        await _scope.markSendExported(
          assemblyId: target.assemblyId,
          fragmentIndexes:
              target.frames.map((frame) => frame.fragmentIndex).toSet(),
          exportedAt: exportedAt,
        );
      }
    });
  }

  Future<void> markMessagePartExported(
    V3ApplicationMessageExport export, {
    required String assemblyId,
    required int fragmentIndex,
    DateTime? exportedAt,
  }) {
    return _serialized(() async {
      final targets = export.targets
          .where((target) => target.assemblyId == assemblyId)
          .toList(growable: false);
      if (targets.length != 1 ||
          !targets.single.frames
              .any((frame) => frame.fragmentIndex == fragmentIndex)) {
        throw ArgumentError(
          'Layergram v3 export does not contain the selected carrier part',
        );
      }
      await _scope.markSendExported(
        assemblyId: assemblyId,
        fragmentIndexes: <int>{fragmentIndex},
        exportedAt: exportedAt,
      );
    });
  }

  Future<V3SessionSendResult> sendMessage({
    required Uint8List sessionId,
    required int expectedRevision,
    required Uint8List plaintext,
    V3LmfFrameKind kind = V3LmfFrameKind.application,
    int expiresAtUnixSeconds = 0,
    DateTime? persistedAt,
  }) =>
      _serialized(
        () => _scope.sendMessage(
          sessionId: sessionId,
          expectedRevision: expectedRevision,
          plaintext: plaintext,
          kind: kind,
          expiresAtUnixSeconds: expiresAtUnixSeconds,
          persistedAt: persistedAt,
        ),
      );

  Future<V3SessionInboundFrameResult> receiveSessionFrame({
    required V3LmfFrame frame,
    DateTime? receivedAt,
    int? nowUnixSeconds,
  }) =>
      _serialized(
        () => _scope.receiveFrame(
          frame: frame,
          receivedAt: receivedAt,
          nowUnixSeconds: nowUnixSeconds,
        ),
      );

  Future<V3SessionCommitResult> commitSessionDelivery({
    required V3LmfDurableDelivery delivery,
    DateTime? persistedAt,
  }) =>
      _serialized(
        () => _scope.commitDelivery(
          delivery: delivery,
          persistedAt: persistedAt,
        ),
      );

  Future<V3LmfInboxRestoreResult> resumeDeferredSessionFrames({
    int? nowUnixSeconds,
  }) =>
      _serialized(
        () => _scope.resumeDeferred(nowUnixSeconds: nowUnixSeconds),
      );

  Future<List<V3LmfFrame>> pendingSendFrames(String assemblyId) =>
      _serialized(() => _scope.pendingSendFrames(assemblyId));

  Future<V3LmfOutboxEntry> markSendExported({
    required String assemblyId,
    required Set<int> fragmentIndexes,
    DateTime? exportedAt,
  }) =>
      _serialized(
        () => _scope.markSendExported(
          assemblyId: assemblyId,
          fragmentIndexes: fragmentIndexes,
          exportedAt: exportedAt,
        ),
      );

  Future<V3LmfOutboxAckStatus> applySendAcknowledgement({
    required V3LmfFrame acknowledgementFrame,
    DateTime? receivedAt,
  }) =>
      _serialized(
        () async {
          final status = await _scope.applySendAcknowledgement(
            acknowledgementFrame: acknowledgementFrame,
            receivedAt: receivedAt,
          );
          await _collectAcknowledgedSendGroups();
          return status;
        },
      );

  Future<V3TripleRatchetState> snapshotForSession(Uint8List sessionId) =>
      _serialized(() => _scope.snapshotForSession(sessionId));

  Future<V3SessionCompactionResult> compactSession(Uint8List sessionId) =>
      _serialized(() => _scope.compactSession(sessionId));

  /// Opportunistically compacts durable effects and retires only proofs whose
  /// local Normal/Maximum retention window has elapsed.
  ///
  /// The pass stores no global last-run marker, so opening a hidden passphrase
  /// scope does not leave a new enumerable trace. Pending inbox fragments,
  /// unacknowledged outbox frames, and exact ACK exports are never time-purged.
  Future<V3ApplicationRetentionMaintenanceResult> maintainRetainedState({
    required DateTime now,
  }) {
    return _serialized(() async {
      final sessions = await _scope.handshakes.completedSessions();
      final modeBySession = <String, V3HandshakeMode>{};
      var compactedSessions = 0;
      var collectedIncomingEffects = 0;
      var collectedOutgoingEffects = 0;
      var replayWindowEntries = 0;
      for (final session in sessions) {
        final existing = modeBySession[session.sessionId];
        if (existing != null && existing != session.mode) {
          throw const V3LmfPersistenceConflictException(
            'Layergram v3 session has conflicting retention profiles',
          );
        }
        modeBySession[session.sessionId] = session.mode;
      }
      final sessionKeys = modeBySession.keys.toList(growable: false)..sort();
      for (final sessionKey in sessionKeys) {
        final sessionId = _decodeCanonicalId(sessionKey, 16);
        try {
          final compacted = await _scope.compactSession(sessionId);
          compactedSessions++;
          collectedIncomingEffects += compacted.collectedIncomingEffects;
          collectedOutgoingEffects += compacted.collectedOutgoingEffects;
          replayWindowEntries += compacted.replayWindowEntries;
        } finally {
          _wipe(sessionId);
        }
      }

      final candidates = await _scope.receiptRetentionCandidates();
      var retiredReceipts = 0;
      for (final candidate in candidates) {
        final mode = modeBySession[candidate.sessionKey];
        if (mode == null) {
          throw const V3LmfPersistenceConflictException(
            'Layergram v3 checkpoint has no completed handshake binding',
          );
        }
        final result = await _scope.replaceEligibleCheckpointReceipt(
          assemblyId: candidate.assemblyId,
          policy: V3RetentionPolicy.forProfile(
            mode == V3HandshakeMode.maximum
                ? V3RetentionProfile.maximum
                : V3RetentionProfile.normal,
          ),
          now: now,
        );
        if (result.checkpointWasReplaced) retiredReceipts++;
      }
      final collectedDeletedApplicationRecords =
          await _scope.collectDeletedApplicationRecords();
      return V3ApplicationRetentionMaintenanceResult(
        compactedSessions: compactedSessions,
        collectedIncomingEffects: collectedIncomingEffects,
        collectedOutgoingEffects: collectedOutgoingEffects,
        replayWindowEntries: replayWindowEntries,
        examinedReceipts: candidates.length,
        retiredReceipts: retiredReceipts,
        collectedDeletedApplicationRecords: collectedDeletedApplicationRecords,
      );
    });
  }

  Future<V3SessionReceiptRetirementResult> replaceEligibleCheckpointReceipt({
    required String assemblyId,
    required V3RetentionPolicy policy,
    required DateTime now,
  }) =>
      _serialized(
        () => _scope.replaceEligibleCheckpointReceipt(
          assemblyId: assemblyId,
          policy: policy,
          now: now,
        ),
      );

  @override
  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      try {
        await _scope.close();
      } finally {
        try {
          _contactPolicyRepository.setActiveContext(
            scopeToken: null,
            auxStorageKey: null,
          );
          _contactPolicyStorageKey.destroy();
        } finally {
          _localDevice.close();
        }
      }
    }, allowClosed: true);
  }

  Future<
      ({
        V3ApplicationHandshakeExport? outbound,
        V3ApplicationSessionBinding? session,
      })> _processHandshakeAssembly({
    required V3HandshakeFrameAssembly assembly,
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode expectedMode,
    required Set<String> excludedHandshakeIds,
    String? maximumRemoteDeviceId,
    DateTime? receivedAt,
  }) async {
    final counter = assembly.frames.first.metadata.messageCounter;
    final remoteIsInitiator = counter == 0 || counter == 2;
    final opened = await V3HandshakeTransport.open(
      frames: assembly.frames,
      initiatorIdentity:
          remoteIsInitiator ? remoteIdentity : localIdentity.publicIdentity,
      responderIdentity:
          remoteIsInitiator ? localIdentity.publicIdentity : remoteIdentity,
    );
    try {
      if (counter == 0) {
        final offer = opened.decodeOffer();
        _validateMaximumRemoteDevice(
          expectedMode: expectedMode,
          maximumRemoteDeviceId: maximumRemoteDeviceId,
          remoteDeviceId: offer.initiatorDeviceId,
        );
        final outbound = await _scope.handshakes.createReply(
          localIdentity: localIdentity,
          localDevice: _localDevice,
          initiatorIdentity: remoteIdentity,
          offer: offer,
          expectedMode: expectedMode,
          excludedHandshakeIds: excludedHandshakeIds,
          createdAt: receivedAt,
        );
        return (
          outbound: await _sealOutbound(
            outbound,
            initiatorIdentity: remoteIdentity,
            responderIdentity: localIdentity.publicIdentity,
          ),
          session: null,
        );
      }

      if (counter == 1) {
        final reply = opened.decodeReply();
        if (reply.mode != expectedMode) {
          throw const FormatException(
            'Layergram v3 handshake security mode mismatch',
          );
        }
        _validateMaximumRemoteDevice(
          expectedMode: expectedMode,
          maximumRemoteDeviceId: maximumRemoteDeviceId,
          remoteDeviceId: reply.responderDeviceId,
        );
        final handshakeId = _id(reply.handshakeId);
        final stateDigest =
            await _scope.handshakes.stateDigestForId(handshakeId);
        if (stateDigest == null) {
          throw StateError(
            'Layergram v3 initiator pending state was not found',
          );
        }
        final handoff = await _scope.handoffs.completeInitiator(
          handshakeId: handshakeId,
          expectedStateDigest: stateDigest,
          localIdentity: localIdentity,
          localDevice: _localDevice,
          responderIdentity: remoteIdentity,
          reply: reply,
          preparedAt: receivedAt,
          completedAt: receivedAt,
        );
        final confirmationRecord = handoff.confirmationRecord;
        try {
          final outbound = V3DurableHandshakeOutbound(
            handshakeId: handoff.handshakeId,
            kind: V3HandshakeRecordKind.confirmation,
            messageId: _confirmationMessageId(confirmationRecord),
            stateDigest: stateDigest,
            outboundRecord: confirmationRecord,
            restored: handoff.recovered,
          );
          final session = _binding(handoff);
          return (
            outbound: await _sealOutbound(
              outbound,
              initiatorIdentity: localIdentity.publicIdentity,
              responderIdentity: remoteIdentity,
              session: session,
            ),
            session: session,
          );
        } finally {
          _wipe(confirmationRecord);
        }
      }

      if (counter == 2) {
        final confirmation = opened.decodeConfirmation();
        if (confirmation.mode != expectedMode) {
          throw const FormatException(
            'Layergram v3 handshake security mode mismatch',
          );
        }
        _validateMaximumRemoteDevice(
          expectedMode: expectedMode,
          maximumRemoteDeviceId: maximumRemoteDeviceId,
          remoteDeviceId: confirmation.initiatorDeviceId,
        );
        final handshakeId = _id(confirmation.handshakeId);
        final stateDigest =
            await _scope.handshakes.stateDigestForId(handshakeId);
        if (stateDigest == null) {
          throw StateError(
            'Layergram v3 responder pending state was not found',
          );
        }
        final handoff = await _scope.handoffs.completeResponder(
          handshakeId: handshakeId,
          expectedStateDigest: stateDigest,
          initiatorIdentity: remoteIdentity,
          responderIdentity: localIdentity.publicIdentity,
          confirmation: confirmation,
          preparedAt: receivedAt,
          completedAt: receivedAt,
        );
        return (outbound: null, session: _binding(handoff));
      }

      throw const FormatException(
        'Invalid Layergram v3 handshake frame counter',
      );
    } finally {
      opened.close();
    }
  }

  Future<V3ApplicationHandshakeExport> _sealOutbound(
    V3DurableHandshakeOutbound outbound, {
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
    V3ApplicationSessionBinding? session,
  }) async {
    final record = Uint8List.fromList(outbound.outboundRecord);
    try {
      final frames = await V3HandshakeTransport.seal(
        record: record,
        initiatorIdentity: initiatorIdentity,
        responderIdentity: responderIdentity,
      );
      return V3ApplicationHandshakeExport(
        handshakeId: outbound.handshakeId,
        kind: outbound.kind,
        frames: frames,
        restored: outbound.restored,
        session: session,
      );
    } finally {
      _wipe(record);
    }
  }

  Future<V3ApplicationMessageExport> _sendMessageToIdentity({
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode expectedMode,
    required Uint8List plaintext,
    required V3LmfFrameKind kind,
    required int expiresAtUnixSeconds,
    DateTime? persistedAt,
    Set<String>? excludedHandshakeIds,
    String? maximumRemoteDeviceId,
  }) async {
    final sessions = await _sessionsForRemoteIdentity(remoteIdentity);
    final selected = _selectDeviceSessions(
      sessions,
      expectedMode: expectedMode,
      excludedHandshakeIds:
          _effectiveExcludedHandshakeIds(excludedHandshakeIds),
      maximumRemoteDeviceId: maximumRemoteDeviceId,
    );
    final revisions = <String, int>{};
    for (final session in selected) {
      final sessionId = _decodeCanonicalId(session.sessionId, 16);
      V3TripleRatchetState? snapshot;
      try {
        snapshot = await _scope.snapshotForSession(sessionId);
        if (snapshot.lifecycle != V3RatchetLifecycle.active) {
          throw StateError('Layergram v3 session is not active');
        }
        revisions[session.sessionId] = snapshot.revision;
      } finally {
        snapshot?.wipeSecrets();
        _wipe(sessionId);
      }
    }
    final group = await _scope.createSendGroup(
      plaintext: plaintext,
      kind: kind,
      expiresAtUnixSeconds: expiresAtUnixSeconds,
      targetExpectedRevisions: revisions,
      createdAt: persistedAt,
    );
    return _resumeSendGroup(group, persistedAt: persistedAt);
  }

  Future<List<V3CompletedHandshakeSession>> _sessionsForRemoteIdentity(
    V3PublicIdentity remoteIdentity,
  ) async {
    final digest = _identityDigest(remoteIdentity);
    return (await _scope.handshakes.completedSessions())
        .where((session) => session.remoteIdentityDigest == digest)
        .toList(growable: false);
  }

  Future<Set<String>> _handshakeIdsForRemoteIdentity(
    V3PublicIdentity remoteIdentity,
  ) async =>
      <String>{
        for (final session in await _sessionsForRemoteIdentity(remoteIdentity))
          session.handshakeId,
        ...await _scope.handshakes.pendingHandshakeIdsForPeer(
          localIdentity: localIdentity,
          localDevice: _localDevice,
          remoteIdentity: remoteIdentity,
        ),
      };

  Future<V3CompletedHandshakeSession> _completedSessionForId(
    Uint8List sessionId,
  ) async {
    final encoded = _id(sessionId);
    final matches = (await _scope.handshakes.completedSessions())
        .where((session) => session.sessionId == encoded)
        .toList(growable: false);
    if (matches.length != 1) {
      throw const V3LmfPersistenceConflictException(
        'Layergram v3 session has no unique handshake binding',
      );
    }
    return matches.single;
  }

  List<V3CompletedHandshakeSession> _selectDeviceSessions(
    List<V3CompletedHandshakeSession> sessions, {
    required V3HandshakeMode expectedMode,
    Set<String>? excludedHandshakeIds,
    String? maximumRemoteDeviceId,
  }) {
    final eligible = sessions
        .where(
          (session) =>
              session.mode == expectedMode &&
              (excludedHandshakeIds == null ||
                  !excludedHandshakeIds.contains(session.handshakeId)),
        )
        .toList(growable: false);
    if (eligible.isEmpty) {
      throw StateError('Layergram v3 contact requires a completed handshake');
    }
    if (expectedMode == V3HandshakeMode.maximum) {
      final deviceId = maximumRemoteDeviceId;
      if (deviceId == null) {
        throw StateError(
          'Maximum-mode Layergram v3 device pin is unavailable',
        );
      }
      final deviceSessions = eligible
          .where((session) => session.remoteDeviceId == deviceId)
          .toList(growable: false);
      if (deviceSessions.isEmpty) {
        throw StateError('Maximum-mode Layergram v3 device is unavailable');
      }
      deviceSessions.sort(
        (left, right) => right.handshakeId.compareTo(left.handshakeId),
      );
      return List.unmodifiable(
        <V3CompletedHandshakeSession>[deviceSessions.first],
      );
    }
    final newestByDevice = <String, V3CompletedHandshakeSession>{};
    for (final session in eligible) {
      final existing = newestByDevice[session.remoteDeviceId];
      if (existing == null ||
          session.handshakeId.compareTo(existing.handshakeId) > 0) {
        newestByDevice[session.remoteDeviceId] = session;
      }
    }
    final selected = newestByDevice.values.toList(growable: false)
      ..sort(
          (left, right) => left.remoteDeviceId.compareTo(right.remoteDeviceId));
    if (selected.length > maxNormalDeviceTargetsPerMessage) {
      throw const V3LmfPersistenceLimitException(
        'v3 Normal-mode device capacity exceeded',
      );
    }
    return List.unmodifiable(selected);
  }

  bool _isInboundSessionEligible(
    V3CompletedHandshakeSession target,
    List<V3CompletedHandshakeSession> samePeer, {
    required V3HandshakeMode expectedMode,
    required Set<String> excludedHandshakeIds,
    String? maximumRemoteDeviceId,
  }) {
    if (target.mode != expectedMode ||
        excludedHandshakeIds.contains(target.handshakeId)) {
      return false;
    }
    if (expectedMode == V3HandshakeMode.normal) return true;
    if (maximumRemoteDeviceId == null) return false;
    final eligibleDeviceIds = samePeer
        .where(
          (session) =>
              session.mode == expectedMode &&
              !excludedHandshakeIds.contains(session.handshakeId),
        )
        .map((session) => session.remoteDeviceId)
        .toSet()
        .toList(growable: false)
      ..sort();
    if (eligibleDeviceIds.isEmpty) return false;
    return target.remoteDeviceId == maximumRemoteDeviceId;
  }

  Future<V3ApplicationMessageExport> _resumeSendGroup(
    V3ApplicationSendGroup group, {
    DateTime? persistedAt,
  }) async {
    var current = group;
    final plaintext = current.plaintext;
    try {
      for (final target in group.targets) {
        if (target.isCommitted) continue;
        final sessionId = _decodeCanonicalId(target.sessionId, 16);
        try {
          final recovered = await _scope.pendingSendForTransition(
            sessionId: sessionId,
            previousRatchetRevision: target.expectedRevision,
          );
          late final String assemblyId;
          late final int ratchetRevision;
          if (recovered != null) {
            assemblyId = recovered.assemblyId;
            ratchetRevision = recovered.ratchetRevision;
          } else {
            final sent = await _scope.sendMessage(
              sessionId: sessionId,
              expectedRevision: target.expectedRevision,
              plaintext: plaintext,
              kind: current.kind,
              expiresAtUnixSeconds: current.expiresAtUnixSeconds,
              persistedAt: persistedAt,
            );
            assemblyId = sent.assemblyId;
            ratchetRevision = sent.ratchetRevision;
          }
          current = await _scope.markSendGroupTargetCommitted(
            groupId: current.groupId,
            sessionId: target.sessionId,
            assemblyId: assemblyId,
            ratchetRevision: ratchetRevision,
            updatedAt: persistedAt,
          );
        } finally {
          _wipe(sessionId);
        }
      }
    } finally {
      _wipe(plaintext);
    }
    if (!current.isReady) {
      throw StateError('Layergram v3 send group is not ready for export');
    }
    final targets = <V3ApplicationMessageTargetExport>[];
    for (final target in current.targets) {
      final frames = await _scope.pendingSendFrames(target.assemblyId!);
      targets.add(
        V3ApplicationMessageTargetExport(
          sessionId: target.sessionId,
          assemblyId: target.assemblyId!,
          ratchetRevision: target.committedRevision!,
          frames: frames,
        ),
      );
    }
    return V3ApplicationMessageExport(
      groupId: current.groupId,
      targets: targets,
    );
  }

  Future<bool> _isSendGroupFullyAcknowledged(
    V3ApplicationSendGroup group,
  ) async {
    if (!group.isReady) return false;
    for (final target in group.targets) {
      final sessionId = _decodeCanonicalId(target.sessionId, 16);
      try {
        final binding = await _scope.pendingSendForTransition(
          sessionId: sessionId,
          previousRatchetRevision: target.expectedRevision,
        );
        if (binding == null ||
            binding.assemblyId != target.assemblyId ||
            !binding.isFullyAcknowledged) {
          return false;
        }
      } finally {
        _wipe(sessionId);
      }
    }
    return true;
  }

  Future<void> _collectAcknowledgedSendGroups() async {
    for (final group in await _scope.pendingSendGroups()) {
      if (await _isSendGroupFullyAcknowledged(group)) {
        await _scope.deleteReadySendGroup(group.groupId);
      }
    }
  }

  V3ApplicationSessionBinding _binding(
    V3HandshakeSessionHandoffResult handoff,
  ) {
    return V3ApplicationSessionBinding(
      handshakeId: handoff.handshakeId,
      sessionId: handoff.sessionId,
      checkpointDigest: handoff.checkpointDigest,
      role: handoff.role,
      recovered: handoff.recovered,
    );
  }

  Future<T> _serialized<T>(
    Future<T> Function() operation, {
    bool allowClosed = false,
  }) {
    final completer = Completer<T>();
    final previous = _operationTail;
    _operationTail = previous.catchError((_) {}).then((_) async {
      try {
        if (_closed && !allowClosed) {
          throw StateError('Layergram v3 application runtime is closed');
        }
        completer.complete(await operation());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  Set<String> _effectiveExcludedHandshakeIds(Set<String>? persisted) =>
      Set<String>.unmodifiable(<String>{
        ..._locallyExcludedHandshakeIds,
        ...?persisted,
      });

  void _validateMaximumRemoteDevice({
    required V3HandshakeMode expectedMode,
    required String? maximumRemoteDeviceId,
    required Uint8List remoteDeviceId,
  }) {
    try {
      if (expectedMode == V3HandshakeMode.maximum &&
          maximumRemoteDeviceId != null &&
          _id(remoteDeviceId) != maximumRemoteDeviceId) {
        throw const FormatException(
          'Maximum-mode Layergram v3 peer device does not match the pin',
        );
      }
    } finally {
      _wipe(remoteDeviceId);
    }
  }

  bool _isTerminalHandshakeCandidateFailure(Object error) {
    if (error is FormatException ||
        error is ArgumentError ||
        error is SecretBoxAuthenticationError) {
      return true;
    }
    if (error is! StateError) return false;
    final message = error.message;
    return message == 'Layergram v3 initiator pending state was not found' ||
        message == 'Layergram v3 responder pending state was not found';
  }
}

String _id(Uint8List value) => base64UrlEncode(value).replaceAll('=', '');

String _identityDigest(V3PublicIdentity identity) {
  final bytes = _identityDigestBytes(identity);
  try {
    return _id(bytes);
  } finally {
    _wipe(bytes);
  }
}

Uint8List _identityDigestBytes(V3PublicIdentity identity) => Uint8List.fromList(
      crypto.sha384.convert(identity.identityBindingBytes).bytes,
    );

final Random _secureRandom = Random.secure();

Uint8List _newRandomId(int length) {
  for (var attempt = 0; attempt < 16; attempt++) {
    final bytes = Uint8List.fromList(
      List<int>.generate(length, (_) => _secureRandom.nextInt(256)),
    );
    if (bytes.any((byte) => byte != 0)) return bytes;
    _wipe(bytes);
  }
  throw StateError('Unable to allocate a Layergram v3 identifier');
}

String _confirmationMessageId(Uint8List record) {
  final confirmation = V3HandshakeCodec.decodeConfirmation(record);
  final messageId = confirmation.messageId;
  try {
    return _id(messageId);
  } finally {
    _wipe(messageId);
  }
}

Uint8List _decodeCanonicalId(String value, int expectedLength) {
  late final Uint8List decoded;
  try {
    decoded = Uint8List.fromList(
      base64Url.decode(base64Url.normalize(value)),
    );
  } on FormatException {
    throw const FormatException('Invalid Layergram v3 identifier');
  }
  if (decoded.length != expectedLength || _id(decoded) != value) {
    _wipe(decoded);
    throw const FormatException('Invalid Layergram v3 identifier');
  }
  return decoded;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
