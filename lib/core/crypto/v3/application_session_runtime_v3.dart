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
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../../storage/aux_record_repository.dart';
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

/// Application-facing owner of one protocol-v3 identity/passphrase scope.
///
/// This is the only layer allowed to combine the installation device key,
/// durable HP3 controller, HP3-to-TR3 handoff and session inbox/outbox. It
/// deliberately does not own [localIdentity]; the process-level identity
/// runtime closes that handle only after this runtime has drained.
final class V3ApplicationSessionRuntime {
  V3ApplicationSessionRuntime._({
    required this.localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3SessionPersistenceScope scope,
    required this.restoreResult,
  })  : _localDevice = localDevice,
        _scope = scope;

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
  }) async {
    if (localIdentity.isClosed) {
      throw StateError('Layergram v3 local identity is closed');
    }

    final derivedKey = await localIdentity.deriveAuxStorageKey();
    final extractedKey = await derivedKey.extract();
    final deviceRepository = AuxRecordRepository();
    V3LocalDeviceHandle? device;
    V3SessionPersistenceScope? scope;
    try {
      deviceRepository.setActiveContext(
        scopeToken: scopeToken,
        auxStorageKey: extractedKey,
      );
      device = await V3DeviceKeyRepository(
        store: V3LmfAuxRecordStore(deviceRepository),
      ).loadOrCreate();
      scope = await V3SessionPersistenceScope.open(
        scopeToken: scopeToken,
        auxStorageKey: extractedKey,
        sckaBackend: sckaBackend,
        snapshotValidator: snapshotValidator,
        maxSessions: maxSessions,
      );
      final restored = await scope.restore(
        checkpoints: bootstrapCheckpoints,
      );
      return V3ApplicationSessionRuntime._(
        localIdentity: localIdentity,
        localDevice: device,
        scope: scope,
        restoreResult: restored,
      );
    } catch (_) {
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
  final V3SessionPersistenceRestoreResult restoreResult;

  Future<void> _operationTail = Future<void>.value();
  bool _closed = false;

  bool get requiresRecovery => _scope.requiresRecovery;

  Uint8List get localDeviceId => _localDevice.deviceId;

  /// Starts or durably retries an offer before returning exportable frames.
  Future<V3ApplicationHandshakeExport> createOffer({
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode mode,
    DateTime? createdAt,
  }) {
    return _serialized(() async {
      final outbound = await _scope.handshakes.createOffer(
        localIdentity: localIdentity,
        localDevice: _localDevice,
        remoteIdentity: remoteIdentity,
        mode: mode,
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
    DateTime? receivedAt,
  }) {
    return _serialized(() async {
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

      final processed = await _processHandshakeAssembly(
        assembly: assembly,
        remoteIdentity: remoteIdentity,
        expectedMode: expectedMode,
        receivedAt: receivedAt,
      );
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
        () => _scope.applySendAcknowledgement(
          acknowledgementFrame: acknowledgementFrame,
          receivedAt: receivedAt,
        ),
      );

  Future<V3TripleRatchetState> snapshotForSession(Uint8List sessionId) =>
      _serialized(() => _scope.snapshotForSession(sessionId));

  Future<V3SessionCompactionResult> compactSession(Uint8List sessionId) =>
      _serialized(() => _scope.compactSession(sessionId));

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

  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      try {
        await _scope.close();
      } finally {
        _localDevice.close();
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
        final outbound = await _scope.handshakes.createReply(
          localIdentity: localIdentity,
          localDevice: _localDevice,
          initiatorIdentity: remoteIdentity,
          offer: offer,
          expectedMode: expectedMode,
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
}

String _id(Uint8List value) => base64UrlEncode(value).replaceAll('=', '');

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
