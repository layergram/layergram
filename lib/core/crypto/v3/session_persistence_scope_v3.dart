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

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../../storage/aux_record_repository.dart';
import 'acknowledgement_outbox_v3.dart';
import 'application_send_group_v3.dart';
import 'application_presentation_state_v3.dart';
import 'committed_record_materializer_v3.dart';
import 'handshake_frame_inbox_v3.dart';
import 'handshake_persistence_v3.dart';
import 'handshake_session_handoff_v3.dart';
import 'initial_session_handoff_authority_v3.dart';
import 'lmf_v3.dart';
import 'lmf_v3_atomic_commit.dart';
import 'lmf_v3_acknowledgement.dart';
import 'lmf_v3_outbox.dart';
import 'lmf_v3_persistence.dart';
import 'retention_policy_v3.dart';
import 'scka_candidate_ffi.dart';
import 'session_checkpoint_v3.dart';
import 'session_commit_controller_v3.dart';
import 'session_ratchet_key_resolver_v3.dart';
import 'session_retention_binding_v3.dart';
import 'session_send_journal_v3.dart';
import 'session_retirement_journal_v3.dart';
import 'sparse_pq_ratchet_v3.dart';
import 'triple_ratchet_state_v3.dart';

/// Result of restoring one complete encrypted protocol-v3 persistence scope.
final class V3SessionPersistenceRestoreResult {
  const V3SessionPersistenceRestoreResult({
    required this.inbox,
    required this.handshakeInbox,
    required this.handshakes,
    required this.sendGroups,
    required this.acknowledgements,
    required this.presentation,
    required this.sessions,
    required this.handoffs,
  });

  /// Sealed transport state restored before any session key is requested.
  ///
  /// Every uncommitted frame is deliberately reported as deferred. After the
  /// session controller is ready, the future active integration may construct
  /// its reviewed SCKA-backed resolver and call
  /// [V3SessionPersistenceScope.resumeDeferred].
  final V3LmfInboxRestoreResult inbox;

  /// Public bootstrap frames persisted before HP3 authentication.
  final V3HandshakeFrameInboxRestoreResult handshakeInbox;

  /// Durable pending offer/reply state restored before any new handshake
  /// cryptography or export is allowed.
  final V3HandshakeControllerRestoreResult handshakes;

  /// Logical multi-device sends restored before any new export is created.
  final V3ApplicationSendGroupRestoreResult sendGroups;

  /// Exact sealed ACK frames retained independently of carrier delivery.
  final V3AcknowledgementOutboxRestoreResult acknowledgements;

  /// Durable read/delete state for AR3-backed chat projections.
  final V3ApplicationPresentationRestoreResult presentation;

  /// Reconstructed send/receive session state and durable application state.
  final V3SessionCommitRestoreResult sessions;

  /// Prepared initial sessions recovered only after both durable controllers
  /// have restored their authoritative state.
  final V3HandshakeSessionHandoffRestoreResult handoffs;
}

/// One scope-owned inbound transport result.
///
/// A null acknowledgement means the exact sealed frame was retained because
/// fragment zero (and therefore its ratchet candidate) is not available yet.
/// A complete delivery is not authoritative until [V3SessionPersistenceScope]
/// commits it through the pinned resolver/controller pair.
final class V3SessionInboundFrameResult {
  const V3SessionInboundFrameResult({
    required this.status,
    required this.acknowledgement,
    required this.delivery,
  });

  final V3LmfInboxStatus status;
  final V3LmfAcknowledgement? acknowledgement;
  final V3LmfDurableDelivery? delivery;

  bool get isComplete => status == V3LmfInboxStatus.complete;
}

/// Scope-pinned owner of the complete protocol-v3 durable runtime.
///
/// The retained v2 application path uses a mutable singleton
/// [AuxRecordRepository]. A
/// protocol-v3 controller cannot safely retain that singleton across identity
/// or passphrase changes: a later context switch could otherwise redirect an
/// open journal to a different storage key. This owner instead creates one
/// dedicated repository, pins it to exactly one encrypted scope, and keeps all
/// transport stores, send/receive/retirement journals, materializers, and
/// checkpoints private behind one [V3SessionCommitController].
///
/// [open] copies and owns the supplied auxiliary key. [close] releases the
/// repository context and destroys that owned copy after all journal and inbox
/// operations have drained. The caller remains responsible for closing this
/// object before an identity/passphrase context is expelled.
///
/// Opening the scope admits and pins exactly one caller-selected SCKA backend
/// across restore validation, initial handoff, durable send, and its owned
/// receive resolver. Registration remains owned by the application lifecycle,
/// which reaches this scope only through the all-or-nothing activation policy.
final class V3SessionPersistenceScope {
  V3SessionPersistenceScope._({
    required String scopeToken,
    required Object scopeLease,
    required AuxRecordRepository repository,
    required SecretKeyData ownedAuxStorageKey,
    required V3LmfDurableInbox inbox,
    required this.handshakeInbox,
    required this.handshakes,
    required V3ApplicationSendGroupJournal sendGroups,
    required V3AcknowledgementOutbox acknowledgements,
    required V3ApplicationPresentationJournal presentation,
    required V3SessionCommitController controller,
    required this.handoffs,
    required V3SessionRatchetKeyResolver ratchetKeyResolver,
  })  : _scopeToken = scopeToken,
        _scopeLease = scopeLease,
        _repository = repository,
        _ownedAuxStorageKey = ownedAuxStorageKey,
        _inbox = inbox,
        _sendGroups = sendGroups,
        _acknowledgements = acknowledgements,
        _presentation = presentation,
        _controller = controller,
        _ratchetKeyResolver = ratchetKeyResolver;

  /// Opens a dedicated view of the real encrypted Aux/Hive storage.
  ///
  /// [scopeToken] is the same canonical 16-character base64url identity
  /// namespace used by the active message repository. [auxStorageKey] must be
  /// derived from the effective primary or passphrase identity secret with
  /// [AuxRecordCipher]; this method copies it so destroying this scope never
  /// destroys caller-owned material.
  static Future<V3SessionPersistenceScope> open({
    required String scopeToken,
    required SecretKey auxStorageKey,
    required V3SckaBackend sckaBackend,
    V3SessionSnapshotValidator? snapshotValidator,
    int maxSessions = 4096,
    int maxInboxPersistedFrames = 256,
    int maxInboxPersistedFrameBytes = 128 * 1024,
    int maxAcknowledgementEntries = 4096,
    int maxAcknowledgementTotalBytes = 4 * 1024 * 1024,
    // Direct-controller tests can inject checkpoints without an HP3 binding.
    // Application code uses [openPackagedScka], which exposes no override.
    int? testOnlySkippedKeyLifetimeSeconds,
  }) async {
    if (!_isCanonicalScopeToken(scopeToken)) {
      throw ArgumentError.value(
        scopeToken,
        'scopeToken',
        'must be the canonical 16-character base64url identity token',
      );
    }
    final scopeLease = _claimScopeLease(scopeToken);
    try {
      await V3SparsePqRatchet.ensureBackendReady(sckaBackend);

      final extractedKey = await auxStorageKey.extract();
      late final SecretKeyData ownedKey;
      try {
        if (extractedKey.bytes.length != 32) {
          throw ArgumentError.value(
            extractedKey.bytes.length,
            'auxStorageKey',
            'must contain exactly 32 bytes',
          );
        }
        ownedKey = extractedKey.copy();
      } finally {
        if (!identical(extractedKey, auxStorageKey)) {
          extractedKey.destroy();
        }
      }
      try {
        final repository = AuxRecordRepository();
        repository.setActiveContext(
          scopeToken: scopeToken,
          auxStorageKey: ownedKey,
        );
        final store = V3LmfAuxRecordStore(repository);
        final initialHandoffAuthority = V3InitialSessionHandoffAuthority();
        final inbox = V3LmfDurableInbox(
          store: store,
          maxPersistedFrames: maxInboxPersistedFrames,
          maxPersistedFrameBytes: maxInboxPersistedFrameBytes,
        );
        final handshakeInbox = V3HandshakeFrameInbox(store: store);
        final handshakes = V3HandshakePersistenceController(
          repository: V3HandshakePendingRepository(store: store),
          initialHandoffAuthority: initialHandoffAuthority,
        );
        final sendGroups = V3ApplicationSendGroupJournal(store: store);
        final acknowledgements = V3AcknowledgementOutbox(
          store: store,
          maxEntries: maxAcknowledgementEntries,
          maxTotalBytes: maxAcknowledgementTotalBytes,
          partitionResolver: (frame) =>
              _acknowledgementPartitionFor(handshakes, frame),
        );
        final presentation = V3ApplicationPresentationJournal(store: store);
        final controller = V3SessionCommitController(
          journal: V3LmfAtomicCommitJournal(store: store, inbox: inbox),
          sendJournal: V3SessionSendJournal(store: store),
          outbox: V3LmfDurableOutbox(store: store),
          committedRecordMaterializer:
              V3CommittedRecordMaterializer(store: store),
          checkpointRepository: V3SessionCheckpointRepository(
            store: store,
            maxSessions: maxSessions,
          ),
          retirementJournal: V3SessionRetirementJournal(store: store),
          initialHandoffAuthority: initialHandoffAuthority,
          sckaBackend: sckaBackend,
          snapshotValidator: snapshotValidator,
          maxSessions: maxSessions,
        );
        final handoffs = V3HandshakeSessionHandoffController(
          repository: V3HandshakeHandoffRepository(store: store),
          handshakes: handshakes,
          sessions: controller,
          initialHandoffAuthority: initialHandoffAuthority,
          sckaBackend: sckaBackend,
        );
        final ratchetKeyResolver = V3SessionRatchetKeyResolver(
          backend: sckaBackend,
          controller: controller,
          skippedKeyLifetimeSeconds: testOnlySkippedKeyLifetimeSeconds,
          skippedKeyLifetimeResolver: testOnlySkippedKeyLifetimeSeconds == null
              ? (sessionId) async {
                  return V3SessionRetentionBinding.skippedKeyLifetimeSeconds(
                    sessionId: sessionId,
                    completedSessions: await handshakes.completedSessions(),
                  );
                }
              : null,
        );
        return V3SessionPersistenceScope._(
          scopeToken: scopeToken,
          scopeLease: scopeLease,
          repository: repository,
          ownedAuxStorageKey: ownedKey,
          inbox: inbox,
          handshakeInbox: handshakeInbox,
          handshakes: handshakes,
          sendGroups: sendGroups,
          acknowledgements: acknowledgements,
          presentation: presentation,
          controller: controller,
          handoffs: handoffs,
          ratchetKeyResolver: ratchetKeyResolver,
        );
      } catch (_) {
        ownedKey.destroy();
        rethrow;
      }
    } catch (_) {
      _releaseScopeLease(scopeToken, scopeLease);
      rethrow;
    }
  }

  /// Opens the complete durable scope with the packaged SCKA backend.
  ///
  /// This is the intended application-facing packaged-library boundary. The
  /// backend is created inside the scope and cannot be swapped between restore,
  /// send, receive, handoff, or commit. Official bootstrap calls this method
  /// only after every production activation decision is true.
  static Future<V3SessionPersistenceScope> openPackagedScka({
    required String scopeToken,
    required SecretKey auxStorageKey,
    V3SessionSnapshotValidator? snapshotValidator,
    int maxSessions = 4096,
    int maxInboxPersistedFrames = 256,
    int maxInboxPersistedFrameBytes = 128 * 1024,
    int maxAcknowledgementEntries = 4096,
    int maxAcknowledgementTotalBytes = 4 * 1024 * 1024,
  }) {
    return open(
      scopeToken: scopeToken,
      auxStorageKey: auxStorageKey,
      sckaBackend: V3SckaCandidateFfiBackend.openPackaged(),
      snapshotValidator: snapshotValidator,
      maxSessions: maxSessions,
      maxInboxPersistedFrames: maxInboxPersistedFrames,
      maxInboxPersistedFrameBytes: maxInboxPersistedFrameBytes,
      maxAcknowledgementEntries: maxAcknowledgementEntries,
      maxAcknowledgementTotalBytes: maxAcknowledgementTotalBytes,
    );
  }

  static bool _isCanonicalScopeToken(String value) {
    if (value.length != 16) return false;
    for (final codeUnit in value.codeUnits) {
      final isUppercase = codeUnit >= 0x41 && codeUnit <= 0x5a;
      final isLowercase = codeUnit >= 0x61 && codeUnit <= 0x7a;
      final isDigit = codeUnit >= 0x30 && codeUnit <= 0x39;
      if (!isUppercase &&
          !isLowercase &&
          !isDigit &&
          codeUnit != 0x2d &&
          codeUnit != 0x5f) {
        return false;
      }
    }
    return true;
  }

  static final Map<String, Object> _activeScopeLeases = <String, Object>{};

  static Object _claimScopeLease(String scopeToken) {
    final lease = Object();
    final existing = _activeScopeLeases.putIfAbsent(scopeToken, () => lease);
    if (!identical(existing, lease)) {
      throw StateError(
        'Layergram v3 persistence scope already has an active owner',
      );
    }
    return lease;
  }

  static void _releaseScopeLease(String scopeToken, Object lease) {
    if (identical(_activeScopeLeases[scopeToken], lease)) {
      _activeScopeLeases.remove(scopeToken);
    }
  }

  final String _scopeToken;
  final Object _scopeLease;
  final AuxRecordRepository _repository;
  final SecretKeyData _ownedAuxStorageKey;

  /// Persist-first sealed receive boundary, hidden behind the scope-owned
  /// resolver/controller composition.
  final V3LmfDurableInbox _inbox;

  /// Persist-first public bootstrap transport, kept separate from the
  /// digest-bound application inbox.
  final V3HandshakeFrameInbox handshakeInbox;

  /// Sole authority for pending hybrid-handshake persistence and exact resend.
  final V3HandshakePersistenceController handshakes;

  /// Higher-level all-device send journal, private behind scope methods.
  final V3ApplicationSendGroupJournal _sendGroups;

  /// Durable exact-byte receiver ACK retry storage.
  final V3AcknowledgementOutbox _acknowledgements;

  /// Durable UI state that prevents retained AR3 from resurrecting messages.
  final V3ApplicationPresentationJournal _presentation;

  /// Sole authority for durable session transitions and outgoing exports.
  /// It remains hidden so receive candidates cannot be committed around the
  /// scope-owned resolver/controller binding.
  final V3SessionCommitController _controller;

  /// Sole serialized path from authenticated HP3 state to an initial durable
  /// TR3 checkpoint and completion tombstone.
  final V3HandshakeSessionHandoffController handoffs;

  /// Scope-owned receive-candidate resolver for this pinned backend and
  /// controller. It is deliberately not exposed to callers.
  final V3SessionRatchetKeyResolver _ratchetKeyResolver;

  int get pendingReceiveCandidateCount =>
      _ratchetKeyResolver.pendingCandidateCount;

  Future<void> _operationTail = Future<void>.value();
  bool _restoreStarted = false;
  bool _restored = false;
  bool _closed = false;
  bool _recoveryRequired = false;

  bool get isRestored => _restored;
  bool get requiresRecovery =>
      _recoveryRequired ||
      handshakeInbox.requiresRecovery ||
      handshakes.requiresRecovery ||
      _sendGroups.requiresRecovery ||
      _acknowledgements.requiresRecovery ||
      _presentation.requiresRecovery ||
      _controller.requiresRecovery ||
      handoffs.requiresRecovery;

  /// Restores sealed transport records and pending HP3 first, then durable TR3
  /// state, and finally every prepared initial-session handoff.
  ///
  /// Inbox keys are intentionally unavailable during the first phase. This
  /// breaks the startup cycle safely: the controller reconstructs the durable
  /// TR3 truth before a future SCKA-backed resolver can derive any receive key.
  /// The caller may then invoke [resumeDeferred].
  Future<V3SessionPersistenceRestoreResult> restore({
    required Iterable<V3TripleRatchetState> checkpoints,
  }) {
    return _serialized(() async {
      _ensureOpen();
      if (_restoreStarted) {
        throw StateError('Layergram v3 persistence scope was restored');
      }
      _restoreStarted = true;
      try {
        final inboxResult = await _inbox.restore(keyResolver: (_) => null);
        final handshakeInboxResult = await handshakeInbox.restore();
        final handshakeResult = await handshakes.restore();
        final sendGroupResult = await _sendGroups.restore();
        final acknowledgementResult = await _acknowledgements.restore();
        final presentationResult = await _presentation.restore();
        final sessionResult = await _controller.restore(
          checkpoints: checkpoints,
        );
        final handoffResult = await handoffs.restore();
        _restored = true;
        return V3SessionPersistenceRestoreResult(
          inbox: inboxResult,
          handshakeInbox: handshakeInboxResult,
          handshakes: handshakeResult,
          sendGroups: sendGroupResult,
          acknowledgements: acknowledgementResult,
          presentation: presentationResult,
          sessions: sessionResult,
          handoffs: handoffResult,
        );
      } catch (_) {
        _recoveryRequired = true;
        rethrow;
      }
    });
  }

  /// Receives one canonical sealed frame through the pinned session resolver.
  ///
  /// Continuations that arrive before fragment zero are retained exactly and
  /// reported as deferred. A first fragment derives only an in-memory
  /// candidate; [_inbox] persists the exact frame before AEAD authentication
  /// or plaintext reassembly. Authentication failure removes both the sealed
  /// candidate frame and its non-authoritative ratchet transition.
  Future<V3SessionInboundFrameResult> receiveFrame({
    required V3LmfFrame frame,
    DateTime? receivedAt,
    int? nowUnixSeconds,
  }) {
    return _serialized(() async {
      _ensureReady();
      final replay = await _inbox.committedReplayFor(frame);
      if (replay != null) {
        return V3SessionInboundFrameResult(
          status: replay.status,
          acknowledgement: replay.acknowledgement,
          delivery: null,
        );
      }
      if (frame.fragmentIndex == 0) {
        await _inbox.preflightAuthenticatedReceive(frame);
      }
      final key = await _ratchetKeyResolver.resolve(
        frame,
        nowUnixSeconds: nowUnixSeconds,
      );
      if (key == null) {
        final deferred = await _inbox.persistDeferred(
          frame: frame,
          receivedAt: receivedAt,
        );
        return V3SessionInboundFrameResult(
          status: deferred.status,
          acknowledgement: deferred.acknowledgement,
          delivery: deferred.delivery,
        );
      }
      final accepted = await _inbox.receive(
        frame: frame,
        secretKey: key,
        receivedAt: receivedAt,
        onAuthenticationFailure:
            _ratchetKeyResolver.discardUnauthenticatedFirstFragment,
      );
      if (accepted.status == V3LmfInboxStatus.committedReplay) {
        await _ratchetKeyResolver.discardUnauthenticatedFirstFragment(frame);
      }
      var delivery = accepted.delivery;
      var acknowledgement = accepted.acknowledgement;
      var status = accepted.status;
      if (delivery == null && frame.fragmentIndex == 0) {
        final assemblyId = V3LmfFrameCodec.assemblyId(frame);
        final resumed = await _inbox.resumeDeferred(
          onlyAssemblyId: assemblyId,
          keyResolver: (candidate) => _ratchetKeyResolver.resolve(
            candidate,
            nowUnixSeconds: nowUnixSeconds,
          ),
          onAuthenticationFailure:
              _ratchetKeyResolver.discardUnauthenticatedFirstFragment,
        );
        for (final candidate in resumed.deliveries) {
          if (candidate.assemblyId == assemblyId) {
            delivery = candidate;
            acknowledgement = candidate.completeAcknowledgement;
            status = V3LmfInboxStatus.complete;
            break;
          }
        }
      }
      return V3SessionInboundFrameResult(
        status: status,
        acknowledgement: acknowledgement,
        delivery: delivery,
      );
    });
  }

  /// Resolves sealed frames only after the durable session truth is restored.
  ///
  /// The caller cannot substitute a key resolver or authentication-failure
  /// handler: both belong to this scope's pinned backend and controller.
  Future<V3LmfInboxRestoreResult> resumeDeferred({
    int? nowUnixSeconds,
    String? onlyAssemblyId,
  }) {
    return _serialized(() async {
      _ensureReady();
      return _inbox.resumeDeferred(
        onlyAssemblyId: onlyAssemblyId,
        keyResolver: (frame) => _ratchetKeyResolver.resolve(
          frame,
          nowUnixSeconds: nowUnixSeconds,
        ),
        onAuthenticationFailure:
            _ratchetKeyResolver.discardUnauthenticatedFirstFragment,
      );
    });
  }

  /// Atomically commits one complete authenticated delivery through the exact
  /// resolver/controller pair created by [open].
  Future<V3SessionCommitResult> commitDelivery({
    required V3LmfDurableDelivery delivery,
    DateTime? persistedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      return _ratchetKeyResolver.commitDelivery(
        delivery: delivery,
        persistedAt: persistedAt,
      );
    });
  }

  /// Commits one outgoing transition through the same pinned backend and
  /// durable controller used by receive and restore.
  Future<V3SessionSendResult> sendMessage({
    required Uint8List sessionId,
    required int expectedRevision,
    required Uint8List plaintext,
    V3LmfFrameKind kind = V3LmfFrameKind.application,
    int expiresAtUnixSeconds = 0,
    DateTime? persistedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      return _controller.sendMessage(
        sessionId: sessionId,
        expectedRevision: expectedRevision,
        plaintext: plaintext,
        kind: kind,
        expiresAtUnixSeconds: expiresAtUnixSeconds,
        persistedAt: persistedAt,
      );
    });
  }

  Future<V3ApplicationSendGroup> createSendGroup({
    required Uint8List plaintext,
    required V3LmfFrameKind kind,
    required int expiresAtUnixSeconds,
    required Map<String, int> targetExpectedRevisions,
    DateTime? createdAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      return _sendGroups.create(
        plaintext: plaintext,
        kind: kind,
        expiresAtUnixSeconds: expiresAtUnixSeconds,
        targetExpectedRevisions: targetExpectedRevisions,
        createdAt: createdAt,
      );
    });
  }

  Future<List<V3ApplicationSendGroup>> pendingSendGroups() {
    return _serialized(() async {
      _ensureReady();
      return _sendGroups.groups();
    });
  }

  Future<V3ApplicationSendGroup> markSendGroupTargetCommitted({
    required String groupId,
    required String sessionId,
    required String assemblyId,
    required int ratchetRevision,
    DateTime? updatedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      return _sendGroups.markCommitted(
        groupId: groupId,
        sessionId: sessionId,
        assemblyId: assemblyId,
        ratchetRevision: ratchetRevision,
        updatedAt: updatedAt,
      );
    });
  }

  Future<void> deleteReadySendGroup(String groupId) {
    return _serialized(() async {
      _ensureReady();
      await _sendGroups.deleteReady(groupId);
    });
  }

  Future<List<V3LmfFrame>> pendingSendFrames(String assemblyId) {
    return _serialized(() async {
      _ensureReady();
      return _controller.pendingSendFrames(assemblyId);
    });
  }

  Future<V3PendingSessionSendBinding?> pendingSendForTransition({
    required Uint8List sessionId,
    required int previousRatchetRevision,
  }) {
    return _serialized(() async {
      _ensureReady();
      return _controller.pendingSendForTransition(
        sessionId: sessionId,
        previousRatchetRevision: previousRatchetRevision,
      );
    });
  }

  Future<V3LmfOutboxEntry> markSendExported({
    required String assemblyId,
    required Set<int> fragmentIndexes,
    DateTime? exportedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      return _controller.markSendExported(
        assemblyId: assemblyId,
        fragmentIndexes: fragmentIndexes,
        exportedAt: exportedAt,
      );
    });
  }

  Future<V3LmfOutboxAckStatus> applySendAcknowledgement({
    required V3LmfFrame acknowledgementFrame,
    DateTime? receivedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      return _controller.applySendAcknowledgement(
        acknowledgementFrame: acknowledgementFrame,
        receivedAt: receivedAt,
      );
    });
  }

  Future<V3TripleRatchetState> snapshotForSession(Uint8List sessionId) {
    return _serialized(() async {
      _ensureReady();
      return _controller.snapshotForSession(sessionId);
    });
  }

  Future<bool> hasSession(Uint8List sessionId) {
    return _serialized(() async {
      _ensureReady();
      return _controller.hasSession(sessionId);
    });
  }

  /// Detached canonical AR3 application records for idempotent chat projection.
  /// Callers own and must overwrite every returned byte array.
  Future<List<Uint8List>> applicationRecordBytesForProjection() {
    return _serialized(() async {
      _ensureReady();
      return _controller.applicationRecordBytesForProjection();
    });
  }

  Future<Map<String, V3ApplicationPresentationState>> presentationStates() {
    return _serialized(() async {
      _ensureReady();
      return _presentation.states();
    });
  }

  Future<V3ApplicationPresentationState> markProjectedMessageRead({
    required String messageRecordId,
    DateTime? readAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      return _presentation.markRead(
        messageRecordId: messageRecordId,
        readAt: readAt,
      );
    });
  }

  Future<V3ApplicationPresentationState> markProjectedMessageDeleted({
    required String messageRecordId,
    DateTime? deletedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      return _presentation.markDeleted(
        messageRecordId: messageRecordId,
        deletedAt: deletedAt,
      );
    });
  }

  Future<int> collectDeletedApplicationRecords() {
    return _serialized(() async {
      _ensureReady();
      final states = await _presentation.states();
      var deletedRecords = 0;
      final deletedMessageIds = states.values
          .where((state) => state.isDeleted)
          .map((state) => state.messageRecordId)
          .toList(growable: false)
        ..sort();
      for (final messageRecordId in deletedMessageIds) {
        final result = await _controller.collectDeletedApplicationMessage(
          messageRecordId,
        );
        deletedRecords += result.deletedRecords;
        if (result.canForgetPresentationState) {
          await _presentation.forgetDeleted(messageRecordId);
        }
      }
      await _controller.collectObsoleteMaterializedDeletionProofs();
      return deletedRecords;
    });
  }

  /// Checks exact ACK capacity before the receive commit advances TR3/AR3.
  Future<void> preflightAcknowledgementFor(V3LmfFrame targetFrame) {
    return _serialized(() async {
      _ensureReady();
      await _acknowledgements.preflightGetOrCreate(
        V3LmfFrameCodec.assemblyId(targetFrame),
        partitionKey:
            await _acknowledgementPartitionFor(handshakes, targetFrame),
      );
    });
  }

  /// Returns an already-durable ACK or seals and persists one before export.
  Future<V3LmfFrame> acknowledgementFor({
    required V3LmfFrame targetFrame,
    required V3LmfAcknowledgement acknowledgement,
    DateTime? createdAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final targetAssemblyId = V3LmfFrameCodec.assemblyId(targetFrame);
      final partitionKey =
          await _acknowledgementPartitionFor(handshakes, targetFrame);
      final entry = await _acknowledgements.getOrCreate(
        targetAssemblyId: targetAssemblyId,
        partitionKey: partitionKey,
        createdAt: createdAt,
        builder: (messageId) => _controller.sealAcknowledgement(
          targetFrame: targetFrame,
          acknowledgement: acknowledgement,
          messageId: messageId,
        ),
      );
      return entry.frame;
    });
  }

  Future<List<V3LmfFrame>> pendingAcknowledgementFrames() {
    return _serialized(() async {
      _ensureReady();
      return List.unmodifiable(
        (await _acknowledgements.entries()).map((entry) => entry.frame),
      );
    });
  }

  Future<void> deleteAcknowledgementsOlderThan(DateTime cutoff) {
    return _serialized(() async {
      _ensureReady();
      await _acknowledgements.deleteOlderThan(cutoff);
    });
  }

  static Future<String> _acknowledgementPartitionFor(
    V3HandshakePersistenceController handshakes,
    V3LmfFrame frame,
  ) async {
    final sessionId = frame.metadata.sessionId;
    try {
      final encodedSessionId = base64UrlEncode(sessionId).replaceAll('=', '');
      final matches = (await handshakes.completedSessions())
          .where((session) => session.sessionId == encodedSessionId)
          .toList(growable: false);
      if (matches.length != 1) {
        throw const V3LmfPersistenceConflictException(
          'Layergram v3 ACK has no unique contact binding',
        );
      }
      return matches.single.remoteIdentityDigest;
    } finally {
      sessionId.fillRange(0, sessionId.length, 0);
    }
  }

  Future<V3SessionCompactionResult> compactSession(Uint8List sessionId) {
    return _serialized(() async {
      _ensureReady();
      return _controller.compactSession(sessionId);
    });
  }

  Future<List<V3SessionReceiptRetentionCandidate>>
      receiptRetentionCandidates() {
    return _serialized(() async {
      _ensureReady();
      return _controller.receiptRetentionCandidates();
    });
  }

  Future<V3SessionReceiptRetirementResult> replaceEligibleCheckpointReceipt({
    required String assemblyId,
    required V3RetentionPolicy policy,
    required DateTime now,
  }) {
    return _serialized(() async {
      _ensureReady();
      return _controller.replaceEligibleCheckpointReceipt(
        assemblyId: assemblyId,
        policy: policy,
        now: now,
      );
    });
  }

  /// Drains and closes every owned component before releasing the pinned key.
  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      try {
        await _ratchetKeyResolver.close();
      } finally {
        try {
          await handoffs.close();
        } finally {
          try {
            await handshakeInbox.close();
          } finally {
            try {
              await _sendGroups.close();
            } finally {
              try {
                await _acknowledgements.close();
              } finally {
                try {
                  await _presentation.close();
                } finally {
                  try {
                    await handshakes.close();
                  } finally {
                    try {
                      await _controller.close();
                    } finally {
                      try {
                        await _inbox.close();
                      } finally {
                        try {
                          _repository.setActiveContext(
                            scopeToken: null,
                            auxStorageKey: null,
                          );
                          _ownedAuxStorageKey.destroy();
                        } finally {
                          _releaseScopeLease(_scopeToken, _scopeLease);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    });
  }

  Future<T> _serialized<T>(Future<T> Function() operation) {
    final completer = Completer<T>();
    final previous = _operationTail;
    _operationTail = previous.catchError((_) {}).then((_) async {
      try {
        completer.complete(await operation());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('Layergram v3 persistence scope is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored || requiresRecovery) {
      throw StateError(
        'Layergram v3 persistence scope must be reconstructed and restored',
      );
    }
  }
}
