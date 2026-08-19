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
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../../storage/aux_record_repository.dart';
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
/// A complete delivery is still candidate-only until [V3SessionPersistenceScope]
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

/// Inactive, scope-pinned owner of the complete protocol-v3 durable runtime.
///
/// The active v2 application uses a mutable singleton [AuxRecordRepository]. A
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
/// receive resolver. It does not register that provider, connect the inactive
/// Rust ABI, import v3 into the active identity path, or enable v3 messaging in
/// production.
final class V3SessionPersistenceScope {
  V3SessionPersistenceScope._({
    required AuxRecordRepository repository,
    required SecretKeyData ownedAuxStorageKey,
    required V3LmfDurableInbox inbox,
    required this.handshakeInbox,
    required this.handshakes,
    required V3SessionCommitController controller,
    required this.handoffs,
    required V3SessionRatchetKeyResolver ratchetKeyResolver,
  })  : _repository = repository,
        _ownedAuxStorageKey = ownedAuxStorageKey,
        _inbox = inbox,
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
  }) async {
    if (!_isCanonicalScopeToken(scopeToken)) {
      throw ArgumentError.value(
        scopeToken,
        'scopeToken',
        'must be the canonical 16-character base64url identity token',
      );
    }
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
      final inbox = V3LmfDurableInbox(store: store);
      final handshakeInbox = V3HandshakeFrameInbox(store: store);
      final handshakes = V3HandshakePersistenceController(
        repository: V3HandshakePendingRepository(store: store),
        initialHandoffAuthority: initialHandoffAuthority,
      );
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
      );
      return V3SessionPersistenceScope._(
        repository: repository,
        ownedAuxStorageKey: ownedKey,
        inbox: inbox,
        handshakeInbox: handshakeInbox,
        handshakes: handshakes,
        controller: controller,
        handoffs: handoffs,
        ratchetKeyResolver: ratchetKeyResolver,
      );
    } catch (_) {
      ownedKey.destroy();
      rethrow;
    }
  }

  /// Opens the complete durable scope with the packaged SCKA candidate.
  ///
  /// This is the intended application-facing packaged-library boundary. The
  /// backend is created inside the scope and cannot be swapped between restore,
  /// send, receive, handoff, or commit. Protocol v3 remains inactive until a
  /// separately reviewed application bootstrap calls this method.
  static Future<V3SessionPersistenceScope> openPackagedScka({
    required String scopeToken,
    required SecretKey auxStorageKey,
    V3SessionSnapshotValidator? snapshotValidator,
    int maxSessions = 4096,
  }) {
    return open(
      scopeToken: scopeToken,
      auxStorageKey: auxStorageKey,
      sckaBackend: V3SckaCandidateFfiBackend.openPackaged(),
      snapshotValidator: snapshotValidator,
      maxSessions: maxSessions,
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
        final sessionResult = await _controller.restore(
          checkpoints: checkpoints,
        );
        final handoffResult = await handoffs.restore();
        _restored = true;
        return V3SessionPersistenceRestoreResult(
          inbox: inboxResult,
          handshakeInbox: handshakeInboxResult,
          handshakes: handshakeResult,
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
  }) {
    return _serialized(() async {
      _ensureReady();
      return _inbox.resumeDeferred(
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

  Future<List<V3LmfFrame>> pendingSendFrames(String assemblyId) {
    return _serialized(() async {
      _ensureReady();
      return _controller.pendingSendFrames(assemblyId);
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

  Future<V3SessionCompactionResult> compactSession(Uint8List sessionId) {
    return _serialized(() async {
      _ensureReady();
      return _controller.compactSession(sessionId);
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
              await handshakes.close();
            } finally {
              try {
                await _controller.close();
              } finally {
                try {
                  await _inbox.close();
                } finally {
                  _repository.setActiveContext(
                    scopeToken: null,
                    auxStorageKey: null,
                  );
                  _ownedAuxStorageKey.destroy();
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
