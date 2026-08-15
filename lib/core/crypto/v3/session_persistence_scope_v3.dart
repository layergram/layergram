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

import 'package:cryptography/cryptography.dart';

import '../../storage/aux_record_repository.dart';
import 'committed_record_materializer_v3.dart';
import 'handshake_persistence_v3.dart';
import 'handshake_session_handoff_v3.dart';
import 'initial_session_handoff_authority_v3.dart';
import 'lmf_v3_atomic_commit.dart';
import 'lmf_v3_outbox.dart';
import 'lmf_v3_persistence.dart';
import 'session_checkpoint_v3.dart';
import 'session_commit_controller_v3.dart';
import 'session_send_journal_v3.dart';
import 'session_retirement_journal_v3.dart';
import 'triple_ratchet_state_v3.dart';

/// Result of restoring one complete encrypted protocol-v3 persistence scope.
final class V3SessionPersistenceRestoreResult {
  const V3SessionPersistenceRestoreResult({
    required this.inbox,
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

  /// Durable pending offer/reply state restored before any new handshake
  /// cryptography or export is allowed.
  final V3HandshakeControllerRestoreResult handshakes;

  /// Reconstructed send/receive session state and durable application state.
  final V3SessionCommitRestoreResult sessions;

  /// Prepared initial sessions recovered only after both durable controllers
  /// have restored their authoritative state.
  final V3HandshakeSessionHandoffRestoreResult handoffs;
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
/// This is storage wiring only. It does not register a provider, select a
/// native SCKA backend, import v3 into the active identity path, or enable v3
/// messaging in production.
final class V3SessionPersistenceScope {
  V3SessionPersistenceScope._({
    required AuxRecordRepository repository,
    required SecretKeyData ownedAuxStorageKey,
    required this.inbox,
    required this.handshakes,
    required this.controller,
    required this.handoffs,
  })  : _repository = repository,
        _ownedAuxStorageKey = ownedAuxStorageKey;

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
        snapshotValidator: snapshotValidator,
        maxSessions: maxSessions,
      );
      final handoffs = V3HandshakeSessionHandoffController(
        repository: V3HandshakeHandoffRepository(store: store),
        handshakes: handshakes,
        sessions: controller,
        initialHandoffAuthority: initialHandoffAuthority,
      );
      return V3SessionPersistenceScope._(
        repository: repository,
        ownedAuxStorageKey: ownedKey,
        inbox: inbox,
        handshakes: handshakes,
        controller: controller,
        handoffs: handoffs,
      );
    } catch (_) {
      ownedKey.destroy();
      rethrow;
    }
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

  /// Persist-first sealed receive boundary for the pinned scope.
  ///
  /// The journals and backing store intentionally remain private. The future
  /// active transport may feed canonical frames here, but every application or
  /// ratchet commit must go through [controller].
  final V3LmfDurableInbox inbox;

  /// Sole authority for pending hybrid-handshake persistence and exact resend.
  final V3HandshakePersistenceController handshakes;

  /// Sole authority for durable session transitions and outgoing exports.
  final V3SessionCommitController controller;

  /// Sole serialized path from authenticated HP3 state to an initial durable
  /// TR3 checkpoint and completion tombstone.
  final V3HandshakeSessionHandoffController handoffs;

  Future<void> _operationTail = Future<void>.value();
  bool _restoreStarted = false;
  bool _restored = false;
  bool _closed = false;
  bool _recoveryRequired = false;

  bool get isRestored => _restored;
  bool get requiresRecovery =>
      _recoveryRequired ||
      handshakes.requiresRecovery ||
      controller.requiresRecovery ||
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
        final inboxResult = await inbox.restore(keyResolver: (_) => null);
        final handshakeResult = await handshakes.restore();
        final sessionResult = await controller.restore(
          checkpoints: checkpoints,
        );
        final handoffResult = await handoffs.restore();
        _restored = true;
        return V3SessionPersistenceRestoreResult(
          inbox: inboxResult,
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

  /// Resolves sealed frames only after the durable session truth is restored.
  Future<V3LmfInboxRestoreResult> resumeDeferred({
    required V3LmfFrameKeyResolver keyResolver,
    V3LmfFrameAuthenticationFailureHandler? onAuthenticationFailure,
  }) {
    return _serialized(() async {
      _ensureReady();
      return inbox.resumeDeferred(
        keyResolver: keyResolver,
        onAuthenticationFailure: onAuthenticationFailure,
      );
    });
  }

  /// Drains and closes every owned component before releasing the pinned key.
  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      try {
        await handoffs.close();
      } finally {
        try {
          await handshakes.close();
        } finally {
          try {
            await controller.close();
          } finally {
            try {
              await inbox.close();
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
