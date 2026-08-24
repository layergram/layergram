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

import 'package:crypto/crypto.dart' as crypto;

import 'ec_double_ratchet_v3.dart';
import 'handshake_persistence_v3.dart';
import 'initial_session_handoff_authority_v3.dart';
import 'key_schedule_v3.dart';
import 'lmf_v3_persistence.dart';
import 'local_identity_v3.dart';
import 'pq_message_ratchet_v3.dart';
import 'public_identity_v3.dart';
import 'session_commit_controller_v3.dart';
import 'sparse_pq_ratchet_v3.dart';
import 'triple_ratchet_state_v3.dart';

/// Exact durable preparation for one handshake-to-session transition.
///
/// The encoded TR3 contains secrets and is owned by this object. Production
/// storage must therefore be the encrypted, padded, identity/passphrase-scoped
/// Aux store. The public confirmation is retained beside it so an initiator
/// never regenerates different ratchet material after a crash.
final class V3PreparedHandshakeHandoff {
  V3PreparedHandshakeHandoff._({
    required this.storageId,
    required this.handshakeId,
    required this.role,
    required this.pendingStateDigest,
    required Uint8List confirmationRecord,
    required this.sessionId,
    required Uint8List encodedSnapshot,
    required this.snapshotDigest,
    required this.preparedAt,
    required this.recordDigest,
  })  : _confirmationRecord = Uint8List.fromList(confirmationRecord),
        _encodedSnapshot = Uint8List.fromList(encodedSnapshot);

  final String storageId;
  final String handshakeId;
  final V3SessionRole role;
  final String pendingStateDigest;
  final Uint8List _confirmationRecord;
  final String sessionId;
  final Uint8List _encodedSnapshot;
  final String snapshotDigest;
  final DateTime preparedAt;
  final String recordDigest;

  Uint8List get confirmationRecord => Uint8List.fromList(_confirmationRecord);
  int get retainedBytes => _confirmationRecord.length + _encodedSnapshot.length;

  V3HandshakeConfirmation decodeConfirmation() {
    final copy = confirmationRecord;
    try {
      return V3HandshakeCodec.decodeConfirmation(copy);
    } finally {
      _wipe(copy);
    }
  }

  V3TripleRatchetState decodeSnapshot() {
    final copy = Uint8List.fromList(_encodedSnapshot);
    try {
      return V3TripleRatchetStateCodec.decode(copy);
    } finally {
      _wipe(copy);
    }
  }

  void _close() {
    _wipe(_confirmationRecord);
    _wipe(_encodedSnapshot);
  }
}

/// Non-secret outcome of committing one initial session handoff.
final class V3HandshakeSessionHandoffResult {
  V3HandshakeSessionHandoffResult({
    required this.handshakeId,
    required this.role,
    required Uint8List confirmationRecord,
    required this.sessionId,
    required this.checkpointDigest,
    required this.recovered,
  }) : _confirmationRecord = Uint8List.fromList(confirmationRecord);

  final String handshakeId;
  final V3SessionRole role;
  final Uint8List _confirmationRecord;
  final String sessionId;
  final String checkpointDigest;
  final bool recovered;

  Uint8List get confirmationRecord => Uint8List.fromList(_confirmationRecord);
}

final class V3HandshakeSessionHandoffRestoreResult {
  const V3HandshakeSessionHandoffRestoreResult({
    required this.recoveredHandoffs,
    required this.removedDuplicateRecords,
  });

  final List<V3HandshakeSessionHandoffResult> recoveredHandoffs;
  final int removedDuplicateRecords;
}

final class V3HandshakeHandoffRepositoryRestoreResult {
  const V3HandshakeHandoffRepositoryRestoreResult({
    required this.prepared,
    required this.removedDuplicateRecords,
  });

  final List<V3PreparedHandshakeHandoff> prepared;
  final int removedDuplicateRecords;
}

/// Unforgeable ownership token retained by one handoff coordinator.
final class V3HandshakeHandoffAuthority {
  const V3HandshakeHandoffAuthority._();
}

/// Bounded prepare journal that closes every checkpoint/tombstone crash gap.
final class V3HandshakeHandoffRepository {
  V3HandshakeHandoffRepository({
    required V3LmfRecordStore store,
    this.maxPrepared = 64,
    this.maxStoredRecords = 128,
    this.maxTotalRetainedBytes = 16 * 1024 * 1024,
  }) : _store = store {
    if (maxPrepared <= 0 ||
        maxStoredRecords < maxPrepared ||
        maxTotalRetainedBytes <= 0) {
      throw ArgumentError('Layergram v3 handoff persistence limits invalid');
    }
  }

  static const String recordKind = 'v3_handshake_handoff_v1';
  final V3LmfRecordStore _store;
  final int maxPrepared;
  final int maxStoredRecords;
  final int maxTotalRetainedBytes;
  final Map<String, V3PreparedHandshakeHandoff> _prepared =
      <String, V3PreparedHandshakeHandoff>{};
  Future<void> _operationTail = Future<void>.value();
  V3HandshakeHandoffAuthority? _authority;
  bool _restored = false;
  bool _closed = false;
  bool _writeRecoveryRequired = false;
  int _totalRetainedBytes = 0;

  bool get requiresRecovery => _writeRecoveryRequired;
  int get preparedCount => _prepared.length;
  int get totalRetainedBytes => _totalRetainedBytes;

  Future<V3HandshakeHandoffAuthority> claimCoordinatorAuthority() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored || _authority != null) {
        throw StateError('Layergram v3 handoff journal already has an owner');
      }
      final authority = V3HandshakeHandoffAuthority._();
      _authority = authority;
      return authority;
    });
  }

  Future<V3HandshakeHandoffRepositoryRestoreResult> restore({
    V3HandshakeHandoffAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 handoff journal was restored');
      }
      final stored = await _store.readAll();
      final relevant = stored
          .where((record) => record.payload['kind'] == recordKind)
          .toList(growable: false);
      if (relevant.length > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical v3 handoff record limit exceeded',
        );
      }
      final decoded = <V3PreparedHandshakeHandoff>[];
      try {
        for (final record in relevant) {
          decoded.add(_decodePrepared(record));
        }
        final groups = <String, List<V3PreparedHandshakeHandoff>>{};
        for (final value in decoded) {
          groups
              .putIfAbsent(
                value.handshakeId,
                () => <V3PreparedHandshakeHandoff>[],
              )
              .add(value);
        }
        if (groups.length > maxPrepared) {
          throw const V3LmfPersistenceLimitException(
            'v3 prepared handoff limit exceeded',
          );
        }
        var removed = 0;
        var total = 0;
        for (final group in groups.values) {
          group
              .sort((left, right) => left.storageId.compareTo(right.storageId));
          final selected = group.first;
          for (final duplicate in group.skip(1)) {
            if (!_samePrepared(selected, duplicate)) {
              throw const V3LmfPersistenceConflictException(
                'divergent v3 prepared handoff records',
              );
            }
            await _deleteIgnoringFailure(duplicate.storageId);
            duplicate._close();
            removed++;
          }
          total += selected.retainedBytes;
          if (total > maxTotalRetainedBytes) {
            throw const V3LmfPersistenceLimitException(
              'v3 prepared handoff byte limit exceeded',
            );
          }
          _prepared[selected.handshakeId] = selected;
        }
        _totalRetainedBytes = total;
        _restored = true;
        decoded.removeWhere(
          (value) => identical(_prepared[value.handshakeId], value),
        );
        return V3HandshakeHandoffRepositoryRestoreResult(
          prepared: List<V3PreparedHandshakeHandoff>.unmodifiable(
            _prepared.values,
          ),
          removedDuplicateRecords: removed,
        );
      } catch (_) {
        for (final value in _prepared.values) {
          value._close();
        }
        _prepared.clear();
        _totalRetainedBytes = 0;
        rethrow;
      } finally {
        for (final value in decoded) {
          value._close();
        }
      }
    });
  }

  Future<void> preflightCreate({
    required String handshakeId,
    V3HandshakeHandoffAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      if (!_isCanonicalNonZeroId(handshakeId, 16)) {
        throw const FormatException('Invalid Layergram v3 handoff ID');
      }
      if (_prepared.containsKey(handshakeId)) return;
      if (_prepared.length >= maxPrepared) {
        throw const V3LmfPersistenceLimitException(
          'v3 prepared handoff capacity exceeded',
        );
      }
      final worstCase = V3TripleRatchetStateCodec.maxEncodedBytes +
          V3HandshakeCodec.confirmationBytes;
      if (_totalRetainedBytes + worstCase > maxTotalRetainedBytes) {
        throw const V3LmfPersistenceLimitException(
          'v3 prepared handoff byte capacity exceeded',
        );
      }
    });
  }

  Future<V3PreparedHandshakeHandoff> persist({
    required String handshakeId,
    required V3SessionRole role,
    required String pendingStateDigest,
    required V3HandshakeConfirmation confirmation,
    required V3TripleRatchetState snapshot,
    DateTime? preparedAt,
    V3HandshakeHandoffAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final candidate = _preparedFromValues(
        handshakeId: handshakeId,
        role: role,
        pendingStateDigest: pendingStateDigest,
        confirmation: confirmation,
        snapshot: snapshot,
        preparedAt: preparedAt ?? DateTime.now().toUtc(),
      );
      try {
        final existing = _prepared[handshakeId];
        if (existing != null) {
          if (!_samePrepared(existing, candidate)) {
            throw const V3LmfPersistenceConflictException(
              'v3 prepared handoff retry diverged',
            );
          }
          return existing;
        }
        if (_prepared.length >= maxPrepared) {
          throw const V3LmfPersistenceLimitException(
            'v3 prepared handoff capacity exceeded',
          );
        }
        final prospective = _totalRetainedBytes + candidate.retainedBytes;
        if (prospective > maxTotalRetainedBytes) {
          throw const V3LmfPersistenceLimitException(
            'v3 prepared handoff byte capacity exceeded',
          );
        }
        V3PreparedHandshakeHandoff? durable;
        try {
          final storageId = await _store.write(_encodePrepared(candidate));
          durable = _copyPrepared(candidate, storageId: storageId);
          _prepared[handshakeId] = durable;
          _totalRetainedBytes = prospective;
          return durable;
        } catch (_) {
          durable?._close();
          _writeRecoveryRequired = true;
          rethrow;
        }
      } finally {
        candidate._close();
      }
    });
  }

  Future<void> deleteCommitted({
    required String handshakeId,
    required String expectedRecordDigest,
    V3HandshakeHandoffAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final current = _prepared[handshakeId];
      if (current == null) return;
      if (current.recordDigest != expectedRecordDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 prepared handoff deletion binding diverged',
        );
      }
      try {
        await _store.delete(current.storageId);
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      }
      _prepared.remove(handshakeId);
      _totalRetainedBytes -= current.retainedBytes;
      current._close();
    });
  }

  Future<void> close({V3HandshakeHandoffAuthority? authority}) {
    return _serialized(() async {
      _ensureAuthority(authority);
      if (_closed) return;
      _closed = true;
      for (final value in _prepared.values) {
        value._close();
      }
      _prepared.clear();
      _totalRetainedBytes = 0;
    });
  }

  Future<void> _deleteIgnoringFailure(String storageId) async {
    try {
      await _store.delete(storageId);
    } catch (_) {
      // A byte-identical encrypted duplicate is retried on the next restore.
    }
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
      throw StateError('Layergram v3 handoff journal is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored || _writeRecoveryRequired) {
      throw StateError(
        'Layergram v3 handoff journal requires fresh restore',
      );
    }
  }

  void _ensureAuthority(V3HandshakeHandoffAuthority? authority) {
    final claimed = _authority;
    if (claimed != null && !identical(claimed, authority)) {
      throw StateError(
        'Layergram v3 handoff journal is owned by its coordinator',
      );
    }
  }
}

/// Serialized coordinator for the only permitted HP3 -> initial TR3 handoff.
final class V3HandshakeSessionHandoffController {
  V3HandshakeSessionHandoffController({
    required V3HandshakeHandoffRepository repository,
    required V3HandshakePersistenceController handshakes,
    required V3SessionCommitController sessions,
    required V3InitialSessionHandoffAuthority initialHandoffAuthority,
    V3SckaBackend? sckaBackend,
  })  : _repository = repository,
        _handshakes = handshakes,
        _sessions = sessions,
        _initialHandoffAuthority = initialHandoffAuthority,
        _sckaBackend = sckaBackend;

  final V3HandshakeHandoffRepository _repository;
  final V3HandshakePersistenceController _handshakes;
  final V3SessionCommitController _sessions;
  final V3InitialSessionHandoffAuthority _initialHandoffAuthority;
  final V3SckaBackend? _sckaBackend;
  Future<void> _operationTail = Future<void>.value();
  V3HandshakeHandoffAuthority? _authority;
  bool _restored = false;
  bool _closed = false;
  bool _recoveryRequired = false;

  bool get requiresRecovery =>
      _recoveryRequired ||
      _repository.requiresRecovery ||
      _handshakes.requiresRecovery ||
      _sessions.requiresRecovery;

  Future<V3HandshakeSessionHandoffRestoreResult> restore() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored || _authority != null) {
        throw StateError('Layergram v3 handoff controller was restored');
      }
      if (!_handshakes.isRestored || !_sessions.isRestored) {
        throw StateError(
          'Layergram v3 handshake and session controllers must restore first',
        );
      }
      try {
        await _handshakes.claimInitialHandoffAuthority(
          _initialHandoffAuthority,
        );
        await _sessions.claimInitialHandoffAuthority(
          _initialHandoffAuthority,
        );
        _authority = await _repository.claimCoordinatorAuthority();
        final restored = await _repository.restore(authority: _authority);
        _restored = true;
        final recovered = <V3HandshakeSessionHandoffResult>[];
        for (final prepared in restored.prepared) {
          recovered.add(await _commitPrepared(prepared, recovered: true));
        }
        for (final completion in await _handshakes.committedHandoffs(
          authority: _initialHandoffAuthority,
        )) {
          await _sessions.verifyCommittedHandoffSession(
            sessionKey: completion.sessionId,
            initialCheckpointDigest: completion.checkpointDigest,
            authority: _initialHandoffAuthority,
          );
        }
        return V3HandshakeSessionHandoffRestoreResult(
          recoveredHandoffs: List.unmodifiable(recovered),
          removedDuplicateRecords: restored.removedDuplicateRecords,
        );
      } catch (_) {
        _recoveryRequired = true;
        await _failStopDependencies();
        rethrow;
      }
    });
  }

  Future<V3HandshakeSessionHandoffResult> completeInitiator({
    required String handshakeId,
    required String expectedStateDigest,
    required V3LocalIdentityHandle localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3PublicIdentity responderIdentity,
    required V3HandshakeReply reply,
    V3SckaBackend? backend,
    DateTime? preparedAt,
    DateTime? completedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final completed = await _handshakes.committedHandoffForId(
        handshakeId,
        authority: _initialHandoffAuthority,
      );
      if (completed != null) {
        final confirmation = V3HandshakeCodec.decodeConfirmation(
          completed.confirmationRecord,
        );
        final replyMessageId = reply.messageId;
        final confirmationReplyId = confirmation.replyMessageId;
        try {
          if (completed.role != V3SessionRole.initiator ||
              completed.pendingStateDigest != expectedStateDigest ||
              !_bytesEqual(replyMessageId, confirmationReplyId)) {
            throw const V3LmfPersistenceConflictException(
              'v3 completed initiator handoff retry diverged',
            );
          }
        } finally {
          _wipe(replyMessageId);
          _wipe(confirmationReplyId);
        }
        await _sessions.verifyCommittedHandoffSession(
          sessionKey: completed.sessionId,
          initialCheckpointDigest: completed.checkpointDigest,
          authority: _initialHandoffAuthority,
        );
        return _resultFromCompletion(completed, recovered: true);
      }
      await _repository.preflightCreate(
        handshakeId: handshakeId,
        authority: _authority,
      );
      final pendingOutbound =
          await _handshakes.pendingOutboundForId(handshakeId);
      if (pendingOutbound == null ||
          pendingOutbound.kind != V3HandshakeRecordKind.offer ||
          pendingOutbound.stateDigest != expectedStateDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 initiator handoff lost its pending state',
        );
      }
      V3InitiatorPendingHandshake? pending;
      V3InitiatorHandshakeResult? accepted;
      V3TripleRatchetState? snapshot;
      try {
        final selectedBackend = _resolveSckaBackend(backend);
        pending = await _handshakes.resumeInitiator(handshakeId);
        accepted = await V3HybridHandshake.acceptReply(
          pending: pending,
          localIdentity: localIdentity,
          localDevice: localDevice,
          responderIdentity: responderIdentity,
          reply: reply,
        );
        snapshot = await V3InitialSessionFactory.initialize(
          established: accepted.established,
          backend: selectedBackend,
        );
        final prepared = await _repository.persist(
          handshakeId: handshakeId,
          role: V3SessionRole.initiator,
          pendingStateDigest: expectedStateDigest,
          confirmation: accepted.confirmation,
          snapshot: snapshot,
          preparedAt: preparedAt,
          authority: _authority,
        );
        return await _commitPrepared(
          prepared,
          recovered: false,
          completedAt: completedAt,
        );
      } catch (_) {
        if (_repository.requiresRecovery ||
            _handshakes.requiresRecovery ||
            _sessions.requiresRecovery) {
          _recoveryRequired = true;
          await _failStopDependencies();
        }
        rethrow;
      } finally {
        pending?.close();
        accepted?.established.close();
        snapshot?.wipeSecrets();
      }
    });
  }

  Future<V3HandshakeSessionHandoffResult> completeResponder({
    required String handshakeId,
    required String expectedStateDigest,
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
    required V3HandshakeConfirmation confirmation,
    V3SckaBackend? backend,
    DateTime? preparedAt,
    DateTime? completedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final completed = await _handshakes.committedHandoffForId(
        handshakeId,
        authority: _initialHandoffAuthority,
      );
      if (completed != null) {
        final encoded = V3HandshakeCodec.encodeConfirmation(confirmation);
        try {
          if (completed.role != V3SessionRole.responder ||
              completed.pendingStateDigest != expectedStateDigest ||
              !_bytesEqual(completed.confirmationRecord, encoded)) {
            throw const V3LmfPersistenceConflictException(
              'v3 completed responder handoff retry diverged',
            );
          }
        } finally {
          _wipe(encoded);
        }
        await _sessions.verifyCommittedHandoffSession(
          sessionKey: completed.sessionId,
          initialCheckpointDigest: completed.checkpointDigest,
          authority: _initialHandoffAuthority,
        );
        return _resultFromCompletion(completed, recovered: true);
      }
      await _repository.preflightCreate(
        handshakeId: handshakeId,
        authority: _authority,
      );
      final pendingOutbound =
          await _handshakes.pendingOutboundForId(handshakeId);
      if (pendingOutbound == null ||
          pendingOutbound.kind != V3HandshakeRecordKind.reply ||
          pendingOutbound.stateDigest != expectedStateDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 responder handoff lost its pending state',
        );
      }
      V3ResponderPendingHandshake? pending;
      V3HandshakeEstablishedMaterial? established;
      V3TripleRatchetState? snapshot;
      try {
        final selectedBackend = _resolveSckaBackend(backend);
        pending = await _handshakes.resumeResponder(handshakeId);
        established = await V3HybridHandshake.acceptConfirmation(
          pending: pending,
          initiatorIdentity: initiatorIdentity,
          responderIdentity: responderIdentity,
          confirmation: confirmation,
        );
        snapshot = await V3InitialSessionFactory.initialize(
          established: established,
          backend: selectedBackend,
        );
        final prepared = await _repository.persist(
          handshakeId: handshakeId,
          role: V3SessionRole.responder,
          pendingStateDigest: expectedStateDigest,
          confirmation: confirmation,
          snapshot: snapshot,
          preparedAt: preparedAt,
          authority: _authority,
        );
        return await _commitPrepared(
          prepared,
          recovered: false,
          completedAt: completedAt,
        );
      } catch (_) {
        if (_repository.requiresRecovery ||
            _handshakes.requiresRecovery ||
            _sessions.requiresRecovery) {
          _recoveryRequired = true;
          await _failStopDependencies();
        }
        rethrow;
      } finally {
        pending?.close();
        established?.close();
        snapshot?.wipeSecrets();
      }
    });
  }

  Future<V3HandshakeSessionHandoffResult> _commitPrepared(
    V3PreparedHandshakeHandoff prepared, {
    required bool recovered,
    DateTime? completedAt,
  }) async {
    final snapshot = prepared.decodeSnapshot();
    final confirmation = prepared.decodeConfirmation();
    final confirmationBytes = prepared.confirmationRecord;
    final sessionId = snapshot.sessionId;
    try {
      final completion = await _handshakes.committedHandoffForId(
        prepared.handshakeId,
        authority: _initialHandoffAuthority,
      );
      late final String checkpointDigest;
      if (completion != null) {
        checkpointDigest = await _sessions.initialCheckpointDigestFor(
          snapshot,
          authority: _initialHandoffAuthority,
        );
        if (completion.role != prepared.role ||
            completion.pendingStateDigest != prepared.pendingStateDigest ||
            completion.sessionId != prepared.sessionId ||
            completion.checkpointDigest != checkpointDigest ||
            !_bytesEqual(
              completion.confirmationRecord,
              confirmationBytes,
            )) {
          throw const V3LmfPersistenceConflictException(
            'v3 completion does not match its prepared handoff',
          );
        }
        await _sessions.verifySessionExtendsInitial(
          snapshot,
          authority: _initialHandoffAuthority,
        );
      } else {
        final registration = await _sessions.registerInitialSession(
          snapshot: snapshot,
          authority: _initialHandoffAuthority,
          persistedAt: prepared.preparedAt,
        );
        if (registration.sessionKey != prepared.sessionId) {
          throw const V3LmfPersistenceConflictException(
            'v3 initial session registration changed its identifier',
          );
        }
        checkpointDigest = registration.checkpointDigest;
        await _handshakes.markHandoffCommitted(
          handshakeId: prepared.handshakeId,
          expectedStateDigest: prepared.pendingStateDigest,
          confirmation: confirmation,
          sessionId: sessionId,
          checkpointDigest: checkpointDigest,
          completedAt: completedAt ?? prepared.preparedAt,
          authority: _initialHandoffAuthority,
        );
      }
      await _repository.deleteCommitted(
        handshakeId: prepared.handshakeId,
        expectedRecordDigest: prepared.recordDigest,
        authority: _authority,
      );
      return V3HandshakeSessionHandoffResult(
        handshakeId: prepared.handshakeId,
        role: prepared.role,
        confirmationRecord: confirmationBytes,
        sessionId: prepared.sessionId,
        checkpointDigest: checkpointDigest,
        recovered: recovered,
      );
    } catch (_) {
      _recoveryRequired = true;
      await _failStopDependencies();
      rethrow;
    } finally {
      snapshot.wipeSecrets();
      _wipe(confirmationBytes);
      _wipe(sessionId);
    }
  }

  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      await _repository.close(authority: _authority);
    });
  }

  V3SckaBackend _resolveSckaBackend(V3SckaBackend? requested) {
    final pinned = _sckaBackend;
    if (pinned != null) {
      if (requested != null && !identical(requested, pinned)) {
        throw StateError(
          'Layergram v3 handoff scope rejected a different SCKA backend',
        );
      }
      return pinned;
    }
    if (requested == null) {
      throw StateError('Layergram v3 SCKA backend is not configured');
    }
    return requested;
  }

  Future<void> _failStopDependencies() async {
    await _handshakes.markInitialHandoffRecoveryRequired(
      authority: _initialHandoffAuthority,
    );
    await _sessions.markInitialHandoffRecoveryRequired(
      authority: _initialHandoffAuthority,
    );
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
      throw StateError('Layergram v3 handoff controller is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored || requiresRecovery) {
      throw StateError(
        'Layergram v3 handoff controller requires fresh restore',
      );
    }
  }
}

/// Composes authenticated handshake material, EC initialization, epoch-zero
/// PQ chains, and one backend-authenticated SCKA export into a single TR3.
/// The result is still only a candidate until the handoff controller commits
/// it; callers must wipe an abandoned result.
abstract final class V3InitialSessionFactory {
  static Future<V3TripleRatchetState> initialize({
    required V3HandshakeEstablishedMaterial established,
    required V3SckaBackend backend,
  }) async {
    V3EcDoubleRatchetState? ec;
    Uint8List? sessionId;
    Uint8List? transcript;
    Uint8List? initiatorBinding;
    Uint8List? responderBinding;
    Uint8List? ackI2r;
    Uint8List? ackR2i;
    Uint8List? pqSeed;
    Uint8List? sckaStateSealKey;
    Uint8List? nativeState;
    Uint8List? pqRoot;
    V3PqEpochState? pqEpoch;
    Uint8List? ecRoot;
    Uint8List? ecSending;
    Uint8List? ecReceiving;
    Uint8List? ecPrivate;
    Uint8List? ecPublic;
    Uint8List? ecRemote;
    try {
      ec = await V3EcDoubleRatchet.initializeFromHandshake(established);
      sessionId = established.sessionKeys.sessionId;
      transcript = established.sessionKeys.transcriptDigest;
      initiatorBinding = established.sessionKeys.initiatorRoutingBinding;
      responderBinding = established.sessionKeys.responderRoutingBinding;
      ackI2r = established.sessionKeys.initiatorToResponderAckRootKey;
      ackR2i = established.sessionKeys.responderToInitiatorAckRootKey;
      pqSeed = established.sessionKeys.pqRatchetRootKey;
      sckaStateSealKey = established.sessionKeys.sckaStateSealKey;
      nativeState = await V3SparsePqRatchet.initialize(
        backend: backend,
        role: established.role,
        sessionId: sessionId,
        sharedSecret: pqSeed,
        stateSealKey: sckaStateSealKey,
      );
      final initialPq = await V3PqMessageRatchet.deriveInitialEpoch(
        role: established.role,
        sessionId: sessionId,
        pqRootSeed: pqSeed,
      );
      pqRoot = initialPq.rootKey;
      pqEpoch = initialPq.epoch;
      ecRoot = ec.rootKey;
      ecSending = ec.sendingChainKey;
      ecReceiving = ec.receivingChainKey;
      ecPrivate = ec.localDhPrivateKey;
      ecPublic = ec.localDhPublicKey;
      ecRemote = ec.remoteDhPublicKey;
      return V3TripleRatchetState(
        role: established.role,
        lifecycle: V3RatchetLifecycle.active,
        revision: 0,
        sessionId: sessionId,
        transcriptDigest: transcript,
        initiatorRoutingBinding: initiatorBinding,
        responderRoutingBinding: responderBinding,
        initiatorToResponderAckRootKey: ackI2r,
        responderToInitiatorAckRootKey: ackR2i,
        ecRootKey: ecRoot,
        ecSendingChainKey: ecSending,
        ecReceivingChainKey: ecReceiving,
        ecLocalDhPrivateKey: ecPrivate,
        ecLocalDhPublicKey: ecPublic,
        ecRemoteDhPublicKey: ecRemote,
        ecSendCounter: ec.sendCounter,
        ecReceiveCounter: ec.receiveCounter,
        ecPreviousSendingChainLength: ec.previousSendingChainLength,
        pqRootKey: pqRoot,
        sckaStateSealKey: sckaStateSealKey,
        pqCurrentEpoch: 0,
        pqSendingEpoch: 0,
        pqReceivingEpoch: 0,
        pqEpochStates: <V3PqEpochState>[pqEpoch],
        nativeSckaState: nativeState,
      );
    } finally {
      ec?.close();
      if (sessionId != null) _wipe(sessionId);
      if (transcript != null) _wipe(transcript);
      if (initiatorBinding != null) _wipe(initiatorBinding);
      if (responderBinding != null) _wipe(responderBinding);
      if (ackI2r != null) _wipe(ackI2r);
      if (ackR2i != null) _wipe(ackR2i);
      if (pqSeed != null) _wipe(pqSeed);
      if (sckaStateSealKey != null) _wipe(sckaStateSealKey);
      if (nativeState != null) _wipe(nativeState);
      if (pqRoot != null) _wipe(pqRoot);
      pqEpoch?.wipeSecrets();
      if (ecRoot != null) _wipe(ecRoot);
      if (ecSending != null) _wipe(ecSending);
      if (ecReceiving != null) _wipe(ecReceiving);
      if (ecPrivate != null) _wipe(ecPrivate);
      if (ecPublic != null) _wipe(ecPublic);
      if (ecRemote != null) _wipe(ecRemote);
    }
  }
}

V3PreparedHandshakeHandoff _preparedFromValues({
  required String handshakeId,
  required V3SessionRole role,
  required String pendingStateDigest,
  required V3HandshakeConfirmation confirmation,
  required V3TripleRatchetState snapshot,
  required DateTime preparedAt,
}) {
  final confirmationBytes = V3HandshakeCodec.encodeConfirmation(confirmation);
  final snapshotBytes = V3TripleRatchetStateCodec.encode(snapshot);
  final sessionId = snapshot.sessionId;
  try {
    return _validatedPrepared(
      storageId: '',
      handshakeId: handshakeId,
      role: role,
      pendingStateDigest: pendingStateDigest,
      confirmationRecord: confirmationBytes,
      sessionId: _armor(sessionId),
      encodedSnapshot: snapshotBytes,
      snapshotDigest: _snapshotDigest(snapshotBytes),
      preparedAt: preparedAt,
    );
  } finally {
    _wipe(confirmationBytes);
    _wipe(snapshotBytes);
    _wipe(sessionId);
  }
}

V3PreparedHandshakeHandoff _validatedPrepared({
  required String storageId,
  required String handshakeId,
  required V3SessionRole role,
  required String pendingStateDigest,
  required Uint8List confirmationRecord,
  required String sessionId,
  required Uint8List encodedSnapshot,
  required String snapshotDigest,
  required DateTime preparedAt,
  String? expectedRecordDigest,
}) {
  final timestamp = _validatedTimestamp(preparedAt);
  if (!_isCanonicalNonZeroId(handshakeId, 16) ||
      !_isCanonicalNonZeroId(pendingStateDigest, 32) ||
      !_isCanonicalNonZeroId(sessionId, 16) ||
      !_isCanonicalNonZeroId(snapshotDigest, 32) ||
      confirmationRecord.length != V3HandshakeCodec.confirmationBytes ||
      encodedSnapshot.isEmpty ||
      encodedSnapshot.length > V3TripleRatchetStateCodec.maxEncodedBytes ||
      _snapshotDigest(encodedSnapshot) != snapshotDigest) {
    throw const FormatException('Invalid Layergram v3 prepared handoff');
  }
  final confirmation = V3HandshakeCodec.decodeConfirmation(confirmationRecord);
  final snapshot = V3TripleRatchetStateCodec.decode(encodedSnapshot);
  final confirmationHandshakeId = confirmation.handshakeId;
  final snapshotSessionId = snapshot.sessionId;
  try {
    if (_armor(confirmationHandshakeId) != handshakeId ||
        snapshot.role != role ||
        snapshot.lifecycle != V3RatchetLifecycle.active ||
        snapshot.revision != 0 ||
        _armor(snapshotSessionId) != sessionId) {
      throw const FormatException(
        'Mismatched Layergram v3 prepared handoff',
      );
    }
  } finally {
    _wipe(confirmationHandshakeId);
    _wipe(snapshotSessionId);
    snapshot.wipeSecrets();
  }
  final digest = _preparedRecordDigest(
    handshakeId: handshakeId,
    role: role,
    pendingStateDigest: pendingStateDigest,
    confirmationRecord: confirmationRecord,
    sessionId: sessionId,
    encodedSnapshot: encodedSnapshot,
    snapshotDigest: snapshotDigest,
    preparedAt: timestamp,
  );
  if (expectedRecordDigest != null && digest != expectedRecordDigest) {
    throw const FormatException(
      'Mismatched Layergram v3 prepared handoff digest',
    );
  }
  return V3PreparedHandshakeHandoff._(
    storageId: storageId,
    handshakeId: handshakeId,
    role: role,
    pendingStateDigest: pendingStateDigest,
    confirmationRecord: confirmationRecord,
    sessionId: sessionId,
    encodedSnapshot: encodedSnapshot,
    snapshotDigest: snapshotDigest,
    preparedAt: timestamp,
    recordDigest: digest,
  );
}

V3PreparedHandshakeHandoff _decodePrepared(V3LmfStoredRecord record) {
  final payload = record.payload;
  const keys = <String>{
    'kind',
    'v',
    'handshakeId',
    'role',
    'pendingStateDigest',
    'confirmation',
    'sessionId',
    'snapshot',
    'snapshotDigest',
    'preparedAt',
    'recordDigest',
    'reserved',
  };
  if (payload.length != keys.length ||
      !payload.keys.every(keys.contains) ||
      payload['kind'] != V3HandshakeHandoffRepository.recordKind ||
      payload['v'] != 1 ||
      payload['handshakeId'] is! String ||
      payload['role'] is! int ||
      payload['pendingStateDigest'] is! String ||
      payload['confirmation'] is! String ||
      payload['sessionId'] is! String ||
      payload['snapshot'] is! String ||
      payload['snapshotDigest'] is! String ||
      payload['preparedAt'] is! int ||
      payload['recordDigest'] is! String ||
      payload['reserved'] != 0) {
    throw const FormatException('Invalid Layergram v3 handoff envelope');
  }
  final confirmation = _decodeArmoredExact(
    payload['confirmation'] as String,
    V3HandshakeCodec.confirmationBytes,
  );
  final snapshot = _decodeArmoredBounded(
    payload['snapshot'] as String,
    V3TripleRatchetStateCodec.maxEncodedBytes,
  );
  try {
    return _validatedPrepared(
      storageId: record.storageId,
      handshakeId: payload['handshakeId'] as String,
      role: V3SessionRole.fromWireId(payload['role'] as int),
      pendingStateDigest: payload['pendingStateDigest'] as String,
      confirmationRecord: confirmation,
      sessionId: payload['sessionId'] as String,
      encodedSnapshot: snapshot,
      snapshotDigest: payload['snapshotDigest'] as String,
      preparedAt: _timestamp(payload['preparedAt'] as int),
      expectedRecordDigest: payload['recordDigest'] as String,
    );
  } finally {
    _wipe(confirmation);
    _wipe(snapshot);
  }
}

Map<String, dynamic> _encodePrepared(V3PreparedHandshakeHandoff value) =>
    <String, dynamic>{
      'kind': V3HandshakeHandoffRepository.recordKind,
      'v': 1,
      'handshakeId': value.handshakeId,
      'role': value.role.wireId,
      'pendingStateDigest': value.pendingStateDigest,
      'confirmation': _armor(value._confirmationRecord),
      'sessionId': value.sessionId,
      'snapshot': _armor(value._encodedSnapshot),
      'snapshotDigest': value.snapshotDigest,
      'preparedAt': value.preparedAt.millisecondsSinceEpoch,
      'recordDigest': value.recordDigest,
      'reserved': 0,
    };

V3PreparedHandshakeHandoff _copyPrepared(
  V3PreparedHandshakeHandoff value, {
  required String storageId,
}) =>
    V3PreparedHandshakeHandoff._(
      storageId: storageId,
      handshakeId: value.handshakeId,
      role: value.role,
      pendingStateDigest: value.pendingStateDigest,
      confirmationRecord: value._confirmationRecord,
      sessionId: value.sessionId,
      encodedSnapshot: value._encodedSnapshot,
      snapshotDigest: value.snapshotDigest,
      preparedAt: value.preparedAt,
      recordDigest: value.recordDigest,
    );

bool _samePrepared(
  V3PreparedHandshakeHandoff left,
  V3PreparedHandshakeHandoff right,
) =>
    left.handshakeId == right.handshakeId &&
    left.role == right.role &&
    left.pendingStateDigest == right.pendingStateDigest &&
    left.sessionId == right.sessionId &&
    left.snapshotDigest == right.snapshotDigest &&
    left.preparedAt == right.preparedAt &&
    left.recordDigest == right.recordDigest &&
    _bytesEqual(left._confirmationRecord, right._confirmationRecord) &&
    _bytesEqual(left._encodedSnapshot, right._encodedSnapshot);

V3HandshakeSessionHandoffResult _resultFromCompletion(
  V3CommittedHandshakeHandoff completion, {
  required bool recovered,
}) =>
    V3HandshakeSessionHandoffResult(
      handshakeId: completion.handshakeId,
      role: completion.role,
      confirmationRecord: completion.confirmationRecord,
      sessionId: completion.sessionId,
      checkpointDigest: completion.checkpointDigest,
      recovered: recovered,
    );

String _preparedRecordDigest({
  required String handshakeId,
  required V3SessionRole role,
  required String pendingStateDigest,
  required Uint8List confirmationRecord,
  required String sessionId,
  required Uint8List encodedSnapshot,
  required String snapshotDigest,
  required DateTime preparedAt,
}) {
  final numbers = ByteData(12)
    ..setUint64(0, preparedAt.millisecondsSinceEpoch, Endian.big)
    ..setUint32(8, encodedSnapshot.length, Endian.big);
  return _digest(<int>[
    ...utf8.encode('layergram/v3/handshake/handoff-record\x00'),
    role.wireId,
    ...numbers.buffer.asUint8List(),
    ..._decodeId(handshakeId, 16),
    ..._decodeId(pendingStateDigest, 32),
    ...confirmationRecord,
    ..._decodeId(sessionId, 16),
    ..._decodeId(snapshotDigest, 32),
    ...encodedSnapshot,
  ]);
}

String _snapshotDigest(Uint8List encoded) => _digest(<int>[
      ...utf8.encode('layergram/v3/handshake/initial-tr3\x00'),
      ...encoded,
    ]);

String _digest(List<int> value) =>
    base64Url.encode(crypto.sha256.convert(value).bytes).replaceAll('=', '');

String _armor(List<int> value) => base64Url.encode(value).replaceAll('=', '');

Uint8List _decodeId(String value, int expectedBytes) {
  final decoded = _decodeArmoredExact(value, expectedBytes);
  if (_isAllZero(decoded)) {
    _wipe(decoded);
    throw const FormatException('Invalid all-zero Layergram v3 identifier');
  }
  return decoded;
}

Uint8List _decodeArmoredExact(String value, int expectedBytes) {
  final decoded = _decodeArmoredBounded(value, expectedBytes);
  if (decoded.length != expectedBytes) {
    _wipe(decoded);
    throw const FormatException('Invalid Layergram v3 armored field length');
  }
  return decoded;
}

Uint8List _decodeArmoredBounded(String value, int maxBytes) {
  if (value.isEmpty || value.length > ((maxBytes * 4 + 2) ~/ 3)) {
    throw const FormatException('Invalid Layergram v3 armored field');
  }
  try {
    final decoded = Uint8List.fromList(
      base64Url.decode(base64Url.normalize(value)),
    );
    if (decoded.isEmpty ||
        decoded.length > maxBytes ||
        _armor(decoded) != value) {
      _wipe(decoded);
      throw const FormatException('Non-canonical Layergram v3 armored field');
    }
    return decoded;
  } on FormatException {
    rethrow;
  } catch (_) {
    throw const FormatException('Invalid Layergram v3 armored field');
  }
}

bool _isCanonicalNonZeroId(String value, int expectedBytes) {
  Uint8List? decoded;
  try {
    decoded = _decodeArmoredExact(value, expectedBytes);
    return !_isAllZero(decoded);
  } catch (_) {
    return false;
  } finally {
    if (decoded != null) _wipe(decoded);
  }
}

DateTime _validatedTimestamp(DateTime value) {
  if (!value.isUtc) {
    throw const FormatException('Layergram v3 timestamp must be UTC');
  }
  final millis = value.millisecondsSinceEpoch;
  if (millis < 0 || millis > 253402300799999) {
    throw const FormatException('Layergram v3 timestamp is out of range');
  }
  return DateTime.fromMillisecondsSinceEpoch(millis, isUtc: true);
}

DateTime _timestamp(int millis) {
  if (millis < 0 || millis > 253402300799999) {
    throw const FormatException('Layergram v3 timestamp is out of range');
  }
  return DateTime.fromMillisecondsSinceEpoch(millis, isUtc: true);
}

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

bool _isAllZero(List<int> value) {
  var combined = 0;
  for (final byte in value) {
    combined |= byte;
  }
  return combined == 0;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
