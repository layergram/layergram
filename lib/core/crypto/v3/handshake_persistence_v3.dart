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

import 'initial_session_handoff_authority_v3.dart';
import 'key_schedule_v3.dart';
import 'lmf_v3_persistence.dart';
import 'local_identity_v3.dart';
import 'public_identity_v3.dart';

/// Durable metadata and secret pending state for one v3 handshake.
///
/// The encoded HP3 state contains private key material. It is deliberately not
/// exposed as bytes and may only be decoded through the role-specific methods.
/// The exact public outbound record is copied so a restart can resend it
/// without rerunning X25519 or ML-KEM.
final class V3DurablePendingHandshake {
  V3DurablePendingHandshake._({
    required this.storageId,
    required this.handshakeId,
    required this.role,
    required this.mode,
    required this.capabilities,
    required this.localIdentityDigest,
    required this.remoteIdentityDigest,
    required this.localDeviceId,
    required this.remoteDeviceId,
    required this.outboundKind,
    required this.outboundMessageId,
    required this.stateDigest,
    required Uint8List encodedState,
    required Uint8List outboundRecord,
    required this.createdAt,
    required this.recordDigest,
  })  : _encodedState = Uint8List.fromList(encodedState),
        _outboundRecord = Uint8List.fromList(outboundRecord);

  final String storageId;
  final String handshakeId;
  final V3SessionRole role;
  final V3HandshakeMode mode;
  final int capabilities;
  final String localIdentityDigest;
  final String remoteIdentityDigest;
  final String localDeviceId;
  final String? remoteDeviceId;
  final V3HandshakeRecordKind outboundKind;
  final String outboundMessageId;
  final String stateDigest;
  final DateTime createdAt;
  final String recordDigest;
  final Uint8List _encodedState;
  final Uint8List _outboundRecord;

  int get retainedBytes => _encodedState.length + _outboundRecord.length;

  Uint8List get outboundRecord => Uint8List.fromList(_outboundRecord);

  V3InitiatorPendingHandshake decodeInitiator() {
    if (role != V3SessionRole.initiator) {
      throw StateError('Layergram v3 pending handshake is not initiator state');
    }
    final copy = Uint8List.fromList(_encodedState);
    try {
      return V3HandshakePendingStateCodec.decodeInitiator(copy);
    } finally {
      _wipe(copy);
    }
  }

  V3ResponderPendingHandshake decodeResponder() {
    if (role != V3SessionRole.responder) {
      throw StateError('Layergram v3 pending handshake is not responder state');
    }
    final copy = Uint8List.fromList(_encodedState);
    try {
      return V3HandshakePendingStateCodec.decodeResponder(copy);
    } finally {
      _wipe(copy);
    }
  }

  void _close() {
    _wipe(_encodedState);
    _wipe(_outboundRecord);
  }
}

/// Compact replay tombstone written only after the initial session checkpoint
/// is independently durable.
final class V3HandshakeCompletionBinding {
  V3HandshakeCompletionBinding._({
    required this.storageId,
    required this.handshakeId,
    required this.role,
    required this.mode,
    required this.capabilities,
    required this.localIdentityDigest,
    required this.remoteIdentityDigest,
    required this.localDeviceId,
    required this.remoteDeviceId,
    required this.outboundKind,
    required this.outboundMessageId,
    required this.pendingStateDigest,
    required this.terminalMessageId,
    required Uint8List terminalRecord,
    required this.sessionId,
    required this.checkpointDigest,
    required this.completedAt,
    required this.recordDigest,
  }) : _terminalRecord = Uint8List.fromList(terminalRecord);

  final String storageId;
  final String handshakeId;
  final V3SessionRole role;
  final V3HandshakeMode mode;
  final int capabilities;
  final String localIdentityDigest;
  final String remoteIdentityDigest;
  final String localDeviceId;
  final String remoteDeviceId;
  final V3HandshakeRecordKind outboundKind;
  final String outboundMessageId;
  final String pendingStateDigest;
  final String terminalMessageId;
  final Uint8List _terminalRecord;
  final String sessionId;
  final String checkpointDigest;
  final DateTime completedAt;
  final String recordDigest;

  Uint8List get terminalRecord => Uint8List.fromList(_terminalRecord);
  int get retainedBytes => _terminalRecord.length;

  void _close() => _wipe(_terminalRecord);
}

final class V3HandshakePersistenceRestoreResult {
  const V3HandshakePersistenceRestoreResult({
    required this.pending,
    required this.completions,
    required this.removedObsoleteRecords,
    required this.suppressedCompletedPending,
  });

  final List<V3DurablePendingHandshake> pending;
  final List<V3HandshakeCompletionBinding> completions;

  /// Exact duplicates and pending records retired by a matching completion.
  final int removedObsoleteRecords;
  final int suppressedCompletedPending;
}

/// Non-secret controller restore result. Secret HP3 objects remain owned by
/// the repository until one role-specific resume call explicitly requests a
/// detached working copy.
final class V3HandshakeControllerRestoreResult {
  const V3HandshakeControllerRestoreResult({
    required this.pendingOutbound,
    required this.completionCount,
    required this.removedObsoleteRecords,
    required this.suppressedCompletedPending,
  });

  final List<V3DurableHandshakeOutbound> pendingOutbound;
  final int completionCount;
  final int removedObsoleteRecords;
  final int suppressedCompletedPending;
}

/// Detached public metadata for one committed handshake-to-session handoff.
/// The retained confirmation is public wire data; HP3 secrets never leave the
/// repository through this object.
final class V3CommittedHandshakeHandoff {
  V3CommittedHandshakeHandoff({
    required this.handshakeId,
    required this.role,
    required this.pendingStateDigest,
    required Uint8List confirmationRecord,
    required this.sessionId,
    required this.checkpointDigest,
  }) : confirmationRecord = Uint8List.fromList(confirmationRecord);

  final String handshakeId;
  final V3SessionRole role;
  final String pendingStateDigest;
  final Uint8List confirmationRecord;
  final String sessionId;
  final String checkpointDigest;
}

/// Unforgeable authority retained by one handshake persistence controller.
final class V3HandshakePersistenceAuthority {
  const V3HandshakePersistenceAuthority._();
}

/// Bounded crash-consistent repository for HP3 handshake state.
///
/// Records are plaintext only inside the already authenticated and padded
/// identity/passphrase-scoped Aux repository. A successful pending write must
/// precede first export. Completion writes a tombstone before deleting the
/// secret pending state, so every ambiguous boundary is recoverable.
final class V3HandshakePendingRepository {
  V3HandshakePendingRepository({
    required V3LmfRecordStore store,
    this.maxPending = 64,
    this.maxPendingPerRemoteIdentity = 4,
    this.maxCompletions = 4096,
    this.maxStoredRecords = 8192,
    this.maxTotalPendingBytes = 4 * 1024 * 1024,
  }) : _store = store {
    if (maxPending <= 0 ||
        maxPendingPerRemoteIdentity <= 0 ||
        maxPendingPerRemoteIdentity > maxPending ||
        maxCompletions <= 0 ||
        maxStoredRecords <= 0 ||
        maxTotalPendingBytes <= 0) {
      throw ArgumentError('Layergram v3 handshake persistence limits invalid');
    }
  }

  static const String pendingRecordKind = 'v3_handshake_pending_v1';
  static const String completionRecordKind = 'v3_handshake_completion_v1';
  static const int _recordVersion = 1;
  static const int _maxTimestampMillis = 253402300799999;

  final V3LmfRecordStore _store;
  final int maxPending;
  final int maxPendingPerRemoteIdentity;
  final int maxCompletions;
  final int maxStoredRecords;
  final int maxTotalPendingBytes;

  final Map<String, V3DurablePendingHandshake> _pending =
      <String, V3DurablePendingHandshake>{};
  final Map<String, V3HandshakeCompletionBinding> _completions =
      <String, V3HandshakeCompletionBinding>{};
  Future<void> _operationTail = Future<void>.value();
  V3HandshakePersistenceAuthority? _authority;
  bool _restored = false;
  bool _closed = false;
  bool _writeRecoveryRequired = false;
  int _totalPendingBytes = 0;

  int get pendingCount => _pending.length;
  int get completionCount => _completions.length;
  int get totalPendingBytes => _totalPendingBytes;
  bool get requiresRecovery => _writeRecoveryRequired;

  Future<V3HandshakePersistenceAuthority> claimControllerAuthority() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError(
          'Layergram v3 handshake authority must be claimed before restore',
        );
      }
      if (_authority != null) {
        throw StateError(
          'Layergram v3 handshake repository already has a controller',
        );
      }
      final authority = V3HandshakePersistenceAuthority._();
      _authority = authority;
      return authority;
    });
  }

  List<V3DurablePendingHandshake> pending({
    V3HandshakePersistenceAuthority? authority,
  }) {
    _ensureAuthority(authority);
    _ensureReady();
    return List<V3DurablePendingHandshake>.unmodifiable(_pending.values);
  }

  List<V3HandshakeCompletionBinding> completions({
    V3HandshakePersistenceAuthority? authority,
  }) {
    _ensureAuthority(authority);
    _ensureReady();
    return List<V3HandshakeCompletionBinding>.unmodifiable(
      _completions.values,
    );
  }

  V3DurablePendingHandshake? pendingForId(
    String handshakeId, {
    V3HandshakePersistenceAuthority? authority,
  }) {
    _ensureAuthority(authority);
    _ensureReady();
    return _pending[handshakeId];
  }

  V3HandshakeCompletionBinding? completionForId(
    String handshakeId, {
    V3HandshakePersistenceAuthority? authority,
  }) {
    _ensureAuthority(authority);
    _ensureReady();
    return _completions[handshakeId];
  }

  Future<V3HandshakePersistenceRestoreResult> restore({
    V3HandshakePersistenceAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 handshake repository was restored');
      }
      final stored = await _store.readAll();
      final relevant = stored.where((record) {
        final kind = record.payload['kind'];
        return kind == pendingRecordKind || kind == completionRecordKind;
      }).toList(growable: false);
      if (relevant.length > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical v3 handshake record limit exceeded',
        );
      }

      final decodedPending = <V3DurablePendingHandshake>[];
      final decodedCompletions = <V3HandshakeCompletionBinding>[];
      try {
        for (final record in relevant) {
          if (record.payload['kind'] == pendingRecordKind) {
            decodedPending.add(_decodePending(record));
          } else {
            decodedCompletions.add(_decodeCompletion(record));
          }
        }

        final pendingGroups = <String, List<V3DurablePendingHandshake>>{};
        for (final value in decodedPending) {
          pendingGroups
              .putIfAbsent(
                  value.handshakeId, () => <V3DurablePendingHandshake>[])
              .add(value);
        }
        final completionGroups = <String, List<V3HandshakeCompletionBinding>>{};
        for (final value in decodedCompletions) {
          completionGroups
              .putIfAbsent(
                value.handshakeId,
                () => <V3HandshakeCompletionBinding>[],
              )
              .add(value);
        }
        if (completionGroups.length > maxCompletions) {
          throw const V3LmfPersistenceLimitException(
            'v3 handshake completion limit exceeded',
          );
        }

        var removed = 0;
        var suppressed = 0;
        for (final group in completionGroups.values) {
          group.sort(_compareCompletion);
          final selected = group.first;
          for (final duplicate in group.skip(1)) {
            if (!_sameCompletion(selected, duplicate)) {
              throw const V3LmfPersistenceConflictException(
                'divergent v3 handshake completion records',
              );
            }
            await _deleteIgnoringFailure(duplicate.storageId);
            duplicate._close();
            removed++;
          }
          _completions[selected.handshakeId] = selected;
        }

        var totalBytes = 0;
        final perRemote = <String, int>{};
        for (final group in pendingGroups.values) {
          group.sort(_comparePending);
          final selected = group.first;
          for (final duplicate in group.skip(1)) {
            if (!_samePending(selected, duplicate)) {
              throw const V3LmfPersistenceConflictException(
                'divergent v3 handshake pending records',
              );
            }
          }
          final completion = _completions[selected.handshakeId];
          if (completion != null) {
            if (!_completionCoversPending(completion, selected)) {
              throw const V3LmfPersistenceConflictException(
                'v3 handshake completion does not cover pending state',
              );
            }
            for (final obsolete in group) {
              await _deleteIgnoringFailure(obsolete.storageId);
              obsolete._close();
              removed++;
            }
            suppressed++;
            continue;
          }
          if (_pending.length >= maxPending) {
            throw const V3LmfPersistenceLimitException(
              'v3 handshake pending limit exceeded',
            );
          }
          totalBytes += selected.retainedBytes;
          if (totalBytes > maxTotalPendingBytes) {
            throw const V3LmfPersistenceLimitException(
              'v3 handshake pending-byte limit exceeded',
            );
          }
          final remoteCount =
              (perRemote[selected.remoteIdentityDigest] ?? 0) + 1;
          if (remoteCount > maxPendingPerRemoteIdentity) {
            throw const V3LmfPersistenceLimitException(
              'v3 per-contact pending handshake limit exceeded',
            );
          }
          perRemote[selected.remoteIdentityDigest] = remoteCount;
          _pending[selected.handshakeId] = selected;
          for (final duplicate in group.skip(1)) {
            await _deleteIgnoringFailure(duplicate.storageId);
            duplicate._close();
            removed++;
          }
        }
        _totalPendingBytes = totalBytes;
        _restored = true;
        decodedPending.removeWhere(
          (value) => identical(_pending[value.handshakeId], value),
        );
        decodedCompletions.removeWhere(
          (value) => identical(_completions[value.handshakeId], value),
        );
        return V3HandshakePersistenceRestoreResult(
          pending: pending(authority: authority),
          completions: completions(authority: authority),
          removedObsoleteRecords: removed,
          suppressedCompletedPending: suppressed,
        );
      } catch (_) {
        for (final value in _pending.values) {
          value._close();
        }
        _pending.clear();
        for (final value in _completions.values) {
          value._close();
        }
        _completions.clear();
        _totalPendingBytes = 0;
        rethrow;
      } finally {
        for (final value in decodedPending) {
          value._close();
        }
        for (final value in decodedCompletions) {
          value._close();
        }
      }
    });
  }

  Future<void> preflightCreate({
    required String remoteIdentityDigest,
    required int additionalBytes,
    V3HandshakePersistenceAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      if (!_isCanonicalNonZeroId(remoteIdentityDigest, 48)) {
        throw const FormatException(
          'Invalid Layergram v3 remote identity digest',
        );
      }
      if (additionalBytes <= 0 ||
          additionalBytes >
              V3HandshakePendingStateCodec.maxEncodedBytes +
                  V3HandshakeCodec.replyBytes) {
        throw const FormatException(
          'Invalid Layergram v3 pending preflight size',
        );
      }
      _checkPendingCapacity(remoteIdentityDigest, additionalBytes);
    });
  }

  Future<V3DurablePendingHandshake> persistInitiator({
    required V3InitiatorPendingHandshake state,
    DateTime? createdAt,
    V3HandshakePersistenceAuthority? authority,
  }) {
    return _persistPending(
      candidateBuilder: () => _fromInitiator(
        state,
        createdAt: createdAt ?? DateTime.now().toUtc(),
      ),
      authority: authority,
    );
  }

  Future<V3DurablePendingHandshake> persistResponder({
    required V3ResponderPendingHandshake state,
    DateTime? createdAt,
    V3HandshakePersistenceAuthority? authority,
  }) {
    return _persistPending(
      candidateBuilder: () => _fromResponder(
        state,
        createdAt: createdAt ?? DateTime.now().toUtc(),
      ),
      authority: authority,
    );
  }

  Future<V3HandshakeCompletionBinding> markHandoffCommitted({
    required String handshakeId,
    required String expectedStateDigest,
    required V3HandshakeConfirmation confirmation,
    required String sessionId,
    required String checkpointDigest,
    required DateTime completedAt,
    V3HandshakePersistenceAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final terminalRecord = V3HandshakeCodec.encodeConfirmation(confirmation);
      final terminalMessageId = _id(confirmation.messageId);
      final remoteDeviceId = switch (
          _pending[handshakeId]?.role ?? _completions[handshakeId]?.role) {
        V3SessionRole.initiator => _id(confirmation.responderDeviceId),
        V3SessionRole.responder => _id(confirmation.initiatorDeviceId),
        null => '',
      };
      try {
        if (!_isCanonicalNonZeroId(handshakeId, 16) ||
            !_isCanonicalNonZeroId(expectedStateDigest, 32) ||
            !_isCanonicalNonZeroId(remoteDeviceId, 16) ||
            !_isCanonicalNonZeroId(terminalMessageId, 16) ||
            !_isCanonicalNonZeroId(sessionId, 16) ||
            !_isCanonicalNonZeroId(checkpointDigest, 32)) {
          throw const FormatException(
            'Invalid Layergram v3 handshake completion binding',
          );
        }
        final timestamp = _validatedTimestamp(completedAt);
        final existingCompletion = _completions[handshakeId];
        if (existingCompletion != null) {
          if (existingCompletion.pendingStateDigest != expectedStateDigest ||
              existingCompletion.remoteDeviceId != remoteDeviceId ||
              existingCompletion.terminalMessageId != terminalMessageId ||
              !_bytesEqual(
                existingCompletion._terminalRecord,
                terminalRecord,
              ) ||
              existingCompletion.sessionId != sessionId ||
              existingCompletion.checkpointDigest != checkpointDigest) {
            throw const V3LmfPersistenceConflictException(
              'v3 handshake completion binding diverged',
            );
          }
          return existingCompletion;
        }
        final pending = _pending[handshakeId];
        if (pending == null || pending.stateDigest != expectedStateDigest) {
          throw const V3LmfPersistenceConflictException(
            'v3 handshake completion lost its pending state',
          );
        }
        if (pending.remoteDeviceId != null &&
            pending.remoteDeviceId != remoteDeviceId) {
          throw const V3LmfPersistenceConflictException(
            'v3 handshake remote device binding diverged',
          );
        }
        if (_completions.length >= maxCompletions) {
          throw const V3LmfPersistenceLimitException(
            'v3 handshake completion capacity exceeded',
          );
        }
        final candidate = _completionFromPending(
          pending,
          remoteDeviceId: remoteDeviceId,
          terminalMessageId: terminalMessageId,
          sessionId: sessionId,
          checkpointDigest: checkpointDigest,
          terminalRecord: terminalRecord,
          completedAt: timestamp,
        );
        try {
          if (!_completionCoversPending(candidate, pending)) {
            throw const V3LmfPersistenceConflictException(
              'v3 handshake confirmation does not cover pending state',
            );
          }
          final storageId = await _store.write(_encodeCompletion(candidate));
          final durable = _copyCompletion(candidate, storageId: storageId);
          _completions[handshakeId] = durable;
          try {
            await _store.delete(pending.storageId);
          } catch (_) {
            _writeRecoveryRequired = true;
            rethrow;
          }
          _pending.remove(handshakeId);
          _totalPendingBytes -= pending.retainedBytes;
          pending._close();
          return durable;
        } catch (_) {
          _writeRecoveryRequired = true;
          rethrow;
        } finally {
          candidate._close();
        }
      } finally {
        _wipe(terminalRecord);
      }
    });
  }

  Future<void> close({V3HandshakePersistenceAuthority? authority}) {
    return _serialized(() async {
      _ensureAuthority(authority);
      if (_closed) return;
      _closed = true;
      for (final value in _pending.values) {
        value._close();
      }
      _pending.clear();
      for (final value in _completions.values) {
        value._close();
      }
      _completions.clear();
      _totalPendingBytes = 0;
    });
  }

  Future<V3DurablePendingHandshake> _persistPending({
    required V3DurablePendingHandshake Function() candidateBuilder,
    required V3HandshakePersistenceAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final candidate = candidateBuilder();
      try {
        if (_completions.containsKey(candidate.handshakeId)) {
          throw const V3LmfPersistenceConflictException(
            'completed v3 handshake cannot become pending again',
          );
        }
        final existing = _pending[candidate.handshakeId];
        if (existing != null) {
          if (!_samePending(existing, candidate)) {
            throw const V3LmfPersistenceConflictException(
              'v3 handshake pending state diverged',
            );
          }
          return existing;
        }
        _checkPendingCapacity(
          candidate.remoteIdentityDigest,
          candidate.retainedBytes,
        );
        try {
          final storageId = await _store.write(_encodePending(candidate));
          final durable = _copyPending(candidate, storageId: storageId);
          _pending[durable.handshakeId] = durable;
          _totalPendingBytes += durable.retainedBytes;
          return durable;
        } catch (_) {
          _writeRecoveryRequired = true;
          rethrow;
        }
      } finally {
        candidate._close();
      }
    });
  }

  void _checkPendingCapacity(String remoteIdentityDigest, int additionalBytes) {
    if (_pending.length >= maxPending ||
        _totalPendingBytes + additionalBytes > maxTotalPendingBytes) {
      throw const V3LmfPersistenceLimitException(
        'v3 handshake pending capacity exceeded',
      );
    }
    final remoteCount = _pending.values
        .where((value) => value.remoteIdentityDigest == remoteIdentityDigest)
        .length;
    if (remoteCount >= maxPendingPerRemoteIdentity) {
      throw const V3LmfPersistenceLimitException(
        'v3 per-contact pending handshake capacity exceeded',
      );
    }
  }

  V3DurablePendingHandshake _decodePending(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    const keys = <String>{
      'kind',
      'v',
      'handshakeId',
      'role',
      'mode',
      'capabilities',
      'localIdentityDigest',
      'remoteIdentityDigest',
      'localDeviceId',
      'remoteDeviceId',
      'outboundKind',
      'outboundMessageId',
      'stateDigest',
      'pendingState',
      'outboundRecord',
      'createdAt',
      'recordDigest',
      'reserved',
    };
    if (payload.length != keys.length ||
        !payload.keys.every(keys.contains) ||
        payload['kind'] != pendingRecordKind ||
        payload['v'] != _recordVersion ||
        payload['handshakeId'] is! String ||
        payload['role'] is! int ||
        payload['mode'] is! int ||
        payload['capabilities'] is! int ||
        payload['localIdentityDigest'] is! String ||
        payload['remoteIdentityDigest'] is! String ||
        payload['localDeviceId'] is! String ||
        (payload['remoteDeviceId'] != null &&
            payload['remoteDeviceId'] is! String) ||
        payload['outboundKind'] is! int ||
        payload['outboundMessageId'] is! String ||
        payload['stateDigest'] is! String ||
        payload['pendingState'] is! String ||
        payload['outboundRecord'] is! String ||
        payload['createdAt'] is! int ||
        payload['recordDigest'] is! String ||
        payload['reserved'] != 0) {
      throw const FormatException('Invalid Layergram v3 pending envelope');
    }
    final state = _decodeArmored(payload['pendingState'] as String, 4096);
    final outbound = _decodeArmored(
      payload['outboundRecord'] as String,
      V3HandshakeCodec.replyBytes,
    );
    try {
      final candidate = _validatedPending(
        storageId: stored.storageId,
        handshakeId: payload['handshakeId'] as String,
        role: V3SessionRole.fromWireId(payload['role'] as int),
        mode: V3HandshakeMode.fromWireId(payload['mode'] as int),
        capabilities: payload['capabilities'] as int,
        localIdentityDigest: payload['localIdentityDigest'] as String,
        remoteIdentityDigest: payload['remoteIdentityDigest'] as String,
        localDeviceId: payload['localDeviceId'] as String,
        remoteDeviceId: payload['remoteDeviceId'] as String?,
        outboundKind: V3HandshakeRecordKind.fromWireId(
          payload['outboundKind'] as int,
        ),
        outboundMessageId: payload['outboundMessageId'] as String,
        stateDigest: payload['stateDigest'] as String,
        encodedState: state,
        outboundRecord: outbound,
        createdAt: _timestamp(payload['createdAt'] as int),
      );
      if (candidate.recordDigest != payload['recordDigest']) {
        candidate._close();
        throw const FormatException(
          'Mismatched Layergram v3 pending record digest',
        );
      }
      return candidate;
    } finally {
      _wipe(state);
      _wipe(outbound);
    }
  }

  V3HandshakeCompletionBinding _decodeCompletion(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    const keys = <String>{
      'kind',
      'v',
      'handshakeId',
      'role',
      'mode',
      'capabilities',
      'localIdentityDigest',
      'remoteIdentityDigest',
      'localDeviceId',
      'remoteDeviceId',
      'outboundKind',
      'outboundMessageId',
      'pendingStateDigest',
      'terminalMessageId',
      'terminalRecord',
      'sessionId',
      'checkpointDigest',
      'completedAt',
      'recordDigest',
      'reserved',
    };
    if (payload.length != keys.length ||
        !payload.keys.every(keys.contains) ||
        payload['kind'] != completionRecordKind ||
        payload['v'] != _recordVersion ||
        payload['handshakeId'] is! String ||
        payload['role'] is! int ||
        payload['mode'] is! int ||
        payload['capabilities'] is! int ||
        payload['localIdentityDigest'] is! String ||
        payload['remoteIdentityDigest'] is! String ||
        payload['localDeviceId'] is! String ||
        payload['remoteDeviceId'] is! String ||
        payload['outboundKind'] is! int ||
        payload['outboundMessageId'] is! String ||
        payload['pendingStateDigest'] is! String ||
        payload['terminalMessageId'] is! String ||
        payload['terminalRecord'] is! String ||
        payload['sessionId'] is! String ||
        payload['checkpointDigest'] is! String ||
        payload['completedAt'] is! int ||
        payload['recordDigest'] is! String ||
        payload['reserved'] != 0) {
      throw const FormatException('Invalid Layergram v3 completion envelope');
    }
    final terminalRecord = _decodeArmored(
      payload['terminalRecord'] as String,
      V3HandshakeCodec.confirmationBytes,
    );
    try {
      final candidate = _validatedCompletion(
        storageId: stored.storageId,
        handshakeId: payload['handshakeId'] as String,
        role: V3SessionRole.fromWireId(payload['role'] as int),
        mode: V3HandshakeMode.fromWireId(payload['mode'] as int),
        capabilities: payload['capabilities'] as int,
        localIdentityDigest: payload['localIdentityDigest'] as String,
        remoteIdentityDigest: payload['remoteIdentityDigest'] as String,
        localDeviceId: payload['localDeviceId'] as String,
        remoteDeviceId: payload['remoteDeviceId'] as String,
        outboundKind: V3HandshakeRecordKind.fromWireId(
          payload['outboundKind'] as int,
        ),
        outboundMessageId: payload['outboundMessageId'] as String,
        pendingStateDigest: payload['pendingStateDigest'] as String,
        terminalMessageId: payload['terminalMessageId'] as String,
        terminalRecord: terminalRecord,
        sessionId: payload['sessionId'] as String,
        checkpointDigest: payload['checkpointDigest'] as String,
        completedAt: _timestamp(payload['completedAt'] as int),
      );
      if (candidate.recordDigest != payload['recordDigest']) {
        candidate._close();
        throw const FormatException(
          'Mismatched Layergram v3 completion record digest',
        );
      }
      return candidate;
    } finally {
      _wipe(terminalRecord);
    }
  }

  Future<void> _deleteIgnoringFailure(String storageId) async {
    try {
      await _store.delete(storageId);
    } catch (_) {
      // Exact duplicates and tombstone-covered pending records are retried on
      // the next restore; the selected record remains authoritative.
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

  void _ensureAuthority(V3HandshakePersistenceAuthority? authority) {
    final claimed = _authority;
    if (claimed == null) {
      if (authority != null) {
        throw StateError('Layergram v3 handshake authority is invalid');
      }
      return;
    }
    if (!identical(claimed, authority)) {
      throw StateError(
        'Layergram v3 handshake repository is owned by its controller',
      );
    }
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('Layergram v3 handshake repository is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored || _writeRecoveryRequired) {
      throw StateError(
        'Layergram v3 handshake repository requires fresh restore',
      );
    }
  }
}

/// Public, non-secret result returned only after the matching HP3 state is
/// durable. [outboundRecord] is the exact canonical record to wrap/export.
final class V3DurableHandshakeOutbound {
  const V3DurableHandshakeOutbound({
    required this.handshakeId,
    required this.kind,
    required this.messageId,
    required this.stateDigest,
    required this.outboundRecord,
    required this.restored,
  });

  final String handshakeId;
  final V3HandshakeRecordKind kind;
  final String messageId;
  final String stateDigest;
  final Uint8List outboundRecord;
  final bool restored;
}

/// Non-secret routing metadata for one completed HP3 -> TR3 session.
///
/// Identity values are canonical SHA-384 binding digests, while device and
/// session identifiers are canonical base64url strings. This lets the
/// application map a contact to one or more installation sessions without
/// exposing HP3 or TR3 secret state.
final class V3CompletedHandshakeSession {
  const V3CompletedHandshakeSession({
    required this.handshakeId,
    required this.role,
    required this.mode,
    required this.localIdentityDigest,
    required this.remoteIdentityDigest,
    required this.localDeviceId,
    required this.remoteDeviceId,
    required this.sessionId,
    required this.checkpointDigest,
    required this.completedAt,
  });

  final String handshakeId;
  final V3SessionRole role;
  final V3HandshakeMode mode;
  final String localIdentityDigest;
  final String remoteIdentityDigest;
  final String localDeviceId;
  final String remoteDeviceId;
  final String sessionId;
  final String checkpointDigest;
  final DateTime completedAt;
}

/// Single authority that performs cryptography before a durable write but
/// never releases the resulting offer/reply until that write succeeds.
final class V3HandshakePersistenceController {
  V3HandshakePersistenceController({
    required V3HandshakePendingRepository repository,
    V3InitialSessionHandoffAuthority? initialHandoffAuthority,
  })  : _repository = repository,
        _initialHandoffAuthority = initialHandoffAuthority;

  final V3HandshakePendingRepository _repository;
  final V3InitialSessionHandoffAuthority? _initialHandoffAuthority;
  Future<void> _operationTail = Future<void>.value();
  V3HandshakePersistenceAuthority? _authority;
  bool _initialHandoffAuthorityClaimed = false;
  bool _restored = false;
  bool _closed = false;
  bool _recoveryRequired = false;

  bool get requiresRecovery =>
      _recoveryRequired || _repository.requiresRecovery;

  bool get isRestored => _restored && !requiresRecovery && !_closed;

  /// Transfers the initial-session subset of this controller to the sole
  /// handoff coordinator. A forged capability is rejected without mutation.
  Future<void> claimInitialHandoffAuthority(
    V3InitialSessionHandoffAuthority authority,
  ) {
    return _serialized(() async {
      _ensureReady();
      _ensureConfiguredInitialHandoffAuthority(authority);
      if (_initialHandoffAuthorityClaimed) {
        throw StateError(
          'Layergram v3 handshake handoff authority was already claimed',
        );
      }
      _initialHandoffAuthorityClaimed = true;
    });
  }

  Future<V3HandshakeControllerRestoreResult> restore() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored || _authority != null) {
        throw StateError('Layergram v3 handshake controller was restored');
      }
      try {
        _authority = await _repository.claimControllerAuthority();
        final result = await _repository.restore(authority: _authority);
        _restored = true;
        return V3HandshakeControllerRestoreResult(
          pendingOutbound: result.pending
              .map((value) => _outbound(value, restored: true))
              .toList(growable: false),
          completionCount: result.completions.length,
          removedObsoleteRecords: result.removedObsoleteRecords,
          suppressedCompletedPending: result.suppressedCompletedPending,
        );
      } catch (_) {
        _recoveryRequired = true;
        rethrow;
      }
    });
  }

  Future<List<V3DurableHandshakeOutbound>> pendingOutbound() {
    return _serialized(() async {
      _ensureReady();
      return _repository
          .pending(authority: _authority)
          .map((value) => _outbound(value, restored: true))
          .toList(growable: false);
    });
  }

  /// Returns the newest exact pending export for one local device/peer/mode.
  ///
  /// This lets a manual carrier retry a lost setup message without creating a
  /// second HP3 state or rerunning X25519/ML-KEM. Only public outbound bytes
  /// leave the controller; the matching pending state remains encrypted.
  Future<V3DurableHandshakeOutbound?> latestPendingOutboundForPeer({
    required V3LocalIdentityHandle localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode mode,
    Set<String> excludedHandshakeIds = const <String>{},
  }) {
    return _serialized(() async {
      _ensureReady();
      if (localIdentity.isClosed || localDevice.isClosed) {
        throw StateError('Layergram v3 identity/device handle is closed');
      }
      final localDigest = _identityDigest(localIdentity.publicIdentity);
      final remoteDigest = _identityDigest(remoteIdentity);
      final localDeviceId = localDevice.deviceId;
      try {
        final matches = _repository
            .pending(authority: _authority)
            .where(
              (pending) =>
                  pending.localIdentityDigest == localDigest.armored &&
                  pending.remoteIdentityDigest == remoteDigest.armored &&
                  pending.localDeviceId == _id(localDeviceId) &&
                  pending.mode == mode &&
                  !excludedHandshakeIds.contains(pending.handshakeId),
            )
            .toList(growable: false)
          ..sort((left, right) {
            final byCreated = right.createdAt.compareTo(left.createdAt);
            if (byCreated != 0) return byCreated;
            return right.handshakeId.compareTo(left.handshakeId);
          });
        return matches.isEmpty
            ? null
            : _outbound(matches.first, restored: true);
      } finally {
        _wipe(localDigest.bytes);
        _wipe(remoteDigest.bytes);
        _wipe(localDeviceId);
      }
    });
  }

  /// Returns the newest retained initiator confirmation for one peer/mode.
  /// The exact public record remains retryable because a manual carrier can
  /// lose the confirmation even after the initiator committed its session.
  Future<V3DurableHandshakeOutbound?> latestCompletedConfirmationForPeer({
    required V3LocalIdentityHandle localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode mode,
    Set<String> excludedHandshakeIds = const <String>{},
  }) {
    return _serialized(() async {
      _ensureReady();
      if (localIdentity.isClosed || localDevice.isClosed) {
        throw StateError('Layergram v3 identity/device handle is closed');
      }
      final localDigest = _identityDigest(localIdentity.publicIdentity);
      final remoteDigest = _identityDigest(remoteIdentity);
      final localDeviceId = localDevice.deviceId;
      try {
        final matches = _repository
            .completions(authority: _authority)
            .where(
              (completion) =>
                  completion.role == V3SessionRole.initiator &&
                  completion.localIdentityDigest == localDigest.armored &&
                  completion.remoteIdentityDigest == remoteDigest.armored &&
                  completion.localDeviceId == _id(localDeviceId) &&
                  completion.mode == mode &&
                  !excludedHandshakeIds.contains(completion.handshakeId),
            )
            .toList(growable: false)
          ..sort((left, right) {
            final byCompleted = right.completedAt.compareTo(left.completedAt);
            if (byCompleted != 0) return byCompleted;
            return right.handshakeId.compareTo(left.handshakeId);
          });
        if (matches.isEmpty) return null;
        final completion = matches.first;
        return V3DurableHandshakeOutbound(
          handshakeId: completion.handshakeId,
          kind: V3HandshakeRecordKind.confirmation,
          messageId: completion.terminalMessageId,
          stateDigest: completion.pendingStateDigest,
          outboundRecord: completion.terminalRecord,
          restored: true,
        );
      } finally {
        _wipe(localDigest.bytes);
        _wipe(remoteDigest.bytes);
        _wipe(localDeviceId);
      }
    });
  }

  /// Returns non-secret pending handshake IDs for one peer. The application
  /// policy coordinator uses this under the same serialized runtime boundary
  /// as mode reset so delayed setup frames cannot cross that boundary.
  Future<Set<String>> pendingHandshakeIdsForPeer({
    required V3LocalIdentityHandle localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3PublicIdentity remoteIdentity,
  }) {
    return _serialized(() async {
      _ensureReady();
      if (localIdentity.isClosed || localDevice.isClosed) {
        throw StateError('Layergram v3 identity/device handle is closed');
      }
      final localDigest = _identityDigest(localIdentity.publicIdentity);
      final remoteDigest = _identityDigest(remoteIdentity);
      final localDeviceId = localDevice.deviceId;
      try {
        return Set<String>.unmodifiable(
          _repository
              .pending(authority: _authority)
              .where(
                (pending) =>
                    pending.localIdentityDigest == localDigest.armored &&
                    pending.remoteIdentityDigest == remoteDigest.armored &&
                    pending.localDeviceId == _id(localDeviceId),
              )
              .map((pending) => pending.handshakeId),
        );
      } finally {
        _wipe(localDigest.bytes);
        _wipe(remoteDigest.bytes);
        _wipe(localDeviceId);
      }
    });
  }

  Future<List<V3CompletedHandshakeSession>> completedSessions() {
    return _serialized(() async {
      _ensureReady();
      return _repository
          .completions(authority: _authority)
          .map(
            (value) => V3CompletedHandshakeSession(
              handshakeId: value.handshakeId,
              role: value.role,
              mode: value.mode,
              localIdentityDigest: value.localIdentityDigest,
              remoteIdentityDigest: value.remoteIdentityDigest,
              localDeviceId: value.localDeviceId,
              remoteDeviceId: value.remoteDeviceId,
              sessionId: value.sessionId,
              checkpointDigest: value.checkpointDigest,
              completedAt: value.completedAt,
            ),
          )
          .toList(growable: false);
    });
  }

  Future<V3DurableHandshakeOutbound?> pendingOutboundForId(
    String handshakeId,
  ) {
    return _serialized(() async {
      _ensureReady();
      final value = _repository.pendingForId(
        handshakeId,
        authority: _authority,
      );
      return value == null ? null : _outbound(value, restored: true);
    });
  }

  /// Returns the non-secret digest that binds an HP3 pending/completed state.
  ///
  /// The application coordinator needs this for idempotent replay of a
  /// responder confirmation after the secret pending record has already been
  /// replaced by its compact completion tombstone. Returning only the digest
  /// does not expose the encoded HP3 state or any private key material.
  Future<String?> stateDigestForId(String handshakeId) {
    return _serialized(() async {
      _ensureReady();
      final pending = _repository.pendingForId(
        handshakeId,
        authority: _authority,
      );
      final completion = _repository.completionForId(
        handshakeId,
        authority: _authority,
      );
      final pendingDigest = pending?.stateDigest;
      final completionDigest = completion?.pendingStateDigest;
      if (pendingDigest != null &&
          completionDigest != null &&
          pendingDigest != completionDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 handshake pending/completion state diverged',
        );
      }
      return pendingDigest ?? completionDigest;
    });
  }

  /// Returns the exact initiator confirmation retained by the completion
  /// tombstone, allowing loss recovery without rebuilding session material.
  Future<V3DurableHandshakeOutbound?> completedConfirmationForId(
    String handshakeId,
  ) {
    return _serialized(() async {
      _ensureReady();
      final completion = _repository.completionForId(
        handshakeId,
        authority: _authority,
      );
      if (completion == null || completion.role != V3SessionRole.initiator) {
        return null;
      }
      return V3DurableHandshakeOutbound(
        handshakeId: completion.handshakeId,
        kind: V3HandshakeRecordKind.confirmation,
        messageId: completion.terminalMessageId,
        stateDigest: completion.pendingStateDigest,
        outboundRecord: completion.terminalRecord,
        restored: true,
      );
    });
  }

  /// Returns a detached binding used only by the crash-recovery handoff
  /// coordinator to validate and collect an already committed preparation.
  Future<V3CommittedHandshakeHandoff?> committedHandoffForId(
    String handshakeId, {
    required V3InitialSessionHandoffAuthority authority,
  }) {
    return _serialized(() async {
      _ensureReady();
      _ensureClaimedInitialHandoffAuthority(authority);
      final completion = _repository.completionForId(
        handshakeId,
        authority: _authority,
      );
      if (completion == null) return null;
      return V3CommittedHandshakeHandoff(
        handshakeId: completion.handshakeId,
        role: completion.role,
        pendingStateDigest: completion.pendingStateDigest,
        confirmationRecord: completion.terminalRecord,
        sessionId: completion.sessionId,
        checkpointDigest: completion.checkpointDigest,
      );
    });
  }

  /// Returns detached bindings for restore-time checkpoint reconciliation.
  Future<List<V3CommittedHandshakeHandoff>> committedHandoffs({
    required V3InitialSessionHandoffAuthority authority,
  }) {
    return _serialized(() async {
      _ensureReady();
      _ensureClaimedInitialHandoffAuthority(authority);
      return _repository
          .completions(authority: _authority)
          .map(
            (completion) => V3CommittedHandshakeHandoff(
              handshakeId: completion.handshakeId,
              role: completion.role,
              pendingStateDigest: completion.pendingStateDigest,
              confirmationRecord: completion.terminalRecord,
              sessionId: completion.sessionId,
              checkpointDigest: completion.checkpointDigest,
            ),
          )
          .toList(growable: false);
    });
  }

  /// Fails stopped if a higher-level initial-session handoff has crossed a
  /// durable boundary but cannot finish in the current process instance.
  Future<void> markInitialHandoffRecoveryRequired({
    required V3InitialSessionHandoffAuthority authority,
  }) {
    return _serialized(() async {
      _ensureOpen();
      _ensureConfiguredInitialHandoffAuthority(authority);
      _recoveryRequired = true;
    });
  }

  Future<V3DurableHandshakeOutbound> createOffer({
    required V3LocalIdentityHandle localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3PublicIdentity remoteIdentity,
    required V3HandshakeMode mode,
    Set<String> excludedHandshakeIds = const <String>{},
    DateTime? createdAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final remoteDigest = _identityDigest(remoteIdentity);
      final localDigest = _identityDigest(localIdentity.publicIdentity);
      final localDeviceId = localDevice.deviceId;
      try {
        if (mode == V3HandshakeMode.maximum) {
          for (final pending in _repository.pending(authority: _authority)) {
            if (pending.remoteIdentityDigest != remoteDigest.armored) continue;
            if (excludedHandshakeIds.contains(pending.handshakeId)) continue;
            if (pending.role == V3SessionRole.initiator &&
                pending.mode == mode &&
                pending.localIdentityDigest == localDigest.armored &&
                pending.localDeviceId == _id(localDeviceId)) {
              return _outbound(pending, restored: true);
            }
            throw const V3LmfPersistenceConflictException(
              'maximum-mode v3 contact already has a pending session',
            );
          }
        }
        // Completed sessions are retained for delayed ACKs, recovery and
        // explicit policy transitions. The application policy boundary picks
        // only sessions completed after the latest mode change; exclusivity
        // is therefore enforced among pending handshakes, not by deleting
        // historical completion bindings.
        await _repository.preflightCreate(
          remoteIdentityDigest: remoteDigest.armored,
          additionalBytes: V3HandshakePendingStateCodec.initiatorEncodedBytes +
              V3HandshakeCodec.offerBytes,
          authority: _authority,
        );
      } finally {
        _wipe(remoteDigest.bytes);
        _wipe(localDigest.bytes);
        _wipe(localDeviceId);
      }
      V3InitiatorPendingHandshake? state;
      try {
        state = await V3HybridHandshake.createOffer(
          localIdentity: localIdentity,
          localDevice: localDevice,
          remoteIdentity: remoteIdentity,
          mode: mode,
        );
        final durable = await _repository.persistInitiator(
          state: state,
          createdAt: createdAt,
          authority: _authority,
        );
        return _outbound(durable, restored: false);
      } catch (_) {
        if (_repository.requiresRecovery) _recoveryRequired = true;
        rethrow;
      } finally {
        state?.close();
      }
    });
  }

  Future<V3DurableHandshakeOutbound> createReply({
    required V3LocalIdentityHandle localIdentity,
    required V3LocalDeviceHandle localDevice,
    required V3PublicIdentity initiatorIdentity,
    required V3HandshakeOffer offer,
    required V3HandshakeMode expectedMode,
    Set<String> excludedHandshakeIds = const <String>{},
    DateTime? createdAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final handshakeId = _id(offer.handshakeId);
      final existing = _repository.pendingForId(
        handshakeId,
        authority: _authority,
      );
      if (existing != null) {
        if (excludedHandshakeIds.contains(handshakeId)) {
          throw const V3LmfPersistenceConflictException(
            'excluded v3 handshake offer was replayed',
          );
        }
        final localDigest = _identityDigest(localIdentity.publicIdentity);
        final remoteDigest = _identityDigest(initiatorIdentity);
        final localDeviceId = localDevice.deviceId;
        final offerBytes = V3HandshakeCodec.encodeOffer(offer);
        V3ResponderPendingHandshake? restored;
        Uint8List? restoredOfferBytes;
        try {
          restored = existing.decodeResponder();
          restoredOfferBytes = V3HandshakeCodec.encodeOffer(restored.offer);
          if (localIdentity.isClosed ||
              localDevice.isClosed ||
              existing.role != V3SessionRole.responder ||
              existing.mode != expectedMode ||
              existing.localIdentityDigest != localDigest.armored ||
              existing.remoteIdentityDigest != remoteDigest.armored ||
              existing.localDeviceId != _id(localDeviceId) ||
              !_bytesEqual(restoredOfferBytes, offerBytes)) {
            throw const V3LmfPersistenceConflictException(
              'v3 handshake reply retry diverged',
            );
          }
        } finally {
          restored?.close();
          if (restoredOfferBytes != null) _wipe(restoredOfferBytes);
          _wipe(localDigest.bytes);
          _wipe(remoteDigest.bytes);
          _wipe(localDeviceId);
          _wipe(offerBytes);
        }
        return _outbound(existing, restored: true);
      }
      if (_repository.completionForId(
            handshakeId,
            authority: _authority,
          ) !=
          null) {
        throw const V3LmfPersistenceConflictException(
          'completed v3 handshake offer was replayed',
        );
      }
      final initiatorDigest = _identityDigest(initiatorIdentity);
      try {
        _enforceExclusivePendingSession(
          remoteIdentityDigest: initiatorDigest.armored,
          requestedMode: expectedMode,
          excludedHandshakeIds: excludedHandshakeIds,
        );
        await _repository.preflightCreate(
          remoteIdentityDigest: initiatorDigest.armored,
          additionalBytes: V3HandshakePendingStateCodec.responderEncodedBytes +
              V3HandshakeCodec.replyBytes,
          authority: _authority,
        );
      } finally {
        _wipe(initiatorDigest.bytes);
      }
      V3ResponderPendingHandshake? state;
      try {
        state = await V3HybridHandshake.createReply(
          localIdentity: localIdentity,
          localDevice: localDevice,
          initiatorIdentity: initiatorIdentity,
          offer: offer,
          expectedMode: expectedMode,
        );
        final durable = await _repository.persistResponder(
          state: state,
          createdAt: createdAt,
          authority: _authority,
        );
        return _outbound(durable, restored: false);
      } catch (_) {
        if (_repository.requiresRecovery) _recoveryRequired = true;
        rethrow;
      } finally {
        state?.close();
      }
    });
  }

  void _enforceExclusivePendingSession({
    required String remoteIdentityDigest,
    required V3HandshakeMode requestedMode,
    Set<String> excludedHandshakeIds = const <String>{},
  }) {
    for (final pending in _repository.pending(authority: _authority)) {
      if (pending.remoteIdentityDigest != remoteIdentityDigest) continue;
      if (excludedHandshakeIds.contains(pending.handshakeId)) continue;
      if (requestedMode == V3HandshakeMode.maximum ||
          pending.mode == V3HandshakeMode.maximum) {
        throw const V3LmfPersistenceConflictException(
          'maximum-mode v3 contact already has a pending session',
        );
      }
    }
  }

  Future<V3InitiatorPendingHandshake> resumeInitiator(String handshakeId) {
    return _serialized(() async {
      _ensureReady();
      final pending = _repository.pendingForId(
        handshakeId,
        authority: _authority,
      );
      if (pending == null) {
        throw StateError('Layergram v3 initiator pending state was not found');
      }
      return pending.decodeInitiator();
    });
  }

  Future<V3ResponderPendingHandshake> resumeResponder(String handshakeId) {
    return _serialized(() async {
      _ensureReady();
      final pending = _repository.pendingForId(
        handshakeId,
        authority: _authority,
      );
      if (pending == null) {
        throw StateError('Layergram v3 responder pending state was not found');
      }
      return pending.decodeResponder();
    });
  }

  Future<V3HandshakeCompletionBinding> markHandoffCommitted({
    required String handshakeId,
    required String expectedStateDigest,
    required V3HandshakeConfirmation confirmation,
    required Uint8List sessionId,
    required String checkpointDigest,
    required DateTime completedAt,
    required V3InitialSessionHandoffAuthority authority,
  }) {
    return _serialized(() async {
      _ensureReady();
      _ensureClaimedInitialHandoffAuthority(authority);
      return _repository.markHandoffCommitted(
        handshakeId: handshakeId,
        expectedStateDigest: expectedStateDigest,
        confirmation: confirmation,
        sessionId: _id(sessionId),
        checkpointDigest: checkpointDigest,
        completedAt: completedAt,
        authority: _authority,
      );
    });
  }

  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      await _repository.close(authority: _authority);
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
      throw StateError('Layergram v3 handshake controller is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored || requiresRecovery) {
      throw StateError(
        'Layergram v3 handshake controller requires fresh restore',
      );
    }
  }

  void _ensureConfiguredInitialHandoffAuthority(
    V3InitialSessionHandoffAuthority authority,
  ) {
    if (!identical(_initialHandoffAuthority, authority)) {
      throw StateError('Layergram v3 initial handoff authority is invalid');
    }
  }

  void _ensureClaimedInitialHandoffAuthority(
    V3InitialSessionHandoffAuthority authority,
  ) {
    _ensureConfiguredInitialHandoffAuthority(authority);
    if (!_initialHandoffAuthorityClaimed) {
      throw StateError(
        'Layergram v3 initial handoff authority was not claimed',
      );
    }
  }
}

V3DurablePendingHandshake _fromInitiator(
  V3InitiatorPendingHandshake state, {
  required DateTime createdAt,
}) {
  final encoded = V3HandshakePendingStateCodec.encodeInitiator(state);
  final outbound = V3HandshakeCodec.encodeOffer(state.offer);
  try {
    return _validatedPending(
      storageId: '',
      handshakeId: _id(state.offer.handshakeId),
      role: V3SessionRole.initiator,
      mode: state.offer.mode,
      capabilities: state.offer.capabilities,
      localIdentityDigest: _id(state.offer.initiatorIdentityDigest),
      remoteIdentityDigest: _id(state.offer.responderIdentityDigest),
      localDeviceId: _id(state.offer.initiatorDeviceId),
      remoteDeviceId: null,
      outboundKind: V3HandshakeRecordKind.offer,
      outboundMessageId: _id(state.offer.messageId),
      stateDigest: _stateDigest(encoded),
      encodedState: encoded,
      outboundRecord: outbound,
      createdAt: createdAt,
    );
  } finally {
    _wipe(encoded);
    _wipe(outbound);
  }
}

V3DurablePendingHandshake _fromResponder(
  V3ResponderPendingHandshake state, {
  required DateTime createdAt,
}) {
  final encoded = V3HandshakePendingStateCodec.encodeResponder(state);
  final outbound = V3HandshakeCodec.encodeReply(state.reply);
  try {
    return _validatedPending(
      storageId: '',
      handshakeId: _id(state.reply.handshakeId),
      role: V3SessionRole.responder,
      mode: state.reply.mode,
      capabilities: state.reply.capabilities,
      localIdentityDigest: _id(state.reply.responderIdentityDigest),
      remoteIdentityDigest: _id(state.reply.initiatorIdentityDigest),
      localDeviceId: _id(state.reply.responderDeviceId),
      remoteDeviceId: _id(state.reply.initiatorDeviceId),
      outboundKind: V3HandshakeRecordKind.reply,
      outboundMessageId: _id(state.reply.messageId),
      stateDigest: _stateDigest(encoded),
      encodedState: encoded,
      outboundRecord: outbound,
      createdAt: createdAt,
    );
  } finally {
    _wipe(encoded);
    _wipe(outbound);
  }
}

V3DurablePendingHandshake _validatedPending({
  required String storageId,
  required String handshakeId,
  required V3SessionRole role,
  required V3HandshakeMode mode,
  required int capabilities,
  required String localIdentityDigest,
  required String remoteIdentityDigest,
  required String localDeviceId,
  required String? remoteDeviceId,
  required V3HandshakeRecordKind outboundKind,
  required String outboundMessageId,
  required String stateDigest,
  required Uint8List encodedState,
  required Uint8List outboundRecord,
  required DateTime createdAt,
}) {
  final timestamp = _validatedTimestamp(createdAt);
  if (!_isCanonicalNonZeroId(handshakeId, 16) ||
      capabilities != V3HandshakeCodec.requiredCapabilities ||
      !_isCanonicalNonZeroId(localIdentityDigest, 48) ||
      !_isCanonicalNonZeroId(remoteIdentityDigest, 48) ||
      localIdentityDigest == remoteIdentityDigest ||
      !_isCanonicalNonZeroId(localDeviceId, 16) ||
      (remoteDeviceId != null && !_isCanonicalNonZeroId(remoteDeviceId, 16)) ||
      !_isCanonicalNonZeroId(outboundMessageId, 16) ||
      !_isCanonicalNonZeroId(stateDigest, 32) ||
      stateDigest != _stateDigest(encodedState) ||
      encodedState.isEmpty ||
      encodedState.length > 4096) {
    throw const FormatException('Invalid Layergram v3 durable pending state');
  }
  V3InitiatorPendingHandshake? initiator;
  V3ResponderPendingHandshake? responder;
  try {
    switch (role) {
      case V3SessionRole.initiator:
        if (outboundKind != V3HandshakeRecordKind.offer ||
            remoteDeviceId != null ||
            outboundRecord.length != V3HandshakeCodec.offerBytes) {
          throw const FormatException(
            'Invalid Layergram v3 initiator pending binding',
          );
        }
        initiator = V3HandshakePendingStateCodec.decodeInitiator(encodedState);
        final offer = initiator.offer;
        if (_id(offer.handshakeId) != handshakeId ||
            offer.mode != mode ||
            offer.capabilities != capabilities ||
            _id(offer.initiatorIdentityDigest) != localIdentityDigest ||
            _id(offer.responderIdentityDigest) != remoteIdentityDigest ||
            _id(offer.initiatorDeviceId) != localDeviceId ||
            _id(offer.messageId) != outboundMessageId ||
            !_bytesEqual(V3HandshakeCodec.encodeOffer(offer), outboundRecord)) {
          throw const FormatException(
            'Mismatched Layergram v3 initiator pending state',
          );
        }
      case V3SessionRole.responder:
        if (outboundKind != V3HandshakeRecordKind.reply ||
            remoteDeviceId == null ||
            outboundRecord.length != V3HandshakeCodec.replyBytes) {
          throw const FormatException(
            'Invalid Layergram v3 responder pending binding',
          );
        }
        responder = V3HandshakePendingStateCodec.decodeResponder(encodedState);
        final reply = responder.reply;
        if (_id(reply.handshakeId) != handshakeId ||
            reply.mode != mode ||
            reply.capabilities != capabilities ||
            _id(reply.responderIdentityDigest) != localIdentityDigest ||
            _id(reply.initiatorIdentityDigest) != remoteIdentityDigest ||
            _id(reply.responderDeviceId) != localDeviceId ||
            _id(reply.initiatorDeviceId) != remoteDeviceId ||
            _id(reply.messageId) != outboundMessageId ||
            !_bytesEqual(V3HandshakeCodec.encodeReply(reply), outboundRecord)) {
          throw const FormatException(
            'Mismatched Layergram v3 responder pending state',
          );
        }
    }
  } finally {
    initiator?.close();
    responder?.close();
  }
  final digest = _pendingRecordDigest(
    handshakeId: handshakeId,
    role: role,
    mode: mode,
    capabilities: capabilities,
    localIdentityDigest: localIdentityDigest,
    remoteIdentityDigest: remoteIdentityDigest,
    localDeviceId: localDeviceId,
    remoteDeviceId: remoteDeviceId,
    outboundKind: outboundKind,
    outboundMessageId: outboundMessageId,
    stateDigest: stateDigest,
    encodedState: encodedState,
    outboundRecord: outboundRecord,
    createdAt: timestamp,
  );
  return V3DurablePendingHandshake._(
    storageId: storageId,
    handshakeId: handshakeId,
    role: role,
    mode: mode,
    capabilities: capabilities,
    localIdentityDigest: localIdentityDigest,
    remoteIdentityDigest: remoteIdentityDigest,
    localDeviceId: localDeviceId,
    remoteDeviceId: remoteDeviceId,
    outboundKind: outboundKind,
    outboundMessageId: outboundMessageId,
    stateDigest: stateDigest,
    encodedState: encodedState,
    outboundRecord: outboundRecord,
    createdAt: timestamp,
    recordDigest: digest,
  );
}

V3HandshakeCompletionBinding _completionFromPending(
  V3DurablePendingHandshake pending, {
  required String remoteDeviceId,
  required String terminalMessageId,
  required String sessionId,
  required String checkpointDigest,
  required Uint8List terminalRecord,
  required DateTime completedAt,
}) =>
    _validatedCompletion(
      storageId: '',
      handshakeId: pending.handshakeId,
      role: pending.role,
      mode: pending.mode,
      capabilities: pending.capabilities,
      localIdentityDigest: pending.localIdentityDigest,
      remoteIdentityDigest: pending.remoteIdentityDigest,
      localDeviceId: pending.localDeviceId,
      remoteDeviceId: remoteDeviceId,
      outboundKind: pending.outboundKind,
      outboundMessageId: pending.outboundMessageId,
      pendingStateDigest: pending.stateDigest,
      terminalMessageId: terminalMessageId,
      terminalRecord: terminalRecord,
      sessionId: sessionId,
      checkpointDigest: checkpointDigest,
      completedAt: completedAt,
    );

V3HandshakeCompletionBinding _validatedCompletion({
  required String storageId,
  required String handshakeId,
  required V3SessionRole role,
  required V3HandshakeMode mode,
  required int capabilities,
  required String localIdentityDigest,
  required String remoteIdentityDigest,
  required String localDeviceId,
  required String remoteDeviceId,
  required V3HandshakeRecordKind outboundKind,
  required String outboundMessageId,
  required String pendingStateDigest,
  required String terminalMessageId,
  required Uint8List terminalRecord,
  required String sessionId,
  required String checkpointDigest,
  required DateTime completedAt,
}) {
  final timestamp = _validatedTimestamp(completedAt);
  if (!_isCanonicalNonZeroId(handshakeId, 16) ||
      capabilities != V3HandshakeCodec.requiredCapabilities ||
      !_isCanonicalNonZeroId(localIdentityDigest, 48) ||
      !_isCanonicalNonZeroId(remoteIdentityDigest, 48) ||
      localIdentityDigest == remoteIdentityDigest ||
      !_isCanonicalNonZeroId(localDeviceId, 16) ||
      !_isCanonicalNonZeroId(remoteDeviceId, 16) ||
      !_isCanonicalNonZeroId(outboundMessageId, 16) ||
      !_isCanonicalNonZeroId(pendingStateDigest, 32) ||
      !_isCanonicalNonZeroId(terminalMessageId, 16) ||
      terminalRecord.length != V3HandshakeCodec.confirmationBytes ||
      !_isCanonicalNonZeroId(sessionId, 16) ||
      !_isCanonicalNonZeroId(checkpointDigest, 32) ||
      (role == V3SessionRole.initiator &&
          outboundKind != V3HandshakeRecordKind.offer) ||
      (role == V3SessionRole.responder &&
          outboundKind != V3HandshakeRecordKind.reply)) {
    throw const FormatException('Invalid Layergram v3 completion binding');
  }
  final confirmation = V3HandshakeCodec.decodeConfirmation(terminalRecord);
  final localIdentity = role == V3SessionRole.initiator
      ? confirmation.initiatorIdentityDigest
      : confirmation.responderIdentityDigest;
  final remoteIdentity = role == V3SessionRole.initiator
      ? confirmation.responderIdentityDigest
      : confirmation.initiatorIdentityDigest;
  final localDevice = role == V3SessionRole.initiator
      ? confirmation.initiatorDeviceId
      : confirmation.responderDeviceId;
  final remoteDevice = role == V3SessionRole.initiator
      ? confirmation.responderDeviceId
      : confirmation.initiatorDeviceId;
  try {
    if (_id(confirmation.handshakeId) != handshakeId ||
        confirmation.mode != mode ||
        confirmation.capabilities != capabilities ||
        _id(localIdentity) != localIdentityDigest ||
        _id(remoteIdentity) != remoteIdentityDigest ||
        _id(localDevice) != localDeviceId ||
        _id(remoteDevice) != remoteDeviceId ||
        _id(confirmation.messageId) != terminalMessageId ||
        (role == V3SessionRole.initiator &&
            _id(confirmation.offerMessageId) != outboundMessageId) ||
        (role == V3SessionRole.responder &&
            _id(confirmation.replyMessageId) != outboundMessageId)) {
      throw const FormatException(
        'Mismatched Layergram v3 completion confirmation',
      );
    }
  } finally {
    _wipe(localIdentity);
    _wipe(remoteIdentity);
    _wipe(localDevice);
    _wipe(remoteDevice);
  }
  final digest = _completionRecordDigest(
    handshakeId: handshakeId,
    role: role,
    mode: mode,
    capabilities: capabilities,
    localIdentityDigest: localIdentityDigest,
    remoteIdentityDigest: remoteIdentityDigest,
    localDeviceId: localDeviceId,
    remoteDeviceId: remoteDeviceId,
    outboundKind: outboundKind,
    outboundMessageId: outboundMessageId,
    pendingStateDigest: pendingStateDigest,
    terminalMessageId: terminalMessageId,
    terminalRecord: terminalRecord,
    sessionId: sessionId,
    checkpointDigest: checkpointDigest,
    completedAt: timestamp,
  );
  return V3HandshakeCompletionBinding._(
    storageId: storageId,
    handshakeId: handshakeId,
    role: role,
    mode: mode,
    capabilities: capabilities,
    localIdentityDigest: localIdentityDigest,
    remoteIdentityDigest: remoteIdentityDigest,
    localDeviceId: localDeviceId,
    remoteDeviceId: remoteDeviceId,
    outboundKind: outboundKind,
    outboundMessageId: outboundMessageId,
    pendingStateDigest: pendingStateDigest,
    terminalMessageId: terminalMessageId,
    terminalRecord: terminalRecord,
    sessionId: sessionId,
    checkpointDigest: checkpointDigest,
    completedAt: timestamp,
    recordDigest: digest,
  );
}

Map<String, dynamic> _encodePending(V3DurablePendingHandshake value) =>
    <String, dynamic>{
      'kind': V3HandshakePendingRepository.pendingRecordKind,
      'v': 1,
      'handshakeId': value.handshakeId,
      'role': value.role.wireId,
      'mode': value.mode.wireId,
      'capabilities': value.capabilities,
      'localIdentityDigest': value.localIdentityDigest,
      'remoteIdentityDigest': value.remoteIdentityDigest,
      'localDeviceId': value.localDeviceId,
      'remoteDeviceId': value.remoteDeviceId,
      'outboundKind': value.outboundKind.wireId,
      'outboundMessageId': value.outboundMessageId,
      'stateDigest': value.stateDigest,
      'pendingState': _armor(value._encodedState),
      'outboundRecord': _armor(value._outboundRecord),
      'createdAt': value.createdAt.millisecondsSinceEpoch,
      'recordDigest': value.recordDigest,
      'reserved': 0,
    };

Map<String, dynamic> _encodeCompletion(V3HandshakeCompletionBinding value) =>
    <String, dynamic>{
      'kind': V3HandshakePendingRepository.completionRecordKind,
      'v': 1,
      'handshakeId': value.handshakeId,
      'role': value.role.wireId,
      'mode': value.mode.wireId,
      'capabilities': value.capabilities,
      'localIdentityDigest': value.localIdentityDigest,
      'remoteIdentityDigest': value.remoteIdentityDigest,
      'localDeviceId': value.localDeviceId,
      'remoteDeviceId': value.remoteDeviceId,
      'outboundKind': value.outboundKind.wireId,
      'outboundMessageId': value.outboundMessageId,
      'pendingStateDigest': value.pendingStateDigest,
      'terminalMessageId': value.terminalMessageId,
      'terminalRecord': _armor(value._terminalRecord),
      'sessionId': value.sessionId,
      'checkpointDigest': value.checkpointDigest,
      'completedAt': value.completedAt.millisecondsSinceEpoch,
      'recordDigest': value.recordDigest,
      'reserved': 0,
    };

V3DurablePendingHandshake _copyPending(
  V3DurablePendingHandshake value, {
  required String storageId,
}) =>
    V3DurablePendingHandshake._(
      storageId: storageId,
      handshakeId: value.handshakeId,
      role: value.role,
      mode: value.mode,
      capabilities: value.capabilities,
      localIdentityDigest: value.localIdentityDigest,
      remoteIdentityDigest: value.remoteIdentityDigest,
      localDeviceId: value.localDeviceId,
      remoteDeviceId: value.remoteDeviceId,
      outboundKind: value.outboundKind,
      outboundMessageId: value.outboundMessageId,
      stateDigest: value.stateDigest,
      encodedState: value._encodedState,
      outboundRecord: value._outboundRecord,
      createdAt: value.createdAt,
      recordDigest: value.recordDigest,
    );

V3HandshakeCompletionBinding _copyCompletion(
  V3HandshakeCompletionBinding value, {
  required String storageId,
}) =>
    V3HandshakeCompletionBinding._(
      storageId: storageId,
      handshakeId: value.handshakeId,
      role: value.role,
      mode: value.mode,
      capabilities: value.capabilities,
      localIdentityDigest: value.localIdentityDigest,
      remoteIdentityDigest: value.remoteIdentityDigest,
      localDeviceId: value.localDeviceId,
      remoteDeviceId: value.remoteDeviceId,
      outboundKind: value.outboundKind,
      outboundMessageId: value.outboundMessageId,
      pendingStateDigest: value.pendingStateDigest,
      terminalMessageId: value.terminalMessageId,
      terminalRecord: value._terminalRecord,
      sessionId: value.sessionId,
      checkpointDigest: value.checkpointDigest,
      completedAt: value.completedAt,
      recordDigest: value.recordDigest,
    );

V3DurableHandshakeOutbound _outbound(
  V3DurablePendingHandshake value, {
  required bool restored,
}) =>
    V3DurableHandshakeOutbound(
      handshakeId: value.handshakeId,
      kind: value.outboundKind,
      messageId: value.outboundMessageId,
      stateDigest: value.stateDigest,
      outboundRecord: value.outboundRecord,
      restored: restored,
    );

bool _samePending(
  V3DurablePendingHandshake left,
  V3DurablePendingHandshake right,
) =>
    left.handshakeId == right.handshakeId &&
    left.role == right.role &&
    left.mode == right.mode &&
    left.capabilities == right.capabilities &&
    left.localIdentityDigest == right.localIdentityDigest &&
    left.remoteIdentityDigest == right.remoteIdentityDigest &&
    left.localDeviceId == right.localDeviceId &&
    left.remoteDeviceId == right.remoteDeviceId &&
    left.outboundKind == right.outboundKind &&
    left.outboundMessageId == right.outboundMessageId &&
    left.stateDigest == right.stateDigest &&
    _bytesEqual(left._encodedState, right._encodedState) &&
    _bytesEqual(left._outboundRecord, right._outboundRecord);

bool _sameCompletion(
  V3HandshakeCompletionBinding left,
  V3HandshakeCompletionBinding right,
) =>
    left.handshakeId == right.handshakeId &&
    left.role == right.role &&
    left.mode == right.mode &&
    left.capabilities == right.capabilities &&
    left.localIdentityDigest == right.localIdentityDigest &&
    left.remoteIdentityDigest == right.remoteIdentityDigest &&
    left.localDeviceId == right.localDeviceId &&
    left.remoteDeviceId == right.remoteDeviceId &&
    left.outboundKind == right.outboundKind &&
    left.outboundMessageId == right.outboundMessageId &&
    left.pendingStateDigest == right.pendingStateDigest &&
    left.terminalMessageId == right.terminalMessageId &&
    _bytesEqual(left._terminalRecord, right._terminalRecord) &&
    left.sessionId == right.sessionId &&
    left.checkpointDigest == right.checkpointDigest;

bool _completionCoversPending(
  V3HandshakeCompletionBinding completion,
  V3DurablePendingHandshake pending,
) {
  if (completion.handshakeId != pending.handshakeId ||
      completion.role != pending.role ||
      completion.mode != pending.mode ||
      completion.capabilities != pending.capabilities ||
      completion.localIdentityDigest != pending.localIdentityDigest ||
      completion.remoteIdentityDigest != pending.remoteIdentityDigest ||
      completion.localDeviceId != pending.localDeviceId ||
      (pending.remoteDeviceId != null &&
          completion.remoteDeviceId != pending.remoteDeviceId) ||
      completion.outboundKind != pending.outboundKind ||
      completion.outboundMessageId != pending.outboundMessageId ||
      completion.pendingStateDigest != pending.stateDigest) {
    return false;
  }
  final confirmation = V3HandshakeCodec.decodeConfirmation(
    completion._terminalRecord,
  );
  V3InitiatorPendingHandshake? initiator;
  V3ResponderPendingHandshake? responder;
  try {
    switch (pending.role) {
      case V3SessionRole.initiator:
        initiator = pending.decodeInitiator();
        return _id(confirmation.offerMessageId) ==
            _id(initiator.offer.messageId);
      case V3SessionRole.responder:
        responder = pending.decodeResponder();
        return _id(confirmation.offerMessageId) ==
                _id(responder.offer.messageId) &&
            _id(confirmation.replyMessageId) == _id(responder.reply.messageId);
    }
  } finally {
    initiator?.close();
    responder?.close();
  }
}

int _comparePending(
  V3DurablePendingHandshake left,
  V3DurablePendingHandshake right,
) {
  final time = left.createdAt.compareTo(right.createdAt);
  return time != 0 ? time : left.storageId.compareTo(right.storageId);
}

int _compareCompletion(
  V3HandshakeCompletionBinding left,
  V3HandshakeCompletionBinding right,
) {
  final time = left.completedAt.compareTo(right.completedAt);
  return time != 0 ? time : left.storageId.compareTo(right.storageId);
}

String _pendingRecordDigest({
  required String handshakeId,
  required V3SessionRole role,
  required V3HandshakeMode mode,
  required int capabilities,
  required String localIdentityDigest,
  required String remoteIdentityDigest,
  required String localDeviceId,
  required String? remoteDeviceId,
  required V3HandshakeRecordKind outboundKind,
  required String outboundMessageId,
  required String stateDigest,
  required Uint8List encodedState,
  required Uint8List outboundRecord,
  required DateTime createdAt,
}) {
  final numbers = ByteData(20)
    ..setUint32(0, capabilities, Endian.big)
    ..setUint64(4, createdAt.millisecondsSinceEpoch, Endian.big)
    ..setUint32(12, encodedState.length, Endian.big)
    ..setUint32(16, outboundRecord.length, Endian.big);
  return _digest(<int>[
    ...utf8.encode('layergram/v3/handshake/pending-record\x00'),
    role.wireId,
    mode.wireId,
    outboundKind.wireId,
    ...numbers.buffer.asUint8List(),
    ..._decodeId(handshakeId, 16),
    ..._decodeId(localIdentityDigest, 48),
    ..._decodeId(remoteIdentityDigest, 48),
    ..._decodeId(localDeviceId, 16),
    ...(remoteDeviceId == null ? Uint8List(16) : _decodeId(remoteDeviceId, 16)),
    ..._decodeId(outboundMessageId, 16),
    ..._decodeId(stateDigest, 32),
    ...encodedState,
    ...outboundRecord,
  ]);
}

String _completionRecordDigest({
  required String handshakeId,
  required V3SessionRole role,
  required V3HandshakeMode mode,
  required int capabilities,
  required String localIdentityDigest,
  required String remoteIdentityDigest,
  required String localDeviceId,
  required String remoteDeviceId,
  required V3HandshakeRecordKind outboundKind,
  required String outboundMessageId,
  required String pendingStateDigest,
  required String terminalMessageId,
  required Uint8List terminalRecord,
  required String sessionId,
  required String checkpointDigest,
  required DateTime completedAt,
}) {
  final numbers = ByteData(12)
    ..setUint32(0, capabilities, Endian.big)
    ..setUint64(4, completedAt.millisecondsSinceEpoch, Endian.big);
  return _digest(<int>[
    ...utf8.encode('layergram/v3/handshake/completion-record\x00'),
    role.wireId,
    mode.wireId,
    outboundKind.wireId,
    ...numbers.buffer.asUint8List(),
    ..._decodeId(handshakeId, 16),
    ..._decodeId(localIdentityDigest, 48),
    ..._decodeId(remoteIdentityDigest, 48),
    ..._decodeId(localDeviceId, 16),
    ..._decodeId(remoteDeviceId, 16),
    ..._decodeId(outboundMessageId, 16),
    ..._decodeId(pendingStateDigest, 32),
    ..._decodeId(terminalMessageId, 16),
    ...terminalRecord,
    ..._decodeId(sessionId, 16),
    ..._decodeId(checkpointDigest, 32),
  ]);
}

String _stateDigest(Uint8List state) => _digest(<int>[
      ...utf8.encode('layergram/v3/handshake/pending-state-record\x00'),
      ...state,
    ]);

String _digest(List<int> value) =>
    base64Url.encode(crypto.sha256.convert(value).bytes).replaceAll('=', '');

String _armor(Uint8List value) => base64Url.encode(value).replaceAll('=', '');

Uint8List _decodeArmored(String value, int maxBytes) {
  if (value.isEmpty || value.length > ((maxBytes * 4 + 2) ~/ 3)) {
    throw const FormatException('Invalid Layergram v3 armored record length');
  }
  try {
    final decoded = Uint8List.fromList(
      base64Url.decode(base64Url.normalize(value)),
    );
    if (decoded.length > maxBytes || _armor(decoded) != value) {
      _wipe(decoded);
      throw const FormatException('Non-canonical Layergram v3 armored record');
    }
    return decoded;
  } catch (error) {
    if (error is FormatException) rethrow;
    throw const FormatException('Invalid Layergram v3 armored record');
  }
}

String _id(Uint8List value) => _armor(value);

({String armored, Uint8List bytes}) _identityDigest(V3PublicIdentity identity) {
  final encoded = identity.identityBindingBytes;
  try {
    final bytes = Uint8List.fromList(crypto.sha384.convert(encoded).bytes);
    return (armored: _armor(bytes), bytes: bytes);
  } finally {
    _wipe(encoded);
  }
}

bool _isCanonicalNonZeroId(String value, int byteLength) {
  try {
    final decoded = _decodeId(value, byteLength);
    try {
      return decoded.any((byte) => byte != 0);
    } finally {
      _wipe(decoded);
    }
  } catch (_) {
    return false;
  }
}

Uint8List _decodeId(String value, int byteLength) {
  final expectedLength = (byteLength * 4 + 2) ~/ 3;
  if (value.length != expectedLength) {
    throw const FormatException('Invalid Layergram v3 identifier length');
  }
  try {
    final decoded = Uint8List.fromList(
      base64Url.decode(base64Url.normalize(value)),
    );
    if (decoded.length != byteLength || _armor(decoded) != value) {
      _wipe(decoded);
      throw const FormatException('Non-canonical Layergram v3 identifier');
    }
    return decoded;
  } catch (error) {
    if (error is FormatException) rethrow;
    throw const FormatException('Invalid Layergram v3 identifier');
  }
}

DateTime _timestamp(int milliseconds) {
  if (milliseconds < 0 ||
      milliseconds > V3HandshakePendingRepository._maxTimestampMillis) {
    throw const FormatException('Invalid Layergram v3 handshake timestamp');
  }
  return DateTime.fromMillisecondsSinceEpoch(milliseconds, isUtc: true);
}

DateTime _validatedTimestamp(DateTime value) =>
    _timestamp(value.toUtc().millisecondsSinceEpoch);

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
