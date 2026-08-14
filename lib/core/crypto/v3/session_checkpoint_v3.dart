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

import 'committed_record_v3.dart';
import 'ec_double_ratchet_v3.dart';
import 'lmf_v3.dart';
import 'lmf_v3_persistence.dart';
import 'triple_ratchet_state_v3.dart';

enum V3CheckpointEffectDirection {
  incoming(1),
  outgoing(2);

  const V3CheckpointEffectDirection(this.wireId);
  final int wireId;

  static V3CheckpointEffectDirection fromWireId(int wireId) {
    for (final value in values) {
      if (value.wireId == wireId) return value;
    }
    throw const FormatException('Invalid Layergram v3 checkpoint direction');
  }
}

/// Canonical receipt proving which durable AR3/TR3 transition a checkpoint
/// covers. It deliberately excludes send-journal ACK revision metadata: ACK
/// cleanup may change while the underlying application and ratchet transition
/// remains identical.
final class V3CheckpointReceipt {
  factory V3CheckpointReceipt.fromStates({
    required V3CheckpointEffectDirection direction,
    required String assemblyId,
    required Uint8List applicationState,
    required Uint8List ratchetState,
  }) {
    final application = Uint8List.fromList(applicationState);
    final ratchet = Uint8List.fromList(ratchetState);
    V3CommittedRecord? record;
    V3TripleRatchetState? snapshot;
    try {
      record = V3CommittedRecordCodec.decode(application);
      snapshot = V3TripleRatchetStateCodec.decode(ratchet);
      if (assemblyId != record.assemblyId ||
          !_bytesEqual(record.sessionId, snapshot.sessionId) ||
          snapshot.lifecycle != V3RatchetLifecycle.active ||
          snapshot.revision <= 0) {
        throw const V3LmfPersistenceConflictException(
          'v3 checkpoint receipt does not bind one active transition',
        );
      }
      final sessionKey = _sessionKey(snapshot.sessionId);
      return V3CheckpointReceipt._(
        direction: direction,
        assemblyId: assemblyId,
        stableRecordId: record.stableRecordId,
        sessionKey: sessionKey,
        ratchetRevision: snapshot.revision,
        stateDigest: _stateDigest(
          direction: direction,
          assemblyId: assemblyId,
          applicationState: application,
          ratchetState: ratchet,
        ),
      );
    } finally {
      record?.wipeContent();
      snapshot?.wipeSecrets();
      _wipe(application);
      _wipe(ratchet);
    }
  }

  const V3CheckpointReceipt._({
    required this.direction,
    required this.assemblyId,
    required this.stableRecordId,
    required this.sessionKey,
    required this.ratchetRevision,
    required this.stateDigest,
  });

  final V3CheckpointEffectDirection direction;
  final String assemblyId;
  final String stableRecordId;
  final String sessionKey;
  final int ratchetRevision;
  final String stateDigest;

  bool matchesStates({
    required V3CheckpointEffectDirection direction,
    required Uint8List applicationState,
    required Uint8List ratchetState,
  }) {
    V3CheckpointReceipt? other;
    try {
      other = V3CheckpointReceipt.fromStates(
        direction: direction,
        assemblyId: assemblyId,
        applicationState: applicationState,
        ratchetState: ratchetState,
      );
      return _sameReceipt(this, other);
    } catch (_) {
      return false;
    }
  }
}

/// Canonical evidence that one checkpoint was replaced solely to retire one
/// cumulative receipt. The compact replay/completion proof remains durable;
/// this transition alone never authorizes deleting it.
final class V3CheckpointRetirementTransition {
  const V3CheckpointRetirementTransition._({
    required this.sourceCheckpointDigest,
    required this.retiredReceipt,
  });

  final String sourceCheckpointDigest;
  final V3CheckpointReceipt retiredReceipt;
}

/// Highest durable TR3 snapshot for one session plus cumulative transition
/// receipts. The repository owns and wipes the encoded snapshot copy.
final class V3SessionCheckpoint {
  V3SessionCheckpoint._({
    required this.storageId,
    required this.sessionKey,
    required this.revision,
    required this.lineageDigest,
    required this.snapshotDigest,
    required this.checkpointDigest,
    required Uint8List encodedSnapshot,
    required List<V3CheckpointReceipt> receipts,
    required this.retirementTransition,
    required this.persistedAt,
  })  : _encodedSnapshot = Uint8List.fromList(encodedSnapshot),
        receipts = List<V3CheckpointReceipt>.unmodifiable(receipts);

  final String storageId;
  final String sessionKey;
  final int revision;
  final String lineageDigest;
  final String snapshotDigest;
  final String checkpointDigest;
  final List<V3CheckpointReceipt> receipts;
  final V3CheckpointRetirementTransition? retirementTransition;
  final DateTime persistedAt;
  final Uint8List _encodedSnapshot;

  Uint8List get encodedSnapshot => Uint8List.fromList(_encodedSnapshot);
  int get retainedBytes =>
      _encodedSnapshot.length +
      receipts.length * 160 +
      (retirementTransition == null ? 0 : 160);

  V3TripleRatchetState decodeSnapshot() {
    final bytes = encodedSnapshot;
    try {
      return V3TripleRatchetStateCodec.decode(bytes);
    } finally {
      _wipe(bytes);
    }
  }

  V3CheckpointReceipt? receiptForAssembly(String assemblyId) {
    for (final receipt in receipts) {
      if (receipt.assemblyId == assemblyId) return receipt;
    }
    return null;
  }

  /// Confirms a candidate snapshot belongs to this checkpoint's immutable
  /// session/role/transcript/routing lineage without exposing secret bytes.
  bool matchesLineage(V3TripleRatchetState snapshot) {
    return revision >= snapshot.revision &&
        sessionKey == _sessionKey(snapshot.sessionId) &&
        lineageDigest == _lineageDigest(snapshot);
  }

  void _close() => _wipe(_encodedSnapshot);
}

final class V3SessionCheckpointRestoreResult {
  const V3SessionCheckpointRestoreResult({
    required this.checkpoints,
    required this.removedSupersededRecords,
  });

  final List<V3SessionCheckpoint> checkpoints;
  final int removedSupersededRecords;
}

/// Unforgeable ownership token for the unified v3 session coordinator.
final class V3SessionCheckpointAuthority {
  const V3SessionCheckpointAuthority._();
}

/// Encrypted Aux-backed TR3 checkpoint repository.
///
/// Checkpoint writes are write-new-before-delete. Restore selects the highest
/// revision only after proving one stable lineage and monotonic receipt
/// inclusion. The session coordinator, not this repository, verifies these
/// receipts together with AR3 materialization and replay/outbox state before
/// journal collection.
final class V3SessionCheckpointRepository {
  V3SessionCheckpointRepository({
    required V3LmfRecordStore store,
    this.maxSessions = 4096,
    this.maxReceiptsPerSession = 4096,
    this.maxTotalRetainedBytes = 32 * 1024 * 1024,
    this.maxStoredRecords = 8192,
  }) : _store = store {
    if (maxSessions <= 0 ||
        maxReceiptsPerSession <= 0 ||
        maxTotalRetainedBytes <= 0 ||
        maxStoredRecords <= 0) {
      throw ArgumentError('Layergram v3 checkpoint limits are invalid');
    }
  }

  static const String recordKind = 'v3_session_checkpoint_v1';
  static const int _recordVersion = 2;
  static const int _maxTimestampMillis = 253402300799999;

  final V3LmfRecordStore _store;
  final int maxSessions;
  final int maxReceiptsPerSession;
  final int maxTotalRetainedBytes;
  final int maxStoredRecords;

  final Map<String, V3SessionCheckpoint> _checkpoints =
      <String, V3SessionCheckpoint>{};
  final Set<String> _pendingRetirementSourceStorageIds = <String>{};
  Future<void> _operationTail = Future<void>.value();
  bool _restored = false;
  bool _closed = false;
  bool _writeRecoveryRequired = false;
  V3SessionCheckpointAuthority? _authority;
  int _totalRetainedBytes = 0;

  int get checkpointCount => _checkpoints.length;
  int get totalRetainedBytes => _totalRetainedBytes;
  bool get requiresRecovery => _writeRecoveryRequired;
  List<V3SessionCheckpoint> checkpoints({
    V3SessionCheckpointAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return List<V3SessionCheckpoint>.unmodifiable(_checkpoints.values);
  }

  V3SessionCheckpoint? checkpointForSession(
    Uint8List sessionId, {
    V3SessionCheckpointAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return _checkpoints[_sessionKey(sessionId)];
  }

  Future<V3SessionCheckpointAuthority> claimSessionCoordinatorAuthority() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError(
          'Layergram v3 checkpoint authority must be claimed before restore',
        );
      }
      if (_authority != null) {
        throw StateError(
          'Layergram v3 checkpoint repository already has a session coordinator',
        );
      }
      final authority = V3SessionCheckpointAuthority._();
      _authority = authority;
      return authority;
    });
  }

  Future<V3SessionCheckpointRestoreResult> restore({
    V3SessionCheckpointAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 checkpoint repository was restored');
      }
      final storedRecords = await _store.readAll();
      final relevant = storedRecords
          .where((record) => record.payload['kind'] == recordKind)
          .toList(growable: false);
      if (relevant.length > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical v3 checkpoint record limit exceeded',
        );
      }

      final decoded = <V3SessionCheckpoint>[];
      final grouped = <String, List<V3SessionCheckpoint>>{};
      try {
        for (final stored in relevant) {
          final checkpoint = await _decode(stored);
          decoded.add(checkpoint);
          grouped
              .putIfAbsent(
                checkpoint.sessionKey,
                () => <V3SessionCheckpoint>[],
              )
              .add(checkpoint);
        }
        if (grouped.length > maxSessions) {
          throw const V3LmfPersistenceLimitException(
            'v3 checkpoint session limit exceeded',
          );
        }

        var removed = 0;
        var totalBytes = 0;
        final selected = <String, V3SessionCheckpoint>{};
        for (final candidates in grouped.values) {
          final highest = _selectCheckpointHistory(candidates);
          totalBytes += highest.retainedBytes;
          if (totalBytes > maxTotalRetainedBytes) {
            throw const V3LmfPersistenceLimitException(
              'v3 checkpoint retained-byte limit exceeded',
            );
          }
          selected[highest.sessionKey] = highest;
          final retirementAncestors = _retirementAncestorDigests(
            highest,
            candidates,
          );
          for (final candidate in candidates) {
            if (identical(candidate, highest)) continue;
            if (retirementAncestors.contains(candidate.checkpointDigest)) {
              _pendingRetirementSourceStorageIds.add(candidate.storageId);
              continue;
            }
            await _deleteIgnoringFailure(candidate.storageId);
            candidate._close();
            removed++;
          }
        }
        _checkpoints.addAll(selected);
        _totalRetainedBytes = totalBytes;
        _restored = true;
        decoded.removeWhere(
          (checkpoint) => identical(
            _checkpoints[checkpoint.sessionKey],
            checkpoint,
          ),
        );
        return V3SessionCheckpointRestoreResult(
          checkpoints: checkpoints(authority: authority),
          removedSupersededRecords: removed,
        );
      } finally {
        for (final checkpoint in decoded) {
          checkpoint._close();
        }
      }
    });
  }

  Future<V3SessionCheckpoint> persist({
    required V3TripleRatchetState snapshot,
    required Iterable<V3CheckpointReceipt> receipts,
    DateTime? persistedAt,
    V3SessionCheckpointAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      if (snapshot.lifecycle != V3RatchetLifecycle.active) {
        throw StateError('Layergram v3 checkpoint snapshot is not active');
      }
      await _validateCheckpointSnapshot(snapshot);
      final encoded = V3TripleRatchetStateCodec.encode(snapshot);
      try {
        final sessionKey = _sessionKey(snapshot.sessionId);
        final canonicalReceipts = _canonicalReceipts(
          receipts,
          sessionKey: sessionKey,
          revision: snapshot.revision,
          maxReceipts: maxReceiptsPerSession,
        );
        final lineageDigest = _lineageDigest(snapshot);
        final snapshotDigest = _snapshotDigest(encoded);
        final checkpointDigest = _checkpointDigest(
          sessionKey: sessionKey,
          revision: snapshot.revision,
          lineageDigest: lineageDigest,
          snapshotDigest: snapshotDigest,
          receipts: canonicalReceipts,
          retirementTransition: null,
        );
        final timestamp =
            _validatedTimestamp(persistedAt ?? DateTime.now().toUtc());
        final candidate = V3SessionCheckpoint._(
          storageId: '',
          sessionKey: sessionKey,
          revision: snapshot.revision,
          lineageDigest: lineageDigest,
          snapshotDigest: snapshotDigest,
          checkpointDigest: checkpointDigest,
          encodedSnapshot: encoded,
          receipts: canonicalReceipts,
          retirementTransition: null,
          persistedAt: timestamp,
        );
        try {
          final existing = _checkpoints[sessionKey];
          if (existing != null) {
            if (candidate.revision < existing.revision) {
              throw const V3LmfPersistenceConflictException(
                'stale v3 checkpoint revision',
              );
            }
            if (candidate.revision == existing.revision) {
              if (!_sameCheckpoint(candidate, existing)) {
                if (existing.retirementTransition != null &&
                    candidate.retirementTransition == null &&
                    _sameCheckpointStateAndReceipts(candidate, existing)) {
                  return existing;
                }
                throw const V3LmfPersistenceConflictException(
                  'divergent v3 checkpoint at the current revision',
                );
              }
              return existing;
            }
            if (!_extendsCheckpoint(existing, candidate)) {
              throw const V3LmfPersistenceConflictException(
                'v3 checkpoint does not extend the durable receipt history',
              );
            }
          } else if (_checkpoints.length >= maxSessions) {
            throw const V3LmfPersistenceLimitException(
              'v3 checkpoint session capacity exceeded',
            );
          }
          final prospectiveBytes = _totalRetainedBytes -
              (existing?.retainedBytes ?? 0) +
              candidate.retainedBytes;
          if (prospectiveBytes > maxTotalRetainedBytes) {
            throw const V3LmfPersistenceLimitException(
              'v3 checkpoint retained-byte capacity exceeded',
            );
          }

          final payload = _encodePayload(candidate);
          V3SessionCheckpoint? committed;
          try {
            final storageId = await _store.write(payload);
            committed = V3SessionCheckpoint._(
              storageId: storageId,
              sessionKey: candidate.sessionKey,
              revision: candidate.revision,
              lineageDigest: candidate.lineageDigest,
              snapshotDigest: candidate.snapshotDigest,
              checkpointDigest: candidate.checkpointDigest,
              encodedSnapshot: candidate._encodedSnapshot,
              receipts: candidate.receipts,
              retirementTransition: candidate.retirementTransition,
              persistedAt: candidate.persistedAt,
            );
            _checkpoints[sessionKey] = committed;
            _totalRetainedBytes = prospectiveBytes;
          } catch (_) {
            committed?._close();
            _writeRecoveryRequired = true;
            rethrow;
          }
          if (existing != null) {
            existing._close();
            await _deleteIgnoringFailure(existing.storageId);
          }
          return committed;
        } finally {
          candidate._close();
        }
      } finally {
        _wipe(encoded);
      }
    });
  }

  /// Writes a same-revision checkpoint that removes exactly [receipt].
  ///
  /// The replacement embeds the source checkpoint digest and the complete
  /// retired receipt. It is durable before the source record is cleaned up,
  /// allowing restore to validate and select an interrupted replacement. The
  /// compact replay/completion proof is intentionally untouched.
  Future<V3SessionCheckpoint> replaceReceiptForRetirement({
    required String expectedSourceCheckpointDigest,
    required V3CheckpointReceipt receipt,
    DateTime? persistedAt,
    V3SessionCheckpointAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final existing = _checkpoints[receipt.sessionKey];
      if (existing == null) {
        throw StateError('Layergram v3 retirement has no source checkpoint');
      }
      if (existing.checkpointDigest != expectedSourceCheckpointDigest) {
        final transition = existing.retirementTransition;
        if (transition != null &&
            transition.sourceCheckpointDigest ==
                expectedSourceCheckpointDigest &&
            _sameReceipt(transition.retiredReceipt, receipt) &&
            existing.receiptForAssembly(receipt.assemblyId) == null) {
          return existing;
        }
        throw const V3LmfPersistenceConflictException(
          'v3 retirement source checkpoint changed',
        );
      }
      if (existing.retirementTransition != null) {
        throw const V3LmfPersistenceConflictException(
          'v3 checkpoint revision already contains a retirement transition',
        );
      }
      final currentReceipt = existing.receiptForAssembly(receipt.assemblyId);
      if (currentReceipt == null || !_sameReceipt(currentReceipt, receipt)) {
        throw const V3LmfPersistenceConflictException(
          'v3 retirement source receipt changed',
        );
      }
      final timestamp =
          _validatedTimestamp(persistedAt ?? DateTime.now().toUtc());
      if (timestamp.isBefore(existing.persistedAt)) {
        throw const V3LmfPersistenceConflictException(
          'v3 retirement checkpoint timestamp moved backward',
        );
      }
      final remaining = existing.receipts
          .where((candidate) => candidate.assemblyId != receipt.assemblyId)
          .toList(growable: false);
      final transition = V3CheckpointRetirementTransition._(
        sourceCheckpointDigest: existing.checkpointDigest,
        retiredReceipt: receipt,
      );
      final digest = _checkpointDigest(
        sessionKey: existing.sessionKey,
        revision: existing.revision,
        lineageDigest: existing.lineageDigest,
        snapshotDigest: existing.snapshotDigest,
        receipts: remaining,
        retirementTransition: transition,
      );
      final candidate = V3SessionCheckpoint._(
        storageId: '',
        sessionKey: existing.sessionKey,
        revision: existing.revision,
        lineageDigest: existing.lineageDigest,
        snapshotDigest: existing.snapshotDigest,
        checkpointDigest: digest,
        encodedSnapshot: existing._encodedSnapshot,
        receipts: remaining,
        retirementTransition: transition,
        persistedAt: timestamp,
      );
      try {
        if (!_isExactReceiptReplacement(existing, candidate)) {
          throw const V3LmfPersistenceConflictException(
            'v3 retirement checkpoint is not an exact receipt replacement',
          );
        }
        final prospectiveBytes = _totalRetainedBytes -
            existing.retainedBytes +
            candidate.retainedBytes;
        if (prospectiveBytes > maxTotalRetainedBytes) {
          throw const V3LmfPersistenceLimitException(
            'v3 checkpoint retained-byte capacity exceeded',
          );
        }
        V3SessionCheckpoint? committed;
        try {
          final storageId = await _store.write(_encodePayload(candidate));
          committed = V3SessionCheckpoint._(
            storageId: storageId,
            sessionKey: candidate.sessionKey,
            revision: candidate.revision,
            lineageDigest: candidate.lineageDigest,
            snapshotDigest: candidate.snapshotDigest,
            checkpointDigest: candidate.checkpointDigest,
            encodedSnapshot: candidate._encodedSnapshot,
            receipts: candidate.receipts,
            retirementTransition: candidate.retirementTransition,
            persistedAt: candidate.persistedAt,
          );
          _checkpoints[committed.sessionKey] = committed;
          _totalRetainedBytes = prospectiveBytes;
        } catch (_) {
          committed?._close();
          _writeRecoveryRequired = true;
          rethrow;
        }
        existing._close();
        await _deleteIgnoringFailure(existing.storageId);
        return committed;
      } finally {
        candidate._close();
      }
    });
  }

  /// Cleans source checkpoint records retained during restore until the
  /// session coordinator has independently validated the retirement plan.
  /// Failures are harmless and retried by the next restore.
  Future<int> cleanupValidatedRetirementSources({
    V3SessionCheckpointAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      var removed = 0;
      for (final storageId
          in _pendingRetirementSourceStorageIds.toList(growable: false)) {
        try {
          await _store.delete(storageId);
          _pendingRetirementSourceStorageIds.remove(storageId);
          removed++;
        } catch (_) {
          // A source duplicate is non-authoritative after plan validation.
        }
      }
      return removed;
    });
  }

  Future<void> close({V3SessionCheckpointAuthority? authority}) {
    return _serialized(() async {
      _ensureAuthority(authority);
      if (_closed) return;
      _closed = true;
      for (final checkpoint in _checkpoints.values) {
        checkpoint._close();
      }
      _checkpoints.clear();
      _pendingRetirementSourceStorageIds.clear();
      _totalRetainedBytes = 0;
    });
  }

  Future<V3SessionCheckpoint> _decode(V3LmfStoredRecord stored) async {
    final payload = stored.payload;
    const expectedKeys = <String>{
      'kind',
      'version',
      'sessionId',
      'revision',
      'lineageDigest',
      'snapshot',
      'snapshotDigest',
      'receipts',
      'checkpointDigest',
      'retirement',
      'persistedAt',
      'reserved',
    };
    if (payload.length != expectedKeys.length ||
        !payload.keys.every(expectedKeys.contains) ||
        payload['kind'] != recordKind ||
        payload['version'] != _recordVersion ||
        payload['sessionId'] is! String ||
        payload['revision'] is! int ||
        payload['lineageDigest'] is! String ||
        payload['snapshot'] is! String ||
        payload['snapshotDigest'] is! String ||
        payload['receipts'] is! List ||
        payload['checkpointDigest'] is! String ||
        (payload['retirement'] != null && payload['retirement'] is! Map) ||
        payload['persistedAt'] is! int ||
        payload['reserved'] != 0) {
      throw const FormatException('Invalid Layergram v3 checkpoint envelope');
    }
    final encoded = _decodeBinary(
      payload['snapshot'] as String,
      V3TripleRatchetStateCodec.maxEncodedBytes,
    );
    V3TripleRatchetState? snapshot;
    try {
      snapshot = V3TripleRatchetStateCodec.decode(encoded);
      final sessionKey = payload['sessionId'] as String;
      final revision = payload['revision'] as int;
      final lineageDigest = payload['lineageDigest'] as String;
      final snapshotDigest = payload['snapshotDigest'] as String;
      final checkpointDigest = payload['checkpointDigest'] as String;
      final retirementTransition = _decodeRetirementTransition(
        payload['retirement'],
      );
      final rawReceipts = payload['receipts'] as List<dynamic>;
      if (rawReceipts.length > maxReceiptsPerSession) {
        throw const V3LmfPersistenceLimitException(
          'v3 checkpoint receipt limit exceeded',
        );
      }
      final receipts = rawReceipts.map(_decodeReceipt).toList(growable: false);
      final canonicalReceipts = _canonicalReceipts(
        receipts,
        sessionKey: sessionKey,
        revision: revision,
        maxReceipts: maxReceiptsPerSession,
      );
      _validateRetirementTransition(
        retirementTransition,
        sessionKey: sessionKey,
        revision: revision,
        receipts: canonicalReceipts,
        checkpointDigest: checkpointDigest,
      );
      if (snapshot.lifecycle != V3RatchetLifecycle.active ||
          revision != snapshot.revision ||
          sessionKey != _sessionKey(snapshot.sessionId) ||
          lineageDigest != _lineageDigest(snapshot) ||
          snapshotDigest != _snapshotDigest(encoded) ||
          checkpointDigest !=
              _checkpointDigest(
                sessionKey: sessionKey,
                revision: revision,
                lineageDigest: lineageDigest,
                snapshotDigest: snapshotDigest,
                receipts: canonicalReceipts,
                retirementTransition: retirementTransition,
              ) ||
          !_isCanonicalDigest(lineageDigest) ||
          !_isCanonicalDigest(snapshotDigest) ||
          !_isCanonicalDigest(checkpointDigest) ||
          !_sameReceiptList(receipts, canonicalReceipts)) {
        throw const FormatException(
          'Mismatched Layergram v3 checkpoint binding',
        );
      }
      await _validateCheckpointSnapshot(snapshot);
      return V3SessionCheckpoint._(
        storageId: stored.storageId,
        sessionKey: sessionKey,
        revision: revision,
        lineageDigest: lineageDigest,
        snapshotDigest: snapshotDigest,
        checkpointDigest: checkpointDigest,
        encodedSnapshot: encoded,
        receipts: canonicalReceipts,
        retirementTransition: retirementTransition,
        persistedAt: _timestampFromMillis(payload['persistedAt'] as int),
      );
    } finally {
      snapshot?.wipeSecrets();
      _wipe(encoded);
    }
  }

  Map<String, dynamic> _encodePayload(V3SessionCheckpoint checkpoint) =>
      <String, dynamic>{
        'kind': recordKind,
        'version': _recordVersion,
        'sessionId': checkpoint.sessionKey,
        'revision': checkpoint.revision,
        'lineageDigest': checkpoint.lineageDigest,
        'snapshot': _encodeBinary(checkpoint._encodedSnapshot),
        'snapshotDigest': checkpoint.snapshotDigest,
        'receipts':
            checkpoint.receipts.map(_encodeReceipt).toList(growable: false),
        'checkpointDigest': checkpoint.checkpointDigest,
        'retirement': _encodeRetirementTransition(
          checkpoint.retirementTransition,
        ),
        'persistedAt': checkpoint.persistedAt.millisecondsSinceEpoch,
        'reserved': 0,
      };

  Future<void> _deleteIgnoringFailure(String storageId) async {
    try {
      await _store.delete(storageId);
    } catch (_) {
      // A validated superseded encrypted checkpoint is harmless on restore.
    }
  }

  Future<T> _serialized<T>(Future<T> Function() operation) {
    final completer = Completer<T>();
    final previous = _operationTail;
    final next = previous.catchError((_) {}).then((_) async {
      try {
        completer.complete(await operation());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    _operationTail = next;
    return completer.future;
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('Layergram v3 checkpoint repository is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored) {
      throw StateError('Layergram v3 checkpoint repository must be restored');
    }
    if (_writeRecoveryRequired) {
      throw StateError(
        'Layergram v3 checkpoint repository must be reconstructed and restored',
      );
    }
  }

  void _ensureAuthority(V3SessionCheckpointAuthority? authority) {
    final claimed = _authority;
    if (claimed != null && !identical(claimed, authority)) {
      throw StateError(
        'Layergram v3 checkpoint repository is owned by a session coordinator',
      );
    }
  }
}

Future<void> _validateCheckpointSnapshot(
  V3TripleRatchetState snapshot,
) async {
  final restored = await V3EcDoubleRatchet.restore(snapshot);
  restored.close();
}

List<V3CheckpointReceipt> _canonicalReceipts(
  Iterable<V3CheckpointReceipt> values, {
  required String sessionKey,
  required int revision,
  required int maxReceipts,
}) {
  if (revision < 0 || revision > 0x7fffffffffffffff) {
    throw const FormatException('Invalid Layergram v3 checkpoint revision');
  }
  final receipts = <V3CheckpointReceipt>[];
  final assemblies = <String>{};
  final revisions = <int>{};
  for (final value in values) {
    if (receipts.length >= maxReceipts ||
        value.sessionKey != sessionKey ||
        value.ratchetRevision <= 0 ||
        value.ratchetRevision > revision ||
        value.stableRecordId != 'v3:${value.assemblyId}' ||
        !_isCanonicalId(value.assemblyId, 32) ||
        !_isCanonicalId(value.sessionKey, 16) ||
        !_isCanonicalDigest(value.stateDigest) ||
        !assemblies.add(value.assemblyId) ||
        !revisions.add(value.ratchetRevision)) {
      throw const V3LmfPersistenceConflictException(
        'invalid or duplicate v3 checkpoint receipt',
      );
    }
    receipts.add(value);
  }
  receipts.sort((left, right) {
    final revisionOrder = left.ratchetRevision.compareTo(right.ratchetRevision);
    if (revisionOrder != 0) return revisionOrder;
    return left.assemblyId.compareTo(right.assemblyId);
  });
  return List<V3CheckpointReceipt>.unmodifiable(receipts);
}

V3CheckpointReceipt _decodeReceipt(dynamic value) {
  if (value is! Map) {
    throw const FormatException('Invalid Layergram v3 checkpoint receipt');
  }
  late final Map<String, dynamic> map;
  try {
    map = value.cast<String, dynamic>();
  } catch (_) {
    throw const FormatException('Invalid Layergram v3 checkpoint receipt');
  }
  const expectedKeys = <String>{
    'direction',
    'assemblyId',
    'stableRecordId',
    'sessionId',
    'ratchetRevision',
    'stateDigest',
    'reserved',
  };
  if (map.length != expectedKeys.length ||
      !map.keys.every(expectedKeys.contains) ||
      map['direction'] is! int ||
      map['assemblyId'] is! String ||
      map['stableRecordId'] is! String ||
      map['sessionId'] is! String ||
      map['ratchetRevision'] is! int ||
      map['stateDigest'] is! String ||
      map['reserved'] != 0) {
    throw const FormatException('Invalid Layergram v3 checkpoint receipt');
  }
  return V3CheckpointReceipt._(
    direction: V3CheckpointEffectDirection.fromWireId(map['direction'] as int),
    assemblyId: map['assemblyId'] as String,
    stableRecordId: map['stableRecordId'] as String,
    sessionKey: map['sessionId'] as String,
    ratchetRevision: map['ratchetRevision'] as int,
    stateDigest: map['stateDigest'] as String,
  );
}

Map<String, dynamic> _encodeReceipt(V3CheckpointReceipt receipt) =>
    <String, dynamic>{
      'direction': receipt.direction.wireId,
      'assemblyId': receipt.assemblyId,
      'stableRecordId': receipt.stableRecordId,
      'sessionId': receipt.sessionKey,
      'ratchetRevision': receipt.ratchetRevision,
      'stateDigest': receipt.stateDigest,
      'reserved': 0,
    };

V3CheckpointRetirementTransition? _decodeRetirementTransition(dynamic value) {
  if (value == null) return null;
  if (value is! Map) {
    throw const FormatException(
      'Invalid Layergram v3 checkpoint retirement transition',
    );
  }
  late final Map<String, dynamic> map;
  try {
    map = value.cast<String, dynamic>();
  } catch (_) {
    throw const FormatException(
      'Invalid Layergram v3 checkpoint retirement transition',
    );
  }
  const keys = <String>{'sourceCheckpointDigest', 'retiredReceipt', 'reserved'};
  if (map.length != keys.length ||
      !map.keys.every(keys.contains) ||
      map['sourceCheckpointDigest'] is! String ||
      map['reserved'] != 0) {
    throw const FormatException(
      'Invalid Layergram v3 checkpoint retirement transition',
    );
  }
  return V3CheckpointRetirementTransition._(
    sourceCheckpointDigest: map['sourceCheckpointDigest'] as String,
    retiredReceipt: _decodeReceipt(map['retiredReceipt']),
  );
}

Map<String, dynamic>? _encodeRetirementTransition(
  V3CheckpointRetirementTransition? value,
) {
  if (value == null) return null;
  return <String, dynamic>{
    'sourceCheckpointDigest': value.sourceCheckpointDigest,
    'retiredReceipt': _encodeReceipt(value.retiredReceipt),
    'reserved': 0,
  };
}

void _validateRetirementTransition(
  V3CheckpointRetirementTransition? value, {
  required String sessionKey,
  required int revision,
  required List<V3CheckpointReceipt> receipts,
  required String checkpointDigest,
}) {
  if (value == null) return;
  final receipt = value.retiredReceipt;
  if (!_isCanonicalDigest(value.sourceCheckpointDigest) ||
      value.sourceCheckpointDigest == checkpointDigest ||
      receipt.sessionKey != sessionKey ||
      receipt.ratchetRevision <= 0 ||
      receipt.ratchetRevision > revision ||
      receipt.stableRecordId != 'v3:${receipt.assemblyId}' ||
      !_isCanonicalId(receipt.assemblyId, 32) ||
      !_isCanonicalDigest(receipt.stateDigest) ||
      receipts.any((candidate) =>
          candidate.assemblyId == receipt.assemblyId ||
          candidate.ratchetRevision == receipt.ratchetRevision)) {
    throw const FormatException(
      'Invalid Layergram v3 checkpoint retirement binding',
    );
  }
}

V3SessionCheckpoint _selectCheckpointHistory(
  List<V3SessionCheckpoint> candidates,
) {
  if (candidates.isEmpty) {
    throw StateError('Layergram v3 checkpoint history is empty');
  }
  final byDigest = <String, V3SessionCheckpoint>{};
  for (final candidate in candidates) {
    final previous = byDigest[candidate.checkpointDigest];
    if (previous == null) {
      byDigest[candidate.checkpointDigest] = candidate;
    } else if (!_sameCheckpoint(previous, candidate)) {
      throw const V3LmfPersistenceConflictException(
        'divergent v3 checkpoints share a digest',
      );
    }
  }
  for (final candidate in byDigest.values) {
    final sourceDigest = candidate.retirementTransition?.sourceCheckpointDigest;
    if (sourceDigest == null) continue;
    final source = byDigest[sourceDigest];
    if (source != null && !_isExactReceiptReplacement(source, candidate)) {
      throw const V3LmfPersistenceConflictException(
        'v3 checkpoint retirement chain is invalid',
      );
    }
  }

  final byRevision = <int, List<V3SessionCheckpoint>>{};
  for (final candidate in byDigest.values) {
    byRevision
        .putIfAbsent(candidate.revision, () => <V3SessionCheckpoint>[])
        .add(candidate);
  }
  final revisions = byRevision.keys.toList()..sort();
  V3SessionCheckpoint? previous;
  for (final revision in revisions) {
    final selected = _selectCheckpointRevisionTip(byRevision[revision]!);
    if (previous != null && !_extendsCheckpoint(previous, selected)) {
      throw const V3LmfPersistenceConflictException(
        'v3 checkpoint history is not monotonic',
      );
    }
    previous = selected;
  }
  return previous!;
}

V3SessionCheckpoint _selectCheckpointRevisionTip(
  List<V3SessionCheckpoint> candidates,
) {
  if (candidates.length == 1) return candidates.single;
  final byDigest = <String, V3SessionCheckpoint>{
    for (final candidate in candidates) candidate.checkpointDigest: candidate,
  };
  final childBySource = <String, V3SessionCheckpoint>{};
  final roots = <V3SessionCheckpoint>[];
  for (final candidate in candidates) {
    final source = candidate.retirementTransition?.sourceCheckpointDigest;
    if (source == null || !byDigest.containsKey(source)) {
      roots.add(candidate);
      continue;
    }
    final previousChild = childBySource[source];
    if (previousChild != null &&
        previousChild.checkpointDigest != candidate.checkpointDigest) {
      throw const V3LmfPersistenceConflictException(
        'v3 checkpoint retirement history forked',
      );
    }
    childBySource[source] = candidate;
  }
  if (roots.length != 1) {
    throw const V3LmfPersistenceConflictException(
      'v3 checkpoint revision has divergent roots',
    );
  }
  var current = roots.single;
  var visited = 1;
  while (true) {
    final child = childBySource[current.checkpointDigest];
    if (child == null) break;
    current = child;
    visited++;
    if (visited > candidates.length) {
      throw const V3LmfPersistenceConflictException(
        'v3 checkpoint retirement history contains a cycle',
      );
    }
  }
  if (visited != candidates.length) {
    throw const V3LmfPersistenceConflictException(
      'v3 checkpoint retirement history is disconnected',
    );
  }
  return current;
}

Set<String> _retirementAncestorDigests(
  V3SessionCheckpoint selected,
  List<V3SessionCheckpoint> history,
) {
  final byDigest = <String, V3SessionCheckpoint>{
    for (final value in history) value.checkpointDigest: value,
  };
  final ancestors = <String>{};
  var current = selected;
  final visited = <String>{selected.checkpointDigest};
  while (true) {
    final transition = current.retirementTransition;
    if (transition == null) return ancestors;
    final sourceDigest = transition.sourceCheckpointDigest;
    if (!visited.add(sourceDigest)) return ancestors;
    final source = byDigest[sourceDigest];
    if (source == null || source.revision != selected.revision) {
      return ancestors;
    }
    ancestors.add(sourceDigest);
    current = source;
  }
}

bool _sameCheckpoint(V3SessionCheckpoint left, V3SessionCheckpoint right) =>
    left.sessionKey == right.sessionKey &&
    left.revision == right.revision &&
    left.lineageDigest == right.lineageDigest &&
    left.snapshotDigest == right.snapshotDigest &&
    left.checkpointDigest == right.checkpointDigest &&
    _bytesEqual(left._encodedSnapshot, right._encodedSnapshot) &&
    _sameReceiptList(left.receipts, right.receipts) &&
    _sameRetirementTransition(
      left.retirementTransition,
      right.retirementTransition,
    );

bool _sameCheckpointStateAndReceipts(
  V3SessionCheckpoint left,
  V3SessionCheckpoint right,
) =>
    left.sessionKey == right.sessionKey &&
    left.revision == right.revision &&
    left.lineageDigest == right.lineageDigest &&
    left.snapshotDigest == right.snapshotDigest &&
    _bytesEqual(left._encodedSnapshot, right._encodedSnapshot) &&
    _sameReceiptList(left.receipts, right.receipts);

bool _sameRetirementTransition(
  V3CheckpointRetirementTransition? left,
  V3CheckpointRetirementTransition? right,
) {
  if (left == null || right == null) return left == null && right == null;
  return left.sourceCheckpointDigest == right.sourceCheckpointDigest &&
      _sameReceipt(left.retiredReceipt, right.retiredReceipt);
}

bool _isExactReceiptReplacement(
  V3SessionCheckpoint source,
  V3SessionCheckpoint replacement,
) {
  final transition = replacement.retirementTransition;
  if (transition == null ||
      transition.sourceCheckpointDigest != source.checkpointDigest ||
      source.sessionKey != replacement.sessionKey ||
      source.revision != replacement.revision ||
      source.lineageDigest != replacement.lineageDigest ||
      source.snapshotDigest != replacement.snapshotDigest ||
      !_bytesEqual(source._encodedSnapshot, replacement._encodedSnapshot) ||
      replacement.persistedAt.isBefore(source.persistedAt) ||
      source.receipts.length != replacement.receipts.length + 1) {
    return false;
  }
  final retired = source.receiptForAssembly(
    transition.retiredReceipt.assemblyId,
  );
  if (retired == null || !_sameReceipt(retired, transition.retiredReceipt)) {
    return false;
  }
  for (final receipt in replacement.receipts) {
    final previous = source.receiptForAssembly(receipt.assemblyId);
    if (previous == null || !_sameReceipt(previous, receipt)) return false;
  }
  return true;
}

bool _extendsCheckpoint(
  V3SessionCheckpoint earlier,
  V3SessionCheckpoint later,
) {
  if (earlier.sessionKey != later.sessionKey ||
      earlier.revision >= later.revision ||
      earlier.lineageDigest != later.lineageDigest) {
    return false;
  }
  final earlierByRevision = <int, V3CheckpointReceipt>{
    for (final receipt in earlier.receipts) receipt.ratchetRevision: receipt,
  };
  final laterByRevision = <int, V3CheckpointReceipt>{
    for (final receipt in later.receipts) receipt.ratchetRevision: receipt,
  };
  for (final receipt in earlier.receipts) {
    final retained = laterByRevision[receipt.ratchetRevision];
    if (retained == null || !_sameReceipt(receipt, retained)) return false;
  }
  var nextRevision = earlier.revision + 1;
  for (final receipt in later.receipts) {
    if (receipt.ratchetRevision <= earlier.revision) {
      final existing = earlierByRevision[receipt.ratchetRevision];
      if (existing == null || !_sameReceipt(existing, receipt)) return false;
      continue;
    }
    if (receipt.ratchetRevision != nextRevision) return false;
    nextRevision++;
  }
  return nextRevision == later.revision + 1;
}

bool _sameReceiptList(
  List<V3CheckpointReceipt> left,
  List<V3CheckpointReceipt> right,
) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (!_sameReceipt(left[index], right[index])) return false;
  }
  return true;
}

bool _sameReceipt(V3CheckpointReceipt left, V3CheckpointReceipt right) =>
    left.direction == right.direction &&
    left.assemblyId == right.assemblyId &&
    left.stableRecordId == right.stableRecordId &&
    left.sessionKey == right.sessionKey &&
    left.ratchetRevision == right.ratchetRevision &&
    left.stateDigest == right.stateDigest;

String _stateDigest({
  required V3CheckpointEffectDirection direction,
  required String assemblyId,
  required Uint8List applicationState,
  required Uint8List ratchetState,
}) {
  final assembly = _decodeBinary(assemblyId, 32);
  final header = ByteData(9)
    ..setUint8(0, direction.wireId)
    ..setUint32(1, applicationState.length, Endian.big)
    ..setUint32(5, ratchetState.length, Endian.big);
  final bytes = Uint8List(
    utf8.encode('layergram/v3/checkpoint/effect-state\u0000').length +
        assembly.length +
        header.lengthInBytes +
        applicationState.length +
        ratchetState.length,
  );
  var offset = 0;
  void append(List<int> value) {
    bytes.setRange(offset, offset + value.length, value);
    offset += value.length;
  }

  try {
    append(utf8.encode('layergram/v3/checkpoint/effect-state\u0000'));
    append(assembly);
    append(header.buffer.asUint8List());
    append(applicationState);
    append(ratchetState);
    return _sha256Armored(bytes);
  } finally {
    _wipe(assembly);
    _wipe(bytes);
  }
}

String _lineageDigest(V3TripleRatchetState snapshot) {
  final sessionId = snapshot.sessionId;
  final transcript = snapshot.transcriptDigest;
  final initiatorBinding = snapshot.initiatorRoutingBinding;
  final responderBinding = snapshot.responderRoutingBinding;
  final ackI2R = snapshot.initiatorToResponderAckRootKey;
  final ackR2I = snapshot.responderToInitiatorAckRootKey;
  final bytes = Uint8List.fromList(<int>[
    ...utf8.encode('layergram/v3/checkpoint/lineage\u0000'),
    snapshot.role.wireId,
    ...sessionId,
    ...transcript,
    ...initiatorBinding,
    ...responderBinding,
    ...ackI2R,
    ...ackR2I,
  ]);
  try {
    return _sha256Armored(bytes);
  } finally {
    _wipe(sessionId);
    _wipe(transcript);
    _wipe(initiatorBinding);
    _wipe(responderBinding);
    _wipe(ackI2R);
    _wipe(ackR2I);
    _wipe(bytes);
  }
}

String _snapshotDigest(Uint8List encodedSnapshot) {
  final bytes = Uint8List.fromList(<int>[
    ...utf8.encode('layergram/v3/checkpoint/snapshot\u0000'),
    ...encodedSnapshot,
  ]);
  try {
    return _sha256Armored(bytes);
  } finally {
    _wipe(bytes);
  }
}

String _checkpointDigest({
  required String sessionKey,
  required int revision,
  required String lineageDigest,
  required String snapshotDigest,
  required List<V3CheckpointReceipt> receipts,
  required V3CheckpointRetirementTransition? retirementTransition,
}) {
  final session = _decodeBinary(sessionKey, 16);
  final lineage = _decodeBinary(lineageDigest, 32);
  final snapshot = _decodeBinary(snapshotDigest, 32);
  final header = ByteData(12)
    ..setUint64(0, revision, Endian.big)
    ..setUint32(8, receipts.length, Endian.big);
  final receiptBytes = <Uint8List>[];
  Uint8List? retiredReceiptBytes;
  Uint8List? sourceCheckpoint;
  try {
    for (final receipt in receipts) {
      receiptBytes.add(_encodeReceiptDigestBytes(receipt));
    }
    if (retirementTransition != null) {
      sourceCheckpoint = _decodeBinary(
        retirementTransition.sourceCheckpointDigest,
        32,
      );
      retiredReceiptBytes =
          _encodeReceiptDigestBytes(retirementTransition.retiredReceipt);
    }
    final label = utf8.encode('layergram/v3/checkpoint/record\u0000');
    final bytes = Uint8List(
      label.length +
          session.length +
          header.lengthInBytes +
          lineage.length +
          snapshot.length +
          receiptBytes.length * 73 +
          1 +
          32 +
          73,
    );
    var offset = 0;
    void append(List<int> value) {
      bytes.setRange(offset, offset + value.length, value);
      offset += value.length;
    }

    try {
      append(label);
      append(session);
      append(header.buffer.asUint8List());
      append(lineage);
      append(snapshot);
      for (final receipt in receiptBytes) {
        append(receipt);
      }
      append(<int>[retirementTransition == null ? 0 : 1]);
      append(sourceCheckpoint ?? Uint8List(32));
      append(retiredReceiptBytes ?? Uint8List(73));
      return _sha256Armored(bytes);
    } finally {
      _wipe(bytes);
    }
  } finally {
    _wipe(session);
    _wipe(lineage);
    _wipe(snapshot);
    for (final receipt in receiptBytes) {
      _wipe(receipt);
    }
    if (sourceCheckpoint != null) _wipe(sourceCheckpoint);
    if (retiredReceiptBytes != null) _wipe(retiredReceiptBytes);
  }
}

Uint8List _encodeReceiptDigestBytes(V3CheckpointReceipt receipt) {
  final assembly = _decodeBinary(receipt.assemblyId, 32);
  final digest = _decodeBinary(receipt.stateDigest, 32);
  final encoded = Uint8List(73);
  try {
    final data = ByteData.sublistView(encoded);
    encoded[0] = receipt.direction.wireId;
    encoded.setRange(1, 33, assembly);
    data.setUint64(33, receipt.ratchetRevision, Endian.big);
    encoded.setRange(41, 73, digest);
    return encoded;
  } finally {
    _wipe(assembly);
    _wipe(digest);
  }
}

String _sha256Armored(Uint8List value) {
  final digest = Uint8List.fromList(crypto.sha256.convert(value).bytes);
  try {
    return _encodeBinary(digest);
  } finally {
    _wipe(digest);
  }
}

DateTime _validatedTimestamp(DateTime value) =>
    _timestampFromMillis(value.toUtc().millisecondsSinceEpoch);

DateTime _timestampFromMillis(int value) {
  if (value < 0 || value > V3SessionCheckpointRepository._maxTimestampMillis) {
    throw const FormatException('Invalid Layergram v3 checkpoint timestamp');
  }
  return DateTime.fromMillisecondsSinceEpoch(value, isUtc: true);
}

String _sessionKey(Uint8List sessionId) {
  if (sessionId.length != V3LmfFrameCodec.sessionIdBytes ||
      _isAllZero(sessionId)) {
    throw ArgumentError.value(sessionId, 'sessionId');
  }
  return _encodeBinary(sessionId);
}

bool _isCanonicalId(String value, int byteLength) {
  try {
    final decoded = _decodeBinary(value, byteLength);
    final valid = decoded.length == byteLength && !_isAllZero(decoded);
    _wipe(decoded);
    return valid;
  } catch (_) {
    return false;
  }
}

bool _isCanonicalDigest(String value) => _isCanonicalId(value, 32);

String _encodeBinary(Uint8List bytes) =>
    base64UrlEncode(bytes).replaceAll('=', '');

Uint8List _decodeBinary(String armored, int maxBytes) {
  if (armored.isEmpty || armored.length > ((maxBytes * 4 + 2) ~/ 3)) {
    throw const FormatException(
        'Invalid Layergram v3 checkpoint binary length');
  }
  for (final codeUnit in armored.codeUnits) {
    final upper = codeUnit >= 0x41 && codeUnit <= 0x5a;
    final lower = codeUnit >= 0x61 && codeUnit <= 0x7a;
    final digit = codeUnit >= 0x30 && codeUnit <= 0x39;
    if (!upper && !lower && !digit && codeUnit != 0x2d && codeUnit != 0x5f) {
      throw const FormatException('Invalid Layergram v3 checkpoint armor');
    }
  }
  late final Uint8List bytes;
  try {
    bytes = Uint8List.fromList(
      base64Url.decode(base64Url.normalize(armored)),
    );
  } catch (_) {
    throw const FormatException('Invalid Layergram v3 checkpoint armor');
  }
  if (bytes.isEmpty ||
      bytes.length > maxBytes ||
      _encodeBinary(bytes) != armored) {
    _wipe(bytes);
    throw const FormatException('Non-canonical Layergram v3 checkpoint armor');
  }
  return bytes;
}

bool _isAllZero(List<int> bytes) {
  var accumulator = 0;
  for (final byte in bytes) {
    accumulator |= byte;
  }
  return accumulator == 0;
}

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
