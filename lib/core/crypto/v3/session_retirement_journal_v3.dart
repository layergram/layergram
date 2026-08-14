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

import 'lmf_v3_persistence.dart';
import 'session_checkpoint_v3.dart';

/// Durable phase of one conservative proof-and-receipt retirement.
///
/// No phase means that a compact replay/completion proof may be deleted. The
/// future session coordinator must first verify the replacement checkpoint,
/// remove the compact proof, and only then collect this journal record.
enum V3SessionRetirementStage {
  prepared(0),
  checkpointReplaced(1);

  const V3SessionRetirementStage(this.wireId);

  final int wireId;

  static V3SessionRetirementStage fromWireId(int value) {
    for (final stage in values) {
      if (stage.wireId == value) return stage;
    }
    throw const FormatException('Invalid Layergram v3 retirement stage');
  }
}

/// Immutable, non-secret retirement intent retained in encrypted Aux storage.
final class V3SessionRetirementPlan {
  const V3SessionRetirementPlan._({
    required this.storageId,
    required this.planId,
    required this.stage,
    required this.direction,
    required this.assemblyId,
    required this.proofDigest,
    required this.stableRecordId,
    required this.sessionKey,
    required this.ratchetRevision,
    required this.stateDigest,
    required this.sourceCheckpointDigest,
    required this.replacementCheckpointDigest,
    required this.proofRecordedAt,
    required this.preparedAt,
    required this.minimumProofLifetimeSeconds,
    required this.recordDigest,
  });

  final String storageId;
  final String planId;
  final V3SessionRetirementStage stage;
  final V3CheckpointEffectDirection direction;
  final String assemblyId;
  final String proofDigest;
  final String stableRecordId;
  final String sessionKey;
  final int ratchetRevision;
  final String stateDigest;
  final String sourceCheckpointDigest;
  final String? replacementCheckpointDigest;
  final DateTime proofRecordedAt;
  final DateTime preparedAt;
  final int minimumProofLifetimeSeconds;
  final String recordDigest;

  bool get checkpointWasReplaced =>
      stage == V3SessionRetirementStage.checkpointReplaced;
}

final class V3SessionRetirementRestoreResult {
  const V3SessionRetirementRestoreResult({
    required this.plans,
    required this.removedSupersededRecords,
  });

  final List<V3SessionRetirementPlan> plans;
  final int removedSupersededRecords;
}

/// Unforgeable ownership token for the future unified retirement coordinator.
final class V3SessionRetirementAuthority {
  const V3SessionRetirementAuthority._();
}

/// Crash-consistent, deliberately non-destructive retirement journal.
///
/// A prepared record freezes the exact cumulative checkpoint receipt, compact
/// proof, local proof age, and source checkpoint selected for retirement. A
/// second write binds the exact replacement checkpoint digest before any
/// compact proof or cumulative receipt may disappear. The current class does
/// not expose a delete/collect method: activation requires the session
/// coordinator to verify both durable sides and implement recovery for every
/// intervening crash window.
final class V3SessionRetirementJournal {
  V3SessionRetirementJournal({
    required V3LmfRecordStore store,
    this.maxPlans = 4096,
    this.maxStoredRecords = 8192,
    this.maxTotalRetainedBytes = 4 * 1024 * 1024,
  }) : _store = store {
    if (maxPlans <= 0 || maxStoredRecords <= 0 || maxTotalRetainedBytes <= 0) {
      throw ArgumentError('Layergram v3 retirement limits are invalid');
    }
  }

  static const String recordKind = 'v3_session_retirement_v1';
  static const int _recordVersion = 1;
  static const int _maxSigned63 = 0x7fffffffffffffff;
  static const int _maxTimestampMillis = 253402300799999;

  /// Conservative upper bound for the fixed-width canonical JSON envelope.
  static const int _retainedBytesPerPlan = 1024;

  final V3LmfRecordStore _store;
  final int maxPlans;
  final int maxStoredRecords;
  final int maxTotalRetainedBytes;

  final Map<String, V3SessionRetirementPlan> _plans =
      <String, V3SessionRetirementPlan>{};
  Future<void> _operationTail = Future<void>.value();
  V3SessionRetirementAuthority? _authority;
  bool _restored = false;
  bool _closed = false;
  bool _writeRecoveryRequired = false;

  int get planCount => _plans.length;
  int get totalRetainedBytes => _plans.length * _retainedBytesPerPlan;
  bool get requiresRecovery => _writeRecoveryRequired;

  List<V3SessionRetirementPlan> plans({
    V3SessionRetirementAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return List<V3SessionRetirementPlan>.unmodifiable(_plans.values);
  }

  V3SessionRetirementPlan? planForId(
    String planId, {
    V3SessionRetirementAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return _plans[planId];
  }

  Future<V3SessionRetirementAuthority> claimSessionCoordinatorAuthority() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError(
          'Layergram v3 retirement authority must be claimed before restore',
        );
      }
      if (_authority != null) {
        throw StateError(
          'Layergram v3 retirement journal already has a coordinator',
        );
      }
      final authority = V3SessionRetirementAuthority._();
      _authority = authority;
      return authority;
    });
  }

  Future<V3SessionRetirementRestoreResult> restore({
    V3SessionRetirementAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 retirement journal was restored');
      }
      final records = await _store.readAll();
      final relevant = records
          .where((record) => record.payload['kind'] == recordKind)
          .toList(growable: false);
      if (relevant.length > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical v3 retirement record limit exceeded',
        );
      }

      final grouped = <String, List<V3SessionRetirementPlan>>{};
      for (final stored in relevant) {
        final plan = _decode(stored);
        grouped
            .putIfAbsent(plan.planId, () => <V3SessionRetirementPlan>[])
            .add(plan);
      }
      if (grouped.length > maxPlans ||
          grouped.length * _retainedBytesPerPlan > maxTotalRetainedBytes) {
        throw const V3LmfPersistenceLimitException(
          'v3 retirement retained-state limit exceeded',
        );
      }

      var removed = 0;
      for (final candidates in grouped.values) {
        candidates.sort((left, right) {
          final stage = right.stage.wireId.compareTo(left.stage.wireId);
          if (stage != 0) return stage;
          return left.storageId.compareTo(right.storageId);
        });
        final selected = candidates.first;
        for (final candidate in candidates.skip(1)) {
          if (candidate.stage == selected.stage) {
            if (!_samePlan(candidate, selected)) {
              throw const V3LmfPersistenceConflictException(
                'divergent v3 retirement records share one stage',
              );
            }
          } else if (!_extendsPrepared(candidate, selected)) {
            throw const V3LmfPersistenceConflictException(
              'v3 retirement stage does not extend its prepared record',
            );
          }
        }
        _plans[selected.planId] = selected;
        for (final candidate in candidates.skip(1)) {
          await _deleteIgnoringFailure(candidate.storageId);
          removed++;
        }
      }
      _restored = true;
      return V3SessionRetirementRestoreResult(
        plans: plans(authority: authority),
        removedSupersededRecords: removed,
      );
    });
  }

  /// Freezes an already-eligible compact proof and its exact source receipt.
  ///
  /// The local age check is repeated here so an integration cannot prepare a
  /// retirement merely by forgetting to call the v3 retention policy.
  Future<V3SessionRetirementPlan> prepare({
    required V3CheckpointEffectDirection direction,
    required String assemblyId,
    required String proofDigest,
    required String stableRecordId,
    required String sessionKey,
    required int ratchetRevision,
    required String stateDigest,
    required String sourceCheckpointDigest,
    required DateTime proofRecordedAt,
    required DateTime preparedAt,
    required int minimumProofLifetimeSeconds,
    V3SessionRetirementAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final candidate = _validatedPlan(
        storageId: '',
        stage: V3SessionRetirementStage.prepared,
        direction: direction,
        assemblyId: assemblyId,
        proofDigest: proofDigest,
        stableRecordId: stableRecordId,
        sessionKey: sessionKey,
        ratchetRevision: ratchetRevision,
        stateDigest: stateDigest,
        sourceCheckpointDigest: sourceCheckpointDigest,
        replacementCheckpointDigest: null,
        proofRecordedAt: proofRecordedAt,
        preparedAt: preparedAt,
        minimumProofLifetimeSeconds: minimumProofLifetimeSeconds,
      );
      final existing = _plans[candidate.planId];
      if (existing != null) {
        if (!_samePreparedIdentity(existing, candidate)) {
          throw const V3LmfPersistenceConflictException(
            'v3 retirement plan diverged for one receipt',
          );
        }
        return existing;
      }
      if (_plans.length >= maxPlans ||
          (_plans.length + 1) * _retainedBytesPerPlan > maxTotalRetainedBytes) {
        throw const V3LmfPersistenceLimitException(
          'v3 retirement journal capacity exceeded',
        );
      }
      try {
        final storageId = await _store.write(_encode(candidate));
        final durable = _copyWith(candidate, storageId: storageId);
        _plans[durable.planId] = durable;
        return durable;
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      }
    });
  }

  /// Records the exact replacement checkpoint after it became durable.
  ///
  /// This is write-new-before-delete. It still does not authorize removal of
  /// the compact proof; the future coordinator must reconcile all three stores
  /// after a restart before adding that final operation.
  Future<V3SessionRetirementPlan> markCheckpointReplaced({
    required String planId,
    required String expectedSourceCheckpointDigest,
    required String replacementCheckpointDigest,
    V3SessionRetirementAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final current = _plans[planId];
      if (current == null) {
        throw StateError('Layergram v3 retirement plan is not prepared');
      }
      if (current.sourceCheckpointDigest != expectedSourceCheckpointDigest ||
          !_isCanonicalDigest(replacementCheckpointDigest) ||
          replacementCheckpointDigest == expectedSourceCheckpointDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 retirement checkpoint binding diverged',
        );
      }
      if (current.checkpointWasReplaced) {
        if (current.replacementCheckpointDigest !=
            replacementCheckpointDigest) {
          throw const V3LmfPersistenceConflictException(
            'v3 retirement replacement checkpoint diverged',
          );
        }
        return current;
      }
      final candidate = _validatedPlan(
        storageId: '',
        stage: V3SessionRetirementStage.checkpointReplaced,
        direction: current.direction,
        assemblyId: current.assemblyId,
        proofDigest: current.proofDigest,
        stableRecordId: current.stableRecordId,
        sessionKey: current.sessionKey,
        ratchetRevision: current.ratchetRevision,
        stateDigest: current.stateDigest,
        sourceCheckpointDigest: current.sourceCheckpointDigest,
        replacementCheckpointDigest: replacementCheckpointDigest,
        proofRecordedAt: current.proofRecordedAt,
        preparedAt: current.preparedAt,
        minimumProofLifetimeSeconds: current.minimumProofLifetimeSeconds,
      );
      try {
        final storageId = await _store.write(_encode(candidate));
        final durable = _copyWith(candidate, storageId: storageId);
        _plans[planId] = durable;
        await _deleteIgnoringFailure(current.storageId);
        return durable;
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      }
    });
  }

  Future<void> close({V3SessionRetirementAuthority? authority}) {
    return _serialized(() async {
      _ensureAuthority(authority);
      if (_closed) return;
      _closed = true;
      _plans.clear();
    });
  }

  V3SessionRetirementPlan _decode(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    const keys = <String>{
      'kind',
      'version',
      'planId',
      'stage',
      'direction',
      'assemblyId',
      'proofDigest',
      'stableRecordId',
      'sessionId',
      'ratchetRevision',
      'stateDigest',
      'sourceCheckpointDigest',
      'replacementCheckpointDigest',
      'proofRecordedAt',
      'preparedAt',
      'minimumProofLifetimeSeconds',
      'recordDigest',
      'reserved',
    };
    if (payload.length != keys.length ||
        !payload.keys.every(keys.contains) ||
        payload['kind'] != recordKind ||
        payload['version'] != _recordVersion ||
        payload['planId'] is! String ||
        payload['stage'] is! int ||
        payload['direction'] is! int ||
        payload['assemblyId'] is! String ||
        payload['proofDigest'] is! String ||
        payload['stableRecordId'] is! String ||
        payload['sessionId'] is! String ||
        payload['ratchetRevision'] is! int ||
        payload['stateDigest'] is! String ||
        payload['sourceCheckpointDigest'] is! String ||
        (payload['replacementCheckpointDigest'] != null &&
            payload['replacementCheckpointDigest'] is! String) ||
        payload['proofRecordedAt'] is! int ||
        payload['preparedAt'] is! int ||
        payload['minimumProofLifetimeSeconds'] is! int ||
        payload['recordDigest'] is! String ||
        payload['reserved'] != 0) {
      throw const FormatException('Invalid Layergram v3 retirement envelope');
    }
    final plan = _validatedPlan(
      storageId: stored.storageId,
      stage: V3SessionRetirementStage.fromWireId(payload['stage'] as int),
      direction: V3CheckpointEffectDirection.fromWireId(
        payload['direction'] as int,
      ),
      assemblyId: payload['assemblyId'] as String,
      proofDigest: payload['proofDigest'] as String,
      stableRecordId: payload['stableRecordId'] as String,
      sessionKey: payload['sessionId'] as String,
      ratchetRevision: payload['ratchetRevision'] as int,
      stateDigest: payload['stateDigest'] as String,
      sourceCheckpointDigest: payload['sourceCheckpointDigest'] as String,
      replacementCheckpointDigest:
          payload['replacementCheckpointDigest'] as String?,
      proofRecordedAt: _timestamp(payload['proofRecordedAt'] as int),
      preparedAt: _timestamp(payload['preparedAt'] as int),
      minimumProofLifetimeSeconds:
          payload['minimumProofLifetimeSeconds'] as int,
    );
    if (plan.planId != payload['planId'] ||
        plan.recordDigest != payload['recordDigest']) {
      throw const FormatException('Mismatched Layergram v3 retirement binding');
    }
    return plan;
  }

  V3SessionRetirementPlan _validatedPlan({
    required String storageId,
    required V3SessionRetirementStage stage,
    required V3CheckpointEffectDirection direction,
    required String assemblyId,
    required String proofDigest,
    required String stableRecordId,
    required String sessionKey,
    required int ratchetRevision,
    required String stateDigest,
    required String sourceCheckpointDigest,
    required String? replacementCheckpointDigest,
    required DateTime proofRecordedAt,
    required DateTime preparedAt,
    required int minimumProofLifetimeSeconds,
  }) {
    final proofAt = _validatedTimestamp(proofRecordedAt);
    final prepared = _validatedTimestamp(preparedAt);
    if (!_isCanonicalDigest(assemblyId) ||
        !_isCanonicalDigest(proofDigest) ||
        stableRecordId != 'v3:$assemblyId' ||
        !_isCanonicalId(sessionKey, 16) ||
        ratchetRevision <= 0 ||
        ratchetRevision > _maxSigned63 ||
        !_isCanonicalDigest(stateDigest) ||
        !_isCanonicalDigest(sourceCheckpointDigest) ||
        minimumProofLifetimeSeconds <= 0 ||
        minimumProofLifetimeSeconds > _maxSigned63 ||
        prepared.isBefore(proofAt) ||
        prepared.difference(proofAt).inSeconds < minimumProofLifetimeSeconds) {
      throw const FormatException('Invalid Layergram v3 retirement plan');
    }
    if ((stage == V3SessionRetirementStage.prepared &&
            replacementCheckpointDigest != null) ||
        (stage == V3SessionRetirementStage.checkpointReplaced &&
            (!_isCanonicalDigest(replacementCheckpointDigest ?? '') ||
                replacementCheckpointDigest == sourceCheckpointDigest))) {
      throw const FormatException('Invalid Layergram v3 retirement transition');
    }
    final planId = _planId(
      direction: direction,
      assemblyId: assemblyId,
      sourceCheckpointDigest: sourceCheckpointDigest,
    );
    final recordDigest = _recordDigest(
      planId: planId,
      stage: stage,
      direction: direction,
      assemblyId: assemblyId,
      proofDigest: proofDigest,
      stableRecordId: stableRecordId,
      sessionKey: sessionKey,
      ratchetRevision: ratchetRevision,
      stateDigest: stateDigest,
      sourceCheckpointDigest: sourceCheckpointDigest,
      replacementCheckpointDigest: replacementCheckpointDigest,
      proofRecordedAt: proofAt,
      preparedAt: prepared,
      minimumProofLifetimeSeconds: minimumProofLifetimeSeconds,
    );
    return V3SessionRetirementPlan._(
      storageId: storageId,
      planId: planId,
      stage: stage,
      direction: direction,
      assemblyId: assemblyId,
      proofDigest: proofDigest,
      stableRecordId: stableRecordId,
      sessionKey: sessionKey,
      ratchetRevision: ratchetRevision,
      stateDigest: stateDigest,
      sourceCheckpointDigest: sourceCheckpointDigest,
      replacementCheckpointDigest: replacementCheckpointDigest,
      proofRecordedAt: proofAt,
      preparedAt: prepared,
      minimumProofLifetimeSeconds: minimumProofLifetimeSeconds,
      recordDigest: recordDigest,
    );
  }

  Map<String, dynamic> _encode(V3SessionRetirementPlan plan) =>
      <String, dynamic>{
        'kind': recordKind,
        'version': _recordVersion,
        'planId': plan.planId,
        'stage': plan.stage.wireId,
        'direction': plan.direction.wireId,
        'assemblyId': plan.assemblyId,
        'proofDigest': plan.proofDigest,
        'stableRecordId': plan.stableRecordId,
        'sessionId': plan.sessionKey,
        'ratchetRevision': plan.ratchetRevision,
        'stateDigest': plan.stateDigest,
        'sourceCheckpointDigest': plan.sourceCheckpointDigest,
        'replacementCheckpointDigest': plan.replacementCheckpointDigest,
        'proofRecordedAt': plan.proofRecordedAt.millisecondsSinceEpoch,
        'preparedAt': plan.preparedAt.millisecondsSinceEpoch,
        'minimumProofLifetimeSeconds': plan.minimumProofLifetimeSeconds,
        'recordDigest': plan.recordDigest,
        'reserved': 0,
      };

  Future<void> _deleteIgnoringFailure(String storageId) async {
    try {
      await _store.delete(storageId);
    } catch (_) {
      // Exact lower-stage duplicates are harmless and removed on next restore.
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
      throw StateError('Layergram v3 retirement journal is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored) {
      throw StateError('Layergram v3 retirement journal must be restored');
    }
    if (_writeRecoveryRequired) {
      throw StateError(
        'Layergram v3 retirement journal must be reconstructed and restored',
      );
    }
  }

  void _ensureAuthority(V3SessionRetirementAuthority? authority) {
    final claimed = _authority;
    if (claimed != null && !identical(claimed, authority)) {
      throw StateError(
        'Layergram v3 retirement journal is owned by a session coordinator',
      );
    }
  }
}

V3SessionRetirementPlan _copyWith(
  V3SessionRetirementPlan value, {
  required String storageId,
}) =>
    V3SessionRetirementPlan._(
      storageId: storageId,
      planId: value.planId,
      stage: value.stage,
      direction: value.direction,
      assemblyId: value.assemblyId,
      proofDigest: value.proofDigest,
      stableRecordId: value.stableRecordId,
      sessionKey: value.sessionKey,
      ratchetRevision: value.ratchetRevision,
      stateDigest: value.stateDigest,
      sourceCheckpointDigest: value.sourceCheckpointDigest,
      replacementCheckpointDigest: value.replacementCheckpointDigest,
      proofRecordedAt: value.proofRecordedAt,
      preparedAt: value.preparedAt,
      minimumProofLifetimeSeconds: value.minimumProofLifetimeSeconds,
      recordDigest: value.recordDigest,
    );

bool _extendsPrepared(
  V3SessionRetirementPlan prepared,
  V3SessionRetirementPlan replacement,
) =>
    prepared.stage == V3SessionRetirementStage.prepared &&
    replacement.stage == V3SessionRetirementStage.checkpointReplaced &&
    _samePreparedIdentity(prepared, replacement);

bool _samePreparedIdentity(
  V3SessionRetirementPlan left,
  V3SessionRetirementPlan right,
) =>
    left.planId == right.planId &&
    left.direction == right.direction &&
    left.assemblyId == right.assemblyId &&
    left.proofDigest == right.proofDigest &&
    left.stableRecordId == right.stableRecordId &&
    left.sessionKey == right.sessionKey &&
    left.ratchetRevision == right.ratchetRevision &&
    left.stateDigest == right.stateDigest &&
    left.sourceCheckpointDigest == right.sourceCheckpointDigest &&
    left.proofRecordedAt == right.proofRecordedAt &&
    left.preparedAt == right.preparedAt &&
    left.minimumProofLifetimeSeconds == right.minimumProofLifetimeSeconds;

bool _samePlan(
  V3SessionRetirementPlan left,
  V3SessionRetirementPlan right,
) =>
    _samePreparedIdentity(left, right) &&
    left.stage == right.stage &&
    left.replacementCheckpointDigest == right.replacementCheckpointDigest &&
    left.recordDigest == right.recordDigest;

String _planId({
  required V3CheckpointEffectDirection direction,
  required String assemblyId,
  required String sourceCheckpointDigest,
}) {
  final bytes = <int>[
    ...utf8.encode('layergram/v3/retirement/plan\u0000'),
    direction.wireId,
    ..._decodeDigest(assemblyId),
    ..._decodeDigest(sourceCheckpointDigest),
  ];
  return _digest(bytes);
}

String _recordDigest({
  required String planId,
  required V3SessionRetirementStage stage,
  required V3CheckpointEffectDirection direction,
  required String assemblyId,
  required String proofDigest,
  required String stableRecordId,
  required String sessionKey,
  required int ratchetRevision,
  required String stateDigest,
  required String sourceCheckpointDigest,
  required String? replacementCheckpointDigest,
  required DateTime proofRecordedAt,
  required DateTime preparedAt,
  required int minimumProofLifetimeSeconds,
}) {
  final numbers = ByteData(32)
    ..setUint64(0, ratchetRevision, Endian.big)
    ..setUint64(
      8,
      proofRecordedAt.millisecondsSinceEpoch,
      Endian.big,
    )
    ..setUint64(16, preparedAt.millisecondsSinceEpoch, Endian.big)
    ..setUint64(24, minimumProofLifetimeSeconds, Endian.big);
  final replacement = replacementCheckpointDigest == null
      ? Uint8List(32)
      : _decodeDigest(replacementCheckpointDigest);
  final stable = utf8.encode(stableRecordId);
  final bytes = <int>[
    ...utf8.encode('layergram/v3/retirement/record\u0000'),
    stage.wireId,
    direction.wireId,
    ..._decodeDigest(planId),
    ..._decodeDigest(assemblyId),
    ..._decodeDigest(proofDigest),
    stable.length,
    ...stable,
    ..._decodeId(sessionKey, 16),
    ...numbers.buffer.asUint8List(),
    ..._decodeDigest(stateDigest),
    ..._decodeDigest(sourceCheckpointDigest),
    ...replacement,
  ];
  return _digest(bytes);
}

String _digest(List<int> value) =>
    base64Url.encode(crypto.sha256.convert(value).bytes).replaceAll('=', '');

Uint8List _decodeDigest(String value) => _decodeId(value, 32);

Uint8List _decodeId(String value, int expectedLength) {
  final expectedEncodedLength = (expectedLength * 4 + 2) ~/ 3;
  if (value.length != expectedEncodedLength) {
    throw const FormatException('Invalid Layergram v3 identifier length');
  }
  try {
    final decoded = base64Url.decode(base64Url.normalize(value));
    if (decoded.length != expectedLength ||
        base64Url.encode(decoded).replaceAll('=', '') != value) {
      throw const FormatException('Non-canonical Layergram v3 identifier');
    }
    return Uint8List.fromList(decoded);
  } on FormatException {
    rethrow;
  } catch (_) {
    throw const FormatException('Invalid Layergram v3 identifier');
  }
}

bool _isCanonicalDigest(String value) {
  if (value.length != 43) return false;
  try {
    return _decodeDigest(value).length == 32;
  } on FormatException {
    return false;
  }
}

bool _isCanonicalId(String value, int length) {
  try {
    return _decodeId(value, length).length == length;
  } on FormatException {
    return false;
  }
}

DateTime _validatedTimestamp(DateTime value) {
  final utc = value.toUtc();
  final millis = utc.millisecondsSinceEpoch;
  if (millis < 0 || millis > V3SessionRetirementJournal._maxTimestampMillis) {
    throw const FormatException('Invalid Layergram v3 retirement timestamp');
  }
  return DateTime.fromMillisecondsSinceEpoch(millis, isUtc: true);
}

DateTime _timestamp(int millis) {
  if (millis < 0 || millis > V3SessionRetirementJournal._maxTimestampMillis) {
    throw const FormatException('Invalid Layergram v3 retirement timestamp');
  }
  return DateTime.fromMillisecondsSinceEpoch(millis, isUtc: true);
}
