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
import 'lmf_v3_persistence.dart';

/// One canonical AR3 record materialized in encrypted identity-scoped storage.
///
/// The encoded record is copied on construction and access. The materializer
/// owns its copy and wipes it when closed. The record remains an inactive v3
/// source of truth; projecting it into the current chat UI is a later gate.
final class V3MaterializedCommittedRecord {
  V3MaterializedCommittedRecord._({
    required this.storageId,
    required this.stableRecordId,
    required this.assemblyId,
    required this.sessionKey,
    required this.recordDigest,
    required Uint8List encodedRecord,
    required this.persistedAt,
  }) : _encodedRecord = Uint8List.fromList(encodedRecord);

  final String storageId;
  final String stableRecordId;
  final String assemblyId;
  final String sessionKey;
  final String recordDigest;
  final DateTime persistedAt;
  final Uint8List _encodedRecord;

  Uint8List get encodedRecord => Uint8List.fromList(_encodedRecord);
  int get retainedBytes => _encodedRecord.length;

  V3CommittedRecord decodeRecord() {
    final bytes = encodedRecord;
    try {
      return V3CommittedRecordCodec.decode(bytes);
    } finally {
      _wipe(bytes);
    }
  }

  void _close() => _wipe(_encodedRecord);
}

final class V3MaterializedRecordDeletion {
  const V3MaterializedRecordDeletion._({
    required this.storageId,
    required this.stableRecordId,
    required this.assemblyId,
    required this.sessionKey,
    required this.recordDigest,
    required this.retirementStateDigest,
    required this.deletedAt,
  });

  final String storageId;
  final String stableRecordId;
  final String assemblyId;
  final String sessionKey;
  final String recordDigest;
  final String retirementStateDigest;
  final DateTime deletedAt;
}

final class V3CommittedRecordMaterializerRestoreResult {
  const V3CommittedRecordMaterializerRestoreResult({
    required this.records,
    required this.removedExactDuplicates,
  });

  final List<V3MaterializedCommittedRecord> records;
  final int removedExactDuplicates;
}

/// Unforgeable ownership token for the unified v3 session coordinator.
final class V3CommittedRecordMaterializerAuthority {
  const V3CommittedRecordMaterializerAuthority._();
}

/// Idempotently materializes canonical AR3 records in the encrypted Aux store.
///
/// The logical key is [V3CommittedRecord.stableRecordId]. Replaying the exact
/// same record returns the existing durable value; a different AR3 record for
/// the same assembly fails closed. A write error has an ambiguous durable
/// outcome, therefore the current instance requires reconstruction and restore.
final class V3CommittedRecordMaterializer {
  V3CommittedRecordMaterializer({
    required V3LmfRecordStore store,
    this.maxRecords = 4096,
    this.maxDeletedRecords = 4096,
    this.maxTotalRecordBytes = 16 * 1024 * 1024,
    this.maxStoredRecords = 8192,
  }) : _store = store {
    if (maxRecords <= 0 ||
        maxDeletedRecords <= 0 ||
        maxTotalRecordBytes <= 0 ||
        maxStoredRecords <= 0) {
      throw ArgumentError('Layergram v3 materializer limits are invalid');
    }
  }

  static const String recordKind = 'v3_application_record_v1';
  static const String deletionRecordKind = 'v3_application_record_deleted_v1';
  static const int _recordVersion = 1;
  static const int _maxTimestampMillis = 253402300799999;

  final V3LmfRecordStore _store;
  final int maxRecords;
  final int maxDeletedRecords;
  final int maxTotalRecordBytes;
  final int maxStoredRecords;

  final Map<String, V3MaterializedCommittedRecord> _records =
      <String, V3MaterializedCommittedRecord>{};
  final Map<String, V3MaterializedRecordDeletion> _deletions =
      <String, V3MaterializedRecordDeletion>{};
  Future<void> _operationTail = Future<void>.value();
  bool _restored = false;
  bool _closed = false;
  bool _writeRecoveryRequired = false;
  V3CommittedRecordMaterializerAuthority? _authority;
  int _totalRecordBytes = 0;

  int get recordCount => _records.length;
  int get deletionCount => _deletions.length;
  int get totalRecordBytes => _totalRecordBytes;
  bool get requiresRecovery => _writeRecoveryRequired;

  V3MaterializedCommittedRecord? recordForStableId(
    String stableRecordId, {
    V3CommittedRecordMaterializerAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return _records[stableRecordId];
  }

  V3MaterializedRecordDeletion? deletionForStableId(
    String stableRecordId, {
    V3CommittedRecordMaterializerAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return _deletions[stableRecordId];
  }

  List<V3MaterializedCommittedRecord> records({
    V3CommittedRecordMaterializerAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return List<V3MaterializedCommittedRecord>.unmodifiable(_records.values);
  }

  List<V3MaterializedRecordDeletion> deletions({
    V3CommittedRecordMaterializerAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return List<V3MaterializedRecordDeletion>.unmodifiable(_deletions.values);
  }

  Future<V3CommittedRecordMaterializerAuthority>
      claimSessionCoordinatorAuthority() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError(
          'Layergram v3 materializer authority must be claimed before restore',
        );
      }
      if (_authority != null) {
        throw StateError(
          'Layergram v3 materializer already has a session coordinator',
        );
      }
      final authority = V3CommittedRecordMaterializerAuthority._();
      _authority = authority;
      return authority;
    });
  }

  Future<V3CommittedRecordMaterializerRestoreResult> restore({
    V3CommittedRecordMaterializerAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 materializer was already restored');
      }
      final storedRecords = await _store.readAll();
      final relevant = storedRecords
          .where(
            (record) =>
                record.payload['kind'] == recordKind ||
                record.payload['kind'] == deletionRecordKind,
          )
          .toList(growable: false);
      if (relevant.length > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical v3 materialized-record limit exceeded',
        );
      }
      var removed = 0;
      final deletionGroups = <String, List<V3MaterializedRecordDeletion>>{};
      for (final stored in relevant.where(
        (record) => record.payload['kind'] == deletionRecordKind,
      )) {
        final deletion = _decodeDeletion(stored);
        deletionGroups
            .putIfAbsent(
              deletion.stableRecordId,
              () => <V3MaterializedRecordDeletion>[],
            )
            .add(deletion);
      }
      if (deletionGroups.length > maxDeletedRecords) {
        throw const V3LmfPersistenceLimitException(
          'v3 materialized-record deletion limit exceeded',
        );
      }
      for (final candidates in deletionGroups.values) {
        candidates.sort((left, right) {
          final time = left.deletedAt.compareTo(right.deletedAt);
          if (time != 0) return time;
          return left.storageId.compareTo(right.storageId);
        });
        final canonical = candidates.first;
        for (final duplicate in candidates.skip(1)) {
          if (!_sameDeletion(canonical, duplicate)) {
            throw const V3LmfPersistenceConflictException(
              'divergent v3 deletion records share a stable ID',
            );
          }
          await _deleteIgnoringFailure(duplicate.storageId);
          removed++;
        }
        _deletions[canonical.stableRecordId] = canonical;
      }

      final decoded = <V3MaterializedCommittedRecord>[];
      final grouped = <String, List<V3MaterializedCommittedRecord>>{};
      try {
        for (final stored in relevant.where(
          (record) => record.payload['kind'] == recordKind,
        )) {
          final record = _decode(stored);
          decoded.add(record);
          grouped
              .putIfAbsent(
                record.stableRecordId,
                () => <V3MaterializedCommittedRecord>[],
              )
              .add(record);
        }
        if (grouped.length > maxRecords) {
          throw const V3LmfPersistenceLimitException(
            'v3 materialized-record limit exceeded',
          );
        }

        var totalBytes = 0;
        final selected = <String, V3MaterializedCommittedRecord>{};
        for (final candidates in grouped.values) {
          candidates.sort((left, right) {
            final time = left.persistedAt.compareTo(right.persistedAt);
            if (time != 0) return time;
            return left.storageId.compareTo(right.storageId);
          });
          final canonical = candidates.first;
          for (final duplicate in candidates.skip(1)) {
            if (!_sameLogicalRecord(canonical, duplicate)) {
              throw const V3LmfPersistenceConflictException(
                'divergent v3 materialized records share a stable ID',
              );
            }
          }
          totalBytes += canonical.retainedBytes;
          if (totalBytes > maxTotalRecordBytes) {
            throw const V3LmfPersistenceLimitException(
              'v3 materialized-record byte limit exceeded',
            );
          }
          selected[canonical.stableRecordId] = canonical;
          for (final duplicate in candidates.skip(1)) {
            await _deleteIgnoringFailure(duplicate.storageId);
            duplicate._close();
            removed++;
          }
        }
        _records.addAll(selected);
        _totalRecordBytes = totalBytes;
        _restored = true;
        decoded.removeWhere(
          (record) => identical(_records[record.stableRecordId], record),
        );
        return V3CommittedRecordMaterializerRestoreResult(
          records: records(authority: authority),
          removedExactDuplicates: removed,
        );
      } finally {
        for (final record in decoded) {
          record._close();
        }
      }
    });
  }

  Future<V3MaterializedCommittedRecord> materialize(
    Uint8List encodedRecord, {
    DateTime? persistedAt,
    V3CommittedRecordMaterializerAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final localBytes = Uint8List.fromList(encodedRecord);
      V3CommittedRecord? decoded;
      try {
        decoded = V3CommittedRecordCodec.decode(localBytes);
        final stableRecordId = decoded.stableRecordId;
        final existing = _records[stableRecordId];
        if (existing != null) {
          if (!_bytesEqual(existing._encodedRecord, localBytes)) {
            throw const V3LmfPersistenceConflictException(
              'divergent v3 application record already materialized',
            );
          }
          return existing;
        }
        if (_deletions.containsKey(stableRecordId)) {
          throw const V3LmfPersistenceConflictException(
            'deleted v3 application material cannot be rematerialized',
          );
        }
        if (_records.length >= maxRecords ||
            _totalRecordBytes + localBytes.length > maxTotalRecordBytes) {
          throw const V3LmfPersistenceLimitException(
            'v3 materialized-record capacity exceeded',
          );
        }

        final timestamp =
            _validatedTimestamp(persistedAt ?? DateTime.now().toUtc());
        final digest = _recordDigest(localBytes);
        final sessionKey = _encodeBinary(decoded.sessionId);
        final payload = <String, dynamic>{
          'kind': recordKind,
          'version': _recordVersion,
          'stableRecordId': stableRecordId,
          'assemblyId': decoded.assemblyId,
          'sessionId': sessionKey,
          'record': _encodeBinary(localBytes),
          'recordDigest': digest,
          'persistedAt': timestamp.millisecondsSinceEpoch,
          'reserved': 0,
        };
        V3MaterializedCommittedRecord? materialized;
        try {
          final storageId = await _store.write(payload);
          materialized = V3MaterializedCommittedRecord._(
            storageId: storageId,
            stableRecordId: stableRecordId,
            assemblyId: decoded.assemblyId,
            sessionKey: sessionKey,
            recordDigest: digest,
            encodedRecord: localBytes,
            persistedAt: timestamp,
          );
          _records[stableRecordId] = materialized;
          _totalRecordBytes += materialized.retainedBytes;
        } catch (_) {
          materialized?._close();
          _writeRecoveryRequired = true;
          rethrow;
        }
        return materialized;
      } finally {
        decoded?.wipeContent();
        _wipe(localBytes);
      }
    });
  }

  Future<bool> deleteExact({
    required String stableRecordId,
    required String assemblyId,
    required String sessionKey,
    required String recordDigest,
    String? retirementStateDigest,
    DateTime? deletedAt,
    V3CommittedRecordMaterializerAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      if (retirementStateDigest != null &&
          !_isCanonicalDigest(retirementStateDigest)) {
        throw const FormatException(
          'Invalid v3 materialized-record retirement digest',
        );
      }
      var deletion = _deletions[stableRecordId];
      if (deletion != null &&
          (deletion.assemblyId != assemblyId ||
              deletion.sessionKey != sessionKey ||
              deletion.recordDigest != recordDigest ||
              (retirementStateDigest != null &&
                  deletion.retirementStateDigest != retirementStateDigest))) {
        throw const V3LmfPersistenceConflictException(
          'v3 materialized-record deletion proof diverged',
        );
      }
      final existing = _records[stableRecordId];
      if (existing == null) return false;
      if (existing.assemblyId != assemblyId ||
          existing.sessionKey != sessionKey ||
          existing.recordDigest != recordDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 materialized-record deletion binding diverged',
        );
      }
      if (deletion == null && retirementStateDigest != null) {
        if (_deletions.length >= maxDeletedRecords) {
          throw const V3LmfPersistenceLimitException(
            'v3 materialized-record deletion capacity exceeded',
          );
        }
        final timestamp =
            _validatedTimestamp(deletedAt ?? DateTime.now().toUtc());
        final payload = <String, dynamic>{
          'kind': deletionRecordKind,
          'version': _recordVersion,
          'stableRecordId': stableRecordId,
          'assemblyId': assemblyId,
          'sessionId': sessionKey,
          'recordDigest': recordDigest,
          'retirementStateDigest': retirementStateDigest,
          'deletedAt': timestamp.millisecondsSinceEpoch,
          'reserved': 0,
        };
        try {
          final storageId = await _store.write(payload);
          deletion = V3MaterializedRecordDeletion._(
            storageId: storageId,
            stableRecordId: stableRecordId,
            assemblyId: assemblyId,
            sessionKey: sessionKey,
            recordDigest: recordDigest,
            retirementStateDigest: retirementStateDigest,
            deletedAt: timestamp,
          );
          _deletions[stableRecordId] = deletion;
        } catch (_) {
          _writeRecoveryRequired = true;
          rethrow;
        }
      }
      try {
        await _store.delete(existing.storageId);
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      }
      _records.remove(stableRecordId);
      _totalRecordBytes -= existing.retainedBytes;
      existing._close();
      return true;
    });
  }

  Future<bool> deleteDeletionExact({
    required String stableRecordId,
    required String assemblyId,
    required String sessionKey,
    required String recordDigest,
    required String retirementStateDigest,
    V3CommittedRecordMaterializerAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final existing = _deletions[stableRecordId];
      if (existing == null) return false;
      if (existing.assemblyId != assemblyId ||
          existing.sessionKey != sessionKey ||
          existing.recordDigest != recordDigest ||
          existing.retirementStateDigest != retirementStateDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 materialized-record deletion proof binding diverged',
        );
      }
      try {
        await _store.delete(existing.storageId);
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      }
      _deletions.remove(stableRecordId);
      return true;
    });
  }

  Future<void> close({
    V3CommittedRecordMaterializerAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      if (_closed) return;
      _closed = true;
      for (final record in _records.values) {
        record._close();
      }
      _records.clear();
      _deletions.clear();
      _totalRecordBytes = 0;
    });
  }

  V3MaterializedCommittedRecord _decode(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    const expectedKeys = <String>{
      'kind',
      'version',
      'stableRecordId',
      'assemblyId',
      'sessionId',
      'record',
      'recordDigest',
      'persistedAt',
      'reserved',
    };
    if (payload.length != expectedKeys.length ||
        !payload.keys.every(expectedKeys.contains) ||
        payload['kind'] != recordKind ||
        payload['version'] != _recordVersion ||
        payload['stableRecordId'] is! String ||
        payload['assemblyId'] is! String ||
        payload['sessionId'] is! String ||
        payload['record'] is! String ||
        payload['recordDigest'] is! String ||
        payload['persistedAt'] is! int ||
        payload['reserved'] != 0) {
      throw const FormatException(
        'Invalid Layergram v3 materialized-record envelope',
      );
    }

    final stableRecordId = payload['stableRecordId'] as String;
    final assemblyId = payload['assemblyId'] as String;
    final sessionKey = payload['sessionId'] as String;
    final encoded = _decodeBinary(
      payload['record'] as String,
      V3CommittedRecordCodec.maxEncodedBytes,
    );
    V3CommittedRecord? record;
    try {
      record = V3CommittedRecordCodec.decode(encoded);
      final timestamp = _timestampFromMillis(payload['persistedAt'] as int);
      final digest = payload['recordDigest'] as String;
      if (stableRecordId != record.stableRecordId ||
          assemblyId != record.assemblyId ||
          sessionKey != _encodeBinary(record.sessionId) ||
          digest != _recordDigest(encoded) ||
          !_isCanonicalDigest(digest)) {
        throw const FormatException(
          'Mismatched Layergram v3 materialized-record binding',
        );
      }
      return V3MaterializedCommittedRecord._(
        storageId: stored.storageId,
        stableRecordId: stableRecordId,
        assemblyId: assemblyId,
        sessionKey: sessionKey,
        recordDigest: digest,
        encodedRecord: encoded,
        persistedAt: timestamp,
      );
    } finally {
      record?.wipeContent();
      _wipe(encoded);
    }
  }

  V3MaterializedRecordDeletion _decodeDeletion(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    const expectedKeys = <String>{
      'kind',
      'version',
      'stableRecordId',
      'assemblyId',
      'sessionId',
      'recordDigest',
      'retirementStateDigest',
      'deletedAt',
      'reserved',
    };
    if (payload.length != expectedKeys.length ||
        !payload.keys.every(expectedKeys.contains) ||
        payload['kind'] != deletionRecordKind ||
        payload['version'] != _recordVersion ||
        payload['stableRecordId'] is! String ||
        payload['assemblyId'] is! String ||
        payload['sessionId'] is! String ||
        payload['recordDigest'] is! String ||
        payload['retirementStateDigest'] is! String ||
        payload['deletedAt'] is! int ||
        payload['reserved'] != 0) {
      throw const FormatException(
        'Invalid Layergram v3 materialized-record deletion',
      );
    }
    final stableRecordId = payload['stableRecordId'] as String;
    final assemblyId = payload['assemblyId'] as String;
    final sessionKey = payload['sessionId'] as String;
    final recordDigest = payload['recordDigest'] as String;
    final retirementStateDigest = payload['retirementStateDigest'] as String;
    final sessionId = _decodeBinary(sessionKey, 16);
    try {
      if (stableRecordId != 'v3:$assemblyId' ||
          !_isCanonicalDigest(assemblyId) ||
          sessionId.length != 16 ||
          sessionId.every((byte) => byte == 0) ||
          !_isCanonicalDigest(recordDigest) ||
          !_isCanonicalDigest(retirementStateDigest)) {
        throw const FormatException(
          'Mismatched Layergram v3 materialized-record deletion',
        );
      }
    } finally {
      _wipe(sessionId);
    }
    return V3MaterializedRecordDeletion._(
      storageId: stored.storageId,
      stableRecordId: stableRecordId,
      assemblyId: assemblyId,
      sessionKey: sessionKey,
      recordDigest: recordDigest,
      retirementStateDigest: retirementStateDigest,
      deletedAt: _timestampFromMillis(payload['deletedAt'] as int),
    );
  }

  Future<void> _deleteIgnoringFailure(String storageId) async {
    try {
      await _store.delete(storageId);
    } catch (_) {
      // An exact duplicate encrypted record is harmless on the next restore.
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
      throw StateError('Layergram v3 materializer is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored) {
      throw StateError('Layergram v3 materializer must be restored');
    }
    if (_writeRecoveryRequired) {
      throw StateError(
        'Layergram v3 materializer must be reconstructed and restored',
      );
    }
  }

  void _ensureAuthority(V3CommittedRecordMaterializerAuthority? authority) {
    final claimed = _authority;
    if (claimed != null && !identical(claimed, authority)) {
      throw StateError(
        'Layergram v3 materializer is owned by a session coordinator',
      );
    }
  }
}

DateTime _validatedTimestamp(DateTime value) =>
    _timestampFromMillis(value.toUtc().millisecondsSinceEpoch);

DateTime _timestampFromMillis(int value) {
  if (value < 0 || value > V3CommittedRecordMaterializer._maxTimestampMillis) {
    throw const FormatException('Invalid v3 materialized-record timestamp');
  }
  return DateTime.fromMillisecondsSinceEpoch(value, isUtc: true);
}

String _recordDigest(Uint8List encodedRecord) {
  final bytes = Uint8List.fromList(<int>[
    ...utf8.encode('layergram/v3/materialized-record\u0000'),
    ...encodedRecord,
  ]);
  try {
    final digest = Uint8List.fromList(crypto.sha256.convert(bytes).bytes);
    try {
      return _encodeBinary(digest);
    } finally {
      _wipe(digest);
    }
  } finally {
    _wipe(bytes);
  }
}

bool _sameLogicalRecord(
  V3MaterializedCommittedRecord left,
  V3MaterializedCommittedRecord right,
) =>
    left.stableRecordId == right.stableRecordId &&
    left.assemblyId == right.assemblyId &&
    left.sessionKey == right.sessionKey &&
    left.recordDigest == right.recordDigest &&
    _bytesEqual(left._encodedRecord, right._encodedRecord);

bool _isCanonicalDigest(String value) {
  if (value.length != 43) return false;
  Uint8List? decoded;
  try {
    decoded = _decodeBinary(value, 32);
    return decoded.length == 32 && _encodeBinary(decoded) == value;
  } catch (_) {
    return false;
  } finally {
    if (decoded != null) _wipe(decoded);
  }
}

bool _sameDeletion(
  V3MaterializedRecordDeletion left,
  V3MaterializedRecordDeletion right,
) =>
    left.stableRecordId == right.stableRecordId &&
    left.assemblyId == right.assemblyId &&
    left.sessionKey == right.sessionKey &&
    left.recordDigest == right.recordDigest &&
    left.retirementStateDigest == right.retirementStateDigest;

String _encodeBinary(Uint8List bytes) =>
    base64UrlEncode(bytes).replaceAll('=', '');

Uint8List _decodeBinary(String armored, int maxBytes) {
  if (armored.isEmpty || armored.length > ((maxBytes * 4 + 2) ~/ 3)) {
    throw const FormatException('Invalid v3 materialized-record binary length');
  }
  for (final codeUnit in armored.codeUnits) {
    final upper = codeUnit >= 0x41 && codeUnit <= 0x5a;
    final lower = codeUnit >= 0x61 && codeUnit <= 0x7a;
    final digit = codeUnit >= 0x30 && codeUnit <= 0x39;
    if (!upper && !lower && !digit && codeUnit != 0x2d && codeUnit != 0x5f) {
      throw const FormatException('Invalid v3 materialized-record armor');
    }
  }
  late final Uint8List bytes;
  try {
    bytes = Uint8List.fromList(
      base64Url.decode(base64Url.normalize(armored)),
    );
  } catch (_) {
    throw const FormatException('Invalid v3 materialized-record armor');
  }
  if (bytes.isEmpty ||
      bytes.length > maxBytes ||
      _encodeBinary(bytes) != armored) {
    _wipe(bytes);
    throw const FormatException('Non-canonical v3 materialized-record armor');
  }
  return bytes;
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
