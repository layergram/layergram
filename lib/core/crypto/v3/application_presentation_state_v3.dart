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

import 'application_payload_v3.dart';
import 'lmf_v3_persistence.dart';

final class V3ApplicationPresentationState {
  const V3ApplicationPresentationState._({
    required this.storageId,
    required this.messageRecordId,
    required this.revision,
    required this.readAtUnixSeconds,
    required this.deletedAtUnixSeconds,
    required this.updatedAt,
  });

  final String storageId;
  final String messageRecordId;
  final int revision;
  final int? readAtUnixSeconds;
  final int? deletedAtUnixSeconds;
  final DateTime updatedAt;

  bool get isDeleted => deletedAtUnixSeconds != null;
}

final class V3ApplicationPresentationRestoreResult {
  const V3ApplicationPresentationRestoreResult({
    required this.states,
    required this.removedSupersededRecords,
  });

  final Map<String, V3ApplicationPresentationState> states;
  final int removedSupersededRecords;
}

/// Durable read/delete state for chat metadata projected from retained AR3.
///
/// AR3 remains immutable for replay and ratchet proofs. This encrypted journal
/// prevents a later reconciliation from resurrecting user-deleted messages or
/// losing delete-after-read state while that source record is retained.
final class V3ApplicationPresentationJournal {
  V3ApplicationPresentationJournal({
    required V3LmfRecordStore store,
    this.maxStates = 4096,
    this.maxStoredRecords = 8192,
  }) : _store = store {
    if (maxStates <= 0 || maxStoredRecords <= 0) {
      throw ArgumentError('Layergram v3 presentation-state limits are invalid');
    }
  }

  static const String recordKind = 'v3_application_presentation_v1';
  static const int _formatVersion = 1;
  static const int _maxCounter = 0x7fffffffffffffff;
  static const int _maxTimestampMillis = 253402300799999;

  final V3LmfRecordStore _store;
  final int maxStates;
  final int maxStoredRecords;
  final Map<String, V3ApplicationPresentationState> _states = {};
  Future<void> _operationTail = Future<void>.value();
  bool _restored = false;
  bool _closed = false;
  bool _writeRecoveryRequired = false;

  bool get requiresRecovery => _writeRecoveryRequired;

  Future<V3ApplicationPresentationRestoreResult> restore() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 presentation journal was restored');
      }
      final records = (await _store.readAll())
          .where((record) => record.payload['kind'] == recordKind)
          .toList(growable: false);
      if (records.length > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical v3 presentation-state record limit exceeded',
        );
      }
      final grouped = <String, List<V3ApplicationPresentationState>>{};
      for (final record in records) {
        final state = _decode(record);
        grouped.putIfAbsent(state.messageRecordId, () => []).add(state);
      }
      if (grouped.length > maxStates) {
        throw const V3LmfPersistenceLimitException(
          'v3 presentation-state count limit exceeded',
        );
      }
      final selected = <String, V3ApplicationPresentationState>{};
      final obsolete = <V3ApplicationPresentationState>[];
      for (final history in grouped.values) {
        history.sort((left, right) {
          final revision = left.revision.compareTo(right.revision);
          if (revision != 0) return revision;
          return left.storageId.compareTo(right.storageId);
        });
        var current = history.first;
        for (final candidate in history.skip(1)) {
          if (candidate.revision == current.revision) {
            if (!_sameState(current, candidate)) {
              throw const V3LmfPersistenceConflictException(
                'divergent v3 presentation state at the same revision',
              );
            }
          } else if (!_extendsState(current, candidate)) {
            throw const V3LmfPersistenceConflictException(
              'v3 presentation-state history is not monotonic',
            );
          }
          current = candidate;
        }
        selected[current.messageRecordId] = current;
        obsolete.addAll(history.where((state) => !identical(state, current)));
      }
      for (final state in obsolete) {
        try {
          await _store.delete(state.storageId);
        } catch (_) {
          // A validated obsolete predecessor remains safe for later cleanup.
        }
      }
      _states.addAll(selected);
      _restored = true;
      return V3ApplicationPresentationRestoreResult(
        states: Map.unmodifiable(_states),
        removedSupersededRecords: obsolete.length,
      );
    });
  }

  Future<Map<String, V3ApplicationPresentationState>> states() {
    return _serialized(() async {
      _ensureReady();
      return Map.unmodifiable(_states);
    });
  }

  Future<V3ApplicationPresentationState> markRead({
    required String messageRecordId,
    DateTime? readAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final current = _states[messageRecordId];
      if (current?.readAtUnixSeconds != null || current?.isDeleted == true) {
        return current!;
      }
      final timestamp = _validatedTimestamp(readAt ?? DateTime.now());
      return _persistTransition(
        messageRecordId: messageRecordId,
        readAtUnixSeconds: timestamp.millisecondsSinceEpoch ~/ 1000,
        deletedAtUnixSeconds: null,
        updatedAt: timestamp,
      );
    });
  }

  Future<V3ApplicationPresentationState> markDeleted({
    required String messageRecordId,
    DateTime? deletedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final current = _states[messageRecordId];
      if (current?.isDeleted == true) return current!;
      final timestamp = _validatedTimestamp(deletedAt ?? DateTime.now());
      return _persistTransition(
        messageRecordId: messageRecordId,
        readAtUnixSeconds: current?.readAtUnixSeconds,
        deletedAtUnixSeconds: timestamp.millisecondsSinceEpoch ~/ 1000,
        updatedAt: timestamp,
      );
    });
  }

  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      _states.clear();
    }, allowClosed: true);
  }

  Future<V3ApplicationPresentationState> _persistTransition({
    required String messageRecordId,
    required int? readAtUnixSeconds,
    required int? deletedAtUnixSeconds,
    required DateTime updatedAt,
  }) async {
    _validateMessageRecordId(messageRecordId);
    if (readAtUnixSeconds == null && deletedAtUnixSeconds == null) {
      throw ArgumentError('Layergram v3 presentation transition is empty');
    }
    _validateOptionalCounter(readAtUnixSeconds, 'readAtUnixSeconds');
    _validateOptionalCounter(deletedAtUnixSeconds, 'deletedAtUnixSeconds');
    final current = _states[messageRecordId];
    if (_states.length >= maxStates && current == null) {
      throw const V3LmfPersistenceLimitException(
        'v3 presentation-state capacity exceeded',
      );
    }
    final revision = (current?.revision ?? -1) + 1;
    if (current != null && updatedAt.isBefore(current.updatedAt)) {
      throw ArgumentError(
        'Layergram v3 presentation time cannot move backward',
      );
    }
    if (readAtUnixSeconds != null &&
        deletedAtUnixSeconds != null &&
        deletedAtUnixSeconds < readAtUnixSeconds) {
      throw ArgumentError(
        'Layergram v3 deletion cannot precede its read state',
      );
    }
    if (revision > _maxCounter) {
      throw StateError('Layergram v3 presentation revision exhausted');
    }
    final payload = <String, dynamic>{
      'kind': recordKind,
      'version': _formatVersion,
      'messageRecordId': messageRecordId,
      'revision': revision,
      'readAt': readAtUnixSeconds,
      'deletedAt': deletedAtUnixSeconds,
      'updatedAt': updatedAt.millisecondsSinceEpoch,
      'reserved': 0,
    };
    try {
      final storageId = await _store.write(payload);
      final next = V3ApplicationPresentationState._(
        storageId: storageId,
        messageRecordId: messageRecordId,
        revision: revision,
        readAtUnixSeconds: readAtUnixSeconds,
        deletedAtUnixSeconds: deletedAtUnixSeconds,
        updatedAt: updatedAt,
      );
      _states[messageRecordId] = next;
      if (current != null) {
        try {
          await _store.delete(current.storageId);
        } catch (_) {
          // Write-new-before-delete leaves a valid predecessor for restore.
        }
      }
      return next;
    } catch (_) {
      _writeRecoveryRequired = true;
      rethrow;
    }
  }

  V3ApplicationPresentationState _decode(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    if (payload.length != 8 ||
        payload['kind'] != recordKind ||
        payload['version'] != _formatVersion ||
        payload['messageRecordId'] is! String ||
        payload['revision'] is! int ||
        (payload['readAt'] != null && payload['readAt'] is! int) ||
        (payload['deletedAt'] != null && payload['deletedAt'] is! int) ||
        payload['updatedAt'] is! int ||
        payload['reserved'] != 0) {
      throw const FormatException(
        'Invalid Layergram v3 presentation-state record',
      );
    }
    final messageRecordId = payload['messageRecordId'] as String;
    final revision = payload['revision'] as int;
    final readAt = payload['readAt'] as int?;
    final deletedAt = payload['deletedAt'] as int?;
    _validateMessageRecordId(messageRecordId);
    _validateCounter(revision, 'revision');
    _validateOptionalCounter(readAt, 'readAt');
    _validateOptionalCounter(deletedAt, 'deletedAt');
    if (readAt == null && deletedAt == null) {
      throw const FormatException(
        'Empty Layergram v3 presentation-state record',
      );
    }
    if (readAt != null && deletedAt != null && deletedAt < readAt) {
      throw const FormatException(
        'Invalid Layergram v3 presentation-state chronology',
      );
    }
    return V3ApplicationPresentationState._(
      storageId: stored.storageId,
      messageRecordId: messageRecordId,
      revision: revision,
      readAtUnixSeconds: readAt,
      deletedAtUnixSeconds: deletedAt,
      updatedAt: _validatedTimestampMillis(payload['updatedAt'] as int),
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
          throw StateError('Layergram v3 presentation journal is closed');
        }
        completer.complete(await operation());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('Layergram v3 presentation journal is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored || requiresRecovery) {
      throw StateError('Layergram v3 presentation journal requires restore');
    }
  }
}

bool _sameState(
  V3ApplicationPresentationState left,
  V3ApplicationPresentationState right,
) {
  return left.messageRecordId == right.messageRecordId &&
      left.revision == right.revision &&
      left.readAtUnixSeconds == right.readAtUnixSeconds &&
      left.deletedAtUnixSeconds == right.deletedAtUnixSeconds &&
      left.updatedAt == right.updatedAt;
}

bool _extendsState(
  V3ApplicationPresentationState previous,
  V3ApplicationPresentationState next,
) {
  if (next.messageRecordId != previous.messageRecordId ||
      next.revision != previous.revision + 1 ||
      next.updatedAt.isBefore(previous.updatedAt)) {
    return false;
  }
  final readIsMonotonic = previous.readAtUnixSeconds == null
      ? next.readAtUnixSeconds != null || next.deletedAtUnixSeconds != null
      : next.readAtUnixSeconds == previous.readAtUnixSeconds;
  final deleteIsMonotonic = previous.deletedAtUnixSeconds == null
      ? true
      : next.deletedAtUnixSeconds == previous.deletedAtUnixSeconds;
  final changed =
      (previous.readAtUnixSeconds == null && next.readAtUnixSeconds != null) ||
          (previous.deletedAtUnixSeconds == null &&
              next.deletedAtUnixSeconds != null);
  return readIsMonotonic && deleteIsMonotonic && changed;
}

void _validateMessageRecordId(String value) {
  if (!value.startsWith(V3ApplicationPayloadCodec.messageRecordIdPrefix)) {
    throw const FormatException('Invalid Layergram v3 presentation message ID');
  }
  final armored = value.substring(
    V3ApplicationPayloadCodec.messageRecordIdPrefix.length,
  );
  if (armored.isEmpty || armored.length > 24) {
    throw const FormatException('Invalid Layergram v3 presentation message ID');
  }
  for (final codeUnit in armored.codeUnits) {
    final upper = codeUnit >= 0x41 && codeUnit <= 0x5a;
    final lower = codeUnit >= 0x61 && codeUnit <= 0x7a;
    final digit = codeUnit >= 0x30 && codeUnit <= 0x39;
    if (!upper && !lower && !digit && codeUnit != 0x2d && codeUnit != 0x5f) {
      throw const FormatException(
        'Invalid Layergram v3 presentation message ID',
      );
    }
  }
  Uint8List? decoded;
  try {
    decoded = Uint8List.fromList(
      base64Url.decode(base64Url.normalize(armored)),
    );
    if (decoded.length != 16 ||
        decoded.every((byte) => byte == 0) ||
        base64UrlEncode(decoded).replaceAll('=', '') != armored) {
      throw const FormatException(
        'Invalid Layergram v3 presentation message ID',
      );
    }
  } on FormatException {
    throw const FormatException('Invalid Layergram v3 presentation message ID');
  } finally {
    if (decoded != null) _wipe(decoded);
  }
}

void _validateOptionalCounter(int? value, String name) {
  if (value != null) _validateCounter(value, name);
}

void _validateCounter(int value, String name) {
  if (value < 0 || value > V3ApplicationPresentationJournal._maxCounter) {
    throw FormatException('Invalid Layergram v3 presentation $name');
  }
}

DateTime _validatedTimestamp(DateTime value) =>
    _validatedTimestampMillis(value.toUtc().millisecondsSinceEpoch);

DateTime _validatedTimestampMillis(int value) {
  if (value < 0 ||
      value > V3ApplicationPresentationJournal._maxTimestampMillis) {
    throw const FormatException('Invalid Layergram v3 presentation timestamp');
  }
  return DateTime.fromMillisecondsSinceEpoch(value, isUtc: true);
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
