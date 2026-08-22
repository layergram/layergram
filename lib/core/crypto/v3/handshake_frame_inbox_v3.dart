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

import 'lmf_v3.dart';
import 'lmf_v3_persistence.dart';

enum V3HandshakeFrameInboxStatus {
  accepted,
  duplicate,
  complete,
  committedReplay,
}

/// Complete sealed handshake candidate retained before HP3 authentication.
final class V3HandshakeFrameAssembly {
  const V3HandshakeFrameAssembly({
    required this.assemblyId,
    required this.frames,
  });

  final String assemblyId;
  final List<V3LmfFrame> frames;
}

final class V3HandshakeFrameInboxOutcome {
  const V3HandshakeFrameInboxOutcome({
    required this.status,
    this.assembly,
  });

  final V3HandshakeFrameInboxStatus status;
  final V3HandshakeFrameAssembly? assembly;
}

final class V3HandshakeFrameInboxRestoreResult {
  const V3HandshakeFrameInboxRestoreResult({
    required this.completeAssemblies,
    required this.deferredFrames,
    required this.committedAssemblies,
    required this.removedObsoleteRecords,
  });

  final List<V3HandshakeFrameAssembly> completeAssemblies;
  final int deferredFrames;
  final int committedAssemblies;
  final int removedObsoleteRecords;
}

final class _StoredHandshakeFrame {
  const _StoredHandshakeFrame({
    required this.storageId,
    required this.assemblyId,
    required this.frame,
    required this.encoded,
    required this.receivedAt,
  });

  final String storageId;
  final String assemblyId;
  final V3LmfFrame frame;
  final Uint8List encoded;
  final DateTime receivedAt;
}

/// Persist-first inbox dedicated to public LMF handshake frames.
///
/// It uses record kinds distinct from the authenticated application inbox.
/// A complete assembly is retained until the application coordinator has
/// durably persisted the HP3 reply or HP3-to-TR3 handoff and calls [commit].
/// The compact tombstone then suppresses duplicate carrier deliveries.
final class V3HandshakeFrameInbox {
  V3HandshakeFrameInbox({
    required V3LmfRecordStore store,
    this.maxPendingAssemblies = 64,
    this.maxPendingFrames = 512,
    this.maxCommittedAssemblies = 4096,
    this.maxStoredRecords = 8192,
  }) : _store = store {
    if (maxPendingAssemblies <= 0 ||
        maxPendingFrames <= 0 ||
        maxCommittedAssemblies <= 0 ||
        maxStoredRecords <= 0) {
      throw ArgumentError('Layergram v3 handshake inbox limits are invalid');
    }
  }

  static const String frameRecordKind = 'v3_handshake_frame_v1';
  static const String tombstoneRecordKind = 'v3_handshake_frame_done_v1';
  static const int _formatVersion = 1;
  static const int _maxTimestampMillis = 253402300799999;

  final V3LmfRecordStore _store;
  final int maxPendingAssemblies;
  final int maxPendingFrames;
  final int maxCommittedAssemblies;
  final int maxStoredRecords;

  final Map<String, Map<int, _StoredHandshakeFrame>> _pending =
      <String, Map<int, _StoredHandshakeFrame>>{};
  final Map<String, String> _committedStorageIds = <String, String>{};
  Future<void> _operationTail = Future<void>.value();
  bool _restored = false;
  bool _closed = false;
  bool _writeRecoveryRequired = false;

  bool get requiresRecovery => _writeRecoveryRequired;

  Future<V3HandshakeFrameInboxRestoreResult> restore() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 handshake frame inbox was restored');
      }
      final records = await _store.readAll();
      final relevant = records.where((record) {
        final kind = record.payload['kind'];
        return kind == frameRecordKind || kind == tombstoneRecordKind;
      }).toList(growable: false);
      if (relevant.length > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical v3 handshake frame record limit exceeded',
        );
      }

      final decodedFrames = <_StoredHandshakeFrame>[];
      final tombstones = <String, List<String>>{};
      for (final record in relevant) {
        if (record.payload['kind'] == frameRecordKind) {
          decodedFrames.add(_decodeFrame(record));
        } else {
          final assemblyId = _decodeTombstone(record);
          tombstones.putIfAbsent(assemblyId, () => <String>[]).add(
                record.storageId,
              );
        }
      }
      if (tombstones.length > maxCommittedAssemblies) {
        throw const V3LmfPersistenceLimitException(
          'v3 handshake tombstone limit exceeded',
        );
      }

      var removed = 0;
      for (final entry in tombstones.entries) {
        final ids = entry.value..sort();
        _committedStorageIds[entry.key] = ids.first;
        for (final duplicate in ids.skip(1)) {
          await _store.delete(duplicate);
          removed++;
        }
      }

      for (final stored in decodedFrames) {
        if (_committedStorageIds.containsKey(stored.assemblyId)) {
          await _store.delete(stored.storageId);
          removed++;
          continue;
        }
        final assembly = _pending.putIfAbsent(
          stored.assemblyId,
          () => <int, _StoredHandshakeFrame>{},
        );
        final existing = assembly[stored.frame.fragmentIndex];
        if (existing == null) {
          assembly[stored.frame.fragmentIndex] = stored;
        } else if (_bytesEqual(existing.encoded, stored.encoded)) {
          await _store.delete(stored.storageId);
          removed++;
        } else {
          throw const V3LmfPersistenceConflictException(
            'conflicting persisted Layergram v3 handshake fragment',
          );
        }
      }
      _validateBounds();
      _restored = true;
      final complete = <V3HandshakeFrameAssembly>[];
      var deferred = 0;
      for (final entry in _pending.entries) {
        final candidate = _complete(entry.key, entry.value);
        if (candidate == null) {
          deferred += entry.value.length;
        } else {
          complete.add(candidate);
        }
      }
      return V3HandshakeFrameInboxRestoreResult(
        completeAssemblies: List.unmodifiable(complete),
        deferredFrames: deferred,
        committedAssemblies: _committedStorageIds.length,
        removedObsoleteRecords: removed,
      );
    });
  }

  Future<V3HandshakeFrameInboxOutcome> receive({
    required V3LmfFrame frame,
    DateTime? receivedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      _validateHandshakeFrame(frame);
      final assemblyId = V3LmfFrameCodec.assemblyId(frame);
      if (_committedStorageIds.containsKey(assemblyId)) {
        return const V3HandshakeFrameInboxOutcome(
          status: V3HandshakeFrameInboxStatus.committedReplay,
        );
      }
      final assembly = _pending[assemblyId];
      final encoded = V3LmfFrameCodec.encodeBinary(frame);
      final existing = assembly?[frame.fragmentIndex];
      if (existing != null) {
        if (!_bytesEqual(existing.encoded, encoded)) {
          throw const V3LmfPersistenceConflictException(
            'conflicting Layergram v3 handshake fragment',
          );
        }
        final complete = _complete(assemblyId, assembly!);
        return V3HandshakeFrameInboxOutcome(
          status: complete == null
              ? V3HandshakeFrameInboxStatus.duplicate
              : V3HandshakeFrameInboxStatus.complete,
          assembly: complete,
        );
      }
      await _makeCapacityFor(
        assemblyId: assemblyId,
        createsAssembly: assembly == null,
      );
      final timestamp = _validatedTimestamp(receivedAt ?? DateTime.now());
      try {
        final storageId = await _store.write(
          _encodeFrame(encoded, timestamp),
        );
        final target = _pending.putIfAbsent(
          assemblyId,
          () => <int, _StoredHandshakeFrame>{},
        );
        target[frame.fragmentIndex] = _StoredHandshakeFrame(
          storageId: storageId,
          assemblyId: assemblyId,
          frame: frame,
          encoded: Uint8List.fromList(encoded),
          receivedAt: timestamp,
        );
        final complete = _complete(assemblyId, target);
        return V3HandshakeFrameInboxOutcome(
          status: complete == null
              ? V3HandshakeFrameInboxStatus.accepted
              : V3HandshakeFrameInboxStatus.complete,
          assembly: complete,
        );
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      }
    });
  }

  /// Writes replay suppression before deleting the exact sealed fragments.
  Future<void> commit(String assemblyId, {DateTime? committedAt}) {
    return _serialized(() async {
      _ensureReady();
      _validateArmoredId(assemblyId, 32, 'assemblyId');
      final existing = _committedStorageIds[assemblyId];
      if (existing == null) {
        if (_committedStorageIds.length >= maxCommittedAssemblies) {
          throw const V3LmfPersistenceLimitException(
            'v3 handshake tombstone capacity exceeded',
          );
        }
        final timestamp =
            _validatedTimestamp(committedAt ?? DateTime.now().toUtc());
        try {
          final storageId = await _store.write(
            <String, dynamic>{
              'kind': tombstoneRecordKind,
              'version': _formatVersion,
              'assemblyId': assemblyId,
              'committedAt': timestamp.millisecondsSinceEpoch,
            },
          );
          _committedStorageIds[assemblyId] = storageId;
        } catch (_) {
          _writeRecoveryRequired = true;
          rethrow;
        }
      }
      final frames = _pending.remove(assemblyId);
      if (frames != null) {
        for (final stored in frames.values) {
          await _store.delete(stored.storageId);
        }
      }
    });
  }

  /// Removes an unauthenticated/abandoned candidate without a replay marker.
  Future<void> discard(String assemblyId) {
    return _serialized(() async {
      _ensureReady();
      final frames = _pending.remove(assemblyId);
      if (frames == null) return;
      try {
        for (final stored in frames.values) {
          await _store.delete(stored.storageId);
        }
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      }
    });
  }

  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      _pending.clear();
      _committedStorageIds.clear();
    }, allowClosed: true);
  }

  Future<void> _makeCapacityFor({
    required String assemblyId,
    required bool createsAssembly,
  }) async {
    while (createsAssembly && _pending.length >= maxPendingAssemblies) {
      if (!await _evictOldestIncomplete(exceptAssemblyId: assemblyId)) {
        throw const V3LmfPersistenceLimitException(
          'v3 handshake assembly capacity exceeded',
        );
      }
    }
    while (_pending.values.fold<int>(
          0,
          (total, value) => total + value.length,
        ) >=
        maxPendingFrames) {
      if (!await _evictOldestIncomplete(exceptAssemblyId: assemblyId)) {
        throw const V3LmfPersistenceLimitException(
          'v3 handshake frame capacity exceeded',
        );
      }
    }
  }

  Future<bool> _evictOldestIncomplete(
      {required String exceptAssemblyId}) async {
    MapEntry<String, Map<int, _StoredHandshakeFrame>>? oldest;
    DateTime? oldestReceivedAt;
    String? oldestStorageId;
    for (final entry in _pending.entries) {
      if (entry.key == exceptAssemblyId ||
          _complete(entry.key, entry.value) != null) {
        continue;
      }
      final first = entry.value.values.reduce((left, right) {
        final compared = left.receivedAt.compareTo(right.receivedAt);
        if (compared != 0) return compared < 0 ? left : right;
        return left.storageId.compareTo(right.storageId) <= 0 ? left : right;
      });
      final isOlder = oldest == null ||
          first.receivedAt.isBefore(oldestReceivedAt!) ||
          first.receivedAt == oldestReceivedAt &&
              first.storageId.compareTo(oldestStorageId!) < 0;
      if (isOlder) {
        oldest = entry;
        oldestReceivedAt = first.receivedAt;
        oldestStorageId = first.storageId;
      }
    }
    if (oldest == null) return false;
    final removed = _pending.remove(oldest.key)!;
    try {
      for (final stored in removed.values) {
        await _store.delete(stored.storageId);
      }
      return true;
    } catch (_) {
      _writeRecoveryRequired = true;
      rethrow;
    }
  }

  V3HandshakeFrameAssembly? _complete(
    String assemblyId,
    Map<int, _StoredHandshakeFrame> stored,
  ) {
    if (stored.isEmpty) return null;
    final fragmentCount = stored.values.first.frame.fragmentCount;
    if (stored.length != fragmentCount) return null;
    final frames = <V3LmfFrame>[];
    for (var index = 0; index < fragmentCount; index++) {
      final frame = stored[index];
      if (frame == null) return null;
      frames.add(frame.frame);
    }
    return V3HandshakeFrameAssembly(
      assemblyId: assemblyId,
      frames: List.unmodifiable(frames),
    );
  }

  void _validateBounds() {
    if (_pending.length > maxPendingAssemblies) {
      throw const V3LmfPersistenceLimitException(
        'v3 handshake assembly limit exceeded',
      );
    }
    final frames = _pending.values.fold<int>(
      0,
      (total, value) => total + value.length,
    );
    if (frames > maxPendingFrames) {
      throw const V3LmfPersistenceLimitException(
        'v3 handshake frame limit exceeded',
      );
    }
  }

  static Map<String, dynamic> _encodeFrame(
    Uint8List encoded,
    DateTime receivedAt,
  ) {
    return <String, dynamic>{
      'kind': frameRecordKind,
      'version': _formatVersion,
      'frame': base64UrlEncode(encoded).replaceAll('=', ''),
      'receivedAt': receivedAt.millisecondsSinceEpoch,
    };
  }

  static _StoredHandshakeFrame _decodeFrame(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    if (payload.length != 4 ||
        payload['kind'] != frameRecordKind ||
        payload['version'] != _formatVersion ||
        payload['frame'] is! String ||
        payload['receivedAt'] is! int) {
      throw const FormatException(
        'Invalid Layergram v3 handshake frame record',
      );
    }
    final encoded = _decodeCanonicalBase64Url(
      payload['frame'] as String,
      maximumBytes: V3LmfFrameCodec.maxBinaryFrameBytes,
    );
    final frame = V3LmfFrameCodec.decodeBinary(encoded);
    _validateHandshakeFrame(frame);
    return _StoredHandshakeFrame(
      storageId: stored.storageId,
      assemblyId: V3LmfFrameCodec.assemblyId(frame),
      frame: frame,
      encoded: encoded,
      receivedAt: _validatedTimestampMillis(payload['receivedAt'] as int),
    );
  }

  static String _decodeTombstone(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    if (payload.length != 4 ||
        payload['kind'] != tombstoneRecordKind ||
        payload['version'] != _formatVersion ||
        payload['assemblyId'] is! String ||
        payload['committedAt'] is! int) {
      throw const FormatException(
        'Invalid Layergram v3 handshake tombstone',
      );
    }
    final assemblyId = payload['assemblyId'] as String;
    _validateArmoredId(assemblyId, 32, 'assemblyId');
    _validatedTimestampMillis(payload['committedAt'] as int);
    return assemblyId;
  }

  static void _validateHandshakeFrame(V3LmfFrame frame) {
    if (frame.metadata.kind != V3LmfFrameKind.handshake ||
        frame.metadata.epoch != 0 ||
        frame.metadata.messageCounter < 0 ||
        frame.metadata.messageCounter > 2 ||
        frame.metadata.expiresAtUnixSeconds != 0) {
      throw const FormatException('Invalid Layergram v3 handshake frame');
    }
  }

  static DateTime _validatedTimestamp(DateTime value) =>
      _validatedTimestampMillis(value.toUtc().millisecondsSinceEpoch);

  static DateTime _validatedTimestampMillis(int value) {
    if (value < 0 || value > _maxTimestampMillis) {
      throw const FormatException('Invalid Layergram v3 handshake timestamp');
    }
    return DateTime.fromMillisecondsSinceEpoch(value, isUtc: true);
  }

  static Uint8List _decodeCanonicalBase64Url(
    String value, {
    required int maximumBytes,
  }) {
    if (value.isEmpty ||
        value.length > ((maximumBytes + 2) ~/ 3) * 4 ||
        !_isBase64Url(value)) {
      throw const FormatException('Invalid Layergram v3 handshake frame');
    }
    late final Uint8List decoded;
    try {
      decoded = Uint8List.fromList(
        base64Url.decode(base64Url.normalize(value)),
      );
    } on FormatException {
      throw const FormatException('Invalid Layergram v3 handshake frame');
    }
    if (decoded.isEmpty ||
        decoded.length > maximumBytes ||
        base64UrlEncode(decoded).replaceAll('=', '') != value) {
      throw const FormatException('Invalid Layergram v3 handshake frame');
    }
    return decoded;
  }

  static void _validateArmoredId(
    String value,
    int expectedBytes,
    String name,
  ) {
    final decoded = _decodeCanonicalBase64Url(
      value,
      maximumBytes: expectedBytes,
    );
    if (decoded.length != expectedBytes || decoded.every((byte) => byte == 0)) {
      throw FormatException('Invalid Layergram v3 $name');
    }
  }

  static bool _isBase64Url(String value) {
    for (final codeUnit in value.codeUnits) {
      final upper = codeUnit >= 0x41 && codeUnit <= 0x5a;
      final lower = codeUnit >= 0x61 && codeUnit <= 0x7a;
      final digit = codeUnit >= 0x30 && codeUnit <= 0x39;
      if (!upper && !lower && !digit && codeUnit != 0x2d && codeUnit != 0x5f) {
        return false;
      }
    }
    return true;
  }

  static bool _bytesEqual(Uint8List left, Uint8List right) {
    if (left.length != right.length) return false;
    var difference = 0;
    for (var index = 0; index < left.length; index++) {
      difference |= left[index] ^ right[index];
    }
    return difference == 0;
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
          throw StateError('Layergram v3 handshake frame inbox is closed');
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
      throw StateError('Layergram v3 handshake frame inbox is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored || requiresRecovery) {
      throw StateError(
        'Layergram v3 handshake frame inbox requires fresh restore',
      );
    }
  }
}
