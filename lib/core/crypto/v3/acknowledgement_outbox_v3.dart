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
import 'dart:math';
import 'dart:typed_data';

import 'lmf_v3.dart';
import 'lmf_v3_acknowledgement.dart';
import 'lmf_v3_persistence.dart';

final class V3AcknowledgementOutboxEntry {
  const V3AcknowledgementOutboxEntry._({
    required this.storageId,
    required this.targetAssemblyId,
    required this.partitionKey,
    required this.frame,
    required this.createdAt,
  });

  final String storageId;
  final String targetAssemblyId;
  final String partitionKey;
  final V3LmfFrame frame;
  final DateTime createdAt;
}

final class V3AcknowledgementOutboxRestoreResult {
  const V3AcknowledgementOutboxRestoreResult({
    required this.entries,
    required this.removedExactDuplicates,
  });

  final List<V3AcknowledgementOutboxEntry> entries;
  final int removedExactDuplicates;
}

typedef V3AcknowledgementFrameBuilder = Future<V3LmfFrame> Function(
  Uint8List freshMessageId,
);

typedef V3AcknowledgementPartitionResolver = FutureOr<String> Function(
  V3LmfFrame frame,
);

/// Durable exact-byte retry storage for receiver-generated ACK frames.
///
/// A cumulative ACK gets a fresh message ID before it is sealed. If the same
/// target is replayed, this outbox returns the already-sealed frame instead of
/// reusing an ACK key/nonce with newly encoded plaintext.
final class V3AcknowledgementOutbox {
  V3AcknowledgementOutbox({
    required V3LmfRecordStore store,
    Random? secureRandom,
    this.maxEntries = 4096,
    this.maxStoredRecords = 8192,
    this.maxTotalBytes = 4 * 1024 * 1024,
    int? maxEntriesPerPartition,
    int? maxTotalBytesPerPartition,
    V3AcknowledgementPartitionResolver? partitionResolver,
  })  : _store = store,
        _secureRandom = secureRandom ?? Random.secure(),
        maxEntriesPerPartition = maxEntriesPerPartition ??
            _defaultMaxEntriesPerPartition(maxEntries),
        maxTotalBytesPerPartition = maxTotalBytesPerPartition ??
            _defaultMaxBytesPerPartition(maxTotalBytes),
        _partitionResolver =
            partitionResolver ?? _defaultSessionPartitionResolver {
    if (maxEntries <= 0 || maxStoredRecords <= 0 || maxTotalBytes <= 0) {
      throw ArgumentError('Layergram v3 ACK-outbox limits are invalid');
    }
    if (this.maxEntriesPerPartition <= 0 ||
        this.maxEntriesPerPartition > maxEntries ||
        this.maxTotalBytesPerPartition <= 0 ||
        this.maxTotalBytesPerPartition > maxTotalBytes) {
      throw ArgumentError(
        'Layergram v3 ACK-outbox partition limits are invalid',
      );
    }
  }

  static const String recordKind = 'v3_acknowledgement_outbox_v1';
  static const int _legacyFormatVersion = 1;
  static const int _formatVersion = 2;
  static const int _maxTimestampMillis = 253402300799999;
  static const int acknowledgementFrameBytes = V3LmfFrameCodec.headerBytes +
      V3LmfAcknowledgementCodec.encodedBytes +
      V3LmfFrameCodec.authenticationTagBytes;

  final V3LmfRecordStore _store;
  final Random _secureRandom;
  final int maxEntries;
  final int maxStoredRecords;
  final int maxTotalBytes;
  final int maxEntriesPerPartition;
  final int maxTotalBytesPerPartition;
  final V3AcknowledgementPartitionResolver _partitionResolver;

  final Map<String, V3AcknowledgementOutboxEntry> _entries = {};
  Future<void> _operationTail = Future<void>.value();
  bool _restored = false;
  bool _closed = false;
  bool _writeRecoveryRequired = false;
  int _totalBytes = 0;

  bool get requiresRecovery => _writeRecoveryRequired;

  Future<void> preflightGetOrCreate(
    String targetAssemblyId, {
    required String partitionKey,
  }) {
    return _serialized(() async {
      _ensureReady();
      _validateArmoredId(targetAssemblyId, 32, 'targetAssemblyId');
      _validateArmoredId(partitionKey, 48, 'partitionKey');
      final existing = _entries[targetAssemblyId];
      if (existing != null) {
        if (existing.partitionKey != partitionKey) {
          throw const V3LmfPersistenceConflictException(
            'v3 ACK target changed contact partition',
          );
        }
        return;
      }
      if (_entries.length >= maxEntries) {
        throw const V3LmfPersistenceLimitException(
          'v3 ACK-outbox capacity exceeded',
        );
      }
      if (_totalBytes + acknowledgementFrameBytes > maxTotalBytes) {
        throw const V3LmfPersistenceLimitException(
          'v3 ACK-outbox byte capacity exceeded',
        );
      }
      _ensurePartitionCapacity(partitionKey);
    });
  }

  Future<V3AcknowledgementOutboxRestoreResult> restore() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 ACK outbox was restored');
      }
      final records = (await _store.readAll())
          .where((record) => record.payload['kind'] == recordKind)
          .toList(growable: false);
      if (records.length > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical v3 ACK-outbox record limit exceeded',
        );
      }
      final grouped = <String, List<V3AcknowledgementOutboxEntry>>{};
      for (final record in records) {
        final entry = await _decode(record);
        grouped.putIfAbsent(entry.targetAssemblyId, () => []).add(entry);
      }
      if (grouped.length > maxEntries) {
        throw const V3LmfPersistenceLimitException(
          'v3 ACK-outbox entry limit exceeded',
        );
      }
      final selected = <String, V3AcknowledgementOutboxEntry>{};
      final duplicates = <V3AcknowledgementOutboxEntry>[];
      final partitionEntries = <String, int>{};
      final partitionBytes = <String, int>{};
      var total = 0;
      for (final candidates in grouped.values) {
        candidates.sort((left, right) {
          final time = left.createdAt.compareTo(right.createdAt);
          if (time != 0) return time;
          return left.storageId.compareTo(right.storageId);
        });
        final canonical = candidates.first;
        final canonicalBytes = V3LmfFrameCodec.encodeBinary(canonical.frame);
        try {
          for (final duplicate in candidates.skip(1)) {
            final duplicateBytes =
                V3LmfFrameCodec.encodeBinary(duplicate.frame);
            try {
              if (!_bytesEqual(canonicalBytes, duplicateBytes)) {
                throw const V3LmfPersistenceConflictException(
                  'divergent v3 ACK frames share one target assembly',
                );
              }
            } finally {
              _wipe(duplicateBytes);
            }
            duplicates.add(duplicate);
          }
          total += canonicalBytes.length;
        } finally {
          _wipe(canonicalBytes);
        }
        if (total > maxTotalBytes) {
          throw const V3LmfPersistenceLimitException(
            'v3 ACK-outbox byte limit exceeded',
          );
        }
        final nextPartitionEntries =
            (partitionEntries[canonical.partitionKey] ?? 0) + 1;
        final nextPartitionBytes =
            (partitionBytes[canonical.partitionKey] ?? 0) +
                acknowledgementFrameBytes;
        if (nextPartitionEntries > maxEntriesPerPartition ||
            nextPartitionBytes > maxTotalBytesPerPartition) {
          throw const V3LmfPersistenceLimitException(
            'v3 ACK-outbox contact partition limit exceeded',
          );
        }
        partitionEntries[canonical.partitionKey] = nextPartitionEntries;
        partitionBytes[canonical.partitionKey] = nextPartitionBytes;
        selected[canonical.targetAssemblyId] = canonical;
      }
      for (final duplicate in duplicates) {
        try {
          await _store.delete(duplicate.storageId);
        } catch (_) {
          // An exact duplicate remains safe and is retried on the next restore.
        }
      }
      _entries.addAll(selected);
      _totalBytes = total;
      _restored = true;
      return V3AcknowledgementOutboxRestoreResult(
        entries: List.unmodifiable(_entries.values),
        removedExactDuplicates: duplicates.length,
      );
    });
  }

  Future<V3AcknowledgementOutboxEntry> getOrCreate({
    required String targetAssemblyId,
    required String partitionKey,
    required V3AcknowledgementFrameBuilder builder,
    DateTime? createdAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      _validateArmoredId(targetAssemblyId, 32, 'targetAssemblyId');
      _validateArmoredId(partitionKey, 48, 'partitionKey');
      final existing = _entries[targetAssemblyId];
      if (existing != null) {
        if (existing.partitionKey != partitionKey) {
          throw const V3LmfPersistenceConflictException(
            'v3 ACK target changed contact partition',
          );
        }
        return existing;
      }
      if (_entries.length >= maxEntries) {
        throw const V3LmfPersistenceLimitException(
          'v3 ACK-outbox capacity exceeded',
        );
      }
      _ensurePartitionCapacity(partitionKey);
      final messageId = _newMessageId();
      try {
        final frame = await builder(messageId);
        _validateAcknowledgementFrame(frame, expectedMessageId: messageId);
        final encoded = V3LmfFrameCodec.encodeBinary(frame);
        try {
          if (encoded.length != acknowledgementFrameBytes) {
            throw const V3LmfPersistenceConflictException(
              'v3 ACK frame size diverged from capacity reservation',
            );
          }
          if (_totalBytes + encoded.length > maxTotalBytes) {
            throw const V3LmfPersistenceLimitException(
              'v3 ACK-outbox byte capacity exceeded',
            );
          }
          final timestamp = _validatedTimestamp(createdAt ?? DateTime.now());
          final payload = <String, dynamic>{
            'kind': recordKind,
            'version': _formatVersion,
            'targetAssemblyId': targetAssemblyId,
            'partitionKey': partitionKey,
            'frame': base64UrlEncode(encoded).replaceAll('=', ''),
            'createdAt': timestamp.millisecondsSinceEpoch,
            'reserved': 0,
          };
          try {
            final storageId = await _store.write(payload);
            final entry = V3AcknowledgementOutboxEntry._(
              storageId: storageId,
              targetAssemblyId: targetAssemblyId,
              partitionKey: partitionKey,
              frame: frame,
              createdAt: timestamp,
            );
            _entries[targetAssemblyId] = entry;
            _totalBytes += encoded.length;
            return entry;
          } catch (_) {
            _writeRecoveryRequired = true;
            rethrow;
          }
        } finally {
          _wipe(encoded);
        }
      } finally {
        _wipe(messageId);
      }
    });
  }

  Future<List<V3AcknowledgementOutboxEntry>> entries() {
    return _serialized(() async {
      _ensureReady();
      return List.unmodifiable(_entries.values);
    });
  }

  Future<void> deleteOlderThan(DateTime cutoff) {
    return _serialized(() async {
      _ensureReady();
      final timestamp = _validatedTimestamp(cutoff);
      final expired = _entries.values
          .where((entry) => entry.createdAt.isBefore(timestamp))
          .toList(growable: false);
      for (final entry in expired) {
        final encoded = V3LmfFrameCodec.encodeBinary(entry.frame);
        try {
          try {
            await _store.delete(entry.storageId);
          } catch (_) {
            _writeRecoveryRequired = true;
            rethrow;
          }
          _entries.remove(entry.targetAssemblyId);
          _totalBytes -= encoded.length;
        } finally {
          _wipe(encoded);
        }
      }
    });
  }

  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      _entries.clear();
      _totalBytes = 0;
    }, allowClosed: true);
  }

  Future<V3AcknowledgementOutboxEntry> _decode(
    V3LmfStoredRecord stored,
  ) async {
    final payload = stored.payload;
    final version = payload['version'];
    final legacy = version == _legacyFormatVersion;
    if ((legacy ? payload.length != 6 : payload.length != 7) ||
        payload['kind'] != recordKind ||
        (!legacy && version != _formatVersion) ||
        payload['targetAssemblyId'] is! String ||
        (!legacy && payload['partitionKey'] is! String) ||
        payload['frame'] is! String ||
        payload['createdAt'] is! int ||
        payload['reserved'] != 0) {
      throw const FormatException('Invalid Layergram v3 ACK-outbox record');
    }
    final targetAssemblyId = payload['targetAssemblyId'] as String;
    _validateArmoredId(targetAssemblyId, 32, 'targetAssemblyId');
    final frameBytes = _decodeCanonicalBase64Url(
      payload['frame'] as String,
      maximumBytes: V3LmfFrameCodec.maxBinaryFrameBytes,
    );
    try {
      final frame = V3LmfFrameCodec.decodeBinary(frameBytes);
      _validateAcknowledgementFrame(frame);
      final resolvedPartitionKey = await _partitionResolver(frame);
      _validateArmoredId(resolvedPartitionKey, 48, 'partitionKey');
      final partitionKey =
          legacy ? resolvedPartitionKey : payload['partitionKey'] as String;
      _validateArmoredId(partitionKey, 48, 'partitionKey');
      if (partitionKey != resolvedPartitionKey) {
        throw const V3LmfPersistenceConflictException(
          'v3 ACK contact partition does not match its session binding',
        );
      }
      return V3AcknowledgementOutboxEntry._(
        storageId: stored.storageId,
        targetAssemblyId: targetAssemblyId,
        partitionKey: partitionKey,
        frame: frame,
        createdAt: _validatedTimestampMillis(payload['createdAt'] as int),
      );
    } finally {
      _wipe(frameBytes);
    }
  }

  static void _validateAcknowledgementFrame(
    V3LmfFrame frame, {
    Uint8List? expectedMessageId,
  }) {
    final metadata = frame.metadata;
    if (metadata.kind != V3LmfFrameKind.acknowledgement ||
        frame.fragmentIndex != 0 ||
        frame.fragmentCount != 1 ||
        frame.assembledPlaintextLength !=
            V3LmfAcknowledgementCodec.encodedBytes ||
        frame.hybridRatchetHeader != null ||
        frame.hybridRatchetHeaderLength != 0 ||
        (expectedMessageId != null &&
            !_bytesEqual(metadata.messageId, expectedMessageId))) {
      throw const FormatException(
        'Invalid Layergram v3 ACK-outbox frame',
      );
    }
  }

  void _ensurePartitionCapacity(String partitionKey) {
    var entries = 0;
    var bytes = 0;
    for (final entry in _entries.values) {
      if (entry.partitionKey != partitionKey) continue;
      entries++;
      bytes += acknowledgementFrameBytes;
    }
    if (entries >= maxEntriesPerPartition) {
      throw const V3LmfPersistenceLimitException(
        'v3 ACK-outbox contact capacity exceeded',
      );
    }
    if (bytes + acknowledgementFrameBytes > maxTotalBytesPerPartition) {
      throw const V3LmfPersistenceLimitException(
        'v3 ACK-outbox contact byte capacity exceeded',
      );
    }
  }

  static int _defaultMaxEntriesPerPartition(int maxEntries) {
    if (maxEntries <= 4) return maxEntries;
    return maxEntries - max(1, maxEntries ~/ 4);
  }

  static int _defaultMaxBytesPerPartition(int maxTotalBytes) {
    if (maxTotalBytes <= acknowledgementFrameBytes * 4) {
      return maxTotalBytes;
    }
    return maxTotalBytes -
        max(
          acknowledgementFrameBytes,
          maxTotalBytes ~/ 4,
        );
  }

  static String _defaultSessionPartitionResolver(V3LmfFrame frame) {
    final sessionId = frame.metadata.sessionId;
    try {
      // Test-only/default isolation. Production supplies the durable remote
      // identity binding so one contact cannot rotate sessions around a cap.
      final expanded = Uint8List(48);
      for (var index = 0; index < expanded.length; index++) {
        expanded[index] = sessionId[index % sessionId.length];
      }
      return base64UrlEncode(expanded).replaceAll('=', '');
    } finally {
      _wipe(sessionId);
    }
  }

  Uint8List _newMessageId() {
    for (var attempt = 0; attempt < 16; attempt++) {
      final bytes = Uint8List.fromList(
        List<int>.generate(
          V3LmfFrameCodec.messageIdBytes,
          (_) => _secureRandom.nextInt(256),
        ),
      );
      if (!bytes.every((byte) => byte == 0)) return bytes;
      _wipe(bytes);
    }
    throw StateError('Unable to allocate a Layergram v3 ACK message ID');
  }

  static Uint8List _decodeCanonicalBase64Url(
    String value, {
    required int maximumBytes,
  }) {
    if (value.isEmpty || value.length > ((maximumBytes + 2) ~/ 3) * 4) {
      throw const FormatException('Invalid Layergram v3 base64url value');
    }
    for (final codeUnit in value.codeUnits) {
      final upper = codeUnit >= 0x41 && codeUnit <= 0x5a;
      final lower = codeUnit >= 0x61 && codeUnit <= 0x7a;
      final digit = codeUnit >= 0x30 && codeUnit <= 0x39;
      if (!upper && !lower && !digit && codeUnit != 0x2d && codeUnit != 0x5f) {
        throw const FormatException('Invalid Layergram v3 base64url value');
      }
    }
    late final Uint8List decoded;
    try {
      decoded = Uint8List.fromList(
        base64Url.decode(base64Url.normalize(value)),
      );
    } on FormatException {
      throw const FormatException('Invalid Layergram v3 base64url value');
    }
    if (decoded.length > maximumBytes ||
        base64UrlEncode(decoded).replaceAll('=', '') != value) {
      _wipe(decoded);
      throw const FormatException('Invalid Layergram v3 base64url value');
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
    try {
      if (decoded.length != expectedBytes ||
          decoded.every((byte) => byte == 0)) {
        throw FormatException('Invalid Layergram v3 $name');
      }
    } finally {
      _wipe(decoded);
    }
  }

  static DateTime _validatedTimestamp(DateTime value) =>
      _validatedTimestampMillis(value.toUtc().millisecondsSinceEpoch);

  static DateTime _validatedTimestampMillis(int value) {
    if (value < 0 || value > _maxTimestampMillis) {
      throw const FormatException('Invalid Layergram v3 ACK timestamp');
    }
    return DateTime.fromMillisecondsSinceEpoch(value, isUtc: true);
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
          throw StateError('Layergram v3 ACK outbox is closed');
        }
        completer.complete(await operation());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  void _ensureOpen() {
    if (_closed) throw StateError('Layergram v3 ACK outbox is closed');
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored || requiresRecovery) {
      throw StateError('Layergram v3 ACK outbox requires restore');
    }
  }
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
