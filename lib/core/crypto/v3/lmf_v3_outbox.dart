// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'lmf_v3.dart';
import 'lmf_v3_acknowledgement.dart';
import 'lmf_v3_persistence.dart';

enum V3LmfOutboxAckStatus { advanced, duplicate, complete }

typedef V3LmfOutboxBeforeComplete = FutureOr<void> Function(
  V3LmfOutboxEntry completedEntry,
);

typedef V3LmfOutboxBeforePersist = FutureOr<void> Function(
  V3LmfOutboxEntry updatedEntry,
);

/// Unforgeable ownership token for the inactive v3 send coordinator.
///
/// Direct outbox access remains available to isolated transport tests. Once a
/// coordinator claims an outbox, every lifecycle, read, and mutation call must
/// present this exact token so sealed bytes cannot be exported around the
/// crash-consistent session authority.
final class V3LmfOutboxAuthority {
  const V3LmfOutboxAuthority._();
}

class V3LmfOutboxEntry {
  const V3LmfOutboxEntry._({
    required this.assemblyId,
    required this.frames,
    required this.acknowledgedFragmentIndexes,
    required this.exportAttempts,
    required this.revision,
    required this.updatedAt,
  });

  final String assemblyId;
  final List<V3LmfFrame> frames;
  final Set<int> acknowledgedFragmentIndexes;
  final List<int> exportAttempts;
  final int revision;
  final DateTime updatedAt;

  bool get isFullyAcknowledged =>
      acknowledgedFragmentIndexes.length == frames.length;

  List<V3LmfFrame> get pendingFrames => List<V3LmfFrame>.unmodifiable(
        frames.where(
          (frame) => !acknowledgedFragmentIndexes.contains(frame.fragmentIndex),
        ),
      );
}

class V3LmfOutboxRestoreResult {
  const V3LmfOutboxRestoreResult({
    required this.entries,
    required this.discardedCorruptRecords,
    required this.removedSupersededRecords,
  });

  final List<V3LmfOutboxEntry> entries;
  final int discardedCorruptRecords;
  final int removedSupersededRecords;
}

/// Durable ledger of exact sealed bytes exported through manual transports.
///
/// Retrying never re-encrypts a frame: [pendingFrames] returns the same bytes
/// originally persisted before first export. ACK progress is cumulative and
/// write-new-before-delete. No wall-clock timestamp triggers automatic resend;
/// the user or a future transport policy explicitly requests pending frames.
class V3LmfDurableOutbox {
  V3LmfDurableOutbox({
    required V3LmfRecordStore store,
    this.maxEntries = 64,
    this.maxSealedFrameBytes = 512 * 1024,
    this.maxStoredRecords = 256,
  }) : _store = store {
    if (maxEntries <= 0 || maxSealedFrameBytes <= 0 || maxStoredRecords <= 0) {
      throw ArgumentError('Layergram v3 outbox limits must be positive');
    }
  }

  static const String outboxRecordKind = 'v3_lmf_out_v1';

  final V3LmfRecordStore _store;
  final int maxEntries;
  final int maxSealedFrameBytes;
  final int maxStoredRecords;
  final Map<String, _OutboxRecord> _entries = <String, _OutboxRecord>{};

  Future<void> _operationTail = Future<void>.value();
  bool _restored = false;
  bool _closed = false;
  V3LmfOutboxAuthority? _authority;
  int _sealedFrameBytes = 0;

  int get entryCount => _entries.length;

  int get sealedFrameBytes => _sealedFrameBytes;

  Future<V3LmfOutboxAuthority> claimSessionSendAuthority() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError(
          'Layergram v3 outbox authority must be claimed before restore',
        );
      }
      if (_authority != null) {
        throw StateError(
          'Layergram v3 outbox already has a session send coordinator',
        );
      }
      final authority = V3LmfOutboxAuthority._();
      _authority = authority;
      return authority;
    });
  }

  Future<V3LmfOutboxRestoreResult> restore({
    V3LmfOutboxAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 outbox was already restored');
      }
      final records = await _store.readAll();
      if (records
              .where((record) => record.payload['kind'] == outboxRecordKind)
              .length >
          maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical outbox record limit exceeded',
        );
      }
      final grouped = <String, List<_OutboxRecord>>{};
      var corrupt = 0;
      for (final stored in records) {
        if (stored.payload['kind'] != outboxRecordKind) continue;
        try {
          final decoded = _decodeRecord(stored);
          grouped
              .putIfAbsent(decoded.entry.assemblyId, () => <_OutboxRecord>[])
              .add(decoded);
        } on FormatException {
          corrupt++;
          await _deleteIgnoringFailure(stored.storageId);
        }
      }
      if (grouped.length > maxEntries) {
        throw const V3LmfPersistenceLimitException(
          'outbox entry limit exceeded',
        );
      }

      var superseded = 0;
      for (final candidates in grouped.values) {
        candidates.sort(
          (left, right) => right.entry.revision.compareTo(left.entry.revision),
        );
        final selected = candidates.first;
        for (final candidate in candidates.skip(1)) {
          if (candidate.entry.revision == selected.entry.revision &&
              !_sameEntry(candidate.entry, selected.entry)) {
            throw const V3LmfPersistenceConflictException(
              'conflicting outbox records have the same revision',
            );
          }
          superseded++;
          await _deleteIgnoringFailure(candidate.storageId);
        }
        final bytes = _entryFrameBytes(selected.entry);
        if (_sealedFrameBytes + bytes > maxSealedFrameBytes) {
          throw const V3LmfPersistenceLimitException(
            'outbox sealed-frame byte limit exceeded',
          );
        }
        _entries[selected.entry.assemblyId] = selected;
        _sealedFrameBytes += bytes;
      }
      _restored = true;
      return V3LmfOutboxRestoreResult(
        entries: List<V3LmfOutboxEntry>.unmodifiable(
          _entries.values.map((record) => record.entry),
        ),
        discardedCorruptRecords: corrupt,
        removedSupersededRecords: superseded,
      );
    });
  }

  /// Checks exact capacity without persisting or exposing a frame set.
  Future<void> preflightEnqueue(
    List<V3LmfFrame> frames, {
    V3LmfOutboxAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final canonicalFrames = _validateCompleteFrameSet(frames);
      final assemblyId = V3LmfFrameCodec.assemblyId(canonicalFrames.first);
      final existing = _entries[assemblyId];
      if (existing != null) {
        if (_sameFrameSet(existing.entry.frames, canonicalFrames)) return;
        throw const V3LmfPersistenceConflictException(
          'outbox assembly already exists with different sealed bytes',
        );
      }
      final candidateBytes = canonicalFrames.fold<int>(
        0,
        (sum, frame) => sum + V3LmfFrameCodec.encodeBinary(frame).length,
      );
      if (_entries.length >= maxEntries ||
          _sealedFrameBytes + candidateBytes > maxSealedFrameBytes) {
        throw const V3LmfPersistenceLimitException(
          'outbox capacity exceeded',
        );
      }
    });
  }

  /// Persists a complete canonical frame set before it may be exported.
  Future<V3LmfOutboxEntry> enqueue(
    List<V3LmfFrame> frames, {
    DateTime? queuedAt,
    V3LmfOutboxAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final canonicalFrames = _validateCompleteFrameSet(frames);
      final assemblyId = V3LmfFrameCodec.assemblyId(canonicalFrames.first);
      final existing = _entries[assemblyId];
      final timestamp = _validatedTimestamp(
        queuedAt ?? DateTime.now(),
        'queuedAt',
      );
      final candidate = V3LmfOutboxEntry._(
        assemblyId: assemblyId,
        frames: canonicalFrames,
        acknowledgedFragmentIndexes: const <int>{},
        exportAttempts: List<int>.unmodifiable(
          List<int>.filled(canonicalFrames.length, 0),
        ),
        revision: 0,
        updatedAt: timestamp,
      );
      if (existing != null) {
        if (_sameFrameSet(existing.entry.frames, candidate.frames)) {
          return existing.entry;
        }
        throw const V3LmfPersistenceConflictException(
          'outbox assembly identifier already has different sealed bytes',
        );
      }
      if (_entries.length >= maxEntries) {
        throw const V3LmfPersistenceLimitException(
          'outbox entry limit reached',
        );
      }
      final frameBytes = _entryFrameBytes(candidate);
      if (_sealedFrameBytes + frameBytes > maxSealedFrameBytes) {
        throw const V3LmfPersistenceLimitException(
          'outbox sealed-frame byte limit reached',
        );
      }
      final storageId = await _store.write(_encodeRecord(candidate));
      _ensureOpen();
      _entries[assemblyId] = _OutboxRecord(
        storageId: storageId,
        entry: candidate,
      );
      _sealedFrameBytes += frameBytes;
      return candidate;
    });
  }

  V3LmfOutboxEntry? entry(
    String assemblyId, {
    V3LmfOutboxAuthority? authority,
  }) {
    _ensureAuthority(authority);
    _ensureReady();
    return _entries[assemblyId]?.entry;
  }

  List<V3LmfFrame> pendingFrames(
    String assemblyId, {
    V3LmfOutboxAuthority? authority,
  }) {
    _ensureAuthority(authority);
    _ensureReady();
    final record = _entries[assemblyId];
    if (record == null) return const <V3LmfFrame>[];
    return record.entry.pendingFrames;
  }

  /// Records an explicit export attempt without changing sealed bytes.
  Future<V3LmfOutboxEntry> markExported({
    required String assemblyId,
    required Set<int> fragmentIndexes,
    DateTime? exportedAt,
    V3LmfOutboxBeforePersist? beforePersist,
    V3LmfOutboxAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final current = _entries[assemblyId];
      if (current == null) {
        throw StateError('Unknown Layergram v3 outbox assembly');
      }
      if (fragmentIndexes.isEmpty) {
        throw ArgumentError.value(
          fragmentIndexes,
          'fragmentIndexes',
          'must not be empty',
        );
      }
      final attempts = current.entry.exportAttempts.toList(growable: false);
      var changed = false;
      for (final index in fragmentIndexes) {
        if (index < 0 || index >= current.entry.frames.length) {
          throw ArgumentError.value(index, 'fragmentIndexes');
        }
        if (current.entry.acknowledgedFragmentIndexes.contains(index)) {
          continue;
        }
        if (attempts[index] >= 0x7fffffff) {
          throw StateError('Layergram v3 export attempt counter exhausted');
        }
        attempts[index]++;
        changed = true;
      }
      if (!changed) return current.entry;
      final updated = _copyEntry(
        current.entry,
        exportAttempts: List<int>.unmodifiable(attempts),
        revision: current.entry.revision + 1,
        updatedAt: _validatedTimestamp(
          exportedAt ?? DateTime.now(),
          'exportedAt',
        ),
      );
      if (beforePersist != null) {
        await beforePersist(updated);
        _ensureOpen();
      }
      await _replace(current, updated);
      return updated;
    });
  }

  /// Authenticates and applies a cumulative ACK frame.
  Future<V3LmfOutboxAckStatus> applyAcknowledgement({
    required V3LmfFrame acknowledgementFrame,
    required SecretKey secretKey,
    DateTime? receivedAt,
    V3LmfOutboxBeforeComplete? beforeComplete,
    V3LmfOutboxBeforePersist? beforePersist,
    V3LmfOutboxAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      if (acknowledgementFrame.metadata.kind !=
          V3LmfFrameKind.acknowledgement) {
        throw const FormatException('Layergram v3 frame is not an ACK');
      }
      final plaintext = await V3LmfAead.openSingle(
        frame: acknowledgementFrame,
        secretKey: secretKey,
      );
      late final V3LmfAcknowledgement acknowledgement;
      try {
        acknowledgement = V3LmfAcknowledgementCodec.decode(plaintext);
      } finally {
        plaintext.fillRange(0, plaintext.length, 0);
      }

      _OutboxRecord? target;
      for (final candidate in _entries.values) {
        if (_ackMatchesOutbox(
          acknowledgementFrame,
          acknowledgement,
          candidate.entry,
        )) {
          if (target != null) {
            throw const V3LmfPersistenceConflictException(
              'ACK ambiguously matches multiple outbox entries',
            );
          }
          target = candidate;
        }
      }
      if (target == null) {
        throw const FormatException('ACK does not match a pending v3 message');
      }

      final merged = <int>{
        ...target.entry.acknowledgedFragmentIndexes,
        ...acknowledgement.receivedFragmentIndexes,
      };
      if (merged.length == target.entry.acknowledgedFragmentIndexes.length) {
        return target.entry.isFullyAcknowledged
            ? V3LmfOutboxAckStatus.complete
            : V3LmfOutboxAckStatus.duplicate;
      }
      final updated = _copyEntry(
        target.entry,
        acknowledgedFragmentIndexes: Set<int>.unmodifiable(merged),
        revision: target.entry.revision + 1,
        updatedAt: _validatedTimestamp(
          receivedAt ?? DateTime.now(),
          'receivedAt',
        ),
      );
      if (updated.isFullyAcknowledged && beforeComplete != null) {
        await beforeComplete(updated);
        _ensureOpen();
      }
      if (beforePersist != null) {
        await beforePersist(updated);
        _ensureOpen();
      }
      await _replace(target, updated);
      return updated.isFullyAcknowledged
          ? V3LmfOutboxAckStatus.complete
          : V3LmfOutboxAckStatus.advanced;
    });
  }

  Future<void> removeFullyAcknowledged(
    String assemblyId, {
    V3LmfOutboxAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final record = _entries[assemblyId];
      if (record == null) return;
      if (!record.entry.isFullyAcknowledged) {
        throw StateError('Layergram v3 outbox entry is still pending');
      }
      await _store.delete(record.storageId);
      _entries.remove(assemblyId);
      _sealedFrameBytes -= _entryFrameBytes(record.entry);
    });
  }

  /// Removes a controller-owned materialized entry after the send journal has
  /// already committed its authenticated complete-ACK state.
  Future<void> reconcileCompleted(
    String assemblyId, {
    required V3LmfOutboxAuthority authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      final record = _entries[assemblyId];
      if (record == null) return;
      await _store.delete(record.storageId);
      _entries.remove(assemblyId);
      _sealedFrameBytes -= _entryFrameBytes(record.entry);
    });
  }

  Future<void> close({V3LmfOutboxAuthority? authority}) {
    return _serialized(() async {
      _ensureAuthority(authority);
      if (_closed) return;
      _closed = true;
      _entries.clear();
      _sealedFrameBytes = 0;
    });
  }

  Future<void> _replace(
    _OutboxRecord current,
    V3LmfOutboxEntry updated,
  ) async {
    if (updated.revision > 0x7fffffff) {
      throw StateError('Layergram v3 outbox revision exhausted');
    }
    // New revision becomes durable before the previous one is removed.
    final storageId = await _store.write(_encodeRecord(updated));
    _ensureOpen();
    final replacement = _OutboxRecord(storageId: storageId, entry: updated);
    _entries[updated.assemblyId] = replacement;
    await _deleteIgnoringFailure(current.storageId);
  }

  _OutboxRecord _decodeRecord(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    if (payload['v'] != 1 || payload.length != 9) {
      throw const FormatException('Invalid Layergram v3 outbox record');
    }
    final assemblyId = payload['assemblyId'];
    final revision = payload['revision'];
    final frameValues = payload['frames'];
    final ackValues = payload['acked'];
    final attemptValues = payload['attempts'];
    final updatedAt = payload['updatedAt'];
    if (assemblyId is! String ||
        assemblyId.length != 43 ||
        revision is! int ||
        revision < 0 ||
        revision > 0x7fffffff ||
        frameValues is! List ||
        ackValues is! List ||
        attemptValues is! List ||
        !_isValidEpochMilliseconds(updatedAt)) {
      throw const FormatException('Invalid Layergram v3 outbox record');
    }
    if (frameValues.isEmpty ||
        frameValues.length > V3LmfFrameCodec.maxFragments ||
        ackValues.length > V3LmfFrameCodec.maxFragments) {
      throw const FormatException('Invalid Layergram v3 outbox record bounds');
    }
    final frames = <V3LmfFrame>[];
    for (final value in frameValues) {
      if (value is! String) {
        throw const FormatException('Invalid Layergram v3 outbox frame');
      }
      final binary = _decodeBinary(value, V3LmfFrameCodec.maxBinaryFrameBytes);
      final frame = V3LmfFrameCodec.decodeBinary(binary);
      if (!_bytesEqual(binary, V3LmfFrameCodec.encodeBinary(frame))) {
        throw const FormatException('Non-canonical Layergram v3 outbox frame');
      }
      frames.add(frame);
    }
    late final List<V3LmfFrame> canonicalFrames;
    try {
      canonicalFrames = _validateCompleteFrameSet(frames);
    } on ArgumentError {
      throw const FormatException('Invalid Layergram v3 outbox frame set');
    }
    if (V3LmfFrameCodec.assemblyId(canonicalFrames.first) != assemblyId) {
      throw const FormatException('Mismatched Layergram v3 outbox assembly');
    }
    if (attemptValues.length != canonicalFrames.length) {
      throw const FormatException('Invalid Layergram v3 outbox attempts');
    }
    final attempts = <int>[];
    for (final value in attemptValues) {
      if (value is! int || value < 0 || value > 0x7fffffff) {
        throw const FormatException('Invalid Layergram v3 outbox attempts');
      }
      attempts.add(value);
    }
    final acknowledged = <int>{};
    for (final value in ackValues) {
      if (value is! int || value < 0 || value >= canonicalFrames.length) {
        throw const FormatException('Invalid Layergram v3 outbox ACK state');
      }
      if (!acknowledged.add(value)) {
        throw const FormatException('Duplicate Layergram v3 outbox ACK index');
      }
    }
    final sortedAcknowledged = acknowledged.toList()..sort();
    if (!_listEquals(sortedAcknowledged, ackValues.cast<int>())) {
      throw const FormatException(
          'Non-canonical Layergram v3 outbox ACK state');
    }
    final entry = V3LmfOutboxEntry._(
      assemblyId: assemblyId,
      frames: canonicalFrames,
      acknowledgedFragmentIndexes: Set<int>.unmodifiable(acknowledged),
      exportAttempts: List<int>.unmodifiable(attempts),
      revision: revision,
      updatedAt: DateTime.fromMillisecondsSinceEpoch(
        updatedAt as int,
        isUtc: true,
      ),
    );
    if (!_mapEquals(_encodeRecord(entry), payload)) {
      throw const FormatException('Non-canonical Layergram v3 outbox record');
    }
    return _OutboxRecord(storageId: stored.storageId, entry: entry);
  }

  Map<String, dynamic> _encodeRecord(V3LmfOutboxEntry entry) {
    return <String, dynamic>{
      'kind': outboxRecordKind,
      'v': 1,
      'assemblyId': entry.assemblyId,
      'revision': entry.revision,
      'frames': entry.frames
          .map((frame) => _encodeBinary(V3LmfFrameCodec.encodeBinary(frame)))
          .toList(growable: false),
      'acked': (entry.acknowledgedFragmentIndexes.toList()..sort()),
      'attempts': entry.exportAttempts,
      'updatedAt': entry.updatedAt.millisecondsSinceEpoch,
      'reserved': 0,
    };
  }

  Future<void> _deleteIgnoringFailure(String storageId) async {
    try {
      await _store.delete(storageId);
    } catch (_) {
      // A superseded encrypted revision is harmless and cleaned on restore.
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
    if (_closed) throw StateError('Layergram v3 outbox is closed');
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored) {
      throw StateError('Layergram v3 outbox must be restored before use');
    }
  }

  void _ensureAuthority(V3LmfOutboxAuthority? authority) {
    final claimed = _authority;
    if (claimed != null && !identical(claimed, authority)) {
      throw StateError(
        'Layergram v3 outbox is owned by a session send coordinator',
      );
    }
  }
}

class _OutboxRecord {
  const _OutboxRecord({required this.storageId, required this.entry});

  final String storageId;
  final V3LmfOutboxEntry entry;
}

List<V3LmfFrame> _validateCompleteFrameSet(List<V3LmfFrame> frames) {
  if (frames.isEmpty || frames.length > V3LmfFrameCodec.maxFragments) {
    throw ArgumentError.value(frames.length, 'frames.length');
  }
  final sorted = frames.toList()
    ..sort(
      (left, right) => left.fragmentIndex.compareTo(right.fragmentIndex),
    );
  final acknowledgement = V3LmfAcknowledgementCodec.forReceivedFrames(sorted);
  if (!acknowledgement.isComplete ||
      sorted.length != sorted.first.fragmentCount) {
    throw ArgumentError('Outbox requires a complete canonical frame set');
  }
  for (var index = 0; index < sorted.length; index++) {
    if (sorted[index].fragmentIndex != index) {
      throw ArgumentError('Outbox frame set has a gap or duplicate');
    }
  }
  return List<V3LmfFrame>.unmodifiable(sorted);
}

V3LmfOutboxEntry _copyEntry(
  V3LmfOutboxEntry original, {
  Set<int>? acknowledgedFragmentIndexes,
  List<int>? exportAttempts,
  int? revision,
  DateTime? updatedAt,
}) {
  return V3LmfOutboxEntry._(
    assemblyId: original.assemblyId,
    frames: original.frames,
    acknowledgedFragmentIndexes:
        acknowledgedFragmentIndexes ?? original.acknowledgedFragmentIndexes,
    exportAttempts: exportAttempts ?? original.exportAttempts,
    revision: revision ?? original.revision,
    updatedAt: updatedAt ?? original.updatedAt,
  );
}

bool _ackMatchesOutbox(
  V3LmfFrame ackFrame,
  V3LmfAcknowledgement ack,
  V3LmfOutboxEntry entry,
) {
  final target = entry.frames.first;
  final targetMetadata = target.metadata;
  final ackMetadata = ackFrame.metadata;
  return ack.targetSuite == targetMetadata.suite &&
      ack.targetKind == targetMetadata.kind &&
      ack.targetEpoch == targetMetadata.epoch &&
      ack.targetMessageCounter == targetMetadata.messageCounter &&
      ack.targetAssembledPlaintextLength == target.assembledPlaintextLength &&
      ack.targetFragmentCount == target.fragmentCount &&
      _bytesEqual(ack.targetMessageId, targetMetadata.messageId) &&
      ackMetadata.suite == targetMetadata.suite &&
      _bytesEqual(ackMetadata.sessionId, targetMetadata.sessionId) &&
      _bytesEqual(
        ackMetadata.senderBinding,
        targetMetadata.recipientBinding,
      ) &&
      _bytesEqual(
        ackMetadata.recipientBinding,
        targetMetadata.senderBinding,
      );
}

int _entryFrameBytes(V3LmfOutboxEntry entry) => entry.frames.fold<int>(
      0,
      (sum, frame) => sum + V3LmfFrameCodec.encodeBinary(frame).length,
    );

bool _sameEntry(V3LmfOutboxEntry left, V3LmfOutboxEntry right) {
  return left.assemblyId == right.assemblyId &&
      left.revision == right.revision &&
      left.updatedAt == right.updatedAt &&
      _sameFrameSet(left.frames, right.frames) &&
      _setEquals(
        left.acknowledgedFragmentIndexes,
        right.acknowledgedFragmentIndexes,
      ) &&
      _listEquals(left.exportAttempts, right.exportAttempts);
}

bool _sameFrameSet(List<V3LmfFrame> left, List<V3LmfFrame> right) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (!_bytesEqual(
      V3LmfFrameCodec.encodeBinary(left[index]),
      V3LmfFrameCodec.encodeBinary(right[index]),
    )) {
      return false;
    }
  }
  return true;
}

String _encodeBinary(Uint8List bytes) =>
    base64UrlEncode(bytes).replaceAll('=', '');

Uint8List _decodeBinary(String armored, int maxBytes) {
  if (armored.isEmpty || armored.length > ((maxBytes * 4 + 2) ~/ 3)) {
    throw const FormatException('Invalid Layergram v3 outbox binary length');
  }
  for (final codeUnit in armored.codeUnits) {
    final upper = codeUnit >= 0x41 && codeUnit <= 0x5a;
    final lower = codeUnit >= 0x61 && codeUnit <= 0x7a;
    final digit = codeUnit >= 0x30 && codeUnit <= 0x39;
    if (!upper && !lower && !digit && codeUnit != 0x2d && codeUnit != 0x5f) {
      throw const FormatException('Invalid Layergram v3 outbox binary armor');
    }
  }
  late final Uint8List bytes;
  try {
    bytes = Uint8List.fromList(base64Url.decode(base64Url.normalize(armored)));
  } on FormatException {
    throw const FormatException('Invalid Layergram v3 outbox binary armor');
  }
  if (bytes.length > maxBytes || _encodeBinary(bytes) != armored) {
    throw const FormatException(
      'Non-canonical Layergram v3 outbox binary armor',
    );
  }
  return bytes;
}

bool _bytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

bool _listEquals(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) return false;
  }
  return true;
}

bool _setEquals(Set<int> left, Set<int> right) {
  return left.length == right.length && left.containsAll(right);
}

bool _mapEquals(Map<String, dynamic> left, Map<String, dynamic> right) {
  if (left.length != right.length) return false;
  for (final entry in left.entries) {
    if (!right.containsKey(entry.key)) return false;
    final other = right[entry.key];
    if (entry.value is List && other is List) {
      if (jsonEncode(entry.value) != jsonEncode(other)) return false;
    } else if (entry.value != other) {
      return false;
    }
  }
  return true;
}

bool _isValidEpochMilliseconds(Object? value) =>
    value is int && value >= 0 && value <= 8640000000000000;

DateTime _validatedTimestamp(DateTime value, String name) {
  final utc = value.toUtc();
  if (!_isValidEpochMilliseconds(utc.millisecondsSinceEpoch)) {
    throw ArgumentError.value(value, name, 'must not precede Unix epoch');
  }
  return utc;
}
