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
import 'package:cryptography/cryptography.dart';

import '../../storage/aux_record_repository.dart';
import 'lmf_v3.dart';
import 'lmf_v3_acknowledgement.dart';

/// One opaque-storage record after the outer local encryption was opened.
class V3LmfStoredRecord {
  V3LmfStoredRecord({required this.storageId, required this.payload});

  final String storageId;
  final Map<String, dynamic> payload;
}

/// Minimal persistence seam used by inactive v3 transport state.
///
/// Production adapts [AuxRecordRepository], retaining its write-new-before-
/// delete update behavior and externally opaque padded records. Tests can use a
/// deterministic fault-injecting implementation to model process crashes.
abstract interface class V3LmfRecordStore {
  Future<String> write(Map<String, dynamic> payload);

  Future<List<V3LmfStoredRecord>> readAll();

  Future<void> delete(String storageId);
}

class V3LmfAuxRecordStore implements V3LmfRecordStore {
  V3LmfAuxRecordStore(this._repository);

  final AuxRecordRepository _repository;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final result = await _repository.write(payload: payload);
    return result.storageId;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async {
    final result = <V3LmfStoredRecord>[];
    for (final entry in _repository.getAllAuxRecordIds().entries) {
      final payload = await _repository.read(
        storageId: entry.key,
        recordId: entry.value,
      );
      if (payload == null) continue;
      result.add(V3LmfStoredRecord(storageId: entry.key, payload: payload));
    }
    return result;
  }

  @override
  Future<void> delete(String storageId) => _repository.delete(storageId);
}

typedef V3LmfFrameKeyResolver = FutureOr<SecretKey?> Function(V3LmfFrame frame);

enum V3LmfInboxStatus {
  accepted,
  duplicate,
  complete,
  committedReplay,
}

/// Durable delivery. The plaintext is copied on construction and access.
///
/// The caller must persist its higher-level idempotency/application state
/// before calling [V3LmfDurableInbox.commit]. The inbox intentionally provides
/// at-least-once delivery across a crash; exact-once effects require the future
/// application/ratchet transaction keyed by [assemblyId].
class V3LmfDurableDelivery {
  V3LmfDurableDelivery._({
    required this.assemblyId,
    required Uint8List plaintext,
    required List<V3LmfFrame> frames,
  })  : _plaintext = Uint8List.fromList(plaintext),
        frames = List<V3LmfFrame>.unmodifiable(frames);

  final String assemblyId;
  final Uint8List _plaintext;
  final List<V3LmfFrame> frames;

  Uint8List get plaintext => Uint8List.fromList(_plaintext);

  V3LmfAcknowledgement get completeAcknowledgement =>
      V3LmfAcknowledgementCodec.forReceivedFrames(frames);
}

class V3LmfInboxOutcome {
  const V3LmfInboxOutcome._({
    required this.status,
    required this.acknowledgement,
    this.delivery,
  });

  final V3LmfInboxStatus status;
  final V3LmfAcknowledgement acknowledgement;
  final V3LmfDurableDelivery? delivery;

  bool get isComplete => status == V3LmfInboxStatus.complete;
}

class V3LmfInboxRestoreResult {
  const V3LmfInboxRestoreResult({
    required this.deliveries,
    required this.deferredFrames,
    required this.discardedCorruptRecords,
    required this.suppressedCommittedFrames,
  });

  final List<V3LmfDurableDelivery> deliveries;
  final int deferredFrames;
  final int discardedCorruptRecords;
  final int suppressedCommittedFrames;
}

class V3LmfPersistenceLimitException implements Exception {
  const V3LmfPersistenceLimitException(this.message);

  final String message;

  @override
  String toString() => 'V3LmfPersistenceLimitException: $message';
}

class V3LmfPersistenceConflictException implements Exception {
  const V3LmfPersistenceConflictException(this.message);

  final String message;

  @override
  String toString() => 'V3LmfPersistenceConflictException: $message';
}

/// Crash-consistent inbox for canonical, still-sealed LMF v3 frames.
///
/// Receive order is:
///
/// 1. strict structural decode by the caller/transport;
/// 2. outer encrypted local write of the exact sealed frame;
/// 3. frame authentication and private in-memory reassembly;
/// 4. at-least-once complete delivery;
/// 5. higher-level idempotent commit;
/// 6. encrypted tombstone write;
/// 7. deletion of obsolete frame records.
///
/// A crash cannot turn a partially persisted message into exposed plaintext.
/// A crash after the tombstone write but before cleanup suppresses redelivery
/// and lets the next restore finish cleanup.
class V3LmfDurableInbox {
  V3LmfDurableInbox({
    required V3LmfRecordStore store,
    this.maxPersistedFrames = 256,
    this.maxPersistedFrameBytes = 128 * 1024,
    this.maxCommittedTombstones = 4096,
    this.maxStoredRecords = 8192,
    int maxPendingAssemblies = 8,
    int maxBufferedPlaintextBytes = 64 * 1024,
  })  : _store = store,
        _reassembler = V3LmfReassembler(
          maxPendingAssemblies: maxPendingAssemblies,
          maxBufferedPlaintextBytes: maxBufferedPlaintextBytes,
        ) {
    if (maxPersistedFrames <= 0 ||
        maxPersistedFrameBytes <= 0 ||
        maxCommittedTombstones <= 0 ||
        maxStoredRecords <= 0) {
      throw ArgumentError('Layergram v3 persistence limits must be positive');
    }
  }

  static const String inboxRecordKind = 'v3_lmf_in_v1';
  static const String committedRecordKind = 'v3_lmf_done_v1';

  final V3LmfRecordStore _store;
  final int maxPersistedFrames;
  final int maxPersistedFrameBytes;
  final int maxCommittedTombstones;
  final int maxStoredRecords;
  final V3LmfReassembler _reassembler;

  final Map<String, _PersistedFrame> _recordsByDigest =
      <String, _PersistedFrame>{};
  final Map<String, _PersistedFrame> _recordsByStorageId =
      <String, _PersistedFrame>{};
  final Map<String, Set<String>> _recordIdsByAssembly = <String, Set<String>>{};
  final Map<String, _PersistedFrame> _acceptedByAssemblyIndex =
      <String, _PersistedFrame>{};
  final Map<String, Map<int, V3LmfFrame>> _acceptedFramesByAssembly =
      <String, Map<int, V3LmfFrame>>{};
  final Map<String, V3LmfDurableDelivery> _ready =
      <String, V3LmfDurableDelivery>{};
  final Map<String, _CommittedRecord> _committed = <String, _CommittedRecord>{};

  Future<void> _operationTail = Future<void>.value();
  bool _restored = false;
  bool _closed = false;
  int _persistedFrameBytes = 0;

  int get persistedFrameCount => _recordsByStorageId.length;

  int get persistedFrameBytes => _persistedFrameBytes;

  int get committedTombstoneCount => _committed.length;

  int get readyDeliveryCount => _ready.length;

  Future<V3LmfInboxRestoreResult> restore({
    required V3LmfFrameKeyResolver keyResolver,
  }) {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 inbox was already restored');
      }
      final records = await _store.readAll();
      final relevantRecordCount = records.where((record) {
        final kind = record.payload['kind'];
        return kind == inboxRecordKind || kind == committedRecordKind;
      }).length;
      if (relevantRecordCount > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical inbox record limit exceeded',
        );
      }
      var discardedCorrupt = 0;
      var suppressedCommitted = 0;

      // Tombstones must be known before any sealed frame is replayed.
      for (final stored in records) {
        if (stored.payload['kind'] != committedRecordKind) continue;
        try {
          final committed = _decodeCommitted(stored);
          final previous = _committed[committed.assemblyId];
          if (previous == null) {
            _committed[committed.assemblyId] = committed;
          } else {
            if (!_sameCommittedTarget(previous, committed)) {
              throw const V3LmfPersistenceConflictException(
                'conflicting commit tombstones for one v3 assembly',
              );
            }
            if (committed.committedAt.isBefore(previous.committedAt)) {
              _committed[committed.assemblyId] = committed;
              await _deleteIgnoringFailure(previous.storageId);
            } else {
              await _deleteIgnoringFailure(committed.storageId);
            }
          }
        } on FormatException {
          discardedCorrupt++;
          await _deleteIgnoringFailure(stored.storageId);
        }
      }
      if (_committed.length > maxCommittedTombstones) {
        throw const V3LmfPersistenceLimitException(
          'committed tombstone limit exceeded',
        );
      }

      final pending = <_PersistedFrame>[];
      for (final stored in records) {
        if (stored.payload['kind'] != inboxRecordKind) continue;
        try {
          final frame = _decodePersistedFrame(stored);
          if (_committed.containsKey(frame.assemblyId)) {
            suppressedCommitted++;
            await _deleteIgnoringFailure(stored.storageId);
            continue;
          }
          _checkCapacityFor(frame.binary.length);
          _indexPersisted(frame);
          pending.add(frame);
        } on FormatException {
          discardedCorrupt++;
          await _deleteIgnoringFailure(stored.storageId);
        }
      }

      _restored = true;
      pending.sort((left, right) {
        final time = left.receivedAt.compareTo(right.receivedAt);
        return time != 0 ? time : left.storageId.compareTo(right.storageId);
      });
      var deferred = 0;
      final deliveries = <V3LmfDurableDelivery>[];
      for (final persisted in pending) {
        if (!_recordsByDigest.containsKey(persisted.digest)) continue;
        final key = await keyResolver(persisted.frame);
        if (key == null) {
          deferred++;
          continue;
        }
        try {
          final outcome = await _acceptPersisted(persisted, key);
          if (outcome.delivery != null &&
              !deliveries.any(
                (delivery) =>
                    delivery.assemblyId == outcome.delivery!.assemblyId,
              )) {
            deliveries.add(outcome.delivery!);
          }
        } on SecretBoxAuthenticationError {
          await _removePersisted(persisted);
        }
      }
      return V3LmfInboxRestoreResult(
        deliveries: List<V3LmfDurableDelivery>.unmodifiable(deliveries),
        deferredFrames: deferred,
        discardedCorruptRecords: discardedCorrupt,
        suppressedCommittedFrames: suppressedCommitted,
      );
    });
  }

  Future<V3LmfInboxOutcome> receive({
    required V3LmfFrame frame,
    required SecretKey secretKey,
    DateTime? receivedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final assemblyId = V3LmfFrameCodec.assemblyId(frame);
      final committed = _committed[assemblyId];
      if (committed != null) {
        return V3LmfInboxOutcome._(
          status: V3LmfInboxStatus.committedReplay,
          acknowledgement: committed.acknowledgement,
        );
      }

      final binary = V3LmfFrameCodec.encodeBinary(frame);
      final digest = _digest(binary);
      final existing = _recordsByDigest[digest];
      if (existing != null && _bytesEqual(existing.binary, binary)) {
        final accepted = _acceptedByAssemblyIndex[
            _assemblyIndexKey(assemblyId, frame.fragmentIndex)];
        if (accepted == null) {
          return _acceptPersisted(existing, secretKey);
        }
        return V3LmfInboxOutcome._(
          status: _ready.containsKey(assemblyId)
              ? V3LmfInboxStatus.complete
              : V3LmfInboxStatus.duplicate,
          acknowledgement: _currentAcknowledgement(assemblyId),
          delivery: _ready[assemblyId],
        );
      }

      _checkCapacityFor(binary.length);
      final timestamp = (receivedAt ?? DateTime.now()).toUtc();
      final payload = <String, dynamic>{
        'kind': inboxRecordKind,
        'v': 1,
        'frame': _encodeBinary(binary),
        'receivedAt': timestamp.millisecondsSinceEpoch,
      };
      final storageId = await _store.write(payload);
      _ensureOpen();
      final persisted = _PersistedFrame(
        storageId: storageId,
        frame: frame,
        binary: binary,
        digest: digest,
        assemblyId: assemblyId,
        receivedAt: timestamp,
      );
      _indexPersisted(persisted);
      try {
        return await _acceptPersisted(persisted, secretKey);
      } on SecretBoxAuthenticationError {
        await _removePersisted(persisted);
        rethrow;
      }
    });
  }

  /// Retries frames retained while their passphrase/session key was unavailable.
  Future<V3LmfInboxRestoreResult> resumeDeferred({
    required V3LmfFrameKeyResolver keyResolver,
  }) {
    return _serialized(() async {
      _ensureReady();
      var deferred = 0;
      final deliveries = <V3LmfDurableDelivery>[];
      final pending = _recordsByDigest.values.toList(growable: false);
      for (final persisted in pending) {
        if (_acceptedByAssemblyIndex.containsKey(
          _assemblyIndexKey(
            persisted.assemblyId,
            persisted.frame.fragmentIndex,
          ),
        )) {
          continue;
        }
        final key = await keyResolver(persisted.frame);
        if (key == null) {
          deferred++;
          continue;
        }
        try {
          final outcome = await _acceptPersisted(persisted, key);
          if (outcome.delivery != null &&
              !deliveries.any(
                (delivery) =>
                    delivery.assemblyId == outcome.delivery!.assemblyId,
              )) {
            deliveries.add(outcome.delivery!);
          }
        } on SecretBoxAuthenticationError {
          await _removePersisted(persisted);
        }
      }
      return V3LmfInboxRestoreResult(
        deliveries: List<V3LmfDurableDelivery>.unmodifiable(deliveries),
        deferredFrames: deferred,
        discardedCorruptRecords: 0,
        suppressedCommittedFrames: 0,
      );
    });
  }

  /// Commits a previously completed delivery by writing a replay tombstone
  /// before deleting any sealed frame records.
  Future<void> commit(
    V3LmfDurableDelivery delivery, {
    DateTime? committedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      if (_committed.containsKey(delivery.assemblyId)) return;
      final ready = _ready[delivery.assemblyId];
      if (ready == null || ready != delivery) {
        throw StateError('Layergram v3 delivery is not ready for commit');
      }
      if (_committed.length >= maxCommittedTombstones) {
        throw const V3LmfPersistenceLimitException(
          'committed tombstone limit reached',
        );
      }
      final timestamp = (committedAt ?? DateTime.now()).toUtc();
      final acknowledgement = delivery.completeAcknowledgement;
      final representative = delivery.frames.first;
      final payload = <String, dynamic>{
        'kind': committedRecordKind,
        'v': 1,
        'assemblyId': delivery.assemblyId,
        'ack': _encodeBinary(V3LmfAcknowledgementCodec.encode(acknowledgement)),
        'target': _encodeBinary(V3LmfFrameCodec.encodeBinary(representative)),
        'committedAt': timestamp.millisecondsSinceEpoch,
      };

      // Durable replay suppression is established before any cleanup.
      final storageId = await _store.write(payload);
      _ensureOpen();
      _committed[delivery.assemblyId] = _CommittedRecord(
        storageId: storageId,
        assemblyId: delivery.assemblyId,
        acknowledgement: acknowledgement,
        targetFrame: representative,
        committedAt: timestamp,
      );
      _ready.remove(delivery.assemblyId);
      await _deleteAssemblyRecords(delivery.assemblyId);
      delivery._plaintext.fillRange(0, delivery._plaintext.length, 0);
    });
  }

  /// Explicit local-retention maintenance. No remote timestamp is trusted.
  ///
  /// The caller must purge only after its durable ratchet/application replay
  /// window will independently reject every corresponding old message.
  Future<int> purgeCommittedBefore(DateTime cutoff) {
    return _serialized(() async {
      _ensureReady();
      final normalized = cutoff.toUtc();
      final entries = _committed.values
          .where(
            (entry) =>
                entry.committedAt.isBefore(normalized) ||
                entry.committedAt.isAtSameMomentAs(normalized),
          )
          .toList(growable: false);
      var removed = 0;
      for (final entry in entries) {
        await _store.delete(entry.storageId);
        _committed.remove(entry.assemblyId);
        removed++;
      }
      return removed;
    });
  }

  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      _reassembler.close();
      for (final delivery in _ready.values) {
        delivery._plaintext.fillRange(0, delivery._plaintext.length, 0);
      }
      _ready.clear();
      _acceptedFramesByAssembly.clear();
      _acceptedByAssemblyIndex.clear();
      _recordsByDigest.clear();
      _recordsByStorageId.clear();
      _recordIdsByAssembly.clear();
      _persistedFrameBytes = 0;
    });
  }

  Future<V3LmfInboxOutcome> _acceptPersisted(
    _PersistedFrame persisted,
    SecretKey secretKey,
  ) async {
    final frame = persisted.frame;
    final assemblyId = persisted.assemblyId;
    final assemblyIndex = _assemblyIndexKey(assemblyId, frame.fragmentIndex);
    final accepted = _acceptedByAssemblyIndex[assemblyIndex];
    if (accepted != null) {
      if (_bytesEqual(accepted.binary, persisted.binary)) {
        if (accepted.storageId != persisted.storageId) {
          await _removePersisted(persisted);
        }
        return V3LmfInboxOutcome._(
          status: _ready.containsKey(assemblyId)
              ? V3LmfInboxStatus.complete
              : V3LmfInboxStatus.duplicate,
          acknowledgement: _currentAcknowledgement(assemblyId),
          delivery: _ready[assemblyId],
        );
      }

      // Persist-first was already satisfied. Only an authenticated competing
      // candidate poisons the assembly; unauthenticated junk is deleted alone.
      await V3LmfAead.authenticate(frame: frame, secretKey: secretKey);
      await _poisonAssembly(assemblyId, frame);
      throw const V3LmfPersistenceConflictException(
        'authenticated competing fragment for one assembly index',
      );
    }

    late final V3LmfReassemblyOutcome outcome;
    try {
      outcome = await _reassembler.accept(
        frame: frame,
        secretKey: secretKey,
        receivedAt: persisted.receivedAt,
      );
    } on V3LmfReassemblyConflictException {
      await _poisonAssembly(assemblyId, frame);
      rethrow;
    }
    _acceptedByAssemblyIndex[assemblyIndex] = persisted;
    final acceptedFrames = _acceptedFramesByAssembly.putIfAbsent(
      assemblyId,
      () => <int, V3LmfFrame>{},
    );
    acceptedFrames[frame.fragmentIndex] = frame;

    if (!outcome.isComplete) {
      return V3LmfInboxOutcome._(
        status: outcome.status == V3LmfReassemblyStatus.duplicate
            ? V3LmfInboxStatus.duplicate
            : V3LmfInboxStatus.accepted,
        acknowledgement: _currentAcknowledgement(assemblyId),
      );
    }

    final frames = acceptedFrames.entries.toList()
      ..sort((left, right) => left.key.compareTo(right.key));
    final assembledPlaintext = outcome.plaintext!;
    outcome.wipePlaintext();
    late final V3LmfDurableDelivery delivery;
    try {
      delivery = V3LmfDurableDelivery._(
        assemblyId: assemblyId,
        plaintext: assembledPlaintext,
        frames: frames.map((entry) => entry.value).toList(growable: false),
      );
    } finally {
      assembledPlaintext.fillRange(0, assembledPlaintext.length, 0);
    }
    _ready[assemblyId] = delivery;
    return V3LmfInboxOutcome._(
      status: V3LmfInboxStatus.complete,
      acknowledgement: delivery.completeAcknowledgement,
      delivery: delivery,
    );
  }

  V3LmfAcknowledgement _currentAcknowledgement(String assemblyId) {
    final frames = _acceptedFramesByAssembly[assemblyId]?.values;
    if (frames == null || frames.isEmpty) {
      throw StateError('Layergram v3 assembly has no authenticated frames');
    }
    return V3LmfAcknowledgementCodec.forReceivedFrames(frames);
  }

  void _checkCapacityFor(int binaryLength) {
    if (_recordsByStorageId.length >= maxPersistedFrames) {
      throw const V3LmfPersistenceLimitException(
        'persisted frame count limit reached',
      );
    }
    if (_persistedFrameBytes + binaryLength > maxPersistedFrameBytes) {
      throw const V3LmfPersistenceLimitException(
        'persisted frame byte limit reached',
      );
    }
  }

  void _indexPersisted(_PersistedFrame persisted) {
    _recordsByStorageId[persisted.storageId] = persisted;
    _recordsByDigest.putIfAbsent(persisted.digest, () => persisted);
    _recordIdsByAssembly
        .putIfAbsent(persisted.assemblyId, () => <String>{})
        .add(persisted.storageId);
    _persistedFrameBytes += persisted.binary.length;
  }

  Future<void> _removePersisted(_PersistedFrame persisted) async {
    await _deleteIgnoringFailure(persisted.storageId);
    final removed = _recordsByStorageId.remove(persisted.storageId);
    if (removed != null) {
      _persistedFrameBytes -= persisted.binary.length;
    }
    final indexed = _recordsByDigest[persisted.digest];
    if (indexed?.storageId == persisted.storageId) {
      final replacement = _firstPersistedWithDigest(persisted.digest);
      if (replacement == null) {
        _recordsByDigest.remove(persisted.digest);
      } else {
        _recordsByDigest[persisted.digest] = replacement;
      }
    }
    final ids = _recordIdsByAssembly[persisted.assemblyId];
    ids?.remove(persisted.storageId);
    if (ids != null && ids.isEmpty) {
      _recordIdsByAssembly.remove(persisted.assemblyId);
    }
  }

  Future<void> _deleteAssemblyRecords(String assemblyId) async {
    final ids = _recordIdsByAssembly[assemblyId]?.toList(growable: false) ??
        const <String>[];
    for (final storageId in ids) {
      await _deleteIgnoringFailure(storageId);
    }
    final persistedRecords = _recordsByStorageId.values
        .where((record) => record.assemblyId == assemblyId)
        .toList(growable: false);
    final affectedDigests = <String>{};
    for (final persisted in persistedRecords) {
      _recordsByStorageId.remove(persisted.storageId);
      _persistedFrameBytes -= persisted.binary.length;
      affectedDigests.add(persisted.digest);
    }
    for (final digest in affectedDigests) {
      final replacement = _firstPersistedWithDigest(digest);
      if (replacement == null) {
        _recordsByDigest.remove(digest);
      } else {
        _recordsByDigest[digest] = replacement;
      }
    }
    _recordIdsByAssembly.remove(assemblyId);
    _acceptedFramesByAssembly.remove(assemblyId);
    final acceptedKeys = _acceptedByAssemblyIndex.keys
        .where((key) => key.startsWith('$assemblyId:'))
        .toList(growable: false);
    for (final key in acceptedKeys) {
      _acceptedByAssemblyIndex.remove(key);
    }
  }

  Future<void> _poisonAssembly(String assemblyId, V3LmfFrame frame) async {
    _reassembler.discardAssembly(frame);
    final ready = _ready.remove(assemblyId);
    ready?._plaintext.fillRange(0, ready._plaintext.length, 0);
    await _deleteAssemblyRecords(assemblyId);
  }

  _PersistedFrame? _firstPersistedWithDigest(String digest) {
    for (final candidate in _recordsByStorageId.values) {
      if (candidate.digest == digest) return candidate;
    }
    return null;
  }

  _PersistedFrame _decodePersistedFrame(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    if (payload['v'] != 1 || payload.length != 4) {
      throw const FormatException('Invalid persisted Layergram v3 frame');
    }
    final armored = payload['frame'];
    final receivedAt = payload['receivedAt'];
    if (armored is! String ||
        armored.length > V3LmfFrameCodec.maxTokenCharacters ||
        !_isValidEpochMilliseconds(receivedAt)) {
      throw const FormatException('Invalid persisted Layergram v3 frame');
    }
    final binary = _decodeBinary(armored, V3LmfFrameCodec.maxBinaryFrameBytes);
    final frame = V3LmfFrameCodec.decodeBinary(binary);
    if (!_bytesEqual(V3LmfFrameCodec.encodeBinary(frame), binary)) {
      throw const FormatException('Non-canonical persisted Layergram v3 frame');
    }
    return _PersistedFrame(
      storageId: stored.storageId,
      frame: frame,
      binary: binary,
      digest: _digest(binary),
      assemblyId: V3LmfFrameCodec.assemblyId(frame),
      receivedAt: DateTime.fromMillisecondsSinceEpoch(
        receivedAt as int,
        isUtc: true,
      ),
    );
  }

  _CommittedRecord _decodeCommitted(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    if (payload['v'] != 1 || payload.length != 6) {
      throw const FormatException('Invalid Layergram v3 commit tombstone');
    }
    final assemblyId = payload['assemblyId'];
    final ackArmored = payload['ack'];
    final targetArmored = payload['target'];
    final committedAt = payload['committedAt'];
    if (assemblyId is! String ||
        !_isCanonicalDigest(assemblyId) ||
        ackArmored is! String ||
        targetArmored is! String ||
        !_isValidEpochMilliseconds(committedAt)) {
      throw const FormatException('Invalid Layergram v3 commit tombstone');
    }
    final acknowledgement = V3LmfAcknowledgementCodec.decode(
      _decodeBinary(ackArmored, V3LmfAcknowledgementCodec.encodedBytes),
    );
    final targetBinary = _decodeBinary(
      targetArmored,
      V3LmfFrameCodec.maxBinaryFrameBytes,
    );
    final target = V3LmfFrameCodec.decodeBinary(targetBinary);
    if (V3LmfFrameCodec.assemblyId(target) != assemblyId ||
        !_ackMatchesFrame(acknowledgement, target) ||
        !acknowledgement.isComplete) {
      throw const FormatException('Mismatched Layergram v3 commit tombstone');
    }
    return _CommittedRecord(
      storageId: stored.storageId,
      assemblyId: assemblyId,
      acknowledgement: acknowledgement,
      targetFrame: target,
      committedAt: DateTime.fromMillisecondsSinceEpoch(
        committedAt as int,
        isUtc: true,
      ),
    );
  }

  Future<void> _deleteIgnoringFailure(String storageId) async {
    try {
      await _store.delete(storageId);
    } catch (_) {
      // The record remains sealed and will be retried/suppressed on restore.
    }
  }

  Future<T> _serialized<T>(Future<T> Function() operation) {
    final completer = Completer<T>();
    final previous = _operationTail;
    final next = previous.catchError((_) {}).then((_) async {
      if (completer.isCompleted) return;
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
    if (_closed) throw StateError('Layergram v3 inbox is closed');
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored) {
      throw StateError('Layergram v3 inbox must be restored before use');
    }
  }
}

class _PersistedFrame {
  const _PersistedFrame({
    required this.storageId,
    required this.frame,
    required this.binary,
    required this.digest,
    required this.assemblyId,
    required this.receivedAt,
  });

  final String storageId;
  final V3LmfFrame frame;
  final Uint8List binary;
  final String digest;
  final String assemblyId;
  final DateTime receivedAt;
}

class _CommittedRecord {
  const _CommittedRecord({
    required this.storageId,
    required this.assemblyId,
    required this.acknowledgement,
    required this.targetFrame,
    required this.committedAt,
  });

  final String storageId;
  final String assemblyId;
  final V3LmfAcknowledgement acknowledgement;
  final V3LmfFrame targetFrame;
  final DateTime committedAt;
}

String _assemblyIndexKey(String assemblyId, int fragmentIndex) =>
    '$assemblyId:$fragmentIndex';

String _digest(Uint8List bytes) =>
    base64UrlEncode(crypto.sha256.convert(bytes).bytes).replaceAll('=', '');

String _encodeBinary(Uint8List bytes) =>
    base64UrlEncode(bytes).replaceAll('=', '');

Uint8List _decodeBinary(String armored, int maxBytes) {
  if (armored.isEmpty || armored.length > ((maxBytes * 4 + 2) ~/ 3)) {
    throw const FormatException('Invalid persisted binary length');
  }
  for (final codeUnit in armored.codeUnits) {
    final upper = codeUnit >= 0x41 && codeUnit <= 0x5a;
    final lower = codeUnit >= 0x61 && codeUnit <= 0x7a;
    final digit = codeUnit >= 0x30 && codeUnit <= 0x39;
    if (!upper && !lower && !digit && codeUnit != 0x2d && codeUnit != 0x5f) {
      throw const FormatException('Invalid persisted binary armor');
    }
  }
  late final Uint8List bytes;
  try {
    bytes = Uint8List.fromList(base64Url.decode(base64Url.normalize(armored)));
  } on FormatException {
    throw const FormatException('Invalid persisted binary armor');
  }
  if (bytes.length > maxBytes || _encodeBinary(bytes) != armored) {
    throw const FormatException('Non-canonical persisted binary armor');
  }
  return bytes;
}

bool _isCanonicalDigest(String value) {
  if (value.length != 43) return false;
  try {
    return _encodeBinary(_decodeBinary(value, 32)) == value;
  } on FormatException {
    return false;
  }
}

bool _isValidEpochMilliseconds(Object? value) =>
    value is int && value >= 0 && value <= 8640000000000000;

bool _ackMatchesFrame(V3LmfAcknowledgement ack, V3LmfFrame frame) {
  final metadata = frame.metadata;
  return ack.targetSuite == metadata.suite &&
      ack.targetKind == metadata.kind &&
      ack.targetEpoch == metadata.epoch &&
      ack.targetMessageCounter == metadata.messageCounter &&
      ack.targetAssembledPlaintextLength == frame.assembledPlaintextLength &&
      ack.targetFragmentCount == frame.fragmentCount &&
      _bytesEqual(ack.targetMessageId, metadata.messageId);
}

bool _sameCommittedTarget(_CommittedRecord left, _CommittedRecord right) {
  return _bytesEqual(
        V3LmfAcknowledgementCodec.encode(left.acknowledgement),
        V3LmfAcknowledgementCodec.encode(right.acknowledgement),
      ) &&
      _bytesEqual(
        V3LmfFrameCodec.encodeBinary(left.targetFrame),
        V3LmfFrameCodec.encodeBinary(right.targetFrame),
      );
}

bool _bytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
