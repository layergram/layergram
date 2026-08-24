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

/// Minimal persistence seam used by v3 transport state.
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
typedef V3LmfFrameAuthenticationFailureHandler = FutureOr<void> Function(
  V3LmfFrame frame,
);

enum V3LmfInboxStatus {
  accepted,
  deferred,
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

/// Result of durably retaining a frame before its key is available.
class V3LmfDeferredInboxOutcome {
  const V3LmfDeferredInboxOutcome({
    required this.status,
    this.acknowledgement,
    this.delivery,
  });

  final V3LmfInboxStatus status;
  final V3LmfAcknowledgement? acknowledgement;
  final V3LmfDurableDelivery? delivery;
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

/// Durable proof that a full inbox tombstone was retired into the compact
/// replay window only after its application record and ratchet checkpoint
/// became independently durable.
final class V3LmfReplayWindowBinding {
  const V3LmfReplayWindowBinding._({
    required this.assemblyId,
    required this.higherLevelCommitDigest,
    required this.stableRecordId,
    required this.sessionKey,
    required this.ratchetRevision,
    required this.checkpointDigest,
    required this.committedAt,
  });

  final String assemblyId;
  final String higherLevelCommitDigest;
  final String stableRecordId;
  final String sessionKey;
  final int ratchetRevision;
  final String checkpointDigest;
  final DateTime committedAt;
}

/// Unforgeable authority used by the atomic journal to retire an exact compact
/// replay-window proof after a self-contained checkpoint finalization exists.
final class V3LmfReplayWindowRetirementAuthority {
  const V3LmfReplayWindowRetirementAuthority._();
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
  static const String replayWindowRecordKind = 'v3_lmf_replay_v1';

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
  bool _atomicCommitJournalAttached = false;
  Object? _atomicCommitJournalOwner;
  V3LmfReplayWindowRetirementAuthority? _replayRetirementAuthority;
  int _persistedFrameBytes = 0;

  int get persistedFrameCount => _recordsByStorageId.length;

  int get persistedFrameBytes => _persistedFrameBytes;

  int get committedTombstoneCount => _committed.length;

  /// Higher-level atomic effect binding for every committed assembly.
  ///
  /// A null value represents a transport-only tombstone created without the
  /// atomic application/ratchet journal. The getter is available only
  /// after restore so the journal can fail closed on missing or mismatched
  /// cross-record state.
  Map<String, String?> get committedHigherLevelBindings {
    _ensureReady();
    return Map<String, String?>.unmodifiable(
      _committed.map(
        (assemblyId, record) =>
            MapEntry(assemblyId, record.higherLevelCommitDigest),
      ),
    );
  }

  /// Replay-window entries that already replaced their full commit tombstone.
  ///
  /// The returned proof is immutable and contains no message plaintext. The
  /// atomic journal uses it to distinguish a safely compacted binding from a
  /// missing effect/tombstone pair after restart.
  Map<String, V3LmfReplayWindowBinding> get replayWindowBindings {
    _ensureReady();
    final bindings = <String, V3LmfReplayWindowBinding>{};
    for (final MapEntry(key: assemblyId, value: record) in _committed.entries) {
      if (!record.isReplayWindow) continue;
      bindings[assemblyId] = V3LmfReplayWindowBinding._(
        assemblyId: assemblyId,
        higherLevelCommitDigest: record.higherLevelCommitDigest!,
        stableRecordId: record.stableRecordId!,
        sessionKey: record.sessionKey!,
        ratchetRevision: record.ratchetRevision!,
        checkpointDigest: record.checkpointDigest!,
        committedAt: record.committedAt,
      );
    }
    return Map<String, V3LmfReplayWindowBinding>.unmodifiable(bindings);
  }

  int get readyDeliveryCount => _ready.length;

  /// Returns the durable replay result before a higher-level resolver spends
  /// work or creates a non-authoritative ratchet candidate for this frame.
  Future<V3LmfDeferredInboxOutcome?> committedReplayFor(V3LmfFrame frame) {
    return _serialized(() async {
      _ensureReady();
      final committed = _committed[V3LmfFrameCodec.assemblyId(frame)];
      if (committed == null) return null;
      return V3LmfDeferredInboxOutcome(
        status: V3LmfInboxStatus.committedReplay,
        acknowledgement: committed.acknowledgement,
      );
    });
  }

  /// Ensures a first fragment can be persisted before the ratchet resolver
  /// derives a candidate. The owning persistence scope serializes this call
  /// with the subsequent [receive], so the capacity cannot be consumed by a
  /// sibling receive in between.
  Future<void> preflightAuthenticatedReceive(V3LmfFrame frame) {
    return _serialized(() async {
      _ensureReady();
      final assemblyId = V3LmfFrameCodec.assemblyId(frame);
      if (_committed.containsKey(assemblyId)) return;
      final binary = V3LmfFrameCodec.encodeBinary(frame);
      final existing = _recordsByDigest[_digest(binary)];
      if (existing != null && _bytesEqual(existing.binary, binary)) return;
      await _makeCapacityFor(
        binary.length,
        exceptAssemblyId: assemblyId,
      );
    });
  }

  /// Makes higher-level digest binding mandatory for this inbox lifetime.
  ///
  /// The atomic journal calls this during restore. It prevents an
  /// older transport-only commit path from racing or running after the journal
  /// has taken responsibility for application/ratchet durability.
  Future<V3LmfReplayWindowRetirementAuthority> attachAtomicCommitJournal({
    required Object owner,
  }) {
    return _serialized(() async {
      _ensureReady();
      if (_atomicCommitJournalAttached) {
        throw StateError(
          'Layergram v3 inbox already has an atomic commit journal',
        );
      }
      _atomicCommitJournalAttached = true;
      _atomicCommitJournalOwner = owner;
      final authority = V3LmfReplayWindowRetirementAuthority._();
      _replayRetirementAuthority = authority;
      return authority;
    });
  }

  /// Releases the exact journal attachment when its owner is closed, allowing
  /// an explicitly reconstructed journal to recover on the same inbox.
  Future<void> detachAtomicCommitJournal({
    required Object owner,
    required V3LmfReplayWindowRetirementAuthority authority,
  }) {
    return _serialized(() async {
      if (!_restored) {
        throw StateError('Layergram v3 inbox must be restored before detach');
      }
      if (!_atomicCommitJournalAttached ||
          !identical(_atomicCommitJournalOwner, owner) ||
          !identical(_replayRetirementAuthority, authority)) {
        throw StateError(
          'Layergram v3 inbox atomic journal attachment diverged',
        );
      }
      _atomicCommitJournalAttached = false;
      _atomicCommitJournalOwner = null;
      _replayRetirementAuthority = null;
    });
  }

  Future<V3LmfInboxRestoreResult> restore({
    required V3LmfFrameKeyResolver keyResolver,
    V3LmfFrameAuthenticationFailureHandler? onAuthenticationFailure,
  }) {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 inbox was already restored');
      }
      final records = await _store.readAll();
      final relevantRecordCount = records.where((record) {
        final kind = record.payload['kind'];
        return kind == inboxRecordKind ||
            kind == committedRecordKind ||
            kind == replayWindowRecordKind;
      }).length;
      if (relevantRecordCount > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical inbox record limit exceeded',
        );
      }
      var discardedCorrupt = 0;
      var suppressedCommitted = 0;

      // Tombstones and their compact replay-window replacements must be known
      // before any sealed frame is replayed.
      for (final stored in records) {
        final kind = stored.payload['kind'];
        if (kind != committedRecordKind && kind != replayWindowRecordKind) {
          continue;
        }
        try {
          final committed = kind == committedRecordKind
              ? _decodeCommitted(stored)
              : _decodeReplayWindow(stored);
          final previous = _committed[committed.assemblyId];
          if (previous == null) {
            _committed[committed.assemblyId] = committed;
          } else {
            if (!_sameCommittedTarget(previous, committed)) {
              throw const V3LmfPersistenceConflictException(
                'conflicting commit tombstones for one v3 assembly',
              );
            }
            if (previous.isReplayWindow &&
                committed.isReplayWindow &&
                !_sameReplayProof(previous, committed)) {
              throw const V3LmfPersistenceConflictException(
                'conflicting replay-window proofs for one v3 assembly',
              );
            }
            final preferCommitted =
                committed.isReplayWindow && !previous.isReplayWindow ||
                    committed.isReplayWindow == previous.isReplayWindow &&
                        committed.committedAt.isBefore(previous.committedAt);
            if (preferCommitted) {
              _committed[committed.assemblyId] = committed;
              await _deleteIgnoringFailure(previous.storageId);
            } else {
              await _deleteIgnoringFailure(committed.storageId);
            }
          }
        } on FormatException {
          if (kind == replayWindowRecordKind) {
            // Once its journal effect is collected this record is the sole
            // transport replay barrier. Corruption must fail closed and must
            // never be converted into silent replay eligibility.
            rethrow;
          }
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
          await onAuthenticationFailure?.call(persisted.frame);
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
    V3LmfFrameAuthenticationFailureHandler? onAuthenticationFailure,
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
          try {
            return await _acceptPersisted(existing, secretKey);
          } on SecretBoxAuthenticationError {
            await _removePersisted(existing);
            await onAuthenticationFailure?.call(existing.frame);
            rethrow;
          }
        }
        return V3LmfInboxOutcome._(
          status: _ready.containsKey(assemblyId)
              ? V3LmfInboxStatus.complete
              : V3LmfInboxStatus.duplicate,
          acknowledgement: _currentAcknowledgement(assemblyId),
          delivery: _ready[assemblyId],
        );
      }

      await _makeCapacityFor(
        binary.length,
        exceptAssemblyId: assemblyId,
      );
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
        await onAuthenticationFailure?.call(persisted.frame);
        rethrow;
      }
    });
  }

  /// Persists one still-sealed frame while its exact session key is unavailable.
  ///
  /// This permits a continuation fragment to arrive before fragment zero. It
  /// is authenticated only after [resumeDeferred] resolves the matching key.
  Future<V3LmfDeferredInboxOutcome> persistDeferred({
    required V3LmfFrame frame,
    DateTime? receivedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final assemblyId = V3LmfFrameCodec.assemblyId(frame);
      final committed = _committed[assemblyId];
      if (committed != null) {
        return V3LmfDeferredInboxOutcome(
          status: V3LmfInboxStatus.committedReplay,
          acknowledgement: committed.acknowledgement,
        );
      }

      final binary = V3LmfFrameCodec.encodeBinary(frame);
      final digest = _digest(binary);
      final existing = _recordsByDigest[digest];
      if (existing != null && _bytesEqual(existing.binary, binary)) {
        final hasAuthenticatedFrames =
            _acceptedFramesByAssembly[assemblyId]?.isNotEmpty ?? false;
        return V3LmfDeferredInboxOutcome(
          status: _ready.containsKey(assemblyId)
              ? V3LmfInboxStatus.complete
              : V3LmfInboxStatus.duplicate,
          acknowledgement: hasAuthenticatedFrames
              ? _currentAcknowledgement(assemblyId)
              : null,
          delivery: _ready[assemblyId],
        );
      }

      await _makeCapacityFor(
        binary.length,
        exceptAssemblyId: assemblyId,
      );
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
      return const V3LmfDeferredInboxOutcome(
        status: V3LmfInboxStatus.deferred,
      );
    });
  }

  /// Retries frames retained while their passphrase/session key was unavailable.
  Future<V3LmfInboxRestoreResult> resumeDeferred({
    required V3LmfFrameKeyResolver keyResolver,
    String? onlyAssemblyId,
    V3LmfFrameAuthenticationFailureHandler? onAuthenticationFailure,
  }) {
    return _serialized(() async {
      _ensureReady();
      var deferred = 0;
      var discarded = 0;
      final deliveries = <V3LmfDurableDelivery>[];
      final pending = _recordsByDigest.values.toList(growable: false)
        ..sort((left, right) {
          final time = left.receivedAt.compareTo(right.receivedAt);
          return time != 0 ? time : left.storageId.compareTo(right.storageId);
        });
      for (final persisted in pending) {
        if (onlyAssemblyId != null && persisted.assemblyId != onlyAssemblyId) {
          continue;
        }
        if (_acceptedByAssemblyIndex.containsKey(
          _assemblyIndexKey(
            persisted.assemblyId,
            persisted.frame.fragmentIndex,
          ),
        )) {
          continue;
        }
        try {
          final key = await keyResolver(persisted.frame);
          if (key == null) {
            deferred++;
            continue;
          }
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
          await onAuthenticationFailure?.call(persisted.frame);
          discarded++;
        } on FormatException {
          await _removePersisted(persisted);
          await onAuthenticationFailure?.call(persisted.frame);
          discarded++;
        } on ArgumentError {
          await _removePersisted(persisted);
          await onAuthenticationFailure?.call(persisted.frame);
          discarded++;
        }
      }
      return V3LmfInboxRestoreResult(
        deliveries: List<V3LmfDurableDelivery>.unmodifiable(deliveries),
        deferredFrames: deferred,
        discardedCorruptRecords: discarded,
        suppressedCommittedFrames: 0,
      );
    });
  }

  /// Commits a previously completed delivery by writing a replay tombstone
  /// before deleting any sealed frame records.
  Future<void> commit(
    V3LmfDurableDelivery delivery, {
    DateTime? committedAt,
    String? higherLevelCommitDigest,
  }) {
    return _serialized(() async {
      _ensureReady();
      if (higherLevelCommitDigest != null &&
          !_isCanonicalDigest(higherLevelCommitDigest)) {
        throw ArgumentError.value(
          higherLevelCommitDigest,
          'higherLevelCommitDigest',
          'must be a canonical 32-byte digest',
        );
      }
      if (_atomicCommitJournalAttached && higherLevelCommitDigest == null) {
        throw const V3LmfPersistenceConflictException(
          'transport-only commit is forbidden after the v3 atomic journal '
          'is attached',
        );
      }
      final existingCommit = _committed[delivery.assemblyId];
      if (existingCommit != null) {
        if (existingCommit.higherLevelCommitDigest != higherLevelCommitDigest) {
          throw const V3LmfPersistenceConflictException(
            'higher-level effect does not match the v3 commit tombstone',
          );
        }
        return;
      }
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
        'v': 2,
        'assemblyId': delivery.assemblyId,
        'ack': _encodeBinary(V3LmfAcknowledgementCodec.encode(acknowledgement)),
        'target': _encodeBinary(V3LmfFrameCodec.encodeBinary(representative)),
        'higherLevelCommitDigest': higherLevelCommitDigest,
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
        higherLevelCommitDigest: higherLevelCommitDigest,
        committedAt: timestamp,
      );
      _ready.remove(delivery.assemblyId);
      await _deleteAssemblyRecords(delivery.assemblyId);
      delivery._plaintext.fillRange(0, delivery._plaintext.length, 0);
    });
  }

  /// Replaces a full commit tombstone with a compact replay-window proof.
  ///
  /// The replacement is written before the tombstone is deleted. Callers must
  /// first verify the exact higher-level effect is materialized and covered by
  /// [checkpointDigest]. Repeating the exact operation is idempotent; any
  /// divergent proof for the same assembly fails closed.
  Future<V3LmfReplayWindowBinding> retireCommittedToReplayWindow({
    required String assemblyId,
    required String higherLevelCommitDigest,
    required String stableRecordId,
    required String sessionKey,
    required int ratchetRevision,
    required String checkpointDigest,
  }) {
    return _serialized(() async {
      _ensureReady();
      if (!_isCanonicalDigest(assemblyId) ||
          !_isCanonicalDigest(higherLevelCommitDigest) ||
          stableRecordId != 'v3:$assemblyId' ||
          !_isCanonicalSessionKey(sessionKey) ||
          ratchetRevision <= 0 ||
          ratchetRevision > 0x7fffffffffffffff ||
          !_isCanonicalDigest(checkpointDigest)) {
        throw const FormatException(
          'Invalid Layergram v3 replay-window proof',
        );
      }
      final existing = _committed[assemblyId];
      if (existing == null ||
          existing.higherLevelCommitDigest != higherLevelCommitDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 replay-window retirement has no matching commit tombstone',
        );
      }
      if (existing.isReplayWindow) {
        if (existing.stableRecordId != stableRecordId ||
            existing.sessionKey != sessionKey ||
            existing.ratchetRevision != ratchetRevision ||
            existing.checkpointDigest != checkpointDigest) {
          throw const V3LmfPersistenceConflictException(
            'v3 replay-window retirement proof diverged',
          );
        }
        return _replayBinding(existing);
      }

      final payload = <String, dynamic>{
        'kind': replayWindowRecordKind,
        'v': 1,
        'assemblyId': assemblyId,
        'ack': _encodeBinary(
          V3LmfAcknowledgementCodec.encode(existing.acknowledgement),
        ),
        'target': _encodeBinary(
          V3LmfFrameCodec.encodeBinary(existing.targetFrame),
        ),
        'higherLevelCommitDigest': higherLevelCommitDigest,
        'stableRecordId': stableRecordId,
        'sessionId': sessionKey,
        'ratchetRevision': ratchetRevision,
        'checkpointDigest': checkpointDigest,
        'committedAt': existing.committedAt.millisecondsSinceEpoch,
        'reserved': 0,
      };
      final storageId = await _store.write(payload);
      _ensureOpen();
      final compacted = _CommittedRecord(
        storageId: storageId,
        assemblyId: assemblyId,
        acknowledgement: existing.acknowledgement,
        targetFrame: existing.targetFrame,
        higherLevelCommitDigest: higherLevelCommitDigest,
        committedAt: existing.committedAt,
        stableRecordId: stableRecordId,
        sessionKey: sessionKey,
        ratchetRevision: ratchetRevision,
        checkpointDigest: checkpointDigest,
      );
      _committed[assemblyId] = compacted;
      await _deleteIgnoringFailure(existing.storageId);
      return _replayBinding(compacted);
    });
  }

  /// Deletes only the exact compact proof authorized by the attached atomic
  /// journal. Absence is idempotent for crash recovery; a full tombstone or a
  /// divergent binding always fails closed.
  Future<bool> deleteReplayWindowProof({
    required String assemblyId,
    required String higherLevelCommitDigest,
    required String stableRecordId,
    required String sessionKey,
    required int ratchetRevision,
    required DateTime committedAt,
    required V3LmfReplayWindowRetirementAuthority authority,
  }) {
    return _serialized(() async {
      _ensureReady();
      if (!_atomicCommitJournalAttached ||
          !identical(_replayRetirementAuthority, authority)) {
        throw StateError(
          'Layergram v3 replay retirement is owned by the atomic journal',
        );
      }
      if (!_isCanonicalDigest(assemblyId) ||
          !_isCanonicalDigest(higherLevelCommitDigest) ||
          stableRecordId != 'v3:$assemblyId' ||
          !_isCanonicalSessionKey(sessionKey) ||
          ratchetRevision <= 0 ||
          ratchetRevision > 0x7fffffffffffffff) {
        throw const FormatException(
          'Invalid Layergram v3 replay-window deletion binding',
        );
      }
      final timestamp = committedAt.toUtc();
      if (!_isValidEpochMilliseconds(timestamp.millisecondsSinceEpoch)) {
        throw const FormatException(
          'Invalid Layergram v3 replay-window deletion timestamp',
        );
      }
      final existing = _committed[assemblyId];
      if (existing == null) return false;
      if (!existing.isReplayWindow ||
          existing.higherLevelCommitDigest != higherLevelCommitDigest ||
          existing.stableRecordId != stableRecordId ||
          existing.sessionKey != sessionKey ||
          existing.ratchetRevision != ratchetRevision ||
          existing.committedAt.millisecondsSinceEpoch !=
              timestamp.millisecondsSinceEpoch) {
        throw const V3LmfPersistenceConflictException(
          'v3 replay-window deletion proof diverged',
        );
      }
      await _store.delete(existing.storageId);
      _committed.remove(assemblyId);
      return true;
    });
  }

  /// Explicit local-retention maintenance. No remote timestamp is trusted.
  ///
  /// This legacy maintenance path removes only unbound transport tombstones.
  /// Higher-level-bound tombstones and compact replay-window records are never
  /// eligible here; their eventual expiry requires the future skipped-key
  /// retirement policy.
  Future<int> purgeCommittedBefore(DateTime cutoff) {
    return _serialized(() async {
      _ensureReady();
      if (_atomicCommitJournalAttached) {
        throw StateError(
          'Layergram v3 replay retention is owned by the session coordinator',
        );
      }
      final normalized = cutoff.toUtc();
      final entries = _committed.values
          .where(
            (entry) =>
                entry.higherLevelCommitDigest == null &&
                (entry.committedAt.isBefore(normalized) ||
                    entry.committedAt.isAtSameMomentAs(normalized)),
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

  Future<void> _makeCapacityFor(
    int binaryLength, {
    required String exceptAssemblyId,
  }) async {
    while (_recordsByStorageId.length >= maxPersistedFrames ||
        _persistedFrameBytes + binaryLength > maxPersistedFrameBytes) {
      if (!await _evictOldestDeferredAssembly(
        exceptAssemblyId: exceptAssemblyId,
      )) {
        _checkCapacityFor(binaryLength);
      }
    }
  }

  Future<bool> _evictOldestDeferredAssembly({
    required String exceptAssemblyId,
  }) async {
    String? oldestAssemblyId;
    _PersistedFrame? oldestFrame;
    for (final entry in _recordIdsByAssembly.entries) {
      final assemblyId = entry.key;
      if (assemblyId == exceptAssemblyId ||
          _ready.containsKey(assemblyId) ||
          (_acceptedFramesByAssembly[assemblyId]?.isNotEmpty ?? false)) {
        continue;
      }
      for (final storageId in entry.value) {
        final candidate = _recordsByStorageId[storageId];
        if (candidate == null) continue;
        final isOlder = oldestFrame == null ||
            candidate.receivedAt.isBefore(oldestFrame.receivedAt) ||
            candidate.receivedAt == oldestFrame.receivedAt &&
                candidate.storageId.compareTo(oldestFrame.storageId) < 0;
        if (isOlder) {
          oldestAssemblyId = assemblyId;
          oldestFrame = candidate;
        }
      }
    }
    if (oldestAssemblyId == null) return false;
    await _deleteAssemblyRecords(oldestAssemblyId);
    return true;
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
    final version = payload['v'];
    if ((version != 1 && version != 2) ||
        (version == 1 && payload.length != 6) ||
        (version == 2 && payload.length != 7)) {
      throw const FormatException('Invalid Layergram v3 commit tombstone');
    }
    final assemblyId = payload['assemblyId'];
    final ackArmored = payload['ack'];
    final targetArmored = payload['target'];
    final higherLevelCommitDigest =
        version == 2 ? payload['higherLevelCommitDigest'] : null;
    final committedAt = payload['committedAt'];
    if (assemblyId is! String ||
        !_isCanonicalDigest(assemblyId) ||
        ackArmored is! String ||
        targetArmored is! String ||
        (higherLevelCommitDigest != null &&
            (higherLevelCommitDigest is! String ||
                !_isCanonicalDigest(higherLevelCommitDigest))) ||
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
      higherLevelCommitDigest: higherLevelCommitDigest as String?,
      committedAt: DateTime.fromMillisecondsSinceEpoch(
        committedAt as int,
        isUtc: true,
      ),
    );
  }

  _CommittedRecord _decodeReplayWindow(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    const expectedKeys = <String>{
      'kind',
      'v',
      'assemblyId',
      'ack',
      'target',
      'higherLevelCommitDigest',
      'stableRecordId',
      'sessionId',
      'ratchetRevision',
      'checkpointDigest',
      'committedAt',
      'reserved',
    };
    if (payload.length != expectedKeys.length ||
        !payload.keys.every(expectedKeys.contains) ||
        payload['kind'] != replayWindowRecordKind ||
        payload['v'] != 1 ||
        payload['reserved'] != 0) {
      throw const FormatException('Invalid Layergram v3 replay-window record');
    }
    final assemblyId = payload['assemblyId'];
    final ackArmored = payload['ack'];
    final targetArmored = payload['target'];
    final higherLevelCommitDigest = payload['higherLevelCommitDigest'];
    final stableRecordId = payload['stableRecordId'];
    final sessionKey = payload['sessionId'];
    final ratchetRevision = payload['ratchetRevision'];
    final checkpointDigest = payload['checkpointDigest'];
    final committedAt = payload['committedAt'];
    if (assemblyId is! String ||
        !_isCanonicalDigest(assemblyId) ||
        ackArmored is! String ||
        targetArmored is! String ||
        higherLevelCommitDigest is! String ||
        !_isCanonicalDigest(higherLevelCommitDigest) ||
        stableRecordId != 'v3:$assemblyId' ||
        sessionKey is! String ||
        !_isCanonicalSessionKey(sessionKey) ||
        ratchetRevision is! int ||
        ratchetRevision <= 0 ||
        ratchetRevision > 0x7fffffffffffffff ||
        checkpointDigest is! String ||
        !_isCanonicalDigest(checkpointDigest) ||
        !_isValidEpochMilliseconds(committedAt)) {
      throw const FormatException('Invalid Layergram v3 replay-window proof');
    }
    final acknowledgement = V3LmfAcknowledgementCodec.decode(
      _decodeBinary(ackArmored, V3LmfAcknowledgementCodec.encodedBytes),
    );
    final target = V3LmfFrameCodec.decodeBinary(
      _decodeBinary(targetArmored, V3LmfFrameCodec.maxBinaryFrameBytes),
    );
    if (V3LmfFrameCodec.assemblyId(target) != assemblyId ||
        !_ackMatchesFrame(acknowledgement, target) ||
        !acknowledgement.isComplete) {
      throw const FormatException('Mismatched Layergram v3 replay window');
    }
    return _CommittedRecord(
      storageId: stored.storageId,
      assemblyId: assemblyId,
      acknowledgement: acknowledgement,
      targetFrame: target,
      higherLevelCommitDigest: higherLevelCommitDigest,
      committedAt: DateTime.fromMillisecondsSinceEpoch(
        committedAt as int,
        isUtc: true,
      ),
      stableRecordId: stableRecordId as String,
      sessionKey: sessionKey,
      ratchetRevision: ratchetRevision,
      checkpointDigest: checkpointDigest,
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
    required this.higherLevelCommitDigest,
    required this.committedAt,
    this.stableRecordId,
    this.sessionKey,
    this.ratchetRevision,
    this.checkpointDigest,
  });

  final String storageId;
  final String assemblyId;
  final V3LmfAcknowledgement acknowledgement;
  final V3LmfFrame targetFrame;
  final String? higherLevelCommitDigest;
  final DateTime committedAt;
  final String? stableRecordId;
  final String? sessionKey;
  final int? ratchetRevision;
  final String? checkpointDigest;

  bool get isReplayWindow => checkpointDigest != null;
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

bool _isCanonicalSessionKey(String value) {
  Uint8List? decoded;
  try {
    decoded = _decodeBinary(value, 16);
    return decoded.length == 16;
  } on FormatException {
    return false;
  } finally {
    if (decoded != null) decoded.fillRange(0, decoded.length, 0);
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
  return left.higherLevelCommitDigest == right.higherLevelCommitDigest &&
      _bytesEqual(
        V3LmfAcknowledgementCodec.encode(left.acknowledgement),
        V3LmfAcknowledgementCodec.encode(right.acknowledgement),
      ) &&
      _bytesEqual(
        V3LmfFrameCodec.encodeBinary(left.targetFrame),
        V3LmfFrameCodec.encodeBinary(right.targetFrame),
      );
}

bool _sameReplayProof(_CommittedRecord left, _CommittedRecord right) {
  return left.stableRecordId == right.stableRecordId &&
      left.sessionKey == right.sessionKey &&
      left.ratchetRevision == right.ratchetRevision &&
      left.checkpointDigest == right.checkpointDigest;
}

V3LmfReplayWindowBinding _replayBinding(_CommittedRecord record) {
  if (!record.isReplayWindow || record.higherLevelCommitDigest == null) {
    throw StateError('Layergram v3 record is not a replay-window proof');
  }
  return V3LmfReplayWindowBinding._(
    assemblyId: record.assemblyId,
    higherLevelCommitDigest: record.higherLevelCommitDigest!,
    stableRecordId: record.stableRecordId!,
    sessionKey: record.sessionKey!,
    ratchetRevision: record.ratchetRevision!,
    checkpointDigest: record.checkpointDigest!,
    committedAt: record.committedAt,
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
