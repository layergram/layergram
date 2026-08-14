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

import 'lmf_v3.dart';
import 'lmf_v3_persistence.dart';

/// Builds one higher-level effect from a complete authenticated delivery.
///
/// The builder is invoked only when no effect for the delivery is already
/// durable. The plaintext passed to it is a temporary copy that is wiped when
/// the builder returns or throws.
typedef V3LmfAtomicEffectBuilder = FutureOr<V3LmfAtomicEffect> Function(
  Uint8List plaintext,
);

/// Opaque higher-level state that must become durable as one unit.
///
/// [applicationState] is the canonical inactive `AR3` application/control
/// record. [ratchetState] is the matching complete inactive `TR3` Triple
/// Ratchet snapshot. This layer establishes their crash-consistent commit
/// boundary; the real handshake and ratchet transition engines remain gated.
class V3LmfAtomicEffect {
  factory V3LmfAtomicEffect({
    required Uint8List applicationState,
    required Uint8List ratchetState,
    int applicationStateVersion = 1,
    int ratchetStateVersion = 1,
  }) {
    _validateVersion(applicationStateVersion, 'applicationStateVersion');
    _validateVersion(ratchetStateVersion, 'ratchetStateVersion');
    if (ratchetState.isEmpty) {
      throw ArgumentError.value(
        ratchetState,
        'ratchetState',
        'a complete ratchet snapshot is required',
      );
    }
    return V3LmfAtomicEffect._(
      applicationState: Uint8List.fromList(applicationState),
      ratchetState: Uint8List.fromList(ratchetState),
      applicationStateVersion: applicationStateVersion,
      ratchetStateVersion: ratchetStateVersion,
    );
  }

  const V3LmfAtomicEffect._({
    required Uint8List applicationState,
    required Uint8List ratchetState,
    required this.applicationStateVersion,
    required this.ratchetStateVersion,
  })  : _applicationState = applicationState,
        _ratchetState = ratchetState;

  final Uint8List _applicationState;
  final Uint8List _ratchetState;
  final int applicationStateVersion;
  final int ratchetStateVersion;

  Uint8List get applicationState => Uint8List.fromList(_applicationState);

  Uint8List get ratchetState => Uint8List.fromList(_ratchetState);

  void _wipe() {
    _applicationState.fillRange(0, _applicationState.length, 0);
    _ratchetState.fillRange(0, _ratchetState.length, 0);
  }
}

/// One durable application/ratchet effect keyed by the LMF assembly ID.
///
/// The contained byte arrays are copied on construction and access. The
/// stable [messageRecordId] can be used by the future application repository
/// instead of allocating a new ID during replay.
class V3LmfCommittedEffect {
  V3LmfCommittedEffect._({
    required this.storageId,
    required this.assemblyId,
    required this.deliveryDigest,
    required this.effectDigest,
    required this.targetFrame,
    required Uint8List applicationState,
    required Uint8List ratchetState,
    required this.applicationStateVersion,
    required this.ratchetStateVersion,
    required this.persistedAt,
  })  : _applicationState = Uint8List.fromList(applicationState),
        _ratchetState = Uint8List.fromList(ratchetState);

  final String storageId;
  final String assemblyId;
  final String deliveryDigest;
  final String effectDigest;
  final V3LmfFrame targetFrame;
  final Uint8List _applicationState;
  final Uint8List _ratchetState;
  final int applicationStateVersion;
  final int ratchetStateVersion;
  final DateTime persistedAt;

  String get messageRecordId => 'v3:$assemblyId';

  Uint8List get applicationState => Uint8List.fromList(_applicationState);

  Uint8List get ratchetState => Uint8List.fromList(_ratchetState);

  int get stateBytes => _applicationState.length + _ratchetState.length;

  void _wipe() {
    _applicationState.fillRange(0, _applicationState.length, 0);
    _ratchetState.fillRange(0, _ratchetState.length, 0);
  }
}

class V3LmfAtomicCommitRestoreResult {
  const V3LmfAtomicCommitRestoreResult({
    required this.effects,
    required this.removedExactDuplicates,
    required this.pendingInboxCommitAssemblyIds,
    this.replayWindowBindings = const <String, V3LmfReplayWindowBinding>{},
  });

  final List<V3LmfCommittedEffect> effects;
  final int removedExactDuplicates;
  final Set<String> pendingInboxCommitAssemblyIds;
  final Map<String, V3LmfReplayWindowBinding> replayWindowBindings;
}

/// Unforgeable ownership token for the inactive v3 session coordinator.
///
/// A coordinator claims the journal before restore. From that point on direct
/// lifecycle or commit calls are rejected unless they present this exact
/// token. This keeps one serialized authority above a journal while preserving
/// the lower-level journal API for isolated tests and pre-controller research
/// callers.
final class V3LmfAtomicCommitAuthority {
  const V3LmfAtomicCommitAuthority._();
}

/// Inactive crash-consistent commit boundary above [V3LmfDurableInbox].
///
/// The single encrypted journal record contains both the future application
/// effect and its matching future ratchet snapshot. That record is the commit
/// point: only after it is durable may a caller expose the effect. The inbox
/// replay tombstone is written second.
///
/// Crash behavior:
///
/// * before the effect write: the sealed delivery is redelivered;
/// * after the effect write but before the inbox tombstone: restore finds the
///   effect, the builder is not rerun, and [resume] finishes the tombstone;
/// * after the tombstone: the effect remains the durable source of truth while
///   inbox replay is suppressed.
///
/// This journal does not implement Triple Ratchet transitions. It also cannot
/// make external side effects atomic: future integration must read application
/// state from this journal or materialize it idempotently using
/// [V3LmfCommittedEffect.messageRecordId].
///
/// The inbox must be restored before this journal. If an effect-store write
/// returns an error after its durable outcome has become ambiguous, the current
/// journal instance fails stopped. The caller must construct and restore a new
/// journal before retrying, so the builder cannot run twice for a record that
/// may already be durable.
class V3LmfAtomicCommitJournal {
  V3LmfAtomicCommitJournal({
    required V3LmfRecordStore store,
    required V3LmfDurableInbox inbox,
    this.maxCommittedEffects = 4096,
    this.maxApplicationStateBytes =
        V3LmfFrameCodec.maxAssembledPlaintextBytes + 1024,
    this.maxRatchetStateBytes = 256 * 1024,
    this.maxTotalStateBytes = 16 * 1024 * 1024,
    this.maxStoredRecords = 8192,
  })  : _store = store,
        _inbox = inbox {
    if (maxCommittedEffects <= 0 ||
        maxApplicationStateBytes < 0 ||
        maxRatchetStateBytes <= 0 ||
        maxTotalStateBytes <= 0 ||
        maxStoredRecords <= 0) {
      throw ArgumentError('Layergram v3 atomic commit limits are invalid');
    }
  }

  static const String recordKind = 'v3_lmf_effect_v1';

  final V3LmfRecordStore _store;
  final V3LmfDurableInbox _inbox;
  final int maxCommittedEffects;
  final int maxApplicationStateBytes;
  final int maxRatchetStateBytes;
  final int maxTotalStateBytes;
  final int maxStoredRecords;

  final Map<String, V3LmfCommittedEffect> _effects =
      <String, V3LmfCommittedEffect>{};
  Future<void> _operationTail = Future<void>.value();
  bool _restored = false;
  bool _closed = false;
  bool _writeRecoveryRequired = false;
  final Object _inboxAttachmentOwner = Object();
  V3LmfReplayWindowRetirementAuthority? _replayRetirementAuthority;
  V3LmfAtomicCommitAuthority? _authority;
  int _totalStateBytes = 0;

  int get committedEffectCount => _effects.length;

  int get totalStateBytes => _totalStateBytes;

  bool get requiresRecovery => _writeRecoveryRequired;

  List<V3LmfCommittedEffect> get effects {
    _ensureAuthority(null);
    return List<V3LmfCommittedEffect>.unmodifiable(_effects.values);
  }

  V3LmfCommittedEffect? effectForAssembly(
    String assemblyId, {
    V3LmfAtomicCommitAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return _effects[assemblyId];
  }

  V3LmfReplayWindowBinding? replayWindowBindingForAssembly(
    String assemblyId, {
    V3LmfAtomicCommitAuthority? authority,
  }) {
    _ensureAuthority(authority);
    return _inbox.replayWindowBindings[assemblyId];
  }

  /// Claims this journal for exactly one higher-level session coordinator.
  ///
  /// The claim must happen before restore, closing the race window in which a
  /// direct caller could commit between restore and coordinator attachment.
  Future<V3LmfAtomicCommitAuthority> claimSessionCoordinatorAuthority() {
    return _serialized(() async {
      _ensureOpen();
      if (_restored) {
        throw StateError(
          'Layergram v3 atomic journal authority must be claimed before restore',
        );
      }
      if (_authority != null) {
        throw StateError(
          'Layergram v3 atomic journal already has a session coordinator',
        );
      }
      final authority = V3LmfAtomicCommitAuthority._();
      _authority = authority;
      return authority;
    });
  }

  Future<V3LmfAtomicCommitRestoreResult> restore({
    V3LmfAtomicCommitAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureOpen();
      if (_restored) {
        throw StateError('Layergram v3 atomic commit journal was restored');
      }
      _replayRetirementAuthority = await _inbox.attachAtomicCommitJournal(
        owner: _inboxAttachmentOwner,
      );
      final records = await _store.readAll();
      final relevant = records
          .where((record) => record.payload['kind'] == recordKind)
          .toList(growable: false);
      if (relevant.length > maxStoredRecords) {
        throw const V3LmfPersistenceLimitException(
          'physical atomic effect record limit exceeded',
        );
      }

      var removedDuplicates = 0;
      try {
        for (final stored in relevant) {
          final candidate = _decodeEffect(stored);
          final previous = _effects[candidate.assemblyId];
          if (previous == null) {
            try {
              _checkCapacityFor(candidate);
            } catch (_) {
              candidate._wipe();
              rethrow;
            }
            _index(candidate);
            continue;
          }
          if (!_sameEffect(previous, candidate)) {
            candidate._wipe();
            throw const V3LmfPersistenceConflictException(
              'conflicting atomic effects for one v3 assembly',
            );
          }

          removedDuplicates++;
          if (_isEarlier(candidate, previous)) {
            _effects[candidate.assemblyId] = candidate;
            previous._wipe();
            await _deleteIgnoringFailure(previous.storageId);
          } else {
            candidate._wipe();
            await _deleteIgnoringFailure(candidate.storageId);
          }
        }
      } catch (_) {
        _wipeAndClear();
        rethrow;
      }
      final pendingInboxCommits = <String>{};
      final replayBindings = _inbox.replayWindowBindings;
      try {
        final inboxBindings = _inbox.committedHigherLevelBindings;
        for (final binding in inboxBindings.entries) {
          final effect = _effects[binding.key];
          if (binding.value == null) {
            if (effect != null) {
              throw const V3LmfPersistenceConflictException(
                'v3 effect has an unbound transport commit tombstone',
              );
            }
            continue;
          }
          final replay = replayBindings[binding.key];
          if (effect == null && replay != null) {
            if (replay.higherLevelCommitDigest != binding.value) {
              throw const V3LmfPersistenceConflictException(
                'v3 replay-window binding differs from its commit digest',
              );
            }
            continue;
          }
          if (effect == null || effect.effectDigest != binding.value) {
            throw const V3LmfPersistenceConflictException(
              'v3 commit tombstone has no matching durable effect',
            );
          }
        }
        for (final effect in _effects.values) {
          if (!inboxBindings.containsKey(effect.assemblyId)) {
            pendingInboxCommits.add(effect.assemblyId);
          }
        }
      } catch (_) {
        _wipeAndClear();
        rethrow;
      }
      _restored = true;
      final restoredEffects = _effects.values.toList(growable: false)
        ..sort((left, right) {
          final time = left.persistedAt.compareTo(right.persistedAt);
          return time != 0 ? time : left.assemblyId.compareTo(right.assemblyId);
        });
      return V3LmfAtomicCommitRestoreResult(
        effects: List<V3LmfCommittedEffect>.unmodifiable(restoredEffects),
        removedExactDuplicates: removedDuplicates,
        pendingInboxCommitAssemblyIds: Set<String>.unmodifiable(
          pendingInboxCommits,
        ),
        replayWindowBindings: replayBindings,
      );
    });
  }

  /// Persists a complete higher-level effect and then commits the inbox.
  ///
  /// If this assembly already has a durable effect, [builder] is deliberately
  /// not invoked; only the inbox tombstone is reconciled.
  Future<V3LmfCommittedEffect> commit({
    required V3LmfDurableDelivery delivery,
    required V3LmfAtomicEffectBuilder builder,
    DateTime? persistedAt,
    V3LmfAtomicCommitAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      _rejectAcknowledgement(delivery);
      final deliveryDigest = _deliveryDigest(delivery.frames);
      final existing = _effects[delivery.assemblyId];
      if (existing != null) {
        _requireSameDelivery(existing, deliveryDigest);
        await _inbox.commit(
          delivery,
          committedAt: existing.persistedAt,
          higherLevelCommitDigest: existing.effectDigest,
        );
        return existing;
      }
      if (_inbox.committedHigherLevelBindings.containsKey(
        delivery.assemblyId,
      )) {
        throw const V3LmfPersistenceConflictException(
          'v3 inbox was committed without a matching durable atomic effect',
        );
      }

      final plaintext = delivery.plaintext;
      late final V3LmfAtomicEffect effect;
      try {
        effect = await builder(plaintext);
      } finally {
        plaintext.fillRange(0, plaintext.length, 0);
      }
      try {
        _validateEffectSize(effect);
        final timestamp = (persistedAt ?? DateTime.now()).toUtc();
        final target = delivery.frames.first;
        final effectDigest = _effectDigest(
          assemblyId: delivery.assemblyId,
          deliveryDigest: deliveryDigest,
          applicationStateVersion: effect.applicationStateVersion,
          ratchetStateVersion: effect.ratchetStateVersion,
          applicationState: effect._applicationState,
          ratchetState: effect._ratchetState,
        );
        final payload = <String, dynamic>{
          'kind': recordKind,
          'v': 1,
          'assemblyId': delivery.assemblyId,
          'deliveryDigest': deliveryDigest,
          'effectDigest': effectDigest,
          'target': _encodeBinary(V3LmfFrameCodec.encodeBinary(target)),
          'applicationStateVersion': effect.applicationStateVersion,
          'ratchetStateVersion': effect.ratchetStateVersion,
          'applicationState': _encodeBinary(effect._applicationState),
          'ratchetState': _encodeBinary(effect._ratchetState),
          'persistedAt': timestamp.millisecondsSinceEpoch,
        };
        final candidate = V3LmfCommittedEffect._(
          storageId: '',
          assemblyId: delivery.assemblyId,
          deliveryDigest: deliveryDigest,
          effectDigest: effectDigest,
          targetFrame: target,
          applicationState: effect._applicationState,
          ratchetState: effect._ratchetState,
          applicationStateVersion: effect.applicationStateVersion,
          ratchetStateVersion: effect.ratchetStateVersion,
          persistedAt: timestamp,
        );
        try {
          _checkCapacityFor(candidate);
        } finally {
          candidate._wipe();
        }

        late final V3LmfCommittedEffect committed;
        try {
          final storageId = await _store.write(payload);
          _ensureOpen();
          committed = V3LmfCommittedEffect._(
            storageId: storageId,
            assemblyId: delivery.assemblyId,
            deliveryDigest: deliveryDigest,
            effectDigest: effectDigest,
            targetFrame: target,
            applicationState: effect._applicationState,
            ratchetState: effect._ratchetState,
            applicationStateVersion: effect.applicationStateVersion,
            ratchetStateVersion: effect.ratchetStateVersion,
            persistedAt: timestamp,
          );
          _index(committed);
        } catch (_) {
          // A persistence API may report failure after the record became
          // durable. Do not let this instance rerun a possibly committed
          // ratchet transition; a fresh restore resolves the actual outcome.
          _writeRecoveryRequired = true;
          rethrow;
        }

        // The atomic application/ratchet effect is durable before replay
        // suppression. A tombstone failure must leave the effect intact.
        await _inbox.commit(
          delivery,
          committedAt: timestamp,
          higherLevelCommitDigest: committed.effectDigest,
        );
        return committed;
      } finally {
        effect._wipe();
      }
    });
  }

  /// Completes the inbox tombstone for an effect persisted before a crash.
  Future<V3LmfCommittedEffect> resume({
    required V3LmfDurableDelivery delivery,
    V3LmfAtomicCommitAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureAuthority(authority);
      _ensureReady();
      _rejectAcknowledgement(delivery);
      final existing = _effects[delivery.assemblyId];
      if (existing == null) {
        throw StateError('Layergram v3 delivery has no durable atomic effect');
      }
      _requireSameDelivery(existing, _deliveryDigest(delivery.frames));
      await _inbox.commit(
        delivery,
        committedAt: existing.persistedAt,
        higherLevelCommitDigest: existing.effectDigest,
      );
      return existing;
    });
  }

  /// Deletes an incoming journal effect only after the inbox contains an
  /// exact durable replay-window replacement for its bound tombstone.
  Future<bool> collectCompactedEffect({
    required String assemblyId,
    required String expectedEffectDigest,
    V3LmfAtomicCommitAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureCompactionAuthority(authority);
      _ensureReady();
      final replay = _inbox.replayWindowBindings[assemblyId];
      if (replay == null ||
          replay.higherLevelCommitDigest != expectedEffectDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 atomic effect is not covered by the replay window',
        );
      }
      final effect = _effects[assemblyId];
      if (effect == null) return false;
      if (effect.effectDigest != expectedEffectDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 compacted atomic effect digest diverged',
        );
      }
      try {
        await _store.delete(effect.storageId);
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      }
      _effects.remove(assemblyId);
      _totalStateBytes -= effect.stateBytes;
      effect._wipe();
      return true;
    });
  }

  /// Establishes the write-before-delete replay-window proof used by
  /// [collectCompactedEffect].
  Future<V3LmfReplayWindowBinding> retireTombstoneToReplayWindow({
    required String assemblyId,
    required String expectedEffectDigest,
    required String stableRecordId,
    required String sessionKey,
    required int ratchetRevision,
    required String checkpointDigest,
    V3LmfAtomicCommitAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureCompactionAuthority(authority);
      _ensureReady();
      if (!_isCanonicalDigest(assemblyId) ||
          !_isCanonicalDigest(expectedEffectDigest) ||
          stableRecordId != 'v3:$assemblyId' ||
          !_isCanonicalId(sessionKey, V3LmfFrameCodec.sessionIdBytes) ||
          ratchetRevision <= 0 ||
          ratchetRevision > 0x7fffffffffffffff ||
          !_isCanonicalDigest(checkpointDigest)) {
        throw const FormatException(
          'Invalid Layergram v3 replay-window proof',
        );
      }
      final effect = _effects[assemblyId];
      if (effect != null && effect.effectDigest != expectedEffectDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 replay-window effect digest diverged',
        );
      }
      final existingReplay = _inbox.replayWindowBindings[assemblyId];
      if (existingReplay != null) {
        // A marker written before an interrupted journal deletion remains a
        // valid proof when a later cumulative checkpoint advances. Its own
        // checkpoint digest records the earlier write-before-delete boundary;
        // the coordinator separately verifies the current checkpoint still
        // contains this exact receipt before requesting compaction.
        if (existingReplay.higherLevelCommitDigest != expectedEffectDigest ||
            existingReplay.stableRecordId != stableRecordId ||
            existingReplay.sessionKey != sessionKey ||
            existingReplay.ratchetRevision != ratchetRevision) {
          throw const V3LmfPersistenceConflictException(
            'v3 replay-window retirement proof diverged',
          );
        }
        return existingReplay;
      }
      return _inbox.retireCommittedToReplayWindow(
        assemblyId: assemblyId,
        higherLevelCommitDigest: expectedEffectDigest,
        stableRecordId: stableRecordId,
        sessionKey: sessionKey,
        ratchetRevision: ratchetRevision,
        checkpointDigest: checkpointDigest,
      );
    });
  }

  /// Removes an exact compact replay proof only after the session coordinator
  /// has durably finalized the receipt retirement in its checkpoint.
  Future<bool> deleteReplayWindowProof({
    required String assemblyId,
    required String expectedEffectDigest,
    required String stableRecordId,
    required String sessionKey,
    required int ratchetRevision,
    required DateTime committedAt,
    V3LmfAtomicCommitAuthority? authority,
  }) {
    return _serialized(() async {
      _ensureCompactionAuthority(authority);
      _ensureReady();
      final inboxAuthority = _replayRetirementAuthority;
      if (inboxAuthority == null) {
        throw StateError('Layergram v3 replay retirement is not attached');
      }
      final existing = _inbox.replayWindowBindings[assemblyId];
      if (existing == null) return false;
      if (existing.higherLevelCommitDigest != expectedEffectDigest ||
          existing.stableRecordId != stableRecordId ||
          existing.sessionKey != sessionKey ||
          existing.ratchetRevision != ratchetRevision ||
          existing.committedAt.millisecondsSinceEpoch !=
              committedAt.toUtc().millisecondsSinceEpoch) {
        throw const V3LmfPersistenceConflictException(
          'v3 replay-window deletion binding diverged',
        );
      }
      try {
        return await _inbox.deleteReplayWindowProof(
          assemblyId: assemblyId,
          higherLevelCommitDigest: expectedEffectDigest,
          stableRecordId: stableRecordId,
          sessionKey: sessionKey,
          ratchetRevision: ratchetRevision,
          committedAt: committedAt,
          authority: inboxAuthority,
        );
      } catch (_) {
        _writeRecoveryRequired = true;
        rethrow;
      }
    });
  }

  Future<void> close({V3LmfAtomicCommitAuthority? authority}) {
    return _serialized(() async {
      _ensureAuthority(authority);
      if (_closed) return;
      _closed = true;
      final inboxAuthority = _replayRetirementAuthority;
      try {
        _wipeAndClear();
      } finally {
        if (inboxAuthority != null) {
          await _inbox.detachAtomicCommitJournal(
            owner: _inboxAttachmentOwner,
            authority: inboxAuthority,
          );
          _replayRetirementAuthority = null;
        }
      }
    });
  }

  V3LmfCommittedEffect _decodeEffect(V3LmfStoredRecord stored) {
    final payload = stored.payload;
    if (payload['v'] != 1 || payload.length != 11) {
      throw const FormatException('Invalid Layergram v3 atomic effect');
    }
    final assemblyId = payload['assemblyId'];
    final deliveryDigest = payload['deliveryDigest'];
    final effectDigest = payload['effectDigest'];
    final targetArmored = payload['target'];
    final applicationStateVersion = payload['applicationStateVersion'];
    final ratchetStateVersion = payload['ratchetStateVersion'];
    final applicationArmored = payload['applicationState'];
    final ratchetArmored = payload['ratchetState'];
    final persistedAt = payload['persistedAt'];
    if (assemblyId is! String ||
        !_isCanonicalDigest(assemblyId) ||
        deliveryDigest is! String ||
        !_isCanonicalDigest(deliveryDigest) ||
        effectDigest is! String ||
        !_isCanonicalDigest(effectDigest) ||
        targetArmored is! String ||
        applicationStateVersion is! int ||
        ratchetStateVersion is! int ||
        applicationArmored is! String ||
        ratchetArmored is! String ||
        !_isValidEpochMilliseconds(persistedAt)) {
      throw const FormatException('Invalid Layergram v3 atomic effect');
    }
    if (!_isValidVersion(applicationStateVersion) ||
        !_isValidVersion(ratchetStateVersion)) {
      throw const FormatException('Invalid Layergram v3 effect version');
    }
    final target = V3LmfFrameCodec.decodeBinary(
      _decodeBinary(targetArmored, V3LmfFrameCodec.maxBinaryFrameBytes),
    );
    if (target.metadata.kind == V3LmfFrameKind.acknowledgement ||
        V3LmfFrameCodec.assemblyId(target) != assemblyId) {
      throw const FormatException('Mismatched Layergram v3 atomic effect');
    }
    Uint8List? decodedApplicationState;
    Uint8List? decodedRatchetState;
    try {
      decodedApplicationState = _decodeBinary(
        applicationArmored,
        maxApplicationStateBytes,
        allowEmpty: true,
      );
      decodedRatchetState = _decodeBinary(
        ratchetArmored,
        maxRatchetStateBytes,
      );
    } catch (_) {
      decodedApplicationState?.fillRange(
        0,
        decodedApplicationState.length,
        0,
      );
      rethrow;
    }
    final applicationState = decodedApplicationState;
    final ratchetState = decodedRatchetState;
    final computedDigest = _effectDigest(
      assemblyId: assemblyId,
      deliveryDigest: deliveryDigest,
      applicationStateVersion: applicationStateVersion,
      ratchetStateVersion: ratchetStateVersion,
      applicationState: applicationState,
      ratchetState: ratchetState,
    );
    if (computedDigest != effectDigest) {
      applicationState.fillRange(0, applicationState.length, 0);
      ratchetState.fillRange(0, ratchetState.length, 0);
      throw const FormatException('Mismatched Layergram v3 effect digest');
    }
    final result = V3LmfCommittedEffect._(
      storageId: stored.storageId,
      assemblyId: assemblyId,
      deliveryDigest: deliveryDigest,
      effectDigest: effectDigest,
      targetFrame: target,
      applicationState: applicationState,
      ratchetState: ratchetState,
      applicationStateVersion: applicationStateVersion,
      ratchetStateVersion: ratchetStateVersion,
      persistedAt: DateTime.fromMillisecondsSinceEpoch(
        persistedAt as int,
        isUtc: true,
      ),
    );
    applicationState.fillRange(0, applicationState.length, 0);
    ratchetState.fillRange(0, ratchetState.length, 0);
    return result;
  }

  void _validateEffectSize(V3LmfAtomicEffect effect) {
    if (effect._applicationState.length > maxApplicationStateBytes) {
      throw const V3LmfPersistenceLimitException(
        'application state byte limit exceeded',
      );
    }
    if (effect._ratchetState.length > maxRatchetStateBytes) {
      throw const V3LmfPersistenceLimitException(
        'ratchet state byte limit exceeded',
      );
    }
  }

  void _checkCapacityFor(V3LmfCommittedEffect candidate) {
    if (_effects.length >= maxCommittedEffects) {
      throw const V3LmfPersistenceLimitException(
        'committed atomic effect limit reached',
      );
    }
    if (candidate._applicationState.length > maxApplicationStateBytes ||
        candidate._ratchetState.length > maxRatchetStateBytes ||
        _totalStateBytes + candidate.stateBytes > maxTotalStateBytes) {
      throw const V3LmfPersistenceLimitException(
        'atomic effect state byte limit exceeded',
      );
    }
  }

  void _index(V3LmfCommittedEffect effect) {
    _effects[effect.assemblyId] = effect;
    _totalStateBytes += effect.stateBytes;
  }

  void _wipeAndClear() {
    for (final effect in _effects.values) {
      effect._wipe();
    }
    _effects.clear();
    _totalStateBytes = 0;
  }

  void _requireSameDelivery(
    V3LmfCommittedEffect existing,
    String deliveryDigest,
  ) {
    if (existing.deliveryDigest != deliveryDigest) {
      throw const V3LmfPersistenceConflictException(
        'durable effect does not match the redelivered v3 frame set',
      );
    }
  }

  void _rejectAcknowledgement(V3LmfDurableDelivery delivery) {
    if (delivery.frames.first.metadata.kind == V3LmfFrameKind.acknowledgement) {
      throw ArgumentError('ACK frames do not create application effects');
    }
  }

  Future<void> _deleteIgnoringFailure(String storageId) async {
    try {
      await _store.delete(storageId);
    } catch (_) {
      // An exact encrypted duplicate can be retried on the next restore.
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
    if (_closed) {
      throw StateError('Layergram v3 atomic commit journal is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored) {
      throw StateError(
        'Layergram v3 atomic commit journal must be restored before use',
      );
    }
    if (_writeRecoveryRequired) {
      throw StateError(
        'Layergram v3 atomic commit journal must be reconstructed and '
        'restored after an indeterminate effect write',
      );
    }
  }

  void _ensureAuthority(V3LmfAtomicCommitAuthority? authority) {
    final claimed = _authority;
    if (claimed != null && !identical(claimed, authority)) {
      throw StateError(
        'Layergram v3 atomic journal is owned by a session coordinator',
      );
    }
  }

  void _ensureCompactionAuthority(V3LmfAtomicCommitAuthority? authority) {
    final claimed = _authority;
    if (claimed == null || !identical(claimed, authority)) {
      throw StateError(
        'Layergram v3 compaction requires session-coordinator authority',
      );
    }
  }
}

String _deliveryDigest(List<V3LmfFrame> frames) {
  final builder = BytesBuilder(copy: false)
    ..add(utf8.encode('layergram/v3/lmf/delivery-digest\u0000'));
  for (final frame in frames) {
    final binary = V3LmfFrameCodec.encodeBinary(frame);
    final length = ByteData(4)..setUint32(0, binary.length, Endian.big);
    builder
      ..add(length.buffer.asUint8List())
      ..add(binary);
  }
  return _digest(builder.takeBytes());
}

String _effectDigest({
  required String assemblyId,
  required String deliveryDigest,
  required int applicationStateVersion,
  required int ratchetStateVersion,
  required Uint8List applicationState,
  required Uint8List ratchetState,
}) {
  final assemblyBytes = _decodeBinary(assemblyId, 32);
  final deliveryBytes = _decodeBinary(deliveryDigest, 32);
  final versionsAndLengths = ByteData(12)
    ..setUint16(0, applicationStateVersion, Endian.big)
    ..setUint16(2, ratchetStateVersion, Endian.big)
    ..setUint32(4, applicationState.length, Endian.big)
    ..setUint32(8, ratchetState.length, Endian.big);
  final builder = BytesBuilder(copy: false)
    ..add(utf8.encode('layergram/v3/lmf/atomic-effect\u0000'))
    ..add(assemblyBytes)
    ..add(deliveryBytes)
    ..add(versionsAndLengths.buffer.asUint8List())
    ..add(applicationState)
    ..add(ratchetState);
  try {
    return _digest(builder.takeBytes());
  } finally {
    assemblyBytes.fillRange(0, assemblyBytes.length, 0);
    deliveryBytes.fillRange(0, deliveryBytes.length, 0);
  }
}

bool _sameEffect(V3LmfCommittedEffect left, V3LmfCommittedEffect right) {
  return left.assemblyId == right.assemblyId &&
      left.deliveryDigest == right.deliveryDigest &&
      left.effectDigest == right.effectDigest &&
      left.applicationStateVersion == right.applicationStateVersion &&
      left.ratchetStateVersion == right.ratchetStateVersion &&
      _bytesEqual(
        V3LmfFrameCodec.encodeBinary(left.targetFrame),
        V3LmfFrameCodec.encodeBinary(right.targetFrame),
      ) &&
      _bytesEqual(left._applicationState, right._applicationState) &&
      _bytesEqual(left._ratchetState, right._ratchetState);
}

bool _isEarlier(V3LmfCommittedEffect left, V3LmfCommittedEffect right) {
  final time = left.persistedAt.compareTo(right.persistedAt);
  return time < 0 ||
      (time == 0 && left.storageId.compareTo(right.storageId) < 0);
}

void _validateVersion(int value, String name) {
  if (value <= 0 || value > 0xffff) {
    throw ArgumentError.value(value, name, 'must be between 1 and 65535');
  }
}

bool _isValidVersion(int value) => value > 0 && value <= 0xffff;

String _digest(Uint8List bytes) {
  try {
    return base64UrlEncode(crypto.sha256.convert(bytes).bytes)
        .replaceAll('=', '');
  } finally {
    bytes.fillRange(0, bytes.length, 0);
  }
}

String _encodeBinary(Uint8List bytes) =>
    base64UrlEncode(bytes).replaceAll('=', '');

Uint8List _decodeBinary(
  String armored,
  int maxBytes, {
  bool allowEmpty = false,
}) {
  if ((!allowEmpty && armored.isEmpty) ||
      armored.length > ((maxBytes * 4 + 2) ~/ 3)) {
    throw const FormatException('Invalid persisted binary length');
  }
  if (armored.isEmpty) return Uint8List(0);
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

bool _isCanonicalId(String value, int byteLength) {
  Uint8List? decoded;
  try {
    decoded = _decodeBinary(value, byteLength);
    return decoded.length == byteLength;
  } on FormatException {
    return false;
  } finally {
    if (decoded != null) decoded.fillRange(0, decoded.length, 0);
  }
}

bool _isValidEpochMilliseconds(Object? value) =>
    value is int && value >= 0 && value <= 8640000000000000;

bool _bytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
