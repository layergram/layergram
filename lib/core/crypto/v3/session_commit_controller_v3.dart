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

import 'committed_record_materializer_v3.dart';
import 'committed_record_v3.dart';
import 'ec_double_ratchet_v3.dart';
import 'initial_session_handoff_authority_v3.dart';
import 'key_schedule_v3.dart';
import 'lmf_v3.dart';
import 'lmf_v3_acknowledgement.dart';
import 'lmf_v3_atomic_commit.dart';
import 'lmf_v3_outbox.dart';
import 'lmf_v3_persistence.dart';
import 'retention_policy_v3.dart';
import 'session_send_journal_v3.dart';
import 'session_checkpoint_v3.dart';
import 'session_retirement_journal_v3.dart';
import 'sparse_pq_ratchet_v3.dart';
import 'triple_ratchet_engine_v3.dart';
import 'triple_ratchet_state_v3.dart';

/// Builds one candidate receive transition from an authenticated delivery.
///
/// [plaintext] and [currentSnapshot] are temporary controller-owned copies.
/// They must not be retained. The returned snapshot transfers ownership to the
/// controller and is wiped after it has been validated and copied.
typedef V3SessionTransitionBuilder = FutureOr<V3TripleRatchetState> Function(
  Uint8List plaintext,
  V3TripleRatchetState currentSnapshot,
  V3HybridRatchetHeader hybridRatchetHeader,
);

/// Optional semantic validator for backend-owned Triple Ratchet state.
///
/// The controller already validates the canonical TR3 envelope and its X25519
/// key pair. A production SCKA backend must additionally authenticate and
/// semantically validate [V3TripleRatchetState.nativeSckaState] through this
/// callback before protocol v3 can be activated.
typedef V3SessionSnapshotValidator = FutureOr<void> Function(
  V3TripleRatchetState snapshot,
);

final class V3SessionCommitRestoreResult {
  const V3SessionCommitRestoreResult({
    required this.sessionRevisions,
    required this.committedEffectCount,
    required this.pendingInboxCommitAssemblyIds,
    this.committedSendEffectCount = 0,
    this.pendingSendAssemblyIds = const <String>{},
    this.materializedRecordCount = 0,
    this.checkpointCount = 0,
    this.retirementPlanCount = 0,
  });

  final Map<String, int> sessionRevisions;
  final int committedEffectCount;
  final Set<String> pendingInboxCommitAssemblyIds;
  final int committedSendEffectCount;
  final Set<String> pendingSendAssemblyIds;
  final int materializedRecordCount;
  final int checkpointCount;
  final int retirementPlanCount;
}

final class V3SessionCommitResult {
  const V3SessionCommitResult({
    required this.effect,
    required this.ratchetRevision,
    required this.wasAlreadyDurable,
  });

  final V3LmfCommittedEffect effect;
  final int ratchetRevision;
  final bool wasAlreadyDurable;
}

final class V3SessionSendResult {
  const V3SessionSendResult({
    required this.assemblyId,
    required this.messageRecordId,
    required this.ratchetRevision,
    required this.frames,
  });

  final String assemblyId;
  final String messageRecordId;
  final int ratchetRevision;
  final List<V3LmfFrame> frames;
}

/// Non-secret binding used to reconcile a higher-level multi-device group
/// after a crash between the per-session send commit and the group update.
final class V3PendingSessionSendBinding {
  const V3PendingSessionSendBinding({
    required this.assemblyId,
    required this.previousRatchetRevision,
    required this.ratchetRevision,
    required this.isFullyAcknowledged,
  });

  final String assemblyId;
  final int previousRatchetRevision;
  final int ratchetRevision;
  final bool isFullyAcknowledged;
}

/// Result of durably registering the revision-zero TR3 produced by one
/// authenticated hybrid handshake.
final class V3InitialSessionRegistration {
  const V3InitialSessionRegistration({
    required this.sessionKey,
    required this.checkpointDigest,
    required this.wasAlreadyDurable,
  });

  final String sessionKey;
  final String checkpointDigest;
  final bool wasAlreadyDurable;
}

/// Explainable outcome of one fully finalized receipt retirement.
final class V3SessionReceiptRetirementResult {
  const V3SessionReceiptRetirementResult({
    required this.decision,
    required this.planId,
    required this.replacementCheckpointDigest,
  });

  final V3RetentionDecision decision;
  final String? planId;
  final String? replacementCheckpointDigest;

  bool get checkpointWasReplaced => replacementCheckpointDigest != null;
}

final class V3SessionCompactionResult {
  const V3SessionCompactionResult({
    required this.collectedIncomingEffects,
    required this.collectedOutgoingEffects,
    required this.replayWindowEntries,
  });

  final int collectedIncomingEffects;
  final int collectedOutgoingEffects;
  final int replayWindowEntries;
}

/// Non-secret pointer to one cumulative checkpoint receipt that may become
/// eligible for conservative retirement.
final class V3SessionReceiptRetentionCandidate {
  const V3SessionReceiptRetentionCandidate({
    required this.sessionKey,
    required this.assemblyId,
  });

  final String sessionKey;
  final String assemblyId;
}

/// Inactive single-authority coordinator for protocol-v3 session commits.
///
/// One instance owns one [V3LmfAtomicCommitJournal] for an encrypted
/// identity/passphrase scope and serializes every registered session. Passing
/// a journal to this controller transfers exclusive ownership; callers must
/// not retain it for concurrent direct use while [restore] begins. It:
///
/// * claims the journal before restore, blocking direct commit races;
/// * reconstructs each session from a checkpoint plus a contiguous chain of
///   durable AR3/TR3 effects;
/// * validates exact AR3, LMF, routing, session, and stable TR3 bindings;
/// * applies compare-and-swap to the caller's expected TR3 revision before a
///   transition builder can run;
/// * advances in-memory state only after the atomic effect and inbox tombstone
///   have both completed;
/// * fails stopped after an outcome that could have made a candidate durable.
///
/// When [sendJournal] and [outbox] are supplied together, the same serialized
/// authority also commits outgoing application/PQ transitions before their
/// exact sealed bytes become exportable. When the optional durable-state pair
/// is supplied, canonical AR3 records are materialized under stable IDs and a
/// monotonic TR3 checkpoint is reconciled before a commit result is exposed.
/// When a retirement journal is supplied, this authority also owns its entire
/// lifecycle, reconciles every prepared/replaced/final stage, and deletes only
/// an exact compact proof followed by its finalized plan. Any interrupted
/// boundary is resumed on restore before the session is exposed.
/// When [sckaBackend] is supplied, the controller also pins that exact backend
/// instance for restore validation and every durable send; a different
/// per-call backend is rejected before a transition. Hybrid handshake/session
/// creation, the inactive native ABI, projection into the real chat repository
/// and independently reviewed replay-window expiry remain activation gates.
final class V3SessionCommitController {
  V3SessionCommitController({
    required V3LmfAtomicCommitJournal journal,
    V3SckaBackend? sckaBackend,
    V3SessionSendJournal? sendJournal,
    V3LmfDurableOutbox? outbox,
    V3CommittedRecordMaterializer? committedRecordMaterializer,
    V3SessionCheckpointRepository? checkpointRepository,
    V3SessionRetirementJournal? retirementJournal,
    V3InitialSessionHandoffAuthority? initialHandoffAuthority,
    this.snapshotValidator,
    this.maxSessions = 4096,
  })  : _journal = journal,
        _sckaBackend = sckaBackend,
        _sendJournal = sendJournal,
        _outbox = outbox,
        _committedRecordMaterializer = committedRecordMaterializer,
        _checkpointRepository = checkpointRepository,
        _retirementJournal = retirementJournal,
        _initialHandoffAuthority = initialHandoffAuthority {
    if (maxSessions <= 0) {
      throw ArgumentError.value(maxSessions, 'maxSessions');
    }
    if ((sendJournal == null) != (outbox == null)) {
      throw ArgumentError(
        'Layergram v3 send journal and outbox must be configured together',
      );
    }
    if ((committedRecordMaterializer == null) !=
        (checkpointRepository == null)) {
      throw ArgumentError(
        'Layergram v3 materializer and checkpoint repository must be configured together',
      );
    }
    if (retirementJournal != null && checkpointRepository == null) {
      throw ArgumentError(
        'Layergram v3 retirement journal requires durable checkpoint storage',
      );
    }
  }

  final V3LmfAtomicCommitJournal _journal;
  final V3SckaBackend? _sckaBackend;
  final V3SessionSendJournal? _sendJournal;
  final V3LmfDurableOutbox? _outbox;
  final V3CommittedRecordMaterializer? _committedRecordMaterializer;
  final V3SessionCheckpointRepository? _checkpointRepository;
  final V3SessionRetirementJournal? _retirementJournal;
  final V3InitialSessionHandoffAuthority? _initialHandoffAuthority;
  final V3SessionSnapshotValidator? snapshotValidator;
  final int maxSessions;

  final Map<String, V3TripleRatchetState> _sessions =
      <String, V3TripleRatchetState>{};
  final Map<String, int> _effectRevisions = <String, int>{};
  final Set<String> _pendingInboxCommits = <String>{};
  final Map<String, V3SessionSendEffect> _sendEffects =
      <String, V3SessionSendEffect>{};
  Future<void> _operationTail = Future<void>.value();
  V3LmfAtomicCommitAuthority? _authority;
  V3SessionSendJournalAuthority? _sendAuthority;
  V3LmfOutboxAuthority? _outboxAuthority;
  V3CommittedRecordMaterializerAuthority? _materializerAuthority;
  V3SessionCheckpointAuthority? _checkpointAuthority;
  V3SessionRetirementAuthority? _retirementAuthority;
  bool _initialHandoffAuthorityClaimed = false;
  bool _restored = false;
  bool _closed = false;
  bool _recoveryRequired = false;

  int get sessionCount => _sessions.length;
  bool get isRestored => _restored && !requiresRecovery && !_closed;
  bool get requiresRecovery =>
      _recoveryRequired || (_retirementJournal?.requiresRecovery ?? false);

  /// Transfers revision-zero registration and handoff reconciliation to the
  /// sole HP3 -> TR3 coordinator for this encrypted scope.
  Future<void> claimInitialHandoffAuthority(
    V3InitialSessionHandoffAuthority authority,
  ) {
    return _serialized(() async {
      _ensureReady();
      _ensureConfiguredInitialHandoffAuthority(authority);
      if (_initialHandoffAuthorityClaimed) {
        throw StateError(
          'Layergram v3 session handoff authority was already claimed',
        );
      }
      _initialHandoffAuthorityClaimed = true;
    });
  }

  Future<V3SessionCommitRestoreResult> restore({
    required Iterable<V3TripleRatchetState> checkpoints,
  }) {
    return _serialized(() async {
      _ensureOpen();
      if (_restored ||
          _authority != null ||
          _sendAuthority != null ||
          _outboxAuthority != null ||
          _materializerAuthority != null ||
          _checkpointAuthority != null ||
          _retirementAuthority != null) {
        throw StateError('Layergram v3 session controller was restored');
      }

      final working = <String, V3TripleRatchetState>{};
      final durableCheckpoints = <String, V3SessionCheckpoint>{};
      final decodedEffects = <_DecodedEffect>[];
      final decodedSendEffects = <_DecodedSendEffect>[];
      try {
        // Claim before invoking any caller-supplied validator. Once this
        // operation begins, a re-entrant direct restore/close cannot bypass
        // the coordinator's exclusive journal authority.
        _authority = await _journal.claimSessionCoordinatorAuthority();
        final sendJournal = _sendJournal;
        final outbox = _outbox;
        if (sendJournal != null) {
          _sendAuthority = await sendJournal.claimSessionCoordinatorAuthority();
          _outboxAuthority = await outbox!.claimSessionSendAuthority();
        }
        final materializer = _committedRecordMaterializer;
        final checkpointRepository = _checkpointRepository;
        final retirementJournal = _retirementJournal;
        if (retirementJournal != null) {
          _retirementAuthority =
              await retirementJournal.claimSessionCoordinatorAuthority();
        }
        if (materializer != null) {
          _materializerAuthority =
              await materializer.claimSessionCoordinatorAuthority();
          _checkpointAuthority =
              await checkpointRepository!.claimSessionCoordinatorAuthority();
          await materializer.restore(authority: _materializerAuthority);
          await checkpointRepository.restore(authority: _checkpointAuthority);
        }

        final restoredRetirement = retirementJournal == null
            ? null
            : await retirementJournal.restore(authority: _retirementAuthority);
        var checkpointCount = 0;
        for (final checkpoint in checkpoints) {
          checkpointCount++;
          if (checkpointCount > maxSessions) {
            throw const V3LmfPersistenceLimitException(
              'v3 session checkpoint limit exceeded',
            );
          }
          final copied = _copySnapshot(checkpoint);
          var indexed = false;
          try {
            final key = _sessionKey(copied.sessionId);
            if (copied.lifecycle != V3RatchetLifecycle.active) {
              throw StateError(
                'Layergram v3 session checkpoint is not active',
              );
            }
            if (working.containsKey(key)) {
              throw const V3LmfPersistenceConflictException(
                'duplicate Layergram v3 session checkpoint',
              );
            }
            // Index before the awaited validator so the outer failure cleanup
            // owns and wipes this secret snapshot on every validator error.
            working[key] = copied;
            indexed = true;
            await _validateSnapshot(copied);
          } catch (_) {
            if (!indexed) copied.wipeSecrets();
            rethrow;
          }
        }

        // Once present, the encrypted checkpoint repository is the durable
        // restore anchor. It may advance an older caller bootstrap snapshot,
        // but it must never be older than or fork from that caller state.
        if (checkpointRepository != null) {
          for (final durable in checkpointRepository.checkpoints(
            authority: _checkpointAuthority,
          )) {
            durableCheckpoints[durable.sessionKey] = durable;
            _validateDurableCheckpointMaterialization(durable);
            final candidate = durable.decodeSnapshot();
            var retained = false;
            try {
              await _validateSnapshot(candidate);
              final caller = working[durable.sessionKey];
              if (caller == null) {
                if (working.length >= maxSessions) {
                  throw const V3LmfPersistenceLimitException(
                    'v3 session checkpoint limit exceeded',
                  );
                }
                working[durable.sessionKey] = candidate;
                retained = true;
                continue;
              }
              if (!durable.matchesLineage(caller) ||
                  caller.revision > durable.revision) {
                throw const V3LmfPersistenceConflictException(
                  'durable v3 checkpoint does not extend caller state',
                );
              }
              if (caller.revision == durable.revision &&
                  !_snapshotBytesEqual(caller, candidate)) {
                throw const V3LmfPersistenceConflictException(
                  'durable v3 checkpoint forks caller state',
                );
              }
              if (caller.revision < durable.revision) {
                caller.wipeSecrets();
                working[durable.sessionKey] = candidate;
                retained = true;
              }
            } finally {
              if (!retained) candidate.wipeSecrets();
            }
          }
        }

        if (retirementJournal != null) {
          await _reconcileRetirementPlans(
            plans: restoredRetirement!.plans,
            checkpoints: durableCheckpoints,
          );
        }
        var retirementPlans = retirementJournal == null
            ? const <V3SessionRetirementPlan>[]
            : retirementJournal.plans(authority: _retirementAuthority);
        final retirementPlansByAssembly = <String, V3SessionRetirementPlan>{};
        for (final plan in retirementPlans) {
          if (retirementPlansByAssembly.putIfAbsent(
                plan.assemblyId,
                () => plan,
              ) !=
              plan) {
            throw const V3LmfPersistenceConflictException(
              'multiple v3 retirement plans target one assembly',
            );
          }
        }

        final restoredJournal = await _journal.restore(
          authority: _authority,
        );
        if (checkpointRepository != null) {
          for (final binding in restoredJournal.replayWindowBindings.values) {
            final durable = durableCheckpoints[binding.sessionKey];
            if (durable == null) {
              throw const V3LmfPersistenceConflictException(
                'v3 replay window has no matching durable checkpoint receipt',
              );
            }
            final receipt = durable.receiptForAssembly(binding.assemblyId);
            final retirement = retirementPlansByAssembly[binding.assemblyId];
            final matchesReceipt = receipt != null &&
                receipt.direction == V3CheckpointEffectDirection.incoming &&
                receipt.stableRecordId == binding.stableRecordId &&
                receipt.ratchetRevision == binding.ratchetRevision;
            final matchesReplacedRetirement = receipt == null &&
                _allowsReplacedRetirementReceipt(
                  plan: retirement,
                  direction: V3CheckpointEffectDirection.incoming,
                  bindingSessionKey: binding.sessionKey,
                  stableRecordId: binding.stableRecordId,
                  ratchetRevision: binding.ratchetRevision,
                  checkpointDigest: durable.checkpointDigest,
                );
            if (!matchesReceipt && !matchesReplacedRetirement) {
              throw const V3LmfPersistenceConflictException(
                'v3 replay window has no matching durable checkpoint receipt',
              );
            }
          }
        } else if (restoredJournal.replayWindowBindings.isNotEmpty) {
          throw const V3LmfPersistenceConflictException(
            'v3 replay window requires durable checkpoint configuration',
          );
        }
        for (final effect in restoredJournal.effects) {
          decodedEffects.add(_decodeEffect(effect));
        }
        final restoredSendJournal = sendJournal == null
            ? null
            : await sendJournal.restore(authority: _sendAuthority);
        if (restoredSendJournal != null) {
          if (checkpointRepository == null &&
              restoredSendJournal.completionBindings.isNotEmpty) {
            throw const V3LmfPersistenceConflictException(
              'v3 send completion requires durable checkpoint configuration',
            );
          }
          for (final binding in restoredSendJournal.completionBindings.values) {
            final durable = durableCheckpoints[binding.sessionKey];
            if (durable == null) {
              throw const V3LmfPersistenceConflictException(
                'v3 send completion has no durable checkpoint receipt',
              );
            }
            final receipt = durable.receiptForAssembly(binding.assemblyId);
            final retirement = retirementPlansByAssembly[binding.assemblyId];
            final matchesReceipt = receipt != null &&
                receipt.direction == V3CheckpointEffectDirection.outgoing &&
                receipt.stableRecordId == binding.stableRecordId &&
                receipt.ratchetRevision == binding.ratchetRevision;
            final matchesReplacedRetirement = receipt == null &&
                _allowsReplacedRetirementReceipt(
                  plan: retirement,
                  direction: V3CheckpointEffectDirection.outgoing,
                  bindingSessionKey: binding.sessionKey,
                  stableRecordId: binding.stableRecordId,
                  ratchetRevision: binding.ratchetRevision,
                  checkpointDigest: durable.checkpointDigest,
                );
            if (!matchesReceipt && !matchesReplacedRetirement) {
              throw const V3LmfPersistenceConflictException(
                'v3 send completion has no durable checkpoint receipt',
              );
            }
          }
          for (final effect in restoredSendJournal.effects) {
            decodedSendEffects.add(_decodeSendEffect(effect));
          }
        }

        if (restoredRetirement != null) {
          _validateRetirementPlans(
            plans: retirementPlans,
            checkpoints: durableCheckpoints,
            incomingProofs: restoredJournal.replayWindowBindings,
            outgoingProofs: restoredSendJournal?.completionBindings ??
                const <String, V3SessionSendCompletionBinding>{},
          );
          await _finalizeRetirementPlans(
            plans: retirementPlans,
            checkpoints: durableCheckpoints,
          );
          retirementPlans = retirementJournal!.plans(
            authority: _retirementAuthority,
          );
          await checkpointRepository!.cleanupValidatedRetirementSources(
            authority: _checkpointAuthority,
          );
        }

        final ordered = <_RestoredSessionEffect>[
          ...decodedEffects.map(_RestoredSessionEffect.incoming),
          ...decodedSendEffects.map(_RestoredSessionEffect.outgoing),
        ];
        ordered.sort((left, right) {
          final session = left.sessionKey.compareTo(right.sessionKey);
          if (session != 0) return session;
          final revision = left.revision.compareTo(right.revision);
          if (revision != 0) return revision;
          return left.assemblyId.compareTo(right.assemblyId);
        });

        final effectRevisions = <String, int>{};
        final sendEffects = <String, V3SessionSendEffect>{};
        for (final restored in ordered) {
          final previous = working[restored.sessionKey];
          if (previous == null) {
            throw const V3LmfPersistenceConflictException(
              'v3 effect has no registered session checkpoint',
            );
          }
          final incoming = restored.incoming;
          if (restored.revision <= previous.revision) {
            final durable = durableCheckpoints[restored.sessionKey];
            if (durable == null) {
              throw const V3LmfPersistenceConflictException(
                'v3 journal effect precedes an unproven caller checkpoint',
              );
            }
            if (incoming != null) {
              _validateCheckpointCoverage(
                checkpoint: durable,
                direction: V3CheckpointEffectDirection.incoming,
                assemblyId: incoming.effect.assemblyId,
                applicationState: incoming.effect.applicationState,
                ratchetState: incoming.effect.ratchetState,
              );
              if (effectRevisions.containsKey(incoming.effect.assemblyId) ||
                  sendEffects.containsKey(incoming.effect.assemblyId)) {
                throw const V3LmfPersistenceConflictException(
                  'duplicate v3 session effect assembly',
                );
              }
              effectRevisions[incoming.effect.assemblyId] =
                  incoming.snapshot.revision;
            } else {
              final outgoing = restored.outgoing!;
              _validateCheckpointCoverage(
                checkpoint: durable,
                direction: V3CheckpointEffectDirection.outgoing,
                assemblyId: outgoing.effect.assemblyId,
                applicationState: outgoing.effect.applicationState,
                ratchetState: outgoing.effect.ratchetState,
              );
              if (effectRevisions.containsKey(outgoing.effect.assemblyId) ||
                  sendEffects.containsKey(outgoing.effect.assemblyId)) {
                throw const V3LmfPersistenceConflictException(
                  'duplicate v3 session effect assembly',
                );
              }
              sendEffects[outgoing.effect.assemblyId] = outgoing.effect;
            }
            continue;
          }
          if (incoming != null) {
            await _validateTransition(
              previous: previous,
              candidate: incoming.snapshot,
              effect: incoming.effect,
              record: incoming.record,
            );
            if (effectRevisions.containsKey(incoming.effect.assemblyId) ||
                sendEffects.containsKey(incoming.effect.assemblyId)) {
              throw const V3LmfPersistenceConflictException(
                'duplicate v3 session effect assembly',
              );
            }
            effectRevisions[incoming.effect.assemblyId] =
                incoming.snapshot.revision;
          } else {
            final outgoing = restored.outgoing!;
            await _validateOutgoingTransition(
              previous: previous,
              candidate: outgoing.snapshot,
              effect: outgoing.effect,
              record: outgoing.record,
            );
            if (effectRevisions.containsKey(outgoing.effect.assemblyId) ||
                sendEffects.containsKey(outgoing.effect.assemblyId)) {
              throw const V3LmfPersistenceConflictException(
                'duplicate v3 session effect assembly',
              );
            }
            sendEffects[outgoing.effect.assemblyId] = outgoing.effect;
          }
          final candidate = restored.takeSnapshot();
          previous.wipeSecrets();
          working[restored.sessionKey] = candidate;
        }

        // Every cumulative checkpoint receipt must retain one independently
        // durable journal proof. Before compaction that proof is the complete
        // effect; afterwards it is the write-before-delete replay/completion
        // marker. Otherwise deleting both records could silently turn state
        // loss into an apparently clean checkpoint restore.
        if (checkpointRepository != null) {
          for (final durable in durableCheckpoints.values) {
            for (final receipt in durable.receipts) {
              switch (receipt.direction) {
                case V3CheckpointEffectDirection.incoming:
                  if (effectRevisions.containsKey(receipt.assemblyId)) {
                    continue;
                  }
                  if (!restoredJournal.replayWindowBindings.containsKey(
                    receipt.assemblyId,
                  )) {
                    throw const V3LmfPersistenceConflictException(
                      'v3 incoming checkpoint receipt lost its journal proof',
                    );
                  }
                  break;
                case V3CheckpointEffectDirection.outgoing:
                  if (sendEffects.containsKey(receipt.assemblyId)) {
                    continue;
                  }
                  if (!(restoredSendJournal?.completionBindings.containsKey(
                        receipt.assemblyId,
                      ) ??
                      false)) {
                    throw const V3LmfPersistenceConflictException(
                      'v3 outgoing checkpoint receipt lost its journal proof',
                    );
                  }
                  break;
              }
            }
          }
        }

        for (final assemblyId
            in restoredJournal.pendingInboxCommitAssemblyIds) {
          if (!effectRevisions.containsKey(assemblyId)) {
            throw const V3LmfPersistenceConflictException(
              'pending v3 inbox commit has no registered session effect',
            );
          }
        }

        if (outbox != null) {
          final restoredOutbox = await outbox.restore(
            authority: _outboxAuthority,
          );
          for (final entry in restoredOutbox.entries) {
            final effect = sendEffects[entry.assemblyId];
            if (effect == null ||
                !_sameFrameSet(entry.frames, effect.frames) ||
                (entry.isFullyAcknowledged && !effect.isFullyAcknowledged)) {
              throw const V3LmfPersistenceConflictException(
                'v3 outbox entry has no matching durable send effect',
              );
            }
          }
          for (final effect in sendEffects.values) {
            final entry = outbox.entry(
              effect.assemblyId,
              authority: _outboxAuthority,
            );
            if (entry != null && !_sameFrameSet(entry.frames, effect.frames)) {
              throw const V3LmfPersistenceConflictException(
                'v3 outbox bytes differ from the durable send effect',
              );
            }
            if (effect.isFullyAcknowledged) {
              if (entry != null) {
                await outbox.reconcileCompleted(
                  effect.assemblyId,
                  authority: _outboxAuthority!,
                );
              }
            } else if (entry == null) {
              await outbox.enqueue(
                effect.frames,
                queuedAt: effect.persistedAt,
                authority: _outboxAuthority,
              );
            }
          }
        }

        if (materializer != null) {
          await _materializeAndCheckpointRestoredState(
            working: working,
            incomingEffects: decodedEffects,
            outgoingEffects: decodedSendEffects,
          );
        }

        _sessions.addAll(working);
        working.clear();
        _effectRevisions.addAll(effectRevisions);
        _pendingInboxCommits.addAll(
          restoredJournal.pendingInboxCommitAssemblyIds,
        );
        _sendEffects.addAll(sendEffects);
        _restored = true;
        return V3SessionCommitRestoreResult(
          sessionRevisions: Map<String, int>.unmodifiable(
            _sessions.map(
              (key, snapshot) => MapEntry(key, snapshot.revision),
            ),
          ),
          committedEffectCount: effectRevisions.length,
          pendingInboxCommitAssemblyIds: Set<String>.unmodifiable(
            _pendingInboxCommits,
          ),
          committedSendEffectCount: sendEffects.length,
          pendingSendAssemblyIds: Set<String>.unmodifiable(
            sendEffects.values
                .where((effect) => !effect.isFullyAcknowledged)
                .map((effect) => effect.assemblyId),
          ),
          materializedRecordCount: materializer?.recordCount ?? 0,
          checkpointCount: checkpointRepository?.checkpointCount ?? 0,
          retirementPlanCount: retirementPlans.length,
        );
      } catch (_) {
        _recoveryRequired = true;
        rethrow;
      } finally {
        for (final snapshot in working.values) {
          snapshot.wipeSecrets();
        }
        for (final decoded in decodedEffects) {
          decoded.close();
        }
        for (final decoded in decodedSendEffects) {
          decoded.close();
        }
      }
    });
  }

  /// Returns a detached canonical copy of the current committed snapshot.
  Future<V3TripleRatchetState> snapshotForSession(Uint8List sessionId) {
    return _serialized(() async {
      _ensureReady();
      final current = _sessions[_sessionKey(sessionId)];
      if (current == null) {
        throw StateError('Layergram v3 session is not registered');
      }
      return _copySnapshot(current);
    });
  }

  /// Checks routing ownership without exposing a detached secret snapshot.
  Future<bool> hasSession(Uint8List sessionId) {
    return _serialized(() async {
      _ensureReady();
      return _sessions.containsKey(_sessionKey(sessionId));
    });
  }

  /// Returns detached canonical AR3 application records for UI projection.
  ///
  /// The returned byte arrays contain authenticated application plaintext and
  /// are owned by the caller, which must overwrite them after decoding. The
  /// materializer remains the durable source of truth and never transfers its
  /// internal buffers or authority.
  Future<List<Uint8List>> applicationRecordBytesForProjection() {
    return _serialized(() async {
      _ensureReady();
      final materializer = _committedRecordMaterializer;
      if (materializer == null) {
        throw StateError(
          'Layergram v3 application materialization is not configured',
        );
      }
      final result = <Uint8List>[];
      try {
        for (final materialized in materializer.records(
          authority: _materializerAuthority,
        )) {
          final record = materialized.decodeRecord();
          try {
            if (record.kind == V3CommittedRecordKind.application) {
              result.add(materialized.encodedRecord);
            }
          } finally {
            record.wipeContent();
          }
        }
        return List<Uint8List>.unmodifiable(result);
      } catch (_) {
        for (final bytes in result) {
          _wipe(bytes);
        }
        rethrow;
      }
    });
  }

  /// Seals one complete cumulative ACK from committed receive state.
  ///
  /// The caller must durably retain the returned exact frame before exposing
  /// it to a carrier. Every newly sealed cumulative ACK supplies a fresh
  /// [messageId]; retries must reuse the persisted frame instead.
  Future<V3LmfFrame> sealAcknowledgement({
    required V3LmfFrame targetFrame,
    required V3LmfAcknowledgement acknowledgement,
    required Uint8List messageId,
  }) {
    return _serialized(() async {
      _ensureReady();
      if (targetFrame.metadata.kind == V3LmfFrameKind.acknowledgement ||
          messageId.length != V3LmfFrameCodec.messageIdBytes ||
          _isAllZero(messageId)) {
        throw const FormatException(
          'Invalid Layergram v3 acknowledgement target',
        );
      }
      final targetMessageId = targetFrame.metadata.messageId;
      final acknowledgementMessageId = acknowledgement.targetMessageId;
      final sessionId = targetFrame.metadata.sessionId;
      final senderBinding = targetFrame.metadata.senderBinding;
      final recipientBinding = targetFrame.metadata.recipientBinding;
      final snapshot = _sessions[_sessionKey(sessionId)];
      if (snapshot == null) {
        _wipe(targetMessageId);
        _wipe(acknowledgementMessageId);
        _wipe(sessionId);
        _wipe(senderBinding);
        _wipe(recipientBinding);
        throw const FormatException(
          'Layergram v3 acknowledgement session is not registered',
        );
      }
      final initiatorBinding = snapshot.initiatorRoutingBinding;
      final responderBinding = snapshot.responderRoutingBinding;
      final initiatorAckRoot = snapshot.initiatorToResponderAckRootKey;
      final responderAckRoot = snapshot.responderToInitiatorAckRootKey;
      V3AcknowledgementKeyMaterial? material;
      Uint8List? plaintext;
      Uint8List? nonce;
      try {
        _validateInboundRouting(snapshot, targetFrame);
        if (acknowledgement.targetSuite != targetFrame.metadata.suite ||
            acknowledgement.targetKind != targetFrame.metadata.kind ||
            acknowledgement.targetEpoch != targetFrame.metadata.epoch ||
            acknowledgement.targetMessageCounter !=
                targetFrame.metadata.messageCounter ||
            acknowledgement.targetAssembledPlaintextLength !=
                targetFrame.assembledPlaintextLength ||
            acknowledgement.targetFragmentCount != targetFrame.fragmentCount ||
            !_bytesEqual(targetMessageId, acknowledgementMessageId)) {
          throw const FormatException(
            'Layergram v3 acknowledgement does not match its target',
          );
        }
        final direction = snapshot.role == V3SessionRole.initiator
            ? V3TrafficDirection.initiatorToResponder
            : V3TrafficDirection.responderToInitiator;
        final metadata = V3LmfMessageMetadata(
          kind: V3LmfFrameKind.acknowledgement,
          senderBinding: recipientBinding,
          recipientBinding: senderBinding,
          messageId: messageId,
          sessionId: sessionId,
          epoch: targetFrame.metadata.epoch,
          messageCounter: targetFrame.metadata.messageCounter,
        );
        material = await V3KeySchedule.deriveAcknowledgementFromCommittedState(
          sessionId: sessionId,
          initiatorRoutingBinding: initiatorBinding,
          responderRoutingBinding: responderBinding,
          initiatorToResponderAckRootKey: initiatorAckRoot,
          responderToInitiatorAckRootKey: responderAckRoot,
          direction: direction,
          metadata: metadata,
        );
        plaintext = V3LmfAcknowledgementCodec.encode(acknowledgement);
        nonce = material.nonce;
        return V3LmfAead.sealSingle(
          metadata: metadata,
          plaintext: plaintext,
          secretKey: material.secretKey,
          nonce: nonce,
        );
      } finally {
        material?.close();
        if (plaintext != null) _wipe(plaintext);
        if (nonce != null) _wipe(nonce);
        _wipe(targetMessageId);
        _wipe(acknowledgementMessageId);
        _wipe(sessionId);
        _wipe(senderBinding);
        _wipe(recipientBinding);
        _wipe(initiatorBinding);
        _wipe(responderBinding);
        _wipe(initiatorAckRoot);
        _wipe(responderAckRoot);
      }
    });
  }

  /// Persists and registers one exact active revision-zero TR3 before the
  /// handshake controller may retire HP3. Repeating the byte-identical
  /// snapshot is idempotent; a same-session fork fails closed.
  Future<V3InitialSessionRegistration> registerInitialSession({
    required V3TripleRatchetState snapshot,
    required V3InitialSessionHandoffAuthority authority,
    DateTime? persistedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      _ensureClaimedInitialHandoffAuthority(authority);
      final repository = _checkpointRepository;
      if (repository == null) {
        throw StateError(
          'Layergram v3 durable checkpoint storage is not configured',
        );
      }
      if (snapshot.lifecycle != V3RatchetLifecycle.active ||
          snapshot.revision != 0) {
        throw const FormatException(
          'Layergram v3 initial session must be active revision zero',
        );
      }

      final candidate = _copySnapshot(snapshot);
      var retained = false;
      var persistenceAttempted = false;
      try {
        await _validateSnapshot(candidate);
        final sessionKey = _sessionKey(candidate.sessionId);
        final current = _sessions[sessionKey];
        if (current != null) {
          if (current.revision != 0 ||
              !_snapshotBytesEqual(current, candidate)) {
            throw const V3LmfPersistenceConflictException(
              'v3 initial session registration forks durable state',
            );
          }
          final checkpoint = repository.checkpointForSession(
            candidate.sessionId,
            authority: _checkpointAuthority,
          );
          if (checkpoint == null ||
              checkpoint.revision != 0 ||
              !checkpoint.matchesLineage(candidate)) {
            throw const V3LmfPersistenceConflictException(
              'v3 initial session lost its exact durable checkpoint',
            );
          }
          final expectedDigest = await repository.initialCheckpointDigest(
            snapshot: candidate,
            authority: _checkpointAuthority,
          );
          if (checkpoint.checkpointDigest != expectedDigest) {
            throw const V3LmfPersistenceConflictException(
              'v3 initial session checkpoint digest diverged',
            );
          }
          return V3InitialSessionRegistration(
            sessionKey: sessionKey,
            checkpointDigest: checkpoint.checkpointDigest,
            wasAlreadyDurable: true,
          );
        }
        if (_sessions.length >= maxSessions) {
          throw const V3LmfPersistenceLimitException(
            'v3 session checkpoint limit exceeded',
          );
        }
        if (repository.checkpointForSession(
              candidate.sessionId,
              authority: _checkpointAuthority,
            ) !=
            null) {
          throw const V3LmfPersistenceConflictException(
            'v3 unregistered initial session already has a checkpoint',
          );
        }

        persistenceAttempted = true;
        final checkpoint = await repository.persist(
          snapshot: candidate,
          receipts: const <V3CheckpointReceipt>[],
          persistedAt: persistedAt,
          authority: _checkpointAuthority,
        );
        _sessions[sessionKey] = candidate;
        retained = true;
        return V3InitialSessionRegistration(
          sessionKey: sessionKey,
          checkpointDigest: checkpoint.checkpointDigest,
          wasAlreadyDurable: false,
        );
      } catch (_) {
        if (persistenceAttempted || repository.requiresRecovery) {
          _recoveryRequired = true;
        }
        rethrow;
      } finally {
        if (!retained) candidate.wipeSecrets();
      }
    });
  }

  /// Recomputes the deterministic revision-zero checkpoint digest for a
  /// prepared handoff without changing durable state.
  Future<String> initialCheckpointDigestFor(
    V3TripleRatchetState snapshot, {
    required V3InitialSessionHandoffAuthority authority,
  }) {
    return _serialized(() async {
      _ensureReady();
      _ensureClaimedInitialHandoffAuthority(authority);
      final repository = _checkpointRepository;
      if (repository == null) {
        throw StateError(
          'Layergram v3 durable checkpoint storage is not configured',
        );
      }
      return repository.initialCheckpointDigest(
        snapshot: snapshot,
        authority: _checkpointAuthority,
      );
    });
  }

  /// Confirms the currently registered durable session belongs to the stable
  /// lineage of an exact prepared revision-zero snapshot.
  Future<void> verifySessionExtendsInitial(
    V3TripleRatchetState initialSnapshot, {
    required V3InitialSessionHandoffAuthority authority,
  }) {
    return _serialized(() async {
      _ensureReady();
      _ensureClaimedInitialHandoffAuthority(authority);
      if (initialSnapshot.lifecycle != V3RatchetLifecycle.active ||
          initialSnapshot.revision != 0) {
        throw const FormatException(
          'Layergram v3 prepared initial session is invalid',
        );
      }
      await _validateSnapshot(initialSnapshot);
      final sessionId = initialSnapshot.sessionId;
      try {
        final current = _sessions[_sessionKey(sessionId)];
        final checkpoint = _checkpointRepository?.checkpointForSession(
          sessionId,
          authority: _checkpointAuthority,
        );
        if (current == null ||
            checkpoint == null ||
            current.revision < initialSnapshot.revision ||
            !checkpoint.matchesLineage(initialSnapshot)) {
          throw const V3LmfPersistenceConflictException(
            'v3 durable session does not extend prepared initial state',
          );
        }
        _validateStableSession(initialSnapshot, current);
      } finally {
        _wipe(sessionId);
      }
    });
  }

  /// Validates that a durable handshake completion still has a registered
  /// checkpoint. At revision zero the digest must be the exact initial digest;
  /// later checkpoints are accepted only as the controller-validated durable
  /// continuation of that same registered session.
  Future<void> verifyCommittedHandoffSession({
    required String sessionKey,
    required String initialCheckpointDigest,
    required V3InitialSessionHandoffAuthority authority,
  }) {
    return _serialized(() async {
      _ensureReady();
      _ensureClaimedInitialHandoffAuthority(authority);
      Uint8List? sessionId;
      Uint8List? digest;
      V3TripleRatchetState? durableSnapshot;
      try {
        sessionId = Uint8List.fromList(
          base64Url.decode(base64Url.normalize(sessionKey)),
        );
        digest = Uint8List.fromList(
          base64Url.decode(base64Url.normalize(initialCheckpointDigest)),
        );
        if (sessionId.length != V3LmfFrameCodec.sessionIdBytes ||
            digest.length != 32 ||
            _isAllZero(sessionId) ||
            _isAllZero(digest) ||
            _sessionKey(sessionId) != sessionKey ||
            base64UrlEncode(digest).replaceAll('=', '') !=
                initialCheckpointDigest) {
          throw const FormatException(
            'Invalid Layergram v3 committed handoff binding',
          );
        }
        final current = _sessions[sessionKey];
        final checkpoint = _checkpointRepository?.checkpointForSession(
          sessionId,
          authority: _checkpointAuthority,
        );
        if (current == null ||
            checkpoint == null ||
            checkpoint.revision != current.revision ||
            (checkpoint.revision == 0 &&
                checkpoint.checkpointDigest != initialCheckpointDigest)) {
          throw const V3LmfPersistenceConflictException(
            'v3 handshake completion lost its durable session checkpoint',
          );
        }
        durableSnapshot = checkpoint.decodeSnapshot();
        if (!_snapshotBytesEqual(current, durableSnapshot)) {
          throw const V3LmfPersistenceConflictException(
            'v3 handshake completion checkpoint diverged from session state',
          );
        }
      } on FormatException {
        rethrow;
      } catch (error) {
        if (error is V3LmfPersistenceConflictException) rethrow;
        throw FormatException(
          'Invalid Layergram v3 committed handoff binding',
          error,
        );
      } finally {
        if (sessionId != null) _wipe(sessionId);
        if (digest != null) _wipe(digest);
        durableSnapshot?.wipeSecrets();
      }
    });
  }

  /// Prevents direct session use after a higher-level initial handoff crossed
  /// a durable boundary but did not complete in this process instance.
  Future<void> markInitialHandoffRecoveryRequired({
    required V3InitialSessionHandoffAuthority authority,
  }) {
    return _serialized(() async {
      _ensureOpen();
      _ensureConfiguredInitialHandoffAuthority(authority);
      _recoveryRequired = true;
    });
  }

  /// Commits one outgoing Triple-Ratchet transition before exposing frames.
  ///
  /// The send journal is the commit point. If its write or later outbox
  /// materialization has an ambiguous result, this controller fails stopped;
  /// a fresh restore advances from the durable TR3 and reuses the exact stored
  /// frame bytes without invoking the ratchet or AEAD again.
  Future<V3SessionSendResult> sendMessage({
    required Uint8List sessionId,
    required int expectedRevision,
    required Uint8List plaintext,
    V3SckaBackend? backend,
    V3LmfFrameKind kind = V3LmfFrameKind.application,
    int expiresAtUnixSeconds = 0,
    DateTime? persistedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final sendJournal = _sendJournal;
      final outbox = _outbox;
      if (sendJournal == null || outbox == null) {
        throw StateError('Layergram v3 durable sending is not configured');
      }
      if (plaintext.isEmpty ||
          plaintext.length > V3LmfFrameCodec.maxAssembledPlaintextBytes) {
        throw ArgumentError.value(plaintext.length, 'plaintext.length');
      }
      if (kind != V3LmfFrameKind.application &&
          kind != V3LmfFrameKind.pqRatchet) {
        throw ArgumentError.value(kind, 'kind');
      }

      final key = _sessionKey(sessionId);
      final current = _sessions[key];
      if (current == null) {
        throw StateError('Layergram v3 session is not registered');
      }
      _rejectPendingRetirementTransition(key);
      if (current.revision != expectedRevision) {
        throw StateError('Layergram v3 session revision conflict');
      }
      final selectedBackend = _resolveSckaBackend(backend);

      final localPlaintext = Uint8List.fromList(plaintext);
      V3TripleRatchetTransition? transition;
      V3TripleRatchetState? pendingSnapshot;
      V3CommittedRecord? record;
      Uint8List? applicationBytes;
      Uint8List? ratchetBytes;
      Uint8List? encodedHeader;
      final nonces = <Uint8List>[];
      var durableEffect = false;
      try {
        transition = await V3TripleRatchetEngine.send(
          snapshot: current,
          backend: selectedBackend,
          kind: kind,
          expiresAtUnixSeconds: expiresAtUnixSeconds,
        );
        await _validateOutgoingCandidate(
          previous: current,
          candidate: transition.nextSnapshot,
          metadata: transition.metadata,
        );

        encodedHeader = V3HybridRatchetHeaderCodec.encode(transition.header);
        final fragmentCount = V3LmfFrameCodec.canonicalFragmentCount(
          assembledPlaintextLength: localPlaintext.length,
          hybridRatchetHeaderLength: encodedHeader.length,
        );
        for (var index = 0; index < fragmentCount; index++) {
          nonces.add(
            await transition.nonceForFragment(
              fragmentIndex: index,
              fragmentCount: fragmentCount,
              assembledPlaintextLength: localPlaintext.length,
            ),
          );
        }
        final frames = await V3LmfAead.sealFragmented(
          metadata: transition.metadata,
          plaintext: localPlaintext,
          secretKey: transition.secretKey,
          nonceForFragment: (index) => Uint8List.fromList(nonces[index]),
          hybridRatchetHeader: transition.header,
        );
        await outbox.preflightEnqueue(
          frames,
          authority: _outboxAuthority,
        );
        record = V3CommittedRecord.fromDelivery(
          targetFrame: frames.first,
          content: localPlaintext,
        );
        applicationBytes = V3CommittedRecordCodec.encode(record);
        ratchetBytes = V3TripleRatchetStateCodec.encode(
          transition.nextSnapshot,
        );
        pendingSnapshot = _copySnapshot(transition.nextSnapshot);

        final effect = await sendJournal.persist(
          previousRatchetRevision: current.revision,
          frames: frames,
          applicationState: applicationBytes,
          ratchetState: ratchetBytes,
          persistedAt: persistedAt,
          authority: _sendAuthority,
        );
        durableEffect = true;
        final decoded = _decodeSendEffect(effect);
        try {
          if (decoded.sessionKey != key ||
              !_snapshotBytesEqual(decoded.snapshot, pendingSnapshot)) {
            throw const V3LmfPersistenceConflictException(
              'durable v3 send effect differs from its prepared transition',
            );
          }
        } finally {
          decoded.close();
        }

        final queued = await outbox.enqueue(
          effect.frames,
          queuedAt: effect.persistedAt,
          authority: _outboxAuthority,
        );
        if (!_sameFrameSet(queued.frames, effect.frames)) {
          throw const V3LmfPersistenceConflictException(
            'v3 outbox changed committed sealed bytes',
          );
        }

        final next = pendingSnapshot;
        pendingSnapshot = null;
        current.wipeSecrets();
        _sessions[key] = next;
        _sendEffects[effect.assemblyId] = effect;
        await _materializeAndCheckpointSession(key);
        return V3SessionSendResult(
          assemblyId: effect.assemblyId,
          messageRecordId: effect.messageRecordId,
          ratchetRevision: next.revision,
          frames: List<V3LmfFrame>.unmodifiable(effect.frames),
        );
      } catch (_) {
        if (durableEffect || sendJournal.requiresRecovery) {
          _recoveryRequired = true;
        }
        rethrow;
      } finally {
        _wipe(localPlaintext);
        for (final nonce in nonces) {
          _wipe(nonce);
        }
        if (encodedHeader != null) _wipe(encodedHeader);
        if (applicationBytes != null) _wipe(applicationBytes);
        if (ratchetBytes != null) _wipe(ratchetBytes);
        record?.wipeContent();
        pendingSnapshot?.wipeSecrets();
        transition?.close();
      }
    });
  }

  Future<List<V3LmfFrame>> pendingSendFrames(String assemblyId) {
    return _serialized(() async {
      _ensureReady();
      final outbox = _outbox;
      if (outbox == null) {
        throw StateError('Layergram v3 durable sending is not configured');
      }
      final effect = _sendEffects[assemblyId];
      if (effect == null || effect.isFullyAcknowledged) {
        return const <V3LmfFrame>[];
      }
      return outbox.pendingFrames(
        assemblyId,
        authority: _outboxAuthority,
      );
    });
  }

  Future<V3PendingSessionSendBinding?> pendingSendForTransition({
    required Uint8List sessionId,
    required int previousRatchetRevision,
  }) {
    return _serialized(() async {
      _ensureReady();
      final sessionKey = _sessionKey(sessionId);
      V3SessionSendEffect? match;
      for (final effect in _sendEffects.values) {
        final targetSession =
            _sessionKey(effect.frames.first.metadata.sessionId);
        if (targetSession != sessionKey ||
            effect.previousRatchetRevision != previousRatchetRevision) {
          continue;
        }
        if (match != null && match.assemblyId != effect.assemblyId) {
          throw const V3LmfPersistenceConflictException(
            'multiple v3 sends claim one session transition',
          );
        }
        match = effect;
      }
      if (match == null) return null;
      return V3PendingSessionSendBinding(
        assemblyId: match.assemblyId,
        previousRatchetRevision: match.previousRatchetRevision,
        ratchetRevision: match.revision,
        isFullyAcknowledged: match.isFullyAcknowledged,
      );
    });
  }

  Future<V3LmfOutboxEntry> markSendExported({
    required String assemblyId,
    required Set<int> fragmentIndexes,
    DateTime? exportedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final outbox = _outbox;
      final effect = _sendEffects[assemblyId];
      if (outbox == null || effect == null || effect.isFullyAcknowledged) {
        throw StateError('Unknown pending Layergram v3 send assembly');
      }
      var persistenceAttempted = false;
      try {
        return await outbox.markExported(
          assemblyId: assemblyId,
          fragmentIndexes: fragmentIndexes,
          exportedAt: exportedAt,
          beforePersist: (_) {
            persistenceAttempted = true;
          },
          authority: _outboxAuthority,
        );
      } catch (_) {
        if (persistenceAttempted) _recoveryRequired = true;
        rethrow;
      }
    });
  }

  Future<V3LmfOutboxAckStatus> applySendAcknowledgement({
    required V3LmfFrame acknowledgementFrame,
    DateTime? receivedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final sendJournal = _sendJournal;
      final outbox = _outbox;
      if (sendJournal == null || outbox == null) {
        throw StateError('Layergram v3 durable sending is not configured');
      }
      if (acknowledgementFrame.metadata.kind !=
          V3LmfFrameKind.acknowledgement) {
        throw const FormatException('Layergram v3 frame is not an ACK');
      }
      final snapshot =
          _sessions[_sessionKey(acknowledgementFrame.metadata.sessionId)];
      if (snapshot == null) {
        throw const FormatException(
          'Layergram v3 ACK session is not registered',
        );
      }
      final direction = snapshot.role == V3SessionRole.initiator
          ? V3TrafficDirection.responderToInitiator
          : V3TrafficDirection.initiatorToResponder;
      final sessionId = snapshot.sessionId;
      final initiatorBinding = snapshot.initiatorRoutingBinding;
      final responderBinding = snapshot.responderRoutingBinding;
      final initiatorAckRoot = snapshot.initiatorToResponderAckRootKey;
      final responderAckRoot = snapshot.responderToInitiatorAckRootKey;
      V3AcknowledgementKeyMaterial? acknowledgementKeys;
      String? completedAssemblyId;
      var outboxPersistenceAttempted = false;
      try {
        acknowledgementKeys =
            await V3KeySchedule.deriveAcknowledgementFromCommittedState(
          sessionId: sessionId,
          initiatorRoutingBinding: initiatorBinding,
          responderRoutingBinding: responderBinding,
          initiatorToResponderAckRootKey: initiatorAckRoot,
          responderToInitiatorAckRootKey: responderAckRoot,
          direction: direction,
          metadata: acknowledgementFrame.metadata,
        );
        final nonce = acknowledgementFrame.nonce;
        try {
          if (!acknowledgementKeys.matchesNonce(nonce)) {
            throw const FormatException(
              'Layergram v3 ACK nonce does not match committed session state',
            );
          }
        } finally {
          _wipe(nonce);
        }
        final status = await outbox.applyAcknowledgement(
          acknowledgementFrame: acknowledgementFrame,
          secretKey: acknowledgementKeys.secretKey,
          receivedAt: receivedAt,
          authority: _outboxAuthority,
          beforePersist: (_) {
            outboxPersistenceAttempted = true;
          },
          beforeComplete: (completedEntry) async {
            final effect = _sendEffects[completedEntry.assemblyId];
            if (effect == null ||
                !_sameFrameSet(effect.frames, completedEntry.frames)) {
              throw const V3LmfPersistenceConflictException(
                'complete ACK has no matching durable v3 send effect',
              );
            }
            final completed = await sendJournal.markFullyAcknowledged(
              assemblyId: completedEntry.assemblyId,
              acknowledgedAt: receivedAt,
              authority: _sendAuthority,
            );
            _sendEffects[completed.assemblyId] = completed;
            completedAssemblyId = completed.assemblyId;
          },
        );
        if (status == V3LmfOutboxAckStatus.complete) {
          final assemblyId = completedAssemblyId;
          if (assemblyId == null) {
            throw const V3LmfPersistenceConflictException(
              'complete ACK bypassed the v3 send-journal commit',
            );
          }
          await outbox.removeFullyAcknowledged(
            assemblyId,
            authority: _outboxAuthority,
          );
        }
        return status;
      } catch (_) {
        if (outboxPersistenceAttempted ||
            completedAssemblyId != null ||
            sendJournal.requiresRecovery) {
          _recoveryRequired = true;
        }
        rethrow;
      } finally {
        acknowledgementKeys?.close();
        _wipe(sessionId);
        _wipe(initiatorBinding);
        _wipe(responderBinding);
        _wipe(initiatorAckRoot);
        _wipe(responderAckRoot);
      }
    });
  }

  /// Atomically commits one new AR3/TR3 effect under revision CAS.
  Future<V3SessionCommitResult> commitDelivery({
    required V3LmfDurableDelivery delivery,
    required int expectedRevision,
    required V3SessionTransitionBuilder transitionBuilder,
    DateTime? persistedAt,
  }) {
    return _serialized(() async {
      _ensureReady();
      final target = _validatedTarget(delivery);
      final sessionKey = _sessionKey(target.metadata.sessionId);
      final current = _sessions[sessionKey];
      if (current == null) {
        throw StateError('Layergram v3 delivery session is not registered');
      }
      _rejectPendingRetirementTransition(sessionKey);
      _validateInboundRouting(current, target);
      if (current.revision != expectedRevision) {
        throw StateError('Layergram v3 session revision conflict');
      }

      final existing = _journal.effectForAssembly(
        delivery.assemblyId,
        authority: _authority,
      );
      if (existing != null) {
        final revision = await _validateKnownEffect(
          effect: existing,
          current: current,
          expectedSessionKey: sessionKey,
        );
        try {
          final resumed = await _journal.resume(
            delivery: delivery,
            authority: _authority,
          );
          _pendingInboxCommits.remove(delivery.assemblyId);
          return V3SessionCommitResult(
            effect: resumed,
            ratchetRevision: revision,
            wasAlreadyDurable: true,
          );
        } catch (_) {
          _recoveryRequired = true;
          rethrow;
        }
      }

      V3TripleRatchetState? pendingSnapshot;
      var effectPrepared = false;
      try {
        final committed = await _journal.commit(
          delivery: delivery,
          persistedAt: persistedAt,
          authority: _authority,
          builder: (plaintext) async {
            final builderSnapshot = _copySnapshot(current);
            V3TripleRatchetState? candidate;
            final record = V3CommittedRecord.fromDelivery(
              targetFrame: target,
              content: plaintext,
            );
            final transitionPlaintext = Uint8List.fromList(plaintext);
            Uint8List? applicationBytes;
            Uint8List? ratchetBytes;
            try {
              candidate = await transitionBuilder(
                transitionPlaintext,
                builderSnapshot,
                target.hybridRatchetHeader!,
              );
              await _validateTransition(
                previous: current,
                candidate: candidate,
                effect: null,
                record: record,
                targetOverride: target,
              );
              applicationBytes = V3CommittedRecordCodec.encode(record);
              ratchetBytes = V3TripleRatchetStateCodec.encode(candidate);
              pendingSnapshot = _copySnapshot(candidate);
              effectPrepared = true;
              return V3LmfAtomicEffect(
                applicationState: applicationBytes,
                ratchetState: ratchetBytes,
              );
            } finally {
              _wipe(transitionPlaintext);
              builderSnapshot.wipeSecrets();
              candidate?.wipeSecrets();
              record.wipeContent();
              if (applicationBytes != null) _wipe(applicationBytes);
              if (ratchetBytes != null) _wipe(ratchetBytes);
            }
          },
        );
        if (!effectPrepared || pendingSnapshot == null) {
          _recoveryRequired = true;
          throw const V3LmfPersistenceConflictException(
            'v3 journal returned an unexpected pre-existing session effect',
          );
        }

        final decoded = _decodeEffect(committed);
        try {
          if (decoded.sessionKey != sessionKey ||
              !_snapshotBytesEqual(decoded.snapshot, pendingSnapshot!)) {
            _recoveryRequired = true;
            throw const V3LmfPersistenceConflictException(
              'durable v3 effect differs from the prepared session candidate',
            );
          }
        } finally {
          decoded.close();
        }

        final next = pendingSnapshot!;
        pendingSnapshot = null;
        current.wipeSecrets();
        _sessions[sessionKey] = next;
        _effectRevisions[delivery.assemblyId] = next.revision;
        _pendingInboxCommits.remove(delivery.assemblyId);
        await _materializeAndCheckpointSession(sessionKey);
        return V3SessionCommitResult(
          effect: committed,
          ratchetRevision: next.revision,
          wasAlreadyDurable: false,
        );
      } catch (_) {
        if (effectPrepared) _recoveryRequired = true;
        rethrow;
      } finally {
        pendingSnapshot?.wipeSecrets();
      }
    });
  }

  /// Reconciles the inbox tombstone for an already durable session effect.
  Future<V3SessionCommitResult> resumeDurableDelivery({
    required V3LmfDurableDelivery delivery,
  }) {
    return _serialized(() async {
      _ensureReady();
      final target = _validatedTarget(delivery);
      final sessionKey = _sessionKey(target.metadata.sessionId);
      final current = _sessions[sessionKey];
      if (current == null) {
        throw StateError('Layergram v3 delivery session is not registered');
      }
      _validateInboundRouting(current, target);
      final existing = _journal.effectForAssembly(
        delivery.assemblyId,
        authority: _authority,
      );
      if (existing == null) {
        throw StateError('Layergram v3 delivery has no durable session effect');
      }
      final revision = await _validateKnownEffect(
        effect: existing,
        current: current,
        expectedSessionKey: sessionKey,
      );
      try {
        final resumed = await _journal.resume(
          delivery: delivery,
          authority: _authority,
        );
        _pendingInboxCommits.remove(delivery.assemblyId);
        return V3SessionCommitResult(
          effect: resumed,
          ratchetRevision: revision,
          wasAlreadyDurable: true,
        );
      } catch (_) {
        _recoveryRequired = true;
        rethrow;
      }
    });
  }

  /// Safely compacts journal state covered by one durable session checkpoint.
  ///
  /// Incoming effects first replace their bound inbox tombstone with a compact
  /// replay-window record. Outgoing effects are collectable only after a full
  /// authenticated ACK and physical outbox removal. AR3 materialization and an
  /// exact cumulative checkpoint receipt are revalidated before every delete.
  Future<V3SessionCompactionResult> compactSession(Uint8List sessionId) {
    return _serialized(() async {
      _ensureReady();
      final materializer = _committedRecordMaterializer;
      final checkpoints = _checkpointRepository;
      if (materializer == null || checkpoints == null) {
        throw StateError('Layergram v3 durable compaction is not configured');
      }
      final sessionKey = _sessionKey(sessionId);
      final current = _sessions[sessionKey];
      if (current == null) {
        throw StateError('Layergram v3 session is not registered');
      }
      final checkpoint = checkpoints.checkpointForSession(
        sessionId,
        authority: _checkpointAuthority,
      );
      if (checkpoint == null || checkpoint.revision != current.revision) {
        throw const V3LmfPersistenceConflictException(
          'v3 session has no current durable checkpoint',
        );
      }
      final durableSnapshot = checkpoint.decodeSnapshot();
      try {
        if (!_snapshotBytesEqual(current, durableSnapshot)) {
          throw const V3LmfPersistenceConflictException(
            'v3 durable checkpoint differs from current session state',
          );
        }
      } finally {
        durableSnapshot.wipeSecrets();
      }

      var incomingCollected = 0;
      var outgoingCollected = 0;
      try {
        for (final receipt in checkpoint.receipts) {
          if (receipt.sessionKey != sessionKey ||
              receipt.ratchetRevision > checkpoint.revision) {
            throw const V3LmfPersistenceConflictException(
              'v3 checkpoint contains an invalid compaction receipt',
            );
          }
          if (receipt.direction == V3CheckpointEffectDirection.incoming) {
            final effect = _journal.effectForAssembly(
              receipt.assemblyId,
              authority: _authority,
            );
            if (effect == null) continue;
            _validateCheckpointCoverage(
              checkpoint: checkpoint,
              direction: V3CheckpointEffectDirection.incoming,
              assemblyId: effect.assemblyId,
              applicationState: effect.applicationState,
              ratchetState: effect.ratchetState,
            );
            final replay = await _journal.retireTombstoneToReplayWindow(
              assemblyId: effect.assemblyId,
              expectedEffectDigest: effect.effectDigest,
              stableRecordId: receipt.stableRecordId,
              sessionKey: receipt.sessionKey,
              ratchetRevision: receipt.ratchetRevision,
              checkpointDigest: checkpoint.checkpointDigest,
              authority: _authority,
            );
            if (replay.stableRecordId != receipt.stableRecordId ||
                replay.sessionKey != receipt.sessionKey ||
                replay.ratchetRevision != receipt.ratchetRevision) {
              throw const V3LmfPersistenceConflictException(
                'v3 replay window differs from checkpoint receipt',
              );
            }
            if (await _journal.collectCompactedEffect(
              assemblyId: effect.assemblyId,
              expectedEffectDigest: effect.effectDigest,
              authority: _authority,
            )) {
              _effectRevisions.remove(effect.assemblyId);
              _pendingInboxCommits.remove(effect.assemblyId);
              incomingCollected++;
            }
            continue;
          }

          final sendJournal = _sendJournal;
          final outbox = _outbox;
          if (sendJournal == null || outbox == null) continue;
          final effect = sendJournal.effectForAssembly(
            receipt.assemblyId,
            authority: _sendAuthority,
          );
          if (effect == null || !effect.isFullyAcknowledged) continue;
          if (outbox.entry(
                effect.assemblyId,
                authority: _outboxAuthority,
              ) !=
              null) {
            throw const V3LmfPersistenceConflictException(
              'v3 acknowledged send effect still has an outbox entry',
            );
          }
          _validateCheckpointCoverage(
            checkpoint: checkpoint,
            direction: V3CheckpointEffectDirection.outgoing,
            assemblyId: effect.assemblyId,
            applicationState: effect.applicationState,
            ratchetState: effect.ratchetState,
          );
          final effectDigest = effect.effectDigest;
          if (await sendJournal.collectFullyAcknowledged(
            assemblyId: effect.assemblyId,
            expectedEffectDigest: effectDigest,
            stableRecordId: receipt.stableRecordId,
            sessionKey: receipt.sessionKey,
            ratchetRevision: receipt.ratchetRevision,
            checkpointDigest: checkpoint.checkpointDigest,
            authority: _sendAuthority,
          )) {
            _sendEffects.remove(effect.assemblyId);
            outgoingCollected++;
          }
        }
      } catch (_) {
        if (_journal.requiresRecovery ||
            (_sendJournal?.requiresRecovery ?? false)) {
          _recoveryRequired = true;
        }
        rethrow;
      }
      return V3SessionCompactionResult(
        collectedIncomingEffects: incomingCollected,
        collectedOutgoingEffects: outgoingCollected,
        replayWindowEntries: incomingCollected,
      );
    });
  }

  /// Lists current receipt identifiers without exposing checkpoint or ratchet
  /// state. Eligibility is still recomputed by
  /// [replaceEligibleCheckpointReceipt] immediately before any mutation.
  Future<List<V3SessionReceiptRetentionCandidate>>
      receiptRetentionCandidates() {
    return _serialized(() async {
      _ensureReady();
      final checkpoints = _checkpointRepository;
      if (checkpoints == null) {
        throw StateError(
          'Layergram v3 receipt retention is not configured',
        );
      }
      final candidates = <V3SessionReceiptRetentionCandidate>[
        for (final checkpoint in checkpoints.checkpoints(
          authority: _checkpointAuthority,
        ))
          for (final receipt in checkpoint.receipts)
            V3SessionReceiptRetentionCandidate(
              sessionKey: checkpoint.sessionKey,
              assemblyId: receipt.assemblyId,
            ),
      ]..sort((left, right) {
          final bySession = left.sessionKey.compareTo(right.sessionKey);
          return bySession != 0
              ? bySession
              : left.assemblyId.compareTo(right.assemblyId);
        });
      return List<V3SessionReceiptRetentionCandidate>.unmodifiable(
        candidates,
      );
    });
  }

  /// Retires one eligible checkpoint receipt and its compact proof.
  ///
  /// Eligibility is recomputed from the committed snapshot and compact proof.
  /// The retirement intent, pending replacement, and self-contained final
  /// checkpoint are each written before the exact compact proof and plan are
  /// deleted. A restart resumes any interrupted boundary idempotently.
  Future<V3SessionReceiptRetirementResult> replaceEligibleCheckpointReceipt({
    required String assemblyId,
    required V3RetentionPolicy policy,
    required DateTime now,
  }) {
    return _serialized(() async {
      _ensureReady();
      final checkpoints = _checkpointRepository;
      final retirement = _retirementJournal;
      final materializer = _committedRecordMaterializer;
      if (checkpoints == null || retirement == null || materializer == null) {
        throw StateError('Layergram v3 receipt retirement is not configured');
      }

      V3SessionCheckpoint? checkpoint;
      V3CheckpointReceipt? receipt;
      for (final candidate in checkpoints.checkpoints(
        authority: _checkpointAuthority,
      )) {
        final candidateReceipt = candidate.receiptForAssembly(assemblyId);
        final retired = candidate.retirementTransition?.retiredReceipt;
        if (candidateReceipt == null && retired?.assemblyId != assemblyId) {
          continue;
        }
        if (checkpoint != null) {
          throw const V3LmfPersistenceConflictException(
            'v3 receipt retirement assembly is not unique',
          );
        }
        checkpoint = candidate;
        receipt = candidateReceipt ?? retired;
      }
      if (checkpoint == null || receipt == null) {
        throw StateError('Layergram v3 checkpoint receipt was not found');
      }
      final current = _sessions[checkpoint.sessionKey];
      if (current == null || current.revision != checkpoint.revision) {
        throw const V3LmfPersistenceConflictException(
          'v3 receipt retirement has no current committed snapshot',
        );
      }
      final retirementPlans = retirement.plans(
        authority: _retirementAuthority,
      );
      if (retirementPlans.any(
        (candidate) =>
            candidate.sessionKey == checkpoint!.sessionKey &&
            candidate.assemblyId != assemblyId,
      )) {
        throw const V3LmfPersistenceConflictException(
          'v3 session already has a different pending retirement',
        );
      }
      final existingPlans = retirementPlans
          .where((candidate) => candidate.assemblyId == assemblyId)
          .toList(growable: false);
      if (existingPlans.length > 1) {
        throw const V3LmfPersistenceConflictException(
          'multiple v3 retirement plans target one assembly',
        );
      }
      final existingPlan = existingPlans.isEmpty ? null : existingPlans.single;
      final decision = _evaluateRetirementEligibility(
        policy: policy,
        now: now,
        current: current,
        receipt: receipt,
        materializer: materializer,
      );
      if (!decision.eligible) {
        return V3SessionReceiptRetirementResult(
          decision: decision,
          planId: existingPlan?.planId,
          replacementCheckpointDigest: null,
        );
      }

      final proof = _retirementProofForReceipt(receipt);
      if (existingPlan != null &&
          (existingPlan.stage != V3SessionRetirementStage.prepared ||
              existingPlan.sourceCheckpointDigest !=
                  checkpoint.checkpointDigest ||
              !_retirementReceiptMatches(existingPlan, receipt) ||
              existingPlan.proofDigest != proof.digest ||
              !existingPlan.proofRecordedAt.isAtSameMomentAs(
                proof.recordedAt,
              ))) {
        throw const V3LmfPersistenceConflictException(
          'prepared v3 retirement plan no longer matches durable state',
        );
      }
      try {
        final plan = existingPlan ??
            await retirement.prepare(
              direction: receipt.direction,
              assemblyId: receipt.assemblyId,
              proofDigest: proof.digest,
              stableRecordId: receipt.stableRecordId,
              sessionKey: receipt.sessionKey,
              ratchetRevision: receipt.ratchetRevision,
              stateDigest: receipt.stateDigest,
              sourceCheckpointDigest: checkpoint.checkpointDigest,
              proofRecordedAt: proof.recordedAt,
              preparedAt: now,
              minimumProofLifetimeSeconds: policy.minimumProofLifetimeSeconds,
              authority: _retirementAuthority,
            );
        final finalized = await _finalizeRetirementPlan(
          plan: plan,
          checkpoint: checkpoint,
          persistedAt: now,
        );
        await checkpoints.cleanupValidatedRetirementSources(
          authority: _checkpointAuthority,
        );
        return V3SessionReceiptRetirementResult(
          decision: decision,
          planId: plan.planId,
          replacementCheckpointDigest: finalized.checkpointDigest,
        );
      } catch (_) {
        if (retirement.requiresRecovery || checkpoints.requiresRecovery) {
          _recoveryRequired = true;
        }
        rethrow;
      }
    });
  }

  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      try {
        await _journal.close(authority: _authority);
      } finally {
        try {
          final sendJournal = _sendJournal;
          if (sendJournal != null) {
            await sendJournal.close(authority: _sendAuthority);
          }
        } finally {
          try {
            final outbox = _outbox;
            if (outbox != null) {
              await outbox.close(authority: _outboxAuthority);
            }
          } finally {
            try {
              final materializer = _committedRecordMaterializer;
              if (materializer != null) {
                await materializer.close(authority: _materializerAuthority);
              }
            } finally {
              try {
                final checkpointRepository = _checkpointRepository;
                if (checkpointRepository != null) {
                  await checkpointRepository.close(
                    authority: _checkpointAuthority,
                  );
                }
              } finally {
                try {
                  final retirementJournal = _retirementJournal;
                  if (retirementJournal != null) {
                    await retirementJournal.close(
                      authority: _retirementAuthority,
                    );
                  }
                } finally {
                  for (final snapshot in _sessions.values) {
                    snapshot.wipeSecrets();
                  }
                  _sessions.clear();
                  _effectRevisions.clear();
                  _pendingInboxCommits.clear();
                  _sendEffects.clear();
                }
              }
            }
          }
        }
      }
    });
  }

  V3RetentionDecision _evaluateRetirementEligibility({
    required V3RetentionPolicy policy,
    required DateTime now,
    required V3TripleRatchetState current,
    required V3CheckpointReceipt receipt,
    required V3CommittedRecordMaterializer materializer,
  }) {
    switch (receipt.direction) {
      case V3CheckpointEffectDirection.incoming:
        final proof = _journal.replayWindowBindingForAssembly(
          receipt.assemblyId,
          authority: _authority,
        );
        if (proof == null ||
            proof.stableRecordId != receipt.stableRecordId ||
            proof.sessionKey != receipt.sessionKey ||
            proof.ratchetRevision != receipt.ratchetRevision) {
          throw const V3LmfPersistenceConflictException(
            'v3 incoming retirement lost its compact proof',
          );
        }
        final materialized = materializer.recordForStableId(
          receipt.stableRecordId,
          authority: _materializerAuthority,
        );
        if (materialized == null ||
            materialized.sessionKey != receipt.sessionKey ||
            materialized.assemblyId != receipt.assemblyId) {
          throw const V3LmfPersistenceConflictException(
            'v3 incoming retirement lost its application record',
          );
        }
        final record = materialized.decodeRecord();
        final sessionId = current.sessionId;
        try {
          return policy.evaluateIncomingReplay(
            snapshot: current,
            targetSessionId: sessionId,
            targetEpoch: record.epoch,
            targetMessageCounter: record.messageCounter,
            committedAt: proof.committedAt,
            now: now,
          );
        } finally {
          record.wipeContent();
          _wipe(sessionId);
        }
      case V3CheckpointEffectDirection.outgoing:
        final sendJournal = _sendJournal;
        final outbox = _outbox;
        if (sendJournal == null || outbox == null) {
          throw StateError(
              'Layergram v3 outgoing retirement is not configured');
        }
        final proof = sendJournal.completionBindingForAssembly(
          receipt.assemblyId,
          authority: _sendAuthority,
        );
        if (proof == null ||
            proof.stableRecordId != receipt.stableRecordId ||
            proof.sessionKey != receipt.sessionKey ||
            proof.ratchetRevision != receipt.ratchetRevision) {
          throw const V3LmfPersistenceConflictException(
            'v3 outgoing retirement lost its completion proof',
          );
        }
        final outboxAbsent = outbox.entry(
              receipt.assemblyId,
              authority: _outboxAuthority,
            ) ==
            null;
        return policy.evaluateOutgoingCompletion(
          fullyAcknowledged: true,
          outboxEntryAbsent: outboxAbsent,
          completedAt: proof.completedAt,
          now: now,
        );
    }
  }

  void _rejectPendingRetirementTransition(String sessionKey) {
    final retirement = _retirementJournal;
    if (retirement == null) return;
    if (retirement
        .plans(authority: _retirementAuthority)
        .any((plan) => plan.sessionKey == sessionKey)) {
      throw StateError(
        'Layergram v3 session retirement must be finalized before ratchet advance',
      );
    }
  }

  _RetirementProof _retirementProofForReceipt(
    V3CheckpointReceipt receipt,
  ) {
    switch (receipt.direction) {
      case V3CheckpointEffectDirection.incoming:
        final proof = _journal.replayWindowBindingForAssembly(
          receipt.assemblyId,
          authority: _authority,
        );
        if (proof == null ||
            proof.stableRecordId != receipt.stableRecordId ||
            proof.sessionKey != receipt.sessionKey ||
            proof.ratchetRevision != receipt.ratchetRevision) {
          throw const V3LmfPersistenceConflictException(
            'v3 incoming retirement proof diverged',
          );
        }
        return _RetirementProof(
          digest: proof.higherLevelCommitDigest,
          recordedAt: proof.committedAt,
        );
      case V3CheckpointEffectDirection.outgoing:
        final proof = _sendJournal?.completionBindingForAssembly(
          receipt.assemblyId,
          authority: _sendAuthority,
        );
        if (proof == null ||
            proof.stableRecordId != receipt.stableRecordId ||
            proof.sessionKey != receipt.sessionKey ||
            proof.ratchetRevision != receipt.ratchetRevision) {
          throw const V3LmfPersistenceConflictException(
            'v3 outgoing retirement proof diverged',
          );
        }
        return _RetirementProof(
          digest: proof.effectDigest,
          recordedAt: proof.completedAt,
        );
    }
  }

  Future<void> _reconcileRetirementPlans({
    required List<V3SessionRetirementPlan> plans,
    required Map<String, V3SessionCheckpoint> checkpoints,
  }) async {
    final journal = _retirementJournal!;
    final byAssembly = <String, V3SessionRetirementPlan>{};
    for (final plan in plans) {
      if (byAssembly.putIfAbsent(plan.assemblyId, () => plan) != plan) {
        throw const V3LmfPersistenceConflictException(
          'multiple v3 retirement plans target one assembly',
        );
      }
    }
    for (final checkpoint in checkpoints.values) {
      final transition = checkpoint.retirementTransition;
      if (transition == null) continue;
      final plan = byAssembly[transition.retiredReceipt.assemblyId];
      if (plan == null) {
        if (transition.isFinalized) continue;
        throw const V3LmfPersistenceConflictException(
          'pending v3 retirement checkpoint has no prepared plan',
        );
      }
      if (!_retirementTransitionMatchesPlan(
        plan: plan,
        checkpoint: checkpoint,
      )) {
        throw const V3LmfPersistenceConflictException(
          'v3 retirement checkpoint has no exact prepared plan',
        );
      }
      if (!transition.isFinalized &&
          plan.stage == V3SessionRetirementStage.prepared) {
        try {
          await journal.markCheckpointReplaced(
            planId: plan.planId,
            expectedSourceCheckpointDigest: plan.sourceCheckpointDigest,
            replacementCheckpointDigest: checkpoint.checkpointDigest,
            authority: _retirementAuthority,
          );
        } catch (_) {
          if (journal.requiresRecovery) _recoveryRequired = true;
          rethrow;
        }
      } else if (!transition.isFinalized &&
          (plan.stage != V3SessionRetirementStage.checkpointReplaced ||
              plan.replacementCheckpointDigest !=
                  checkpoint.checkpointDigest)) {
        throw const V3LmfPersistenceConflictException(
          'v3 retirement journal and checkpoint replacement diverged',
        );
      } else if (transition.isFinalized &&
          plan.stage == V3SessionRetirementStage.checkpointReplaced) {
        try {
          await journal.markFinalCheckpointWritten(
            planId: plan.planId,
            expectedReplacementCheckpointDigest:
                plan.replacementCheckpointDigest!,
            finalCheckpointDigest: checkpoint.checkpointDigest,
            authority: _retirementAuthority,
          );
        } catch (_) {
          if (journal.requiresRecovery) _recoveryRequired = true;
          rethrow;
        }
      } else if (transition.isFinalized &&
          (plan.stage != V3SessionRetirementStage.finalCheckpointWritten ||
              plan.finalCheckpointDigest != checkpoint.checkpointDigest)) {
        throw const V3LmfPersistenceConflictException(
          'v3 retirement journal and final checkpoint diverged',
        );
      }
    }
  }

  void _validateRetirementPlans({
    required List<V3SessionRetirementPlan> plans,
    required Map<String, V3SessionCheckpoint> checkpoints,
    required Map<String, V3LmfReplayWindowBinding> incomingProofs,
    required Map<String, V3SessionSendCompletionBinding> outgoingProofs,
  }) {
    final plannedSessions = <String>{};
    for (final plan in plans) {
      if (!plannedSessions.add(plan.sessionKey)) {
        throw const V3LmfPersistenceConflictException(
          'multiple v3 retirement plans target one session',
        );
      }
      final checkpoint = checkpoints[plan.sessionKey];
      final expectedCheckpointDigest = switch (plan.stage) {
        V3SessionRetirementStage.prepared => plan.sourceCheckpointDigest,
        V3SessionRetirementStage.checkpointReplaced =>
          plan.replacementCheckpointDigest,
        V3SessionRetirementStage.finalCheckpointWritten =>
          plan.finalCheckpointDigest,
      };
      if (checkpoint == null ||
          checkpoint.checkpointDigest != expectedCheckpointDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 retirement plan has no exact durable checkpoint',
        );
      }

      final receipt = checkpoint.receiptForAssembly(plan.assemblyId);
      if (plan.stage == V3SessionRetirementStage.prepared) {
        if (receipt == null || !_retirementReceiptMatches(plan, receipt)) {
          throw const V3LmfPersistenceConflictException(
            'prepared v3 retirement plan lost its exact checkpoint receipt',
          );
        }
      } else if (receipt != null ||
          !_retirementTransitionMatchesPlan(
            plan: plan,
            checkpoint: checkpoint,
          )) {
        throw const V3LmfPersistenceConflictException(
          'replaced v3 retirement checkpoint has an invalid transition',
        );
      }

      switch (plan.direction) {
        case V3CheckpointEffectDirection.incoming:
          final proof = incomingProofs[plan.assemblyId];
          if (proof == null && plan.finalCheckpointWasWritten) break;
          if (proof == null ||
              proof.higherLevelCommitDigest != plan.proofDigest ||
              proof.stableRecordId != plan.stableRecordId ||
              proof.sessionKey != plan.sessionKey ||
              proof.ratchetRevision != plan.ratchetRevision ||
              !proof.committedAt.isAtSameMomentAs(plan.proofRecordedAt)) {
            throw const V3LmfPersistenceConflictException(
              'v3 retirement plan has no exact incoming replay proof',
            );
          }
          break;
        case V3CheckpointEffectDirection.outgoing:
          final proof = outgoingProofs[plan.assemblyId];
          if (proof == null && plan.finalCheckpointWasWritten) break;
          if (proof == null ||
              proof.effectDigest != plan.proofDigest ||
              proof.stableRecordId != plan.stableRecordId ||
              proof.sessionKey != plan.sessionKey ||
              proof.ratchetRevision != plan.ratchetRevision ||
              !proof.completedAt.isAtSameMomentAs(plan.proofRecordedAt)) {
            throw const V3LmfPersistenceConflictException(
              'v3 retirement plan has no exact outgoing completion proof',
            );
          }
          break;
      }
    }
  }

  Future<void> _finalizeRetirementPlans({
    required List<V3SessionRetirementPlan> plans,
    required Map<String, V3SessionCheckpoint> checkpoints,
  }) async {
    for (final originalPlan in plans) {
      final checkpoint = checkpoints[originalPlan.sessionKey];
      if (checkpoint == null) {
        throw const V3LmfPersistenceConflictException(
          'v3 retirement finalization lost its checkpoint',
        );
      }
      final finalized = await _finalizeRetirementPlan(
        plan: originalPlan,
        checkpoint: checkpoint,
        persistedAt: checkpoint.persistedAt,
      );
      checkpoints[originalPlan.sessionKey] = finalized;
    }
  }

  Future<V3SessionCheckpoint> _finalizeRetirementPlan({
    required V3SessionRetirementPlan plan,
    required V3SessionCheckpoint checkpoint,
    required DateTime persistedAt,
  }) async {
    final retirement = _retirementJournal!;
    final checkpoints = _checkpointRepository!;
    var currentPlan = retirement.planForId(
          plan.planId,
          authority: _retirementAuthority,
        ) ??
        plan;
    var currentCheckpoint = checkpoint;
    final receipt = currentCheckpoint.receiptForAssembly(plan.assemblyId) ??
        currentCheckpoint.retirementTransition?.retiredReceipt;
    if (receipt == null || !_retirementReceiptMatches(plan, receipt)) {
      throw const V3LmfPersistenceConflictException(
        'v3 retirement finalization lost its exact receipt',
      );
    }
    try {
      if (currentPlan.stage == V3SessionRetirementStage.prepared) {
        currentCheckpoint = await checkpoints.replaceReceiptForRetirement(
          expectedSourceCheckpointDigest: currentPlan.sourceCheckpointDigest,
          receipt: receipt,
          persistedAt: persistedAt,
          authority: _checkpointAuthority,
        );
        currentPlan = await retirement.markCheckpointReplaced(
          planId: currentPlan.planId,
          expectedSourceCheckpointDigest: currentPlan.sourceCheckpointDigest,
          replacementCheckpointDigest: currentCheckpoint.checkpointDigest,
          authority: _retirementAuthority,
        );
      }
      if (currentPlan.stage == V3SessionRetirementStage.checkpointReplaced) {
        currentCheckpoint = await checkpoints.finalizeReceiptRetirement(
          expectedPendingCheckpointDigest:
              currentPlan.replacementCheckpointDigest!,
          expectedSourceCheckpointDigest: currentPlan.sourceCheckpointDigest,
          receipt: receipt,
          proofDigest: currentPlan.proofDigest,
          planId: currentPlan.planId,
          persistedAt: persistedAt,
          authority: _checkpointAuthority,
        );
        currentPlan = await retirement.markFinalCheckpointWritten(
          planId: currentPlan.planId,
          expectedReplacementCheckpointDigest:
              currentPlan.replacementCheckpointDigest!,
          finalCheckpointDigest: currentCheckpoint.checkpointDigest,
          authority: _retirementAuthority,
        );
      }
      if (!currentPlan.finalCheckpointWasWritten ||
          currentPlan.finalCheckpointDigest !=
              currentCheckpoint.checkpointDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 retirement did not reach its exact final checkpoint',
        );
      }
      switch (currentPlan.direction) {
        case V3CheckpointEffectDirection.incoming:
          await _journal.deleteReplayWindowProof(
            assemblyId: currentPlan.assemblyId,
            expectedEffectDigest: currentPlan.proofDigest,
            stableRecordId: currentPlan.stableRecordId,
            sessionKey: currentPlan.sessionKey,
            ratchetRevision: currentPlan.ratchetRevision,
            committedAt: currentPlan.proofRecordedAt,
            authority: _authority,
          );
          break;
        case V3CheckpointEffectDirection.outgoing:
          final sendJournal = _sendJournal;
          if (sendJournal == null) {
            throw StateError(
              'Layergram v3 outgoing retirement has no send journal',
            );
          }
          await sendJournal.deleteCompletionProof(
            assemblyId: currentPlan.assemblyId,
            expectedEffectDigest: currentPlan.proofDigest,
            stableRecordId: currentPlan.stableRecordId,
            sessionKey: currentPlan.sessionKey,
            ratchetRevision: currentPlan.ratchetRevision,
            completedAt: currentPlan.proofRecordedAt,
            authority: _sendAuthority,
          );
          break;
      }
      await retirement.deleteFinalizedPlan(
        planId: currentPlan.planId,
        finalCheckpointDigest: currentCheckpoint.checkpointDigest,
        authority: _retirementAuthority,
      );
      return currentCheckpoint;
    } catch (_) {
      if (retirement.requiresRecovery ||
          checkpoints.requiresRecovery ||
          _journal.requiresRecovery ||
          (_sendJournal?.requiresRecovery ?? false)) {
        _recoveryRequired = true;
      }
      rethrow;
    }
  }

  Future<void> _materializeAndCheckpointRestoredState({
    required Map<String, V3TripleRatchetState> working,
    required List<_DecodedEffect> incomingEffects,
    required List<_DecodedSendEffect> outgoingEffects,
  }) async {
    final receiptsBySession = <String, List<V3CheckpointReceipt>>{};
    final repository = _checkpointRepository!;
    for (final entry in working.entries) {
      final existing = repository.checkpointForSession(
        entry.value.sessionId,
        authority: _checkpointAuthority,
      );
      if (existing != null) {
        receiptsBySession[entry.key] = existing.receipts.toList();
      }
    }
    for (final decoded in incomingEffects) {
      final receipt = await _materializeEffect(
        direction: V3CheckpointEffectDirection.incoming,
        assemblyId: decoded.effect.assemblyId,
        applicationState: decoded.effect.applicationState,
        ratchetState: decoded.effect.ratchetState,
        persistedAt: decoded.effect.persistedAt,
      );
      if (receipt.sessionKey != decoded.sessionKey) {
        throw const V3LmfPersistenceConflictException(
          'restored v3 incoming receipt changed session binding',
        );
      }
      _mergeCheckpointReceipt(
        receiptsBySession.putIfAbsent(
            decoded.sessionKey, () => <V3CheckpointReceipt>[]),
        receipt,
      );
    }
    for (final decoded in outgoingEffects) {
      final receipt = await _materializeEffect(
        direction: V3CheckpointEffectDirection.outgoing,
        assemblyId: decoded.effect.assemblyId,
        applicationState: decoded.effect.applicationState,
        ratchetState: decoded.effect.ratchetState,
        persistedAt: decoded.effect.persistedAt,
      );
      if (receipt.sessionKey != decoded.sessionKey) {
        throw const V3LmfPersistenceConflictException(
          'restored v3 outgoing receipt changed session binding',
        );
      }
      _mergeCheckpointReceipt(
        receiptsBySession.putIfAbsent(
            decoded.sessionKey, () => <V3CheckpointReceipt>[]),
        receipt,
      );
    }
    for (final entry in working.entries) {
      await repository.persist(
        snapshot: entry.value,
        receipts: receiptsBySession[entry.key] ?? const <V3CheckpointReceipt>[],
        authority: _checkpointAuthority,
      );
    }
  }

  Future<void> _materializeAndCheckpointSession(String sessionKey) async {
    if (_committedRecordMaterializer == null) return;
    final snapshot = _sessions[sessionKey];
    if (snapshot == null) {
      throw StateError('Layergram v3 checkpoint session is not registered');
    }
    final existingCheckpoint = _checkpointRepository!.checkpointForSession(
      snapshot.sessionId,
      authority: _checkpointAuthority,
    );
    final receipts =
        existingCheckpoint?.receipts.toList() ?? <V3CheckpointReceipt>[];
    for (final assemblyId in _effectRevisions.keys) {
      final effect = _journal.effectForAssembly(
        assemblyId,
        authority: _authority,
      );
      if (effect == null) {
        throw const V3LmfPersistenceConflictException(
          'indexed v3 incoming effect is missing from its journal',
        );
      }
      final receipt = await _materializeEffect(
        direction: V3CheckpointEffectDirection.incoming,
        assemblyId: effect.assemblyId,
        applicationState: effect.applicationState,
        ratchetState: effect.ratchetState,
        persistedAt: effect.persistedAt,
      );
      if (receipt.sessionKey == sessionKey) {
        _mergeCheckpointReceipt(receipts, receipt);
      }
    }
    for (final effect in _sendEffects.values) {
      final receipt = await _materializeEffect(
        direction: V3CheckpointEffectDirection.outgoing,
        assemblyId: effect.assemblyId,
        applicationState: effect.applicationState,
        ratchetState: effect.ratchetState,
        persistedAt: effect.persistedAt,
      );
      if (receipt.sessionKey == sessionKey) {
        _mergeCheckpointReceipt(receipts, receipt);
      }
    }
    await _checkpointRepository.persist(
      snapshot: snapshot,
      receipts: receipts,
      authority: _checkpointAuthority,
    );
  }

  Future<V3CheckpointReceipt> _materializeEffect({
    required V3CheckpointEffectDirection direction,
    required String assemblyId,
    required Uint8List applicationState,
    required Uint8List ratchetState,
    required DateTime persistedAt,
  }) async {
    final application = Uint8List.fromList(applicationState);
    final ratchet = Uint8List.fromList(ratchetState);
    try {
      final receipt = V3CheckpointReceipt.fromStates(
        direction: direction,
        assemblyId: assemblyId,
        applicationState: application,
        ratchetState: ratchet,
      );
      final materialized = await _committedRecordMaterializer!.materialize(
        application,
        persistedAt: persistedAt,
        authority: _materializerAuthority,
      );
      if (materialized.stableRecordId != receipt.stableRecordId ||
          materialized.sessionKey != receipt.sessionKey) {
        throw const V3LmfPersistenceConflictException(
          'materialized v3 record differs from its checkpoint receipt',
        );
      }
      return receipt;
    } finally {
      _wipe(application);
      _wipe(ratchet);
      _wipe(applicationState);
      _wipe(ratchetState);
    }
  }

  void _validateCheckpointCoverage({
    required V3SessionCheckpoint checkpoint,
    required V3CheckpointEffectDirection direction,
    required String assemblyId,
    required Uint8List applicationState,
    required Uint8List ratchetState,
  }) {
    Uint8List? materializedBytes;
    try {
      final receipt = checkpoint.receiptForAssembly(assemblyId);
      if (receipt == null ||
          receipt.direction != direction ||
          !receipt.matchesStates(
            direction: direction,
            applicationState: applicationState,
            ratchetState: ratchetState,
          )) {
        throw const V3LmfPersistenceConflictException(
          'v3 journal effect is not covered by its durable checkpoint',
        );
      }
      final materialized = _committedRecordMaterializer!.recordForStableId(
        receipt.stableRecordId,
        authority: _materializerAuthority,
      );
      if (materialized == null ||
          materialized.assemblyId != assemblyId ||
          materialized.sessionKey != receipt.sessionKey) {
        throw const V3LmfPersistenceConflictException(
          'v3 checkpoint receipt has no materialized application record',
        );
      }
      materializedBytes = materialized.encodedRecord;
      if (!_bytesEqual(materializedBytes, applicationState)) {
        throw const V3LmfPersistenceConflictException(
          'v3 materialized application record differs from journal effect',
        );
      }
    } finally {
      if (materializedBytes != null) _wipe(materializedBytes);
      _wipe(applicationState);
      _wipe(ratchetState);
    }
  }

  void _validateDurableCheckpointMaterialization(
    V3SessionCheckpoint checkpoint,
  ) {
    final retiredReceipt = checkpoint.retirementTransition?.retiredReceipt;
    for (final receipt in <V3CheckpointReceipt>[
      ...checkpoint.receipts,
      if (retiredReceipt != null) retiredReceipt,
    ]) {
      final materialized = _committedRecordMaterializer!.recordForStableId(
        receipt.stableRecordId,
        authority: _materializerAuthority,
      );
      if (materialized == null ||
          materialized.assemblyId != receipt.assemblyId ||
          materialized.sessionKey != receipt.sessionKey ||
          receipt.sessionKey != checkpoint.sessionKey ||
          receipt.ratchetRevision > checkpoint.revision) {
        throw const V3LmfPersistenceConflictException(
          'v3 durable checkpoint has missing application materialization',
        );
      }
    }
  }

  void _mergeCheckpointReceipt(
    List<V3CheckpointReceipt> receipts,
    V3CheckpointReceipt candidate,
  ) {
    for (final existing in receipts) {
      if (existing.assemblyId != candidate.assemblyId) continue;
      if (existing.direction != candidate.direction ||
          existing.stableRecordId != candidate.stableRecordId ||
          existing.sessionKey != candidate.sessionKey ||
          existing.ratchetRevision != candidate.ratchetRevision ||
          existing.stateDigest != candidate.stateDigest) {
        throw const V3LmfPersistenceConflictException(
          'v3 checkpoint receipt diverged for one assembly',
        );
      }
      return;
    }
    receipts.add(candidate);
  }

  V3LmfFrame _validatedTarget(V3LmfDurableDelivery delivery) {
    if (delivery.frames.isEmpty) {
      throw StateError('Layergram v3 delivery has no frames');
    }
    final target = delivery.frames.first;
    if (target.fragmentIndex != 0 ||
        (target.metadata.kind != V3LmfFrameKind.application &&
            target.metadata.kind != V3LmfFrameKind.pqRatchet) ||
        target.hybridRatchetHeader == null ||
        V3LmfFrameCodec.assemblyId(target) != delivery.assemblyId) {
      throw const FormatException(
        'Layergram v3 delivery is not a canonical session effect target',
      );
    }
    return target;
  }

  _DecodedEffect _decodeEffect(V3LmfCommittedEffect effect) {
    if (effect.applicationStateVersion != 1 ||
        effect.ratchetStateVersion != 1) {
      throw const FormatException('Unsupported v3 session effect version');
    }
    final applicationBytes = effect.applicationState;
    final ratchetBytes = effect.ratchetState;
    V3CommittedRecord? record;
    V3TripleRatchetState? snapshot;
    try {
      record = V3CommittedRecordCodec.decode(applicationBytes);
      snapshot = V3TripleRatchetStateCodec.decode(ratchetBytes);
      _validateEffectRecord(effect, record, snapshot);
      final result = _DecodedEffect(
        effect: effect,
        record: record,
        snapshot: snapshot,
        sessionKey: _sessionKey(snapshot.sessionId),
      );
      record = null;
      snapshot = null;
      return result;
    } finally {
      _wipe(applicationBytes);
      _wipe(ratchetBytes);
      record?.wipeContent();
      snapshot?.wipeSecrets();
    }
  }

  _DecodedSendEffect _decodeSendEffect(V3SessionSendEffect effect) {
    final applicationBytes = effect.applicationState;
    final ratchetBytes = effect.ratchetState;
    V3CommittedRecord? record;
    V3TripleRatchetState? snapshot;
    try {
      record = V3CommittedRecordCodec.decode(applicationBytes);
      snapshot = V3TripleRatchetStateCodec.decode(ratchetBytes);
      _validateSendEffectRecord(effect, record, snapshot);
      final result = _DecodedSendEffect(
        effect: effect,
        record: record,
        snapshot: snapshot,
        sessionKey: _sessionKey(snapshot.sessionId),
      );
      record = null;
      snapshot = null;
      return result;
    } finally {
      _wipe(applicationBytes);
      _wipe(ratchetBytes);
      record?.wipeContent();
      snapshot?.wipeSecrets();
    }
  }

  void _validateEffectRecord(
    V3LmfCommittedEffect effect,
    V3CommittedRecord record,
    V3TripleRatchetState snapshot,
  ) {
    final target = effect.targetFrame;
    final metadata = target.metadata;
    if (target.fragmentIndex != 0 ||
        (metadata.kind != V3LmfFrameKind.application &&
            metadata.kind != V3LmfFrameKind.pqRatchet) ||
        target.hybridRatchetHeader == null ||
        V3LmfFrameCodec.assemblyId(target) != effect.assemblyId ||
        record.assemblyId != effect.assemblyId ||
        record.stableRecordId != effect.messageRecordId ||
        record.suite != metadata.suite ||
        record.kind.frameKind != metadata.kind ||
        record.epoch != metadata.epoch ||
        record.messageCounter != metadata.messageCounter ||
        record.contentLength != target.assembledPlaintextLength ||
        !_bytesEqual(record.sessionId, metadata.sessionId) ||
        !_bytesEqual(record.sessionId, snapshot.sessionId) ||
        !_bytesEqual(record.messageId, metadata.messageId) ||
        !_bytesEqual(record.senderBinding, metadata.senderBinding) ||
        !_bytesEqual(record.recipientBinding, metadata.recipientBinding)) {
      throw const V3LmfPersistenceConflictException(
        'v3 atomic effect record does not match its session target',
      );
    }
  }

  void _validateSendEffectRecord(
    V3SessionSendEffect effect,
    V3CommittedRecord record,
    V3TripleRatchetState snapshot,
  ) {
    if (effect.frames.isEmpty) {
      throw const V3LmfPersistenceConflictException(
        'v3 send effect has no sealed frames',
      );
    }
    final target = effect.frames.first;
    final metadata = target.metadata;
    if (target.fragmentIndex != 0 ||
        (metadata.kind != V3LmfFrameKind.application &&
            metadata.kind != V3LmfFrameKind.pqRatchet) ||
        target.hybridRatchetHeader == null ||
        V3LmfFrameCodec.assemblyId(target) != effect.assemblyId ||
        record.assemblyId != effect.assemblyId ||
        record.stableRecordId != effect.messageRecordId ||
        record.suite != metadata.suite ||
        record.kind.frameKind != metadata.kind ||
        record.epoch != metadata.epoch ||
        record.messageCounter != metadata.messageCounter ||
        record.contentLength != target.assembledPlaintextLength ||
        !_bytesEqual(record.sessionId, metadata.sessionId) ||
        !_bytesEqual(record.sessionId, snapshot.sessionId) ||
        !_bytesEqual(record.messageId, metadata.messageId) ||
        !_bytesEqual(record.senderBinding, metadata.senderBinding) ||
        !_bytesEqual(record.recipientBinding, metadata.recipientBinding)) {
      throw const V3LmfPersistenceConflictException(
        'v3 send effect record does not match its sealed target',
      );
    }
  }

  Future<void> _validateTransition({
    required V3TripleRatchetState previous,
    required V3TripleRatchetState candidate,
    required V3CommittedRecord record,
    V3LmfCommittedEffect? effect,
    V3LmfFrame? targetOverride,
  }) async {
    final target = targetOverride ?? effect!.targetFrame;
    if (previous.revision >= 0x7fffffffffffffff ||
        candidate.revision != previous.revision + 1) {
      throw const V3LmfPersistenceConflictException(
        'v3 session effect does not advance one revision',
      );
    }
    _validateStableSession(previous, candidate);
    _validateInboundRouting(previous, target);
    if (!_bytesEqual(record.sessionId, candidate.sessionId)) {
      throw const V3LmfPersistenceConflictException(
        'v3 session effect has an inconsistent session binding',
      );
    }
    await _validateSnapshot(candidate);
  }

  Future<void> _validateOutgoingTransition({
    required V3TripleRatchetState previous,
    required V3TripleRatchetState candidate,
    required V3SessionSendEffect effect,
    required V3CommittedRecord record,
  }) async {
    if (effect.previousRatchetRevision != previous.revision ||
        previous.revision >= 0x7fffffffffffffff ||
        candidate.revision != previous.revision + 1) {
      throw const V3LmfPersistenceConflictException(
        'v3 send effect does not advance one contiguous revision',
      );
    }
    _validateStableSession(previous, candidate);
    _validateOutboundRouting(previous, effect.frames.first);
    if (!_bytesEqual(record.sessionId, candidate.sessionId)) {
      throw const V3LmfPersistenceConflictException(
        'v3 send effect has an inconsistent session binding',
      );
    }
    await _validateSnapshot(candidate);
  }

  Future<void> _validateOutgoingCandidate({
    required V3TripleRatchetState previous,
    required V3TripleRatchetState candidate,
    required V3LmfMessageMetadata metadata,
  }) async {
    if (previous.revision >= 0x7fffffffffffffff ||
        candidate.revision != previous.revision + 1) {
      throw const V3LmfPersistenceConflictException(
        'v3 send candidate does not advance one revision',
      );
    }
    _validateStableSession(previous, candidate);
    final expectedSender = previous.role == V3SessionRole.initiator
        ? previous.initiatorRoutingBinding
        : previous.responderRoutingBinding;
    final expectedRecipient = previous.role == V3SessionRole.initiator
        ? previous.responderRoutingBinding
        : previous.initiatorRoutingBinding;
    try {
      if (!_bytesEqual(metadata.sessionId, previous.sessionId) ||
          !_bytesEqual(metadata.senderBinding, expectedSender) ||
          !_bytesEqual(metadata.recipientBinding, expectedRecipient)) {
        throw const V3LmfPersistenceConflictException(
          'v3 send candidate changed session routing',
        );
      }
    } finally {
      _wipe(expectedSender);
      _wipe(expectedRecipient);
    }
    await _validateSnapshot(candidate);
  }

  Future<int> _validateKnownEffect({
    required V3LmfCommittedEffect effect,
    required V3TripleRatchetState current,
    required String expectedSessionKey,
  }) async {
    final decoded = _decodeEffect(effect);
    try {
      final knownRevision = _effectRevisions[effect.assemblyId];
      if (decoded.sessionKey != expectedSessionKey ||
          knownRevision == null ||
          knownRevision != decoded.snapshot.revision ||
          knownRevision > current.revision) {
        throw const V3LmfPersistenceConflictException(
          'v3 durable effect is outside the restored session chain',
        );
      }
      _validateStableSession(current, decoded.snapshot);
      await _validateSnapshot(decoded.snapshot);
      return knownRevision;
    } finally {
      decoded.close();
    }
  }

  Future<void> _validateSnapshot(V3TripleRatchetState snapshot) async {
    final ec = await V3EcDoubleRatchet.restore(snapshot);
    ec.close();
    final sckaBackend = _sckaBackend;
    if (sckaBackend != null) {
      await V3SparsePqRatchet.validateSnapshot(
        backend: sckaBackend,
        snapshot: snapshot,
      );
    }
    final validator = snapshotValidator;
    if (validator == null) return;
    final detached = _copySnapshot(snapshot);
    try {
      await validator(detached);
    } finally {
      detached.wipeSecrets();
    }
  }

  V3SckaBackend _resolveSckaBackend(V3SckaBackend? requested) {
    final pinned = _sckaBackend;
    if (pinned != null) {
      if (requested != null && !identical(requested, pinned)) {
        throw StateError(
          'Layergram v3 session scope rejected a different SCKA backend',
        );
      }
      return pinned;
    }
    if (requested == null) {
      throw StateError('Layergram v3 SCKA backend is not configured');
    }
    return requested;
  }

  void _validateStableSession(
    V3TripleRatchetState left,
    V3TripleRatchetState right,
  ) {
    if (left.role != right.role ||
        left.lifecycle != V3RatchetLifecycle.active ||
        right.lifecycle != V3RatchetLifecycle.active ||
        !_bytesEqual(left.sessionId, right.sessionId) ||
        !_bytesEqual(left.transcriptDigest, right.transcriptDigest) ||
        !_bytesEqual(
          left.initiatorRoutingBinding,
          right.initiatorRoutingBinding,
        ) ||
        !_bytesEqual(
          left.responderRoutingBinding,
          right.responderRoutingBinding,
        ) ||
        !_secretGetterEqual(
          left.initiatorToResponderAckRootKey,
          right.initiatorToResponderAckRootKey,
        ) ||
        !_secretGetterEqual(
          left.responderToInitiatorAckRootKey,
          right.responderToInitiatorAckRootKey,
        ) ||
        !_secretGetterEqual(
          left.sckaStateSealKey,
          right.sckaStateSealKey,
        )) {
      throw const V3LmfPersistenceConflictException(
        'v3 session effect changed stable session bindings',
      );
    }
  }

  void _validateInboundRouting(
    V3TripleRatchetState snapshot,
    V3LmfFrame target,
  ) {
    final expectedSender = snapshot.role == V3SessionRole.initiator
        ? snapshot.responderRoutingBinding
        : snapshot.initiatorRoutingBinding;
    final expectedRecipient = snapshot.role == V3SessionRole.initiator
        ? snapshot.initiatorRoutingBinding
        : snapshot.responderRoutingBinding;
    try {
      if (!_bytesEqual(target.metadata.sessionId, snapshot.sessionId) ||
          !_bytesEqual(target.metadata.senderBinding, expectedSender) ||
          !_bytesEqual(target.metadata.recipientBinding, expectedRecipient)) {
        throw const FormatException(
          'Layergram v3 delivery routing does not match the local session',
        );
      }
    } finally {
      _wipe(expectedSender);
      _wipe(expectedRecipient);
    }
  }

  void _validateOutboundRouting(
    V3TripleRatchetState snapshot,
    V3LmfFrame target,
  ) {
    final expectedSender = snapshot.role == V3SessionRole.initiator
        ? snapshot.initiatorRoutingBinding
        : snapshot.responderRoutingBinding;
    final expectedRecipient = snapshot.role == V3SessionRole.initiator
        ? snapshot.responderRoutingBinding
        : snapshot.initiatorRoutingBinding;
    try {
      if (!_bytesEqual(target.metadata.sessionId, snapshot.sessionId) ||
          !_bytesEqual(target.metadata.senderBinding, expectedSender) ||
          !_bytesEqual(target.metadata.recipientBinding, expectedRecipient)) {
        throw const FormatException(
          'Layergram v3 send routing does not match the local session',
        );
      }
    } finally {
      _wipe(expectedSender);
      _wipe(expectedRecipient);
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
      throw StateError('Layergram v3 session controller is closed');
    }
  }

  void _ensureReady() {
    _ensureOpen();
    if (!_restored) {
      throw StateError(
        'Layergram v3 session controller must be restored before use',
      );
    }
    if (_recoveryRequired) {
      throw StateError(
        'Layergram v3 session controller must be reconstructed and restored',
      );
    }
  }

  void _ensureConfiguredInitialHandoffAuthority(
    V3InitialSessionHandoffAuthority authority,
  ) {
    if (!identical(_initialHandoffAuthority, authority)) {
      throw StateError('Layergram v3 initial handoff authority is invalid');
    }
  }

  void _ensureClaimedInitialHandoffAuthority(
    V3InitialSessionHandoffAuthority authority,
  ) {
    _ensureConfiguredInitialHandoffAuthority(authority);
    if (!_initialHandoffAuthorityClaimed) {
      throw StateError(
        'Layergram v3 initial handoff authority was not claimed',
      );
    }
  }
}

final class _DecodedEffect {
  _DecodedEffect({
    required this.effect,
    required this.record,
    required V3TripleRatchetState snapshot,
    required this.sessionKey,
  }) : _snapshot = snapshot;

  final V3LmfCommittedEffect effect;
  final V3CommittedRecord record;
  V3TripleRatchetState? _snapshot;
  final String sessionKey;

  V3TripleRatchetState get snapshot => _snapshot!;

  V3TripleRatchetState takeSnapshot() {
    final result = _snapshot!;
    _snapshot = null;
    return result;
  }

  void close() {
    record.wipeContent();
    _snapshot?.wipeSecrets();
    _snapshot = null;
  }
}

final class _RetirementProof {
  const _RetirementProof({required this.digest, required this.recordedAt});

  final String digest;
  final DateTime recordedAt;
}

final class _DecodedSendEffect {
  _DecodedSendEffect({
    required this.effect,
    required this.record,
    required V3TripleRatchetState snapshot,
    required this.sessionKey,
  }) : _snapshot = snapshot;

  final V3SessionSendEffect effect;
  final V3CommittedRecord record;
  V3TripleRatchetState? _snapshot;
  final String sessionKey;

  V3TripleRatchetState get snapshot => _snapshot!;

  V3TripleRatchetState takeSnapshot() {
    final result = _snapshot!;
    _snapshot = null;
    return result;
  }

  void close() {
    record.wipeContent();
    _snapshot?.wipeSecrets();
    _snapshot = null;
  }
}

final class _RestoredSessionEffect {
  const _RestoredSessionEffect._({this.incoming, this.outgoing});

  factory _RestoredSessionEffect.incoming(_DecodedEffect effect) =>
      _RestoredSessionEffect._(incoming: effect);

  factory _RestoredSessionEffect.outgoing(_DecodedSendEffect effect) =>
      _RestoredSessionEffect._(outgoing: effect);

  final _DecodedEffect? incoming;
  final _DecodedSendEffect? outgoing;

  String get sessionKey => incoming?.sessionKey ?? outgoing!.sessionKey;
  int get revision =>
      incoming?.snapshot.revision ?? outgoing!.snapshot.revision;
  String get assemblyId =>
      incoming?.effect.assemblyId ?? outgoing!.effect.assemblyId;

  V3TripleRatchetState takeSnapshot() =>
      incoming?.takeSnapshot() ?? outgoing!.takeSnapshot();
}

V3TripleRatchetState _copySnapshot(V3TripleRatchetState snapshot) {
  final encoded = V3TripleRatchetStateCodec.encode(snapshot);
  try {
    return V3TripleRatchetStateCodec.decode(encoded);
  } finally {
    _wipe(encoded);
  }
}

String _sessionKey(Uint8List sessionId) {
  if (sessionId.length != V3LmfFrameCodec.sessionIdBytes ||
      _isAllZero(sessionId)) {
    throw ArgumentError.value(sessionId, 'sessionId');
  }
  return base64UrlEncode(sessionId).replaceAll('=', '');
}

bool _snapshotBytesEqual(
  V3TripleRatchetState left,
  V3TripleRatchetState right,
) {
  final encodedLeft = V3TripleRatchetStateCodec.encode(left);
  final encodedRight = V3TripleRatchetStateCodec.encode(right);
  try {
    return _bytesEqual(encodedLeft, encodedRight);
  } finally {
    _wipe(encodedLeft);
    _wipe(encodedRight);
  }
}

bool _allowsReplacedRetirementReceipt({
  required V3SessionRetirementPlan? plan,
  required V3CheckpointEffectDirection direction,
  required String bindingSessionKey,
  required String stableRecordId,
  required int ratchetRevision,
  required String? checkpointDigest,
}) =>
    plan != null &&
    plan.checkpointWasReplaced &&
    plan.direction == direction &&
    plan.sessionKey == bindingSessionKey &&
    plan.stableRecordId == stableRecordId &&
    plan.ratchetRevision == ratchetRevision &&
    (plan.finalCheckpointWasWritten
        ? plan.finalCheckpointDigest == checkpointDigest
        : plan.replacementCheckpointDigest == checkpointDigest);

bool _retirementReceiptMatches(
  V3SessionRetirementPlan plan,
  V3CheckpointReceipt receipt,
) =>
    receipt.direction == plan.direction &&
    receipt.assemblyId == plan.assemblyId &&
    receipt.stableRecordId == plan.stableRecordId &&
    receipt.sessionKey == plan.sessionKey &&
    receipt.ratchetRevision == plan.ratchetRevision &&
    receipt.stateDigest == plan.stateDigest;

bool _retirementTransitionMatchesPlan({
  required V3SessionRetirementPlan plan,
  required V3SessionCheckpoint checkpoint,
}) {
  final transition = checkpoint.retirementTransition;
  return transition != null &&
      transition.sourceCheckpointDigest == plan.sourceCheckpointDigest &&
      (!transition.isFinalized ||
          (transition.pendingCheckpointDigest ==
                  plan.replacementCheckpointDigest &&
              transition.proofDigest == plan.proofDigest &&
              transition.planId == plan.planId)) &&
      checkpoint.sessionKey == plan.sessionKey &&
      checkpoint.revision >= plan.ratchetRevision &&
      _retirementReceiptMatches(plan, transition.retiredReceipt) &&
      checkpoint.receiptForAssembly(plan.assemblyId) == null;
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

bool _secretGetterEqual(Uint8List left, Uint8List right) {
  try {
    return _bytesEqual(left, right);
  } finally {
    _wipe(left);
    _wipe(right);
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

bool _isAllZero(List<int> value) {
  var anyNonZero = 0;
  for (final byte in value) {
    anyNonZero |= byte;
  }
  return anyNonZero == 0;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
