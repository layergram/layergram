import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/committed_record_materializer_v3.dart';
import 'package:layergram/core/crypto/v3/committed_record_v3.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/hybrid_ratchet_header_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_atomic_commit.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/retention_policy_v3.dart';
import 'package:layergram/core/crypto/v3/session_commit_controller_v3.dart';
import 'package:layergram/core/crypto/v3/session_checkpoint_v3.dart';
import 'package:layergram/core/crypto/v3/session_retirement_journal_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';

void main() {
  group('inactive v3 session commit controller', () {
    test('claims the journal and atomically advances one canonical session',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final journal = V3LmfAtomicCommitJournal(
        store: fixture.store,
        inbox: fixture.inbox,
      );
      var validatorCalls = 0;
      final controller = V3SessionCommitController(
        journal: journal,
        snapshotValidator: (snapshot) async {
          validatorCalls++;
          expect(snapshot.lifecycle, V3RatchetLifecycle.active);
          if (validatorCalls == 1) {
            await expectLater(journal.restore(), throwsStateError);
            await expectLater(journal.close(), throwsStateError);
          }
        },
      );
      final restored = await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      expect(restored.sessionRevisions.values, <int>[0]);
      expect(restored.committedEffectCount, 0);
      expect(() => journal.effects, throwsStateError);
      expect(
        () => journal.effectForAssembly('not-an-assembly'),
        throwsStateError,
      );
      await expectLater(
        fixture.inbox.purgeCommittedBefore(DateTime.now().toUtc()),
        throwsStateError,
      );
      await expectLater(
        journal.collectCompactedEffect(
          assemblyId: fixture.deliveries.single.assemblyId,
          expectedEffectDigest: fixture.deliveries.single.assemblyId,
        ),
        throwsStateError,
      );

      var directBuilderCalls = 0;
      await expectLater(
        journal.commit(
          delivery: fixture.deliveries.single,
          builder: (_) {
            directBuilderCalls++;
            throw StateError('must not run');
          },
        ),
        throwsStateError,
      );
      expect(directBuilderCalls, 0);

      var transitionCalls = 0;
      final committed = await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        persistedAt: DateTime.utc(2026, 8, 14),
        transitionBuilder: (plaintext, current, header) {
          transitionCalls++;
          expect(plaintext, fixture.plaintexts.single);
          expect(header.sckaMessage.messageCounter, 0);
          return _candidateFrom(current, receivingEpoch: 0);
        },
      );

      expect(transitionCalls, 1);
      expect(committed.wasAlreadyDurable, isFalse);
      expect(committed.ratchetRevision, 1);
      expect(committed.effect.messageRecordId,
          'v3:${fixture.deliveries.single.assemblyId}');
      final application = V3CommittedRecordCodec.decode(
        committed.effect.applicationState,
      );
      final ratchet = V3TripleRatchetStateCodec.decode(
        committed.effect.ratchetState,
      );
      final current = await controller.snapshotForSession(
        fixture.checkpoint.sessionId,
      );
      expect(application.content, fixture.plaintexts.single);
      expect(application.assemblyId, fixture.deliveries.single.assemblyId);
      expect(ratchet.revision, 1);
      expect(current.revision, 1);
      expect(validatorCalls, 2);

      application.wipeContent();
      ratchet.wipeSecrets();
      current.wipeSecrets();
      await controller.close();
      await fixture.inbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('materializes and checkpoints an incoming commit across restart',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      final initialRestore = await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      expect(initialRestore.materializedRecordCount, 0);
      expect(initialRestore.checkpointCount, 1);
      final committed = await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      expect(committed.ratchetRevision, 1);
      expect(
        fixture.store.records.values
            .where(
              (payload) =>
                  payload['kind'] == V3CommittedRecordMaterializer.recordKind,
            )
            .length,
        1,
      );
      final checkpointPayload = fixture.store.records.values.singleWhere(
        (payload) =>
            payload['kind'] == V3SessionCheckpointRepository.recordKind,
      );
      expect(checkpointPayload['revision'], 1);
      expect(checkpointPayload['receipts'], hasLength(1));
      await controller.close();
      await fixture.inbox.close();

      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final restoredController = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      final restored = await restoredController.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      expect(restored.sessionRevisions.values, <int>[1]);
      expect(restored.committedEffectCount, 1);
      expect(restored.materializedRecordCount, 1);
      expect(restored.checkpointCount, 1);
      expect(
        fixture.store.records.values
            .where(
              (payload) =>
                  payload['kind'] == V3CommittedRecordMaterializer.recordKind,
            )
            .length,
        1,
      );

      await restoredController.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test(
        'compacts incoming journal into replay window and restores from durable checkpoint',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );

      final compacted = await controller.compactSession(
        fixture.checkpoint.sessionId,
      );
      expect(compacted.collectedIncomingEffects, 1);
      expect(compacted.collectedOutgoingEffects, 0);
      expect(compacted.replayWindowEntries, 1);
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3LmfAtomicCommitJournal.recordKind,
        ),
        isEmpty,
      );
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3LmfDurableInbox.committedRecordKind,
        ),
        isEmpty,
      );
      expect(
        fixture.store.records.values.where(
          (payload) =>
              payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
        ),
        hasLength(1),
      );
      final replay = await fixture.inbox.receive(
        frame: fixture.frames.single,
        secretKey: fixture.transportKey,
      );
      expect(replay.status, V3LmfInboxStatus.committedReplay);

      await controller.close();
      await fixture.inbox.close();
      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      final inboxRestore = await restoredInbox.restore(
        keyResolver: (_) => fixture.transportKey,
      );
      expect(inboxRestore.deliveries, isEmpty);
      final restoredController = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      final restored = await restoredController.restore(
        checkpoints: const <V3TripleRatchetState>[],
      );
      expect(restored.sessionRevisions.values, <int>[1]);
      expect(restored.committedEffectCount, 0);
      final replayAfterRestart = await restoredInbox.receive(
        frame: fixture.frames.single,
        secretKey: fixture.transportKey,
      );
      expect(replayAfterRestart.status, V3LmfInboxStatus.committedReplay);
      final secondCompaction = await restoredController.compactSession(
        fixture.checkpoint.sessionId,
      );
      expect(secondCompaction.collectedIncomingEffects, 0);

      await restoredController.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('restart finalizes a prepared retirement plan and deletes exact proof',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      await controller.compactSession(fixture.checkpoint.sessionId);
      await controller.close();
      await fixture.inbox.close();

      await _prepareIncomingRetirementPlan(fixture.store);
      final retirementRecordCount = fixture.store.records.values
          .where(
            (payload) =>
                payload['kind'] == V3SessionRetirementJournal.recordKind,
          )
          .length;
      expect(retirementRecordCount, 1);

      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final retirementJournal = V3SessionRetirementJournal(
        store: fixture.store,
      );
      final restoredController = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
        retirementJournal: retirementJournal,
      );
      final restored = await restoredController.restore(
        checkpoints: const <V3TripleRatchetState>[],
      );
      expect(restored.retirementPlanCount, 0);
      expect(() => retirementJournal.plans(), throwsStateError);
      await expectLater(retirementJournal.restore(), throwsStateError);
      await expectLater(retirementJournal.close(), throwsStateError);
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3SessionRetirementJournal.recordKind,
        ),
        isEmpty,
      );
      expect(
        fixture.store.records.values.where(
          (payload) =>
              payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
        ),
        isEmpty,
      );

      await restoredController.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('restart finalizes one retirement then rolls to the next receipt',
        () async {
      final fixture = await _Fixture.create(messageCount: 2);
      final controller = _retirementController(fixture);
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      for (var index = 0; index < fixture.deliveries.length; index++) {
        await controller.commitDelivery(
          delivery: fixture.deliveries[index],
          expectedRevision: index,
          transitionBuilder: (_, current, __) => _candidateFrom(
            current,
            receivingEpoch: 0,
            pqReceiveCounterIncrement: 1,
          ),
        );
      }
      await controller.compactSession(fixture.checkpoint.sessionId);
      await controller.close();
      await fixture.inbox.close();

      await _prepareIncomingRetirementPlan(
        fixture.store,
        assemblyId: fixture.deliveries.first.assemblyId,
      );
      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final restoredController = _retirementController(
        fixture,
        inbox: restoredInbox,
      );
      final restored = await restoredController.restore(
        checkpoints: const <V3TripleRatchetState>[],
      );
      expect(restored.retirementPlanCount, 0);

      final second = await restoredController.replaceEligibleCheckpointReceipt(
        assemblyId: fixture.deliveries.last.assemblyId,
        policy: V3RetentionPolicy.custom(
          skippedKeyLifetimeSeconds: 10,
          minimumProofLifetimeSeconds: 20,
        ),
        now: DateTime.now().toUtc().add(const Duration(days: 366)),
      );
      expect(second.decision.eligible, isTrue);
      expect(second.checkpointWasReplaced, isTrue);
      expect(restoredController.requiresRecovery, isFalse);
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3SessionRetirementJournal.recordKind,
        ),
        isEmpty,
      );
      final checkpoint = fixture.store.records.values.singleWhere(
        (payload) =>
            payload['kind'] == V3SessionCheckpointRepository.recordKind,
      );
      expect(checkpoint['receipts'], isEmpty);
      final transition =
          (checkpoint['retirement'] as Map).cast<String, dynamic>();
      expect(
        (transition['retiredReceipt'] as Map)['assemblyId'],
        fixture.deliveries.last.assemblyId,
      );
      expect(transition['pendingCheckpointDigest'], isNotNull);
      expect(transition['proofDigest'], isNotNull);
      expect(transition['planId'], isNotNull);
      expect(
        fixture.store.records.values.where(
          (payload) =>
              payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
        ),
        isEmpty,
      );

      await restoredController.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('fully retires one eligible incoming receipt and remains restartable',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = _retirementController(fixture);
      final committedAt = DateTime.now().toUtc();
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        persistedAt: committedAt,
        transitionBuilder: (_, current, __) => _candidateFrom(
          current,
          receivingEpoch: 0,
          pqReceiveCounterIncrement: 1,
        ),
      );
      await controller.compactSession(fixture.checkpoint.sessionId);

      final policy = V3RetentionPolicy.custom(
        skippedKeyLifetimeSeconds: 10,
        minimumProofLifetimeSeconds: 20,
      );
      final early = await controller.replaceEligibleCheckpointReceipt(
        assemblyId: fixture.deliveries.single.assemblyId,
        policy: policy,
        now: committedAt.add(const Duration(seconds: 19)),
      );
      expect(early.decision.eligible, isFalse);
      expect(early.checkpointWasReplaced, isFalse);
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3SessionRetirementJournal.recordKind,
        ),
        isEmpty,
      );

      final replaced = await controller.replaceEligibleCheckpointReceipt(
        assemblyId: fixture.deliveries.single.assemblyId,
        policy: policy,
        now: committedAt.add(const Duration(seconds: 20)),
      );
      expect(replaced.decision.eligible, isTrue);
      expect(replaced.checkpointWasReplaced, isTrue);
      final checkpoint = fixture.store.records.values.singleWhere(
        (payload) =>
            payload['kind'] == V3SessionCheckpointRepository.recordKind,
      );
      expect(checkpoint['receipts'], isEmpty);
      final transition =
          (checkpoint['retirement'] as Map).cast<String, dynamic>();
      expect(
        (transition['retiredReceipt'] as Map)['assemblyId'],
        fixture.deliveries.single.assemblyId,
      );
      expect(
        fixture.store.records.values.where(
          (payload) =>
              payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
        ),
        isEmpty,
      );
      expect(transition['pendingCheckpointDigest'], isNotNull);
      expect(transition['proofDigest'], isNotNull);
      expect(transition['planId'], isNotNull);
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3SessionRetirementJournal.recordKind,
        ),
        isEmpty,
      );

      await controller.close();
      await fixture.inbox.close();
      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final restoredController = _retirementController(
        fixture,
        inbox: restoredInbox,
      );
      final restored = await restoredController.restore(
        checkpoints: const <V3TripleRatchetState>[],
      );
      expect(restored.retirementPlanCount, 0);
      expect(restored.sessionRevisions.values.single, 1);
      expect(
        fixture.store.records.values.where(
          (payload) =>
              payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
        ),
        isEmpty,
      );
      await restoredController.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('restart resumes every final retirement crash boundary', () async {
      for (final boundary in <String>[
        'final-checkpoint-write',
        'compact-proof-delete',
        'final-plan-delete',
      ]) {
        final fixture = await _Fixture.create(messageCount: 1);
        final controller = _retirementController(fixture);
        final committedAt = DateTime.now().toUtc();
        await controller.restore(
          checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
        );
        await controller.commitDelivery(
          delivery: fixture.deliveries.single,
          expectedRevision: 0,
          persistedAt: committedAt,
          transitionBuilder: (_, current, __) => _candidateFrom(
            current,
            receivingEpoch: 0,
            pqReceiveCounterIncrement: 1,
          ),
        );
        await controller.compactSession(fixture.checkpoint.sessionId);
        switch (boundary) {
          case 'final-checkpoint-write':
            fixture.store.durableWriteThenThrowFinalCheckpoint = true;
            break;
          case 'compact-proof-delete':
            fixture.store.durableDeleteThenThrowKind =
                V3LmfDurableInbox.replayWindowRecordKind;
            break;
          case 'final-plan-delete':
            fixture.store.durableDeleteThenThrowRetirementStage =
                V3SessionRetirementStage.finalCheckpointWritten.wireId;
            break;
        }
        await expectLater(
          controller.replaceEligibleCheckpointReceipt(
            assemblyId: fixture.deliveries.single.assemblyId,
            policy: V3RetentionPolicy.custom(
              skippedKeyLifetimeSeconds: 1,
              minimumProofLifetimeSeconds: 1,
            ),
            now: committedAt.add(const Duration(seconds: 2)),
          ),
          throwsStateError,
          reason: boundary,
        );
        expect(controller.requiresRecovery, isTrue, reason: boundary);
        await controller.close();
        await fixture.inbox.close();

        final restoredInbox = V3LmfDurableInbox(store: fixture.store);
        await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
        final restoredController = _retirementController(
          fixture,
          inbox: restoredInbox,
        );
        final restored = await restoredController.restore(
          checkpoints: const <V3TripleRatchetState>[],
        );
        expect(restored.retirementPlanCount, 0, reason: boundary);
        expect(restored.sessionRevisions.values.single, 1, reason: boundary);
        expect(
          fixture.store.records.values.where(
            (payload) =>
                payload['kind'] == V3SessionRetirementJournal.recordKind,
          ),
          isEmpty,
          reason: boundary,
        );
        expect(
          fixture.store.records.values.where(
            (payload) =>
                payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
          ),
          isEmpty,
          reason: boundary,
        );
        final checkpoint = fixture.store.records.values.singleWhere(
          (payload) =>
              payload['kind'] == V3SessionCheckpointRepository.recordKind,
        );
        final transition =
            (checkpoint['retirement'] as Map).cast<String, dynamic>();
        expect(transition['pendingCheckpointDigest'], isNotNull);
        expect(transition['proofDigest'], isNotNull);
        expect(transition['planId'], isNotNull);
        await restoredController.close();
        await restoredInbox.close();
        fixture.checkpoint.wipeSecrets();
      }
    });

    test('restart reconciles checkpoint durable before retirement stage',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = _retirementController(fixture);
      final committedAt = DateTime.now().toUtc();
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        persistedAt: committedAt,
        transitionBuilder: (_, current, __) => _candidateFrom(
          current,
          receivingEpoch: 0,
          pqReceiveCounterIncrement: 1,
        ),
      );
      await controller.compactSession(fixture.checkpoint.sessionId);
      fixture.store.durableWriteThenThrowKind =
          V3SessionCheckpointRepository.recordKind;

      await expectLater(
        controller.replaceEligibleCheckpointReceipt(
          assemblyId: fixture.deliveries.single.assemblyId,
          policy: V3RetentionPolicy.custom(
            skippedKeyLifetimeSeconds: 10,
            minimumProofLifetimeSeconds: 20,
          ),
          now: committedAt.add(const Duration(seconds: 20)),
        ),
        throwsStateError,
      );
      expect(controller.requiresRecovery, isTrue);
      expect(
        fixture.store.records.values.where(
          (payload) =>
              payload['kind'] == V3SessionCheckpointRepository.recordKind,
        ),
        hasLength(2),
      );
      expect(
        fixture.store.records.values.singleWhere(
          (payload) => payload['kind'] == V3SessionRetirementJournal.recordKind,
        )['stage'],
        V3SessionRetirementStage.prepared.wireId,
      );

      final unverifiedStore = _FaultStore();
      for (final entry in fixture.store.records.entries) {
        if (entry.value['kind'] == V3SessionRetirementJournal.recordKind) {
          continue;
        }
        unverifiedStore.records[entry.key] = _deepCopy(entry.value);
      }
      final unverifiedInbox = V3LmfDurableInbox(store: unverifiedStore);
      await unverifiedInbox.restore(keyResolver: (_) => fixture.transportKey);
      final unverifiedController = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: unverifiedStore,
          inbox: unverifiedInbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: unverifiedStore,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: unverifiedStore,
        ),
        retirementJournal: V3SessionRetirementJournal(store: unverifiedStore),
      );
      await expectLater(
        unverifiedController.restore(
          checkpoints: const <V3TripleRatchetState>[],
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(
        unverifiedStore.records.values.where(
          (payload) =>
              payload['kind'] == V3SessionCheckpointRepository.recordKind,
        ),
        hasLength(2),
      );
      await unverifiedController.close();
      await unverifiedInbox.close();

      await controller.close();
      await fixture.inbox.close();
      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final restoredController = _retirementController(
        fixture,
        inbox: restoredInbox,
      );
      final restored = await restoredController.restore(
        checkpoints: const <V3TripleRatchetState>[],
      );
      expect(restored.retirementPlanCount, 0);
      expect(
        fixture.store.records.values.where(
          (payload) =>
              payload['kind'] == V3SessionCheckpointRepository.recordKind,
        ),
        hasLength(1),
      );
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3SessionRetirementJournal.recordKind,
        ),
        isEmpty,
      );
      expect(
        fixture.store.records.values.where(
          (payload) =>
              payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
        ),
        isEmpty,
      );
      await restoredController.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('restart completes a retirement stage durable before write returned',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final initial = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await initial.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await initial.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) => _candidateFrom(
          current,
          receivingEpoch: 0,
          pqReceiveCounterIncrement: 1,
        ),
      );
      await initial.compactSession(fixture.checkpoint.sessionId);
      await initial.close();
      await fixture.inbox.close();
      await _prepareIncomingRetirementPlan(fixture.store);

      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final controller = _retirementController(
        fixture,
        inbox: restoredInbox,
      );
      fixture.store.durableWriteThenThrowKind =
          V3SessionRetirementJournal.recordKind;
      await expectLater(
        controller.restore(
          checkpoints: const <V3TripleRatchetState>[],
        ),
        throwsStateError,
      );
      expect(controller.requiresRecovery, isTrue);
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3SessionRetirementJournal.recordKind,
        ),
        hasLength(2),
      );
      await controller.close();
      await restoredInbox.close();

      final finalInbox = V3LmfDurableInbox(store: fixture.store);
      await finalInbox.restore(keyResolver: (_) => fixture.transportKey);
      final finalController = _retirementController(
        fixture,
        inbox: finalInbox,
      );
      final restored = await finalController.restore(
        checkpoints: const <V3TripleRatchetState>[],
      );
      expect(restored.retirementPlanCount, 0);
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3SessionRetirementJournal.recordKind,
        ),
        isEmpty,
      );
      expect(
        fixture.store.records.values.where(
          (payload) =>
              payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
        ),
        isEmpty,
      );
      await finalController.close();
      await finalInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('restore rejects a retirement plan bound to another checkpoint',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      await controller.compactSession(fixture.checkpoint.sessionId);
      await controller.close();
      await fixture.inbox.close();

      await _prepareIncomingRetirementPlan(
        fixture.store,
        sourceCheckpointDigestOverride: fixture.deliveries.single.assemblyId,
      );
      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final restoredController = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
        retirementJournal: V3SessionRetirementJournal(store: fixture.store),
      );
      try {
        await expectLater(
          restoredController.restore(
            checkpoints: const <V3TripleRatchetState>[],
          ),
          throwsA(isA<V3LmfPersistenceConflictException>()),
        );
        expect(restoredController.requiresRecovery, isTrue);
        expect(
          fixture.store.records.values.where(
            (payload) =>
                payload['kind'] == V3SessionRetirementJournal.recordKind,
          ),
          hasLength(1),
        );
      } finally {
        await restoredController.close();
        await restoredInbox.close();
        fixture.checkpoint.wipeSecrets();
      }
    });

    test('restore rejects a checkpoint whose replay-window proof was lost',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      await controller.compactSession(fixture.checkpoint.sessionId);
      final replay = fixture.store.records.entries.singleWhere(
        (entry) =>
            entry.value['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
      );
      fixture.store.records.remove(replay.key);
      await controller.close();
      await fixture.inbox.close();

      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final restoredController = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      try {
        await expectLater(
          restoredController.restore(
            checkpoints: const <V3TripleRatchetState>[],
          ),
          throwsA(isA<V3LmfPersistenceConflictException>()),
        );
        expect(restoredController.requiresRecovery, isTrue);
      } finally {
        await restoredController.close();
        await restoredInbox.close();
        fixture.checkpoint.wipeSecrets();
      }
    });

    test('ambiguous journal collection keeps replay suppression recoverable',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      fixture.store.durableDeleteThenThrowKind =
          V3LmfAtomicCommitJournal.recordKind;
      await expectLater(
        controller.compactSession(fixture.checkpoint.sessionId),
        throwsStateError,
      );
      expect(controller.requiresRecovery, isTrue);
      expect(
        fixture.store.records.values.where(
          (payload) =>
              payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
        ),
        hasLength(1),
      );
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3LmfAtomicCommitJournal.recordKind,
        ),
        isEmpty,
      );

      await controller.close();
      await fixture.inbox.close();
      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final restoredController = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      final restored = await restoredController.restore(
        checkpoints: const <V3TripleRatchetState>[],
      );
      expect(restored.sessionRevisions.values, <int>[1]);
      expect(restored.committedEffectCount, 0);
      expect(
        (await restoredInbox.receive(
          frame: fixture.frames.single,
          secretKey: fixture.transportKey,
        ))
            .status,
        V3LmfInboxStatus.committedReplay,
      );

      await restoredController.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('retries pre-delete compaction after a cumulative checkpoint advances',
        () async {
      final fixture = await _Fixture.create(messageCount: 2);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await controller.commitDelivery(
        delivery: fixture.deliveries.first,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      fixture.store.failDeleteKindOnce = V3LmfAtomicCommitJournal.recordKind;
      await expectLater(
        controller.compactSession(fixture.checkpoint.sessionId),
        throwsStateError,
      );
      expect(controller.requiresRecovery, isTrue);
      final earlierCheckpointDigest = fixture.store.records.values.singleWhere(
        (payload) =>
            payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
      )['checkpointDigest'];
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3LmfAtomicCommitJournal.recordKind,
        ),
        hasLength(1),
      );
      await controller.close();
      await fixture.inbox.close();

      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      final inboxRestore = await restoredInbox.restore(
        keyResolver: (_) => fixture.transportKey,
      );
      expect(inboxRestore.deliveries, hasLength(1));
      final restoredController = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      final restored = await restoredController.restore(
        checkpoints: const <V3TripleRatchetState>[],
      );
      expect(restored.sessionRevisions.values, <int>[1]);
      expect(restored.committedEffectCount, 1);
      await restoredController.commitDelivery(
        delivery: inboxRestore.deliveries.single,
        expectedRevision: 1,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      final currentCheckpointDigest = fixture.store.records.values.singleWhere(
        (payload) =>
            payload['kind'] == V3SessionCheckpointRepository.recordKind,
      )['checkpointDigest'];
      expect(currentCheckpointDigest, isNot(earlierCheckpointDigest));

      final compacted = await restoredController.compactSession(
        fixture.checkpoint.sessionId,
      );
      expect(compacted.collectedIncomingEffects, 2);
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3LmfAtomicCommitJournal.recordKind,
        ),
        isEmpty,
      );
      expect(
        fixture.store.records.values.where(
          (payload) =>
              payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
        ),
        hasLength(2),
      );

      await restoredController.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('corrupt compact replay proof fails closed and is retained', () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      await controller.compactSession(fixture.checkpoint.sessionId);
      await controller.close();
      await fixture.inbox.close();

      final replayEntry = fixture.store.records.entries.singleWhere(
        (entry) =>
            entry.value['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
      );
      replayEntry.value['checkpointDigest'] = 'not-canonical';
      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await expectLater(
        restoredInbox.restore(keyResolver: (_) => fixture.transportKey),
        throwsFormatException,
      );
      expect(fixture.store.records.containsKey(replayEntry.key), isTrue);

      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('checkpoint restore fails closed if compacted AR3 is missing',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      await controller.compactSession(fixture.checkpoint.sessionId);
      await controller.close();
      await fixture.inbox.close();
      final materialized = fixture.store.records.entries.singleWhere(
        (entry) =>
            entry.value['kind'] == V3CommittedRecordMaterializer.recordKind,
      );
      fixture.store.records.remove(materialized.key);

      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final restoredController = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await expectLater(
        restoredController.restore(
          checkpoints: const <V3TripleRatchetState>[],
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(restoredController.requiresRecovery, isTrue);

      await restoredController.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('checkpoint restore rejects a replay proof rebound to another session',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      await controller.compactSession(fixture.checkpoint.sessionId);
      await controller.close();
      await fixture.inbox.close();
      final replayEntry = fixture.store.records.entries.singleWhere(
        (entry) =>
            entry.value['kind'] == V3LmfDurableInbox.replayWindowRecordKind,
      );
      replayEntry.value['sessionId'] =
          base64UrlEncode(_bytes(16, 0xf1)).replaceAll('=', '');

      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final restoredController = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
        committedRecordMaterializer: V3CommittedRecordMaterializer(
          store: fixture.store,
        ),
        checkpointRepository: V3SessionCheckpointRepository(
          store: fixture.store,
        ),
      );
      await expectLater(
        restoredController.restore(
          checkpoints: const <V3TripleRatchetState>[],
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );

      await restoredController.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('commits authenticated plaintext even if a builder mutates its copy',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      final expectedPlaintext = Uint8List.fromList(fixture.plaintexts.single);
      Uint8List? retainedBuilderCopy;

      final committed = await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (plaintext, current, _) {
          retainedBuilderCopy = plaintext;
          plaintext.fillRange(0, plaintext.length, 0xa5);
          return _candidateFrom(current, receivingEpoch: 0);
        },
      );
      final record = V3CommittedRecordCodec.decode(
        committed.effect.applicationState,
      );
      expect(record.content, expectedPlaintext);
      expect(retainedBuilderCopy, everyElement(0));

      record.wipeContent();
      expectedPlaintext.fillRange(0, expectedPlaintext.length, 0);
      await controller.close();
      await fixture.inbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('wipes a copied checkpoint when semantic validation fails', () async {
      final fixture = await _Fixture.create(messageCount: 1);
      V3TripleRatchetState? observedCopy;
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
        snapshotValidator: (snapshot) {
          observedCopy = snapshot;
          throw StateError('semantic validation failed');
        },
      );

      await expectLater(
        controller.restore(
          checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
        ),
        throwsStateError,
      );
      expect(observedCopy, isNotNull);
      expect(observedCopy!.isWiped, isTrue);
      expect(controller.requiresRecovery, isTrue);

      await controller.close();
      await fixture.inbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('serializes competing commits and applies CAS before builders',
        () async {
      final fixture = await _Fixture.create(messageCount: 2);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      var firstCalls = 0;
      var secondCalls = 0;

      final first = controller.commitDelivery(
        delivery: fixture.deliveries[0],
        expectedRevision: 0,
        transitionBuilder: (_, current, __) async {
          firstCalls++;
          await Future<void>.delayed(const Duration(milliseconds: 10));
          return _candidateFrom(current, receivingEpoch: 0);
        },
      );
      final second = controller.commitDelivery(
        delivery: fixture.deliveries[1],
        expectedRevision: 0,
        transitionBuilder: (_, current, __) {
          secondCalls++;
          return _candidateFrom(current, receivingEpoch: 0);
        },
      );

      expect((await first).ratchetRevision, 1);
      await expectLater(second, throwsStateError);
      expect(firstCalls, 1);
      expect(secondCalls, 0);
      expect(
        fixture.store.records.values.where(
            (value) => value['kind'] == V3LmfAtomicCommitJournal.recordKind),
        hasLength(1),
      );

      await controller.close();
      await fixture.inbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('keeps independent revisions for multiple registered sessions',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final alternateSessionId = _bytes(V3LmfFrameCodec.sessionIdBytes, 0x71);
      final alternateInitiator =
          _bytes(V3LmfFrameCodec.routingBindingBytes, 0x31);
      final alternateResponder =
          _bytes(V3LmfFrameCodec.routingBindingBytes, 0x91);
      final alternate = _candidateFrom(
        fixture.checkpoint,
        receivingEpoch: 0,
        revisionIncrement: 0,
        advanceReceiveCounter: false,
        sessionIdOverride: alternateSessionId,
        transcriptOverride: _bytes(48, 0x51),
        initiatorBindingOverride: alternateInitiator,
        responderBindingOverride: alternateResponder,
        ackI2ROverride: _bytes(32, 0x15),
        ackR2IOverride: _bytes(32, 0x95),
      );
      final alternateRemote = alternate.ecRemoteDhPublicKey!;
      final alternatePlaintext = _bytes(72, 0x42);
      final alternateFrame = await V3LmfAead.sealSingle(
        metadata: V3LmfMessageMetadata(
          kind: V3LmfFrameKind.application,
          senderBinding: alternateResponder,
          recipientBinding: alternateInitiator,
          messageId: _bytes(V3LmfFrameCodec.messageIdBytes, 0x61),
          sessionId: alternateSessionId,
          epoch: 0,
          messageCounter: 0,
        ),
        plaintext: alternatePlaintext,
        secretKey: fixture.transportKey,
        nonce: _bytes(V3LmfFrameCodec.nonceBytes, 0x81),
        hybridRatchetHeader: V3HybridRatchetHeader(
          ecHeader: V3EcRatchetHeader(
            ratchetPublicKey: alternateRemote,
            previousSendingChainLength: 0,
            messageCounter: 0,
          ),
          sckaMessage: V3SckaMessage(
            sendingEpoch: 0,
            messageCounter: 0,
            nativePayload: _bytes(24, 0xa1),
          ),
        ),
      );
      final alternateOutcome = await fixture.inbox.receive(
        frame: alternateFrame,
        secretKey: fixture.transportKey,
      );
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
      );
      final restored = await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint, alternate],
      );
      expect(restored.sessionRevisions.values, everyElement(0));
      expect(controller.sessionCount, 2);

      final first = await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      final second = await controller.commitDelivery(
        delivery: alternateOutcome.delivery!,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      expect(first.ratchetRevision, 1);
      expect(second.ratchetRevision, 1);
      final firstCurrent = await controller.snapshotForSession(
        fixture.checkpoint.sessionId,
      );
      final secondCurrent = await controller.snapshotForSession(
        alternate.sessionId,
      );
      expect(firstCurrent.revision, 1);
      expect(secondCurrent.revision, 1);
      firstCurrent.wipeSecrets();
      secondCurrent.wipeSecrets();

      await controller.close();
      await fixture.inbox.close();
      fixture.checkpoint.wipeSecrets();
      alternate.wipeSecrets();
      alternateRemote.fillRange(0, alternateRemote.length, 0);
    });

    test('fails stopped after tombstone failure and resumes after restart',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      fixture.store.failKindOnce = V3LmfDurableInbox.committedRecordKind;
      var builderCalls = 0;
      await expectLater(
        controller.commitDelivery(
          delivery: fixture.deliveries.single,
          expectedRevision: 0,
          transitionBuilder: (_, current, __) {
            builderCalls++;
            return _candidateFrom(current, receivingEpoch: 0);
          },
        ),
        throwsStateError,
      );
      expect(builderCalls, 1);
      expect(controller.requiresRecovery, isTrue);
      await expectLater(
        controller.snapshotForSession(fixture.checkpoint.sessionId),
        throwsStateError,
      );
      await controller.close();
      await fixture.inbox.close();

      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      final inboxState = await restoredInbox.restore(
        keyResolver: (_) => fixture.transportKey,
      );
      expect(inboxState.deliveries, hasLength(1));
      final restoredController = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
      );
      final restored = await restoredController.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );
      expect(restored.sessionRevisions.values, <int>[1]);
      expect(
        restored.pendingInboxCommitAssemblyIds,
        <String>{fixture.deliveries.single.assemblyId},
      );

      final resumed = await restoredController.resumeDurableDelivery(
        delivery: inboxState.deliveries.single,
      );
      expect(resumed.wasAlreadyDurable, isTrue);
      expect(resumed.ratchetRevision, 1);
      final replay = await restoredInbox.receive(
        frame: fixture.frames.single,
        secretKey: fixture.transportKey,
      );
      expect(replay.status, V3LmfInboxStatus.committedReplay);

      await restoredController.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('rejects a non-contiguous durable effect chain during restore',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final directJournal = V3LmfAtomicCommitJournal(
        store: fixture.store,
        inbox: fixture.inbox,
      );
      await directJournal.restore();
      await directJournal.commit(
        delivery: fixture.deliveries.single,
        builder: (plaintext) {
          final record = V3CommittedRecord.fromDelivery(
            targetFrame: fixture.frames.single,
            content: plaintext,
          );
          final candidate = _candidateFrom(
            fixture.checkpoint,
            receivingEpoch: 0,
            revisionIncrement: 2,
          );
          final applicationBytes = V3CommittedRecordCodec.encode(record);
          final ratchetBytes = V3TripleRatchetStateCodec.encode(candidate);
          try {
            return V3LmfAtomicEffect(
              applicationState: applicationBytes,
              ratchetState: ratchetBytes,
            );
          } finally {
            applicationBytes.fillRange(0, applicationBytes.length, 0);
            ratchetBytes.fillRange(0, ratchetBytes.length, 0);
            record.wipeContent();
            candidate.wipeSecrets();
          }
        },
      );
      await directJournal.close();
      await fixture.inbox.close();

      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => fixture.transportKey);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
      );
      await expectLater(
        controller.restore(
          checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(controller.requiresRecovery, isTrue);

      await controller.close();
      await restoredInbox.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('rejects changed stable bindings without poisoning a clean retry',
        () async {
      final fixture = await _Fixture.create(messageCount: 1);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: fixture.inbox,
        ),
      );
      await controller.restore(
        checkpoints: <V3TripleRatchetState>[fixture.checkpoint],
      );

      await expectLater(
        controller.commitDelivery(
          delivery: fixture.deliveries.single,
          expectedRevision: 0,
          transitionBuilder: (_, current, __) => _candidateFrom(
            current,
            receivingEpoch: 0,
            transcriptOverride: _bytes(48, 0xe1),
          ),
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(controller.requiresRecovery, isFalse);
      expect(
        fixture.store.records.values.where(
          (value) => value['kind'] == V3LmfAtomicCommitJournal.recordKind,
        ),
        isEmpty,
      );

      final committed = await controller.commitDelivery(
        delivery: fixture.deliveries.single,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _candidateFrom(current, receivingEpoch: 0),
      );
      expect(committed.ratchetRevision, 1);

      await controller.close();
      await fixture.inbox.close();
      fixture.checkpoint.wipeSecrets();
    });
  });
}

final class _Fixture {
  _Fixture({
    required this.store,
    required this.inbox,
    required this.transportKey,
    required this.checkpoint,
    required this.frames,
    required this.deliveries,
    required this.plaintexts,
  });

  final _FaultStore store;
  final V3LmfDurableInbox inbox;
  final SecretKey transportKey;
  final V3TripleRatchetState checkpoint;
  final List<V3LmfFrame> frames;
  final List<V3LmfDurableDelivery> deliveries;
  final List<Uint8List> plaintexts;

  static Future<_Fixture> create({required int messageCount}) async {
    final store = _FaultStore();
    final transportKey = SecretKeyData(_bytes(32, 0x31));
    final localPair = await X25519().newKeyPairFromSeed(_bytes(32, 0x51));
    final remotePair = await X25519().newKeyPairFromSeed(_bytes(32, 0x91));
    final localPrivate = Uint8List.fromList(
      await localPair.extractPrivateKeyBytes(),
    );
    final localPublic = Uint8List.fromList(
      (await localPair.extractPublicKey()).bytes,
    );
    final remotePublic = Uint8List.fromList(
      (await remotePair.extractPublicKey()).bytes,
    );
    final sessionId = _bytes(V3LmfFrameCodec.sessionIdBytes, 0x11);
    final initiatorBinding = _bytes(V3LmfFrameCodec.routingBindingBytes, 0x21);
    final responderBinding = _bytes(V3LmfFrameCodec.routingBindingBytes, 0x61);
    final checkpoint = V3TripleRatchetState(
      role: V3SessionRole.initiator,
      lifecycle: V3RatchetLifecycle.active,
      revision: 0,
      sessionId: sessionId,
      transcriptDigest: _bytes(48, 0xa1),
      initiatorRoutingBinding: initiatorBinding,
      responderRoutingBinding: responderBinding,
      initiatorToResponderAckRootKey: _bytes(32, 0x41),
      responderToInitiatorAckRootKey: _bytes(32, 0x81),
      ecRootKey: _bytes(32, 0x12),
      ecSendingChainKey: _bytes(32, 0x32),
      ecReceivingChainKey: _bytes(32, 0x52),
      ecLocalDhPrivateKey: localPrivate,
      ecLocalDhPublicKey: localPublic,
      ecRemoteDhPublicKey: remotePublic,
      ecSendCounter: 0,
      ecReceiveCounter: 0,
      ecPreviousSendingChainLength: 0,
      pqRootKey: _bytes(32, 0x72),
      sckaStateSealKey: _bytes(32, 0x82),
      pqCurrentEpoch: 0,
      pqSendingEpoch: 0,
      pqReceivingEpoch: 0,
      pqEpochStates: <V3PqEpochState>[
        V3PqEpochState(
          epoch: 0,
          sendingChainKey: _bytes(32, 0x92),
          receivingChainKey: _bytes(32, 0xb2),
        ),
      ],
      nativeSckaState: _bytes(128, 0xd2),
    );
    localPrivate.fillRange(0, localPrivate.length, 0);

    final frames = <V3LmfFrame>[];
    final plaintexts = <Uint8List>[];
    for (var index = 0; index < messageCount; index++) {
      final plaintext = _bytes(64 + index, 0x30 + index);
      final metadata = V3LmfMessageMetadata(
        kind: V3LmfFrameKind.application,
        senderBinding: responderBinding,
        recipientBinding: initiatorBinding,
        messageId: _bytes(V3LmfFrameCodec.messageIdBytes, 0xc0 + index),
        sessionId: sessionId,
        epoch: 0,
        messageCounter: index,
      );
      final header = V3HybridRatchetHeader(
        ecHeader: V3EcRatchetHeader(
          ratchetPublicKey: remotePublic,
          previousSendingChainLength: 0,
          messageCounter: index,
        ),
        sckaMessage: V3SckaMessage(
          sendingEpoch: 0,
          messageCounter: index,
          nativePayload: _bytes(24, 0xe0 + index),
        ),
      );
      frames.add(
        await V3LmfAead.sealSingle(
          metadata: metadata,
          plaintext: plaintext,
          secretKey: transportKey,
          nonce: _bytes(V3LmfFrameCodec.nonceBytes, 0x10 + index),
          hybridRatchetHeader: header,
        ),
      );
      plaintexts.add(plaintext);
    }

    final inbox = V3LmfDurableInbox(store: store);
    await inbox.restore(keyResolver: (_) => transportKey);
    final deliveries = <V3LmfDurableDelivery>[];
    for (final frame in frames) {
      final outcome =
          await inbox.receive(frame: frame, secretKey: transportKey);
      deliveries.add(outcome.delivery!);
    }
    return _Fixture(
      store: store,
      inbox: inbox,
      transportKey: transportKey,
      checkpoint: checkpoint,
      frames: frames,
      deliveries: deliveries,
      plaintexts: plaintexts,
    );
  }
}

Future<void> _prepareIncomingRetirementPlan(
  _FaultStore store, {
  String? sourceCheckpointDigestOverride,
  String? assemblyId,
}) async {
  final checkpoint = store.records.values.singleWhere(
    (payload) => payload['kind'] == V3SessionCheckpointRepository.recordKind,
  );
  final replay = store.records.values.singleWhere(
    (payload) =>
        payload['kind'] == V3LmfDurableInbox.replayWindowRecordKind &&
        (assemblyId == null || payload['assemblyId'] == assemblyId),
  );
  final receipt = (checkpoint['receipts'] as List<dynamic>)
      .map((value) => (value as Map).cast<String, dynamic>())
      .singleWhere(
        (value) => assemblyId == null || value['assemblyId'] == assemblyId,
      );
  final proofRecordedAt = DateTime.fromMillisecondsSinceEpoch(
    replay['committedAt'] as int,
    isUtc: true,
  );
  const lifetime = Duration(days: 365);
  final journal = V3SessionRetirementJournal(store: store);
  await journal.restore();
  await journal.prepare(
    direction: V3CheckpointEffectDirection.incoming,
    assemblyId: replay['assemblyId'] as String,
    proofDigest: replay['higherLevelCommitDigest'] as String,
    stableRecordId: replay['stableRecordId'] as String,
    sessionKey: replay['sessionId'] as String,
    ratchetRevision: replay['ratchetRevision'] as int,
    stateDigest: receipt['stateDigest'] as String,
    sourceCheckpointDigest: sourceCheckpointDigestOverride ??
        checkpoint['checkpointDigest'] as String,
    proofRecordedAt: proofRecordedAt,
    preparedAt: proofRecordedAt.add(lifetime),
    minimumProofLifetimeSeconds: lifetime.inSeconds,
  );
  await journal.close();
}

V3SessionCommitController _retirementController(
  _Fixture fixture, {
  V3LmfDurableInbox? inbox,
}) {
  return V3SessionCommitController(
    journal: V3LmfAtomicCommitJournal(
      store: fixture.store,
      inbox: inbox ?? fixture.inbox,
    ),
    committedRecordMaterializer: V3CommittedRecordMaterializer(
      store: fixture.store,
    ),
    checkpointRepository: V3SessionCheckpointRepository(
      store: fixture.store,
    ),
    retirementJournal: V3SessionRetirementJournal(store: fixture.store),
  );
}

V3TripleRatchetState _candidateFrom(
  V3TripleRatchetState current, {
  required int receivingEpoch,
  Uint8List? transcriptOverride,
  int revisionIncrement = 1,
  bool advanceReceiveCounter = true,
  int pqReceiveCounterIncrement = 0,
  Uint8List? sessionIdOverride,
  Uint8List? initiatorBindingOverride,
  Uint8List? responderBindingOverride,
  Uint8List? ackI2ROverride,
  Uint8List? ackR2IOverride,
}) {
  final sessionId = sessionIdOverride == null
      ? current.sessionId
      : Uint8List.fromList(sessionIdOverride);
  final transcript = transcriptOverride == null
      ? current.transcriptDigest
      : Uint8List.fromList(transcriptOverride);
  final initiatorBinding = initiatorBindingOverride == null
      ? current.initiatorRoutingBinding
      : Uint8List.fromList(initiatorBindingOverride);
  final responderBinding = responderBindingOverride == null
      ? current.responderRoutingBinding
      : Uint8List.fromList(responderBindingOverride);
  final ackI2R = ackI2ROverride == null
      ? current.initiatorToResponderAckRootKey
      : Uint8List.fromList(ackI2ROverride);
  final ackR2I = ackR2IOverride == null
      ? current.responderToInitiatorAckRootKey
      : Uint8List.fromList(ackR2IOverride);
  final ecRoot = current.ecRootKey;
  final ecSending = current.ecSendingChainKey;
  final ecReceiving = current.ecReceivingChainKey;
  final ecPrivate = current.ecLocalDhPrivateKey;
  final ecPublic = current.ecLocalDhPublicKey;
  final ecRemote = current.ecRemoteDhPublicKey!;
  final pqRoot = current.pqRootKey;
  final epochs = current.pqEpochStates;
  final candidateEpochs = <V3PqEpochState>[];
  final ecSkipped = current.ecSkippedMessageKeys;
  final pqSkipped = current.pqSkippedMessageKeys;
  final nativeState = current.nativeSckaState;
  try {
    for (final epoch in epochs) {
      final sending = epoch.sendingChainKey;
      final receiving = epoch.receivingChainKey;
      try {
        candidateEpochs.add(
          V3PqEpochState(
            epoch: epoch.epoch,
            sendingChainKey: sending,
            sendCounter: epoch.sendCounter,
            receivingChainKey: receiving,
            receiveCounter: epoch.receiveCounter +
                (epoch.epoch == receivingEpoch ? pqReceiveCounterIncrement : 0),
          ),
        );
      } finally {
        sending?.fillRange(0, sending.length, 0);
        receiving?.fillRange(0, receiving.length, 0);
      }
    }
    return V3TripleRatchetState(
      role: current.role,
      lifecycle: current.lifecycle,
      revision: current.revision + revisionIncrement,
      sessionId: sessionId,
      transcriptDigest: transcript,
      initiatorRoutingBinding: initiatorBinding,
      responderRoutingBinding: responderBinding,
      initiatorToResponderAckRootKey: ackI2R,
      responderToInitiatorAckRootKey: ackR2I,
      ecRootKey: ecRoot,
      ecSendingChainKey: ecSending,
      ecReceivingChainKey: ecReceiving,
      ecLocalDhPrivateKey: ecPrivate,
      ecLocalDhPublicKey: ecPublic,
      ecRemoteDhPublicKey: ecRemote,
      ecSendCounter: current.ecSendCounter,
      ecReceiveCounter:
          current.ecReceiveCounter + (advanceReceiveCounter ? 1 : 0),
      ecPreviousSendingChainLength: current.ecPreviousSendingChainLength,
      pqRootKey: pqRoot,
      sckaStateSealKey: current.sckaStateSealKey,
      pqCurrentEpoch: current.pqCurrentEpoch,
      pqSendingEpoch: current.pqSendingEpoch,
      pqReceivingEpoch: receivingEpoch,
      pqEpochStates: candidateEpochs,
      ecSkippedMessageKeys: ecSkipped,
      pqSkippedMessageKeys: pqSkipped,
      nativeSckaState: nativeState,
    );
  } finally {
    for (final value in <Uint8List?>[
      sessionId,
      transcript,
      initiatorBinding,
      responderBinding,
      ackI2R,
      ackR2I,
      ecRoot,
      ecSending,
      ecReceiving,
      ecPrivate,
      ecPublic,
      ecRemote,
      pqRoot,
      nativeState,
    ]) {
      value?.fillRange(0, value.length, 0);
    }
    for (final value in epochs) {
      value.wipeSecrets();
    }
    for (final value in candidateEpochs) {
      value.wipeSecrets();
    }
    for (final value in ecSkipped) {
      value.wipeSecret();
    }
    for (final value in pqSkipped) {
      value.wipeSecret();
    }
  }
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

Map<String, dynamic> _deepCopy(Map<String, dynamic> value) =>
    (jsonDecode(jsonEncode(value)) as Map).cast<String, dynamic>();

final class _FaultStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records =
      <String, Map<String, dynamic>>{};
  var _nextId = 0;
  String? failKindOnce;
  String? durableWriteThenThrowKind;
  bool durableWriteThenThrowFinalCheckpoint = false;
  String? failDeleteKindOnce;
  String? durableDeleteThenThrowKind;
  int? durableDeleteThenThrowRetirementStage;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    if (payload['kind'] == failKindOnce) {
      failKindOnce = null;
      throw StateError('injected write failure');
    }
    final id = 'record-${_nextId++}';
    records[id] = _deepCopy(payload);
    final retirement = payload['retirement'];
    if (durableWriteThenThrowFinalCheckpoint &&
        payload['kind'] == V3SessionCheckpointRepository.recordKind &&
        retirement is Map &&
        retirement['pendingCheckpointDigest'] != null) {
      durableWriteThenThrowFinalCheckpoint = false;
      throw StateError('injected ambiguous final-checkpoint write');
    }
    if (payload['kind'] == durableWriteThenThrowKind) {
      durableWriteThenThrowKind = null;
      throw StateError('injected ambiguous write');
    }
    return id;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async => records.entries
      .map(
        (entry) => V3LmfStoredRecord(
          storageId: entry.key,
          payload: _deepCopy(entry.value),
        ),
      )
      .toList(growable: false);

  @override
  Future<void> delete(String storageId) async {
    final stored = records[storageId];
    if (stored?['kind'] == failDeleteKindOnce) {
      failDeleteKindOnce = null;
      throw StateError('injected pre-delete failure');
    }
    final removed = records.remove(storageId);
    final stageMatches =
        removed?['kind'] == V3SessionRetirementJournal.recordKind &&
            removed?['stage'] == durableDeleteThenThrowRetirementStage;
    if (removed?['kind'] == durableDeleteThenThrowKind || stageMatches) {
      durableDeleteThenThrowKind = null;
      durableDeleteThenThrowRetirementStage = null;
      throw StateError('injected ambiguous delete');
    }
  }
}
