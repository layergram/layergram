import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/committed_record_materializer_v3.dart';
import 'package:layergram/core/crypto/v3/committed_record_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_acknowledgement.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_atomic_commit.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_outbox.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/pq_message_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/session_commit_controller_v3.dart';
import 'package:layergram/core/crypto/v3/session_checkpoint_v3.dart';
import 'package:layergram/core/crypto/v3/session_send_journal_v3.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_engine_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';

void main() {
  group('inactive v3 durable session sending', () {
    test('commits ratchet and exact sealed bytes before export', () async {
      final fixture = await _SendFixture.create();
      final plaintext = _bytes(900, 0x41);
      final result = await fixture.controller.sendMessage(
        sessionId: fixture.checkpoint.sessionId,
        expectedRevision: 0,
        plaintext: plaintext,
        backend: fixture.backend,
        persistedAt: DateTime.utc(2026, 8, 14),
      );

      expect(result.ratchetRevision, 1);
      expect(result.frames.length, greaterThan(1));
      expect(fixture.backend.sendCalls, 1);
      final pending = await fixture.controller.pendingSendFrames(
        result.assemblyId,
      );
      _expectExactFrames(pending, result.frames);
      final current = await fixture.controller.snapshotForSession(
        fixture.checkpoint.sessionId,
      );
      expect(current.revision, 1);
      expect(
        fixture.store.records.values
            .where(
              (payload) => payload['kind'] == V3SessionSendJournal.recordKind,
            )
            .length,
        1,
      );
      expect(
        fixture.store.records.values
            .where(
              (payload) =>
                  payload['kind'] == V3LmfDurableOutbox.outboxRecordKind,
            )
            .length,
        1,
      );

      current.wipeSecrets();
      _wipe(plaintext);
      await fixture.close();
    });

    test('materializes AR3 and checkpoints TR3 before exposing a send',
        () async {
      final fixture = await _SendFixture.create(durableState: true);
      final result = await fixture.controller.sendMessage(
        sessionId: fixture.checkpoint.sessionId,
        expectedRevision: 0,
        plaintext: _bytes(320, 0x49),
        backend: fixture.backend,
        persistedAt: DateTime.utc(2026, 8, 14),
      );
      expect(result.ratchetRevision, 1);
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
      expect(
        (checkpointPayload['receipts'] as List).single['assemblyId'],
        result.assemblyId,
      );
      final backendCalls = fixture.backend.sendCalls;
      await fixture.closeControllerOnly();

      final restored = await _SendFixture.create(
        store: fixture.store,
        checkpoint: fixture.checkpoint,
        backend: fixture.backend,
        durableState: true,
      );
      expect(restored.restoreResult.materializedRecordCount, 1);
      expect(restored.restoreResult.checkpointCount, 1);
      expect(restored.restoreResult.pendingSendAssemblyIds, <String>{
        result.assemblyId,
      });
      expect(restored.backend.sendCalls, backendCalls);
      expect(
        restored.store.records.values
            .where(
              (payload) =>
                  payload['kind'] == V3CommittedRecordMaterializer.recordKind,
            )
            .length,
        1,
      );
      await restored.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('ambiguous durable-state writes self-heal from committed send state',
        () async {
      for (final failingKind in <String>[
        V3CommittedRecordMaterializer.recordKind,
        V3SessionCheckpointRepository.recordKind,
      ]) {
        final store = _FaultStore();
        final fixture = await _SendFixture.create(
          store: store,
          durableState: true,
        );
        store.durableThenThrowKind = failingKind;
        await expectLater(
          fixture.controller.sendMessage(
            sessionId: fixture.checkpoint.sessionId,
            expectedRevision: 0,
            plaintext: _bytes(288, failingKind.length),
            backend: fixture.backend,
          ),
          throwsStateError,
        );
        expect(fixture.controller.requiresRecovery, isTrue);
        expect(fixture.backend.sendCalls, 1);
        await fixture.closeControllerOnly();

        final restored = await _SendFixture.create(
          store: store,
          checkpoint: fixture.checkpoint,
          backend: fixture.backend,
          durableState: true,
        );
        expect(restored.restoreResult.materializedRecordCount, 1);
        expect(restored.restoreResult.checkpointCount, 1);
        expect(restored.restoreResult.pendingSendAssemblyIds, hasLength(1));
        expect(restored.backend.sendCalls, 1);
        await restored.close();
        fixture.checkpoint.wipeSecrets();
      }
    });

    test('durable-then-throw send recovers without ratchet or AEAD rerun',
        () async {
      final store = _FaultStore();
      final fixture = await _SendFixture.create(store: store);
      final plaintext = _bytes(700, 0x51);
      store.durableThenThrowKind = V3SessionSendJournal.recordKind;

      await expectLater(
        fixture.controller.sendMessage(
          sessionId: fixture.checkpoint.sessionId,
          expectedRevision: 0,
          plaintext: plaintext,
          backend: fixture.backend,
        ),
        throwsStateError,
      );
      expect(fixture.controller.requiresRecovery, isTrue);
      expect(fixture.backend.sendCalls, 1);
      final durablePayload = store.records.values.singleWhere(
        (payload) => payload['kind'] == V3SessionSendJournal.recordKind,
      );
      final exactStoredFrames = (durablePayload['frames'] as List<dynamic>)
          .cast<String>()
          .toList(growable: false);
      await expectLater(
        fixture.controller.sendMessage(
          sessionId: fixture.checkpoint.sessionId,
          expectedRevision: 0,
          plaintext: plaintext,
          backend: fixture.backend,
        ),
        throwsStateError,
      );
      expect(fixture.backend.sendCalls, 1);
      await fixture.closeControllerOnly();

      final restored = await _SendFixture.create(
        store: store,
        checkpoint: fixture.checkpoint,
        backend: fixture.backend,
      );
      final state = await restored.controller.snapshotForSession(
        restored.checkpoint.sessionId,
      );
      expect(state.revision, 1);
      final restoreResult = restored.restoreResult;
      expect(restoreResult.committedSendEffectCount, 1);
      expect(restoreResult.pendingSendAssemblyIds, hasLength(1));
      final pending = await restored.controller.pendingSendFrames(
        restoreResult.pendingSendAssemblyIds.single,
      );
      expect(
        pending
            .map(V3LmfFrameCodec.encodeBinary)
            .map(_encodeBinary)
            .toList(growable: false),
        exactStoredFrames,
      );
      expect(restored.backend.sendCalls, 1);

      state.wipeSecrets();
      _wipe(plaintext);
      await restored.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('ambiguous outbox enqueue restores exact journal bytes without rerun',
        () async {
      final store = _FaultStore();
      final fixture = await _SendFixture.create(store: store);
      store.durableThenThrowKind = V3LmfDurableOutbox.outboxRecordKind;
      await expectLater(
        fixture.controller.sendMessage(
          sessionId: fixture.checkpoint.sessionId,
          expectedRevision: 0,
          plaintext: _bytes(620, 0x59),
          backend: fixture.backend,
        ),
        throwsStateError,
      );
      expect(fixture.controller.requiresRecovery, isTrue);
      expect(fixture.backend.sendCalls, 1);
      final journalPayload = store.records.values.singleWhere(
        (payload) => payload['kind'] == V3SessionSendJournal.recordKind,
      );
      final exactStoredFrames = (journalPayload['frames'] as List<dynamic>)
          .cast<String>()
          .toList(growable: false);
      await fixture.closeControllerOnly();

      final restored = await _SendFixture.create(
        store: store,
        checkpoint: fixture.checkpoint,
        backend: fixture.backend,
      );
      final assemblyId = restored.restoreResult.pendingSendAssemblyIds.single;
      final frames = await restored.controller.pendingSendFrames(assemblyId);
      expect(
        frames
            .map(V3LmfFrameCodec.encodeBinary)
            .map(_encodeBinary)
            .toList(growable: false),
        exactStoredFrames,
      );
      expect(restored.backend.sendCalls, 1);

      await restored.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('serializes competing sends and applies revision CAS first', () async {
      final fixture = await _SendFixture.create();
      final first = fixture.controller.sendMessage(
        sessionId: fixture.checkpoint.sessionId,
        expectedRevision: 0,
        plaintext: _bytes(64, 0x61),
        backend: fixture.backend,
      );
      final second = fixture.controller.sendMessage(
        sessionId: fixture.checkpoint.sessionId,
        expectedRevision: 0,
        plaintext: _bytes(64, 0x71),
        backend: fixture.backend,
      );

      final firstResult = await first;
      await expectLater(second, throwsStateError);
      expect(firstResult.ratchetRevision, 1);
      expect(fixture.backend.sendCalls, 1);
      expect(fixture.controller.requiresRecovery, isFalse);

      await fixture.close();
    });

    test('preflights outbox capacity before committing a ratchet effect',
        () async {
      final store = _FaultStore();
      final fixture = await _SendFixture.create(
        store: store,
        outboxMaxEntries: 1,
      );
      await fixture.controller.sendMessage(
        sessionId: fixture.checkpoint.sessionId,
        expectedRevision: 0,
        plaintext: _bytes(80, 0x79),
        backend: fixture.backend,
      );
      await expectLater(
        fixture.controller.sendMessage(
          sessionId: fixture.checkpoint.sessionId,
          expectedRevision: 1,
          plaintext: _bytes(80, 0x7a),
          backend: fixture.backend,
        ),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      expect(fixture.controller.requiresRecovery, isFalse);
      expect(
        store.records.values.where(
          (payload) => payload['kind'] == V3SessionSendJournal.recordKind,
        ),
        hasLength(1),
      );
      final current = await fixture.controller.snapshotForSession(
        fixture.checkpoint.sessionId,
      );
      expect(current.revision, 1);
      current.wipeSecrets();
      await fixture.closeControllerOnly();

      final restored = await _SendFixture.create(
        store: store,
        checkpoint: fixture.checkpoint,
        backend: fixture.backend,
        outboxMaxEntries: 1,
      );
      expect(restored.restoreResult.sessionRevisions.values, <int>[1]);
      expect(restored.restoreResult.committedSendEffectCount, 1);
      expect(restored.restoreResult.pendingSendAssemblyIds, hasLength(1));

      await restored.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('complete ACK commits journal before deleting outbox materialization',
        () async {
      final fixture = await _SendFixture.create();
      final result = await fixture.controller.sendMessage(
        sessionId: fixture.checkpoint.sessionId,
        expectedRevision: 0,
        plaintext: _bytes(512, 0x81),
        backend: fixture.backend,
      );
      final ack = await _completeAckFrame(
        result.frames,
        fixture.checkpoint,
      );
      expect(
        await fixture.controller.applySendAcknowledgement(
          acknowledgementFrame: ack,
          receivedAt: DateTime.utc(2026, 8, 14, 12),
        ),
        V3LmfOutboxAckStatus.complete,
      );
      expect(
        await fixture.controller.pendingSendFrames(result.assemblyId),
        isEmpty,
      );
      final durable = fixture.store.records.values.singleWhere(
        (payload) => payload['kind'] == V3SessionSendJournal.recordKind,
      );
      expect(durable['revision'], 1);
      expect(durable['acknowledged'], isTrue);
      expect(
        fixture.store.records.values.where(
          (payload) => payload['kind'] == V3LmfDurableOutbox.outboxRecordKind,
        ),
        isEmpty,
      );

      await fixture.closeControllerOnly();
      final restored = await _SendFixture.create(
        store: fixture.store,
        checkpoint: fixture.checkpoint,
        backend: fixture.backend,
      );
      expect(restored.restoreResult.pendingSendAssemblyIds, isEmpty);
      expect(
        await restored.controller.pendingSendFrames(result.assemblyId),
        isEmpty,
      );
      expect(restored.backend.sendCalls, 1);

      await restored.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('unauthenticated ACK is rejected without poisoning clean retry',
        () async {
      final fixture = await _SendFixture.create();
      final result = await fixture.controller.sendMessage(
        sessionId: fixture.checkpoint.sessionId,
        expectedRevision: 0,
        plaintext: _bytes(300, 0x89),
        backend: fixture.backend,
      );
      final forgedAck = await _completeAckFrame(
        result.frames,
        fixture.checkpoint,
        useWrongAeadKey: true,
      );
      await expectLater(
        fixture.controller.applySendAcknowledgement(
          acknowledgementFrame: forgedAck,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(fixture.controller.requiresRecovery, isFalse);
      expect(
        await fixture.controller.pendingSendFrames(result.assemblyId),
        hasLength(result.frames.length),
      );
      final wrongNonceAck = await _completeAckFrame(
        result.frames,
        fixture.checkpoint,
        useWrongNonce: true,
      );
      await expectLater(
        fixture.controller.applySendAcknowledgement(
          acknowledgementFrame: wrongNonceAck,
        ),
        throwsFormatException,
      );
      expect(fixture.controller.requiresRecovery, isFalse);
      expect(
        await fixture.controller.pendingSendFrames(result.assemblyId),
        hasLength(result.frames.length),
      );
      expect(
        await fixture.controller.applySendAcknowledgement(
          acknowledgementFrame: await _completeAckFrame(
            result.frames,
            fixture.checkpoint,
          ),
        ),
        V3LmfOutboxAckStatus.complete,
      );

      await fixture.close();
    });

    test('partial ACK changes only outbox progress across restart', () async {
      final fixture = await _SendFixture.create();
      final result = await fixture.controller.sendMessage(
        sessionId: fixture.checkpoint.sessionId,
        expectedRevision: 0,
        plaintext: _bytes(900, 0x99),
        backend: fixture.backend,
      );
      expect(result.frames.length, greaterThan(2));
      final partialIndexes = <int>{0, result.frames.length - 1};
      final partialAck = await _completeAckFrame(
        result.frames,
        fixture.checkpoint,
        fragmentIndexes: partialIndexes,
      );
      expect(
        await fixture.controller.applySendAcknowledgement(
          acknowledgementFrame: partialAck,
        ),
        V3LmfOutboxAckStatus.advanced,
      );
      expect(
        await fixture.controller.pendingSendFrames(result.assemblyId),
        hasLength(result.frames.length - partialIndexes.length),
      );
      final journalPayload = fixture.store.records.values.singleWhere(
        (payload) => payload['kind'] == V3SessionSendJournal.recordKind,
      );
      expect(journalPayload['revision'], 0);
      expect(journalPayload['acknowledged'], isFalse);
      await fixture.closeControllerOnly();

      final restored = await _SendFixture.create(
        store: fixture.store,
        checkpoint: fixture.checkpoint,
        backend: fixture.backend,
      );
      expect(
          restored.restoreResult.pendingSendAssemblyIds, {result.assemblyId});
      expect(
        await restored.controller.pendingSendFrames(result.assemblyId),
        hasLength(result.frames.length - partialIndexes.length),
      );

      await restored.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('ambiguous complete-ACK write restores completed without resend',
        () async {
      final store = _FaultStore();
      final fixture = await _SendFixture.create(store: store);
      final result = await fixture.controller.sendMessage(
        sessionId: fixture.checkpoint.sessionId,
        expectedRevision: 0,
        plaintext: _bytes(400, 0xa1),
        backend: fixture.backend,
      );
      final ack = await _completeAckFrame(
        result.frames,
        fixture.checkpoint,
      );
      store.durableThenThrowKind = V3SessionSendJournal.recordKind;
      await expectLater(
        fixture.controller.applySendAcknowledgement(
          acknowledgementFrame: ack,
        ),
        throwsStateError,
      );
      expect(fixture.controller.requiresRecovery, isTrue);
      await fixture.closeControllerOnly();

      final restored = await _SendFixture.create(
        store: store,
        checkpoint: fixture.checkpoint,
        backend: fixture.backend,
      );
      expect(restored.restoreResult.committedSendEffectCount, 1);
      expect(restored.restoreResult.pendingSendAssemblyIds, isEmpty);
      expect(
        await restored.controller.pendingSendFrames(result.assemblyId),
        isEmpty,
      );
      expect(
        store.records.values.where(
          (payload) => payload['kind'] == V3LmfDurableOutbox.outboxRecordKind,
        ),
        isEmpty,
      );

      await restored.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('ambiguous outbox ACK revision cannot resurrect completed send',
        () async {
      final store = _FaultStore();
      final fixture = await _SendFixture.create(store: store);
      final result = await fixture.controller.sendMessage(
        sessionId: fixture.checkpoint.sessionId,
        expectedRevision: 0,
        plaintext: _bytes(420, 0xb9),
        backend: fixture.backend,
      );
      final ack = await _completeAckFrame(
        result.frames,
        fixture.checkpoint,
      );
      store.durableThenThrowKind = V3LmfDurableOutbox.outboxRecordKind;
      await expectLater(
        fixture.controller.applySendAcknowledgement(
          acknowledgementFrame: ack,
        ),
        throwsStateError,
      );
      expect(fixture.controller.requiresRecovery, isTrue);
      await fixture.closeControllerOnly();

      final restored = await _SendFixture.create(
        store: store,
        checkpoint: fixture.checkpoint,
        backend: fixture.backend,
      );
      expect(restored.restoreResult.pendingSendAssemblyIds, isEmpty);
      expect(
        await restored.controller.pendingSendFrames(result.assemblyId),
        isEmpty,
      );
      expect(
        store.records.values.where(
          (payload) => payload['kind'] == V3LmfDurableOutbox.outboxRecordKind,
        ),
        isEmpty,
      );

      await restored.close();
      fixture.checkpoint.wipeSecrets();
    });

    test('claimed outbox and send journal reject direct lifecycle access',
        () async {
      final fixture = await _SendFixture.create();
      await expectLater(fixture.outbox.close(), throwsStateError);
      await expectLater(fixture.sendJournal.close(), throwsStateError);
      expect(() => fixture.sendJournal.effects(), throwsStateError);
      expect(
        () => fixture.sendJournal.effectForAssembly('not-an-assembly'),
        throwsStateError,
      );
      await fixture.close();
    });

    test('restart merges outgoing then incoming effects by ratchet revision',
        () async {
      final pair = await _pairedSnapshots();
      final fixture = await _SendFixture.create(checkpoint: pair.bob);
      final outgoing = await fixture.controller.sendMessage(
        sessionId: pair.bob.sessionId,
        expectedRevision: 0,
        plaintext: _bytes(96, 0xd1),
        backend: fixture.backend,
      );
      final afterSend = await fixture.controller.snapshotForSession(
        pair.bob.sessionId,
      );
      final incoming = await _prepareIncomingDelivery(
        localSnapshot: afterSend,
        peerSnapshot: pair.alice,
        backend: fixture.backend,
        inbox: fixture.inbox,
        plaintext: _bytes(128, 0xe1),
      );
      try {
        final committed = await fixture.controller.commitDelivery(
          delivery: incoming.delivery,
          expectedRevision: 1,
          transitionBuilder: (_, __, ___) =>
              _copySnapshot(incoming.transition.nextSnapshot),
        );
        expect(committed.ratchetRevision, 2);
      } finally {
        incoming.transition.close();
        afterSend.wipeSecrets();
      }
      await fixture.closeControllerOnly();

      final restored = await _SendFixture.create(
        store: fixture.store,
        checkpoint: pair.bob,
        backend: fixture.backend,
      );
      expect(restored.restoreResult.sessionRevisions.values, <int>[2]);
      expect(restored.restoreResult.committedSendEffectCount, 1);
      expect(restored.restoreResult.committedEffectCount, 1);
      expect(restored.restoreResult.pendingSendAssemblyIds, {
        outgoing.assemblyId,
      });
      _expectExactFrames(
        await restored.controller.pendingSendFrames(outgoing.assemblyId),
        outgoing.frames,
      );

      await restored.close();
      pair.alice.wipeSecrets();
      pair.bob.wipeSecrets();
    });

    test('restore fails closed on a same-revision send/receive fork', () async {
      final pair = await _pairedSnapshots();
      final fixture = await _SendFixture.create(checkpoint: pair.bob);
      await fixture.controller.sendMessage(
        sessionId: pair.bob.sessionId,
        expectedRevision: 0,
        plaintext: _bytes(96, 0x31),
        backend: fixture.backend,
      );
      await fixture.closeControllerOnly();

      final incomingInbox = V3LmfDurableInbox(store: fixture.store);
      await incomingInbox.restore(keyResolver: (_) => null);
      final incoming = await _prepareIncomingDelivery(
        localSnapshot: pair.bob,
        peerSnapshot: pair.alice,
        backend: fixture.backend,
        inbox: incomingInbox,
        plaintext: _bytes(128, 0x41),
      );
      final receiveJournal = V3LmfAtomicCommitJournal(
        store: fixture.store,
        inbox: incomingInbox,
      );
      await receiveJournal.restore();
      try {
        await receiveJournal.commit(
          delivery: incoming.delivery,
          builder: (plaintext) {
            final record = V3CommittedRecord.fromDelivery(
              targetFrame: incoming.delivery.frames.first,
              content: plaintext,
            );
            final application = V3CommittedRecordCodec.encode(record);
            final ratchet = V3TripleRatchetStateCodec.encode(
              incoming.transition.nextSnapshot,
            );
            try {
              return V3LmfAtomicEffect(
                applicationState: application,
                ratchetState: ratchet,
              );
            } finally {
              record.wipeContent();
              _wipe(application);
              _wipe(ratchet);
            }
          },
        );
      } finally {
        incoming.transition.close();
        await receiveJournal.close();
        await incomingInbox.close();
      }

      final restoredInbox = V3LmfDurableInbox(store: fixture.store);
      await restoredInbox.restore(keyResolver: (_) => null);
      final outbox = V3LmfDurableOutbox(store: fixture.store);
      final sendJournal = V3SessionSendJournal(store: fixture.store);
      final controller = V3SessionCommitController(
        journal: V3LmfAtomicCommitJournal(
          store: fixture.store,
          inbox: restoredInbox,
        ),
        sendJournal: sendJournal,
        outbox: outbox,
        snapshotValidator: fixture.backend.validateSnapshot,
      );
      await expectLater(
        controller.restore(
          checkpoints: <V3TripleRatchetState>[pair.bob],
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(controller.requiresRecovery, isTrue);

      await controller.close();
      await restoredInbox.close();
      pair.alice.wipeSecrets();
      pair.bob.wipeSecrets();
    });
  });
}

final class _SendFixture {
  _SendFixture._({
    required this.store,
    required this.checkpoint,
    required this.backend,
    required this.inbox,
    required this.outbox,
    required this.sendJournal,
    required this.controller,
    required this.restoreResult,
  });

  final _FaultStore store;
  final V3TripleRatchetState checkpoint;
  final _DeterministicEpochBackend backend;
  final V3LmfDurableInbox inbox;
  final V3LmfDurableOutbox outbox;
  final V3SessionSendJournal sendJournal;
  final V3SessionCommitController controller;
  final V3SessionCommitRestoreResult restoreResult;

  static Future<_SendFixture> create({
    _FaultStore? store,
    V3TripleRatchetState? checkpoint,
    _DeterministicEpochBackend? backend,
    int outboxMaxEntries = 64,
    bool durableState = false,
  }) async {
    final actualStore = store ?? _FaultStore();
    final pair = checkpoint == null ? await _pairedSnapshots() : null;
    final actualCheckpoint = checkpoint ?? pair!.alice;
    pair?.bob.wipeSecrets();
    final actualBackend = backend ?? _DeterministicEpochBackend();
    final inbox = V3LmfDurableInbox(store: actualStore);
    await inbox.restore(keyResolver: (_) => null);
    final outbox = V3LmfDurableOutbox(
      store: actualStore,
      maxEntries: outboxMaxEntries,
    );
    final sendJournal = V3SessionSendJournal(store: actualStore);
    final materializer =
        durableState ? V3CommittedRecordMaterializer(store: actualStore) : null;
    final checkpointRepository =
        durableState ? V3SessionCheckpointRepository(store: actualStore) : null;
    final controller = V3SessionCommitController(
      journal: V3LmfAtomicCommitJournal(
        store: actualStore,
        inbox: inbox,
      ),
      sendJournal: sendJournal,
      outbox: outbox,
      committedRecordMaterializer: materializer,
      checkpointRepository: checkpointRepository,
      snapshotValidator: actualBackend.validateSnapshot,
    );
    final restored = await controller.restore(
      checkpoints: <V3TripleRatchetState>[actualCheckpoint],
    );
    return _SendFixture._(
      store: actualStore,
      checkpoint: actualCheckpoint,
      backend: actualBackend,
      inbox: inbox,
      outbox: outbox,
      sendJournal: sendJournal,
      controller: controller,
      restoreResult: restored,
    );
  }

  Future<void> closeControllerOnly() async {
    await controller.close();
    await inbox.close();
  }

  Future<void> close() async {
    await closeControllerOnly();
    checkpoint.wipeSecrets();
  }
}

Future<V3LmfFrame> _completeAckFrame(
  List<V3LmfFrame> targetFrames,
  V3TripleRatchetState localSnapshot, {
  bool useWrongAeadKey = false,
  bool useWrongNonce = false,
  Set<int>? fragmentIndexes,
}) async {
  final selectedFrames = fragmentIndexes == null
      ? targetFrames
      : targetFrames
          .where((frame) => fragmentIndexes.contains(frame.fragmentIndex))
          .toList(growable: false);
  final acknowledgement =
      V3LmfAcknowledgementCodec.forReceivedFrames(selectedFrames);
  final plaintext = V3LmfAcknowledgementCodec.encode(acknowledgement);
  final target = targetFrames.first.metadata;
  final metadata = V3LmfMessageMetadata(
    kind: V3LmfFrameKind.acknowledgement,
    senderBinding: target.recipientBinding,
    recipientBinding: target.senderBinding,
    messageId: _bytes(V3LmfFrameCodec.messageIdBytes, 0xc1),
    sessionId: target.sessionId,
    epoch: target.epoch,
    messageCounter: target.messageCounter + 1,
  );
  final sessionId = localSnapshot.sessionId;
  final initiatorBinding = localSnapshot.initiatorRoutingBinding;
  final responderBinding = localSnapshot.responderRoutingBinding;
  final initiatorAckRoot = localSnapshot.initiatorToResponderAckRootKey;
  final responderAckRoot = localSnapshot.responderToInitiatorAckRootKey;
  final material = await V3KeySchedule.deriveAcknowledgementFromCommittedState(
    sessionId: sessionId,
    initiatorRoutingBinding: initiatorBinding,
    responderRoutingBinding: responderBinding,
    initiatorToResponderAckRootKey: initiatorAckRoot,
    responderToInitiatorAckRootKey: responderAckRoot,
    direction: localSnapshot.role == V3SessionRole.initiator
        ? V3TrafficDirection.responderToInitiator
        : V3TrafficDirection.initiatorToResponder,
    metadata: metadata,
  );
  final nonce = material.nonce;
  if (useWrongNonce) nonce[0] ^= 1;
  try {
    return V3LmfAead.sealSingle(
      metadata: metadata,
      plaintext: plaintext,
      secretKey: useWrongAeadKey
          ? SecretKeyData(_bytes(V3KeySchedule.secretBytes, 0xe1))
          : material.secretKey,
      nonce: nonce,
    );
  } finally {
    _wipe(plaintext);
    _wipe(nonce);
    _wipe(sessionId);
    _wipe(initiatorBinding);
    _wipe(responderBinding);
    _wipe(initiatorAckRoot);
    _wipe(responderAckRoot);
    material.close();
  }
}

Future<
    ({
      V3LmfDurableDelivery delivery,
      V3TripleRatchetTransition transition,
    })> _prepareIncomingDelivery({
  required V3TripleRatchetState localSnapshot,
  required V3TripleRatchetState peerSnapshot,
  required _DeterministicEpochBackend backend,
  required V3LmfDurableInbox inbox,
  required Uint8List plaintext,
}) async {
  V3TripleRatchetTransition? sent;
  V3TripleRatchetTransition? received;
  Uint8List? encodedHeader;
  final nonces = <Uint8List>[];
  try {
    sent = await V3TripleRatchetEngine.send(
      snapshot: peerSnapshot,
      backend: backend,
      kind: V3LmfFrameKind.application,
    );
    encodedHeader = V3HybridRatchetHeaderCodec.encode(sent.header);
    final fragmentCount = V3LmfFrameCodec.canonicalFragmentCount(
      assembledPlaintextLength: plaintext.length,
      hybridRatchetHeaderLength: encodedHeader.length,
    );
    for (var index = 0; index < fragmentCount; index++) {
      nonces.add(
        await sent.nonceForFragment(
          fragmentIndex: index,
          fragmentCount: fragmentCount,
          assembledPlaintextLength: plaintext.length,
        ),
      );
    }
    final frames = await V3LmfAead.sealFragmented(
      metadata: sent.metadata,
      plaintext: plaintext,
      secretKey: sent.secretKey,
      nonceForFragment: (index) => Uint8List.fromList(nonces[index]),
      hybridRatchetHeader: sent.header,
    );
    received = await V3TripleRatchetEngine.receiveFirstFragment(
      snapshot: localSnapshot,
      backend: backend,
      metadata: frames.first.metadata,
      header: frames.first.hybridRatchetHeader!,
      nonce: frames.first.nonce,
      fragmentCount: frames.first.fragmentCount,
      assembledPlaintextLength: frames.first.assembledPlaintextLength,
      nowUnixSeconds: 1000,
      skippedKeyLifetimeSeconds: 3600,
    );
    V3LmfDurableDelivery? delivery;
    for (final frame in frames) {
      final outcome = await inbox.receive(
        frame: frame,
        secretKey: received.secretKey,
      );
      delivery = outcome.delivery ?? delivery;
    }
    if (delivery == null) {
      throw StateError('test incoming delivery did not complete');
    }
    final result = (delivery: delivery, transition: received);
    received = null;
    return result;
  } finally {
    sent?.close();
    received?.close();
    if (encodedHeader != null) _wipe(encodedHeader);
    for (final nonce in nonces) {
      _wipe(nonce);
    }
    _wipe(plaintext);
  }
}

V3TripleRatchetState _copySnapshot(V3TripleRatchetState snapshot) {
  final encoded = V3TripleRatchetStateCodec.encode(snapshot);
  try {
    return V3TripleRatchetStateCodec.decode(encoded);
  } finally {
    _wipe(encoded);
  }
}

Future<({V3TripleRatchetState alice, V3TripleRatchetState bob})>
    _pairedSnapshots() async {
  final sessionId = _bytes(16, 0x11);
  final pqSeed = _bytes(32, 0x31);
  final alicePq = await V3PqMessageRatchet.deriveInitialEpoch(
    role: V3SessionRole.initiator,
    sessionId: sessionId,
    pqRootSeed: pqSeed,
  );
  final bobPq = await V3PqMessageRatchet.deriveInitialEpoch(
    role: V3SessionRole.responder,
    sessionId: sessionId,
    pqRootSeed: pqSeed,
  );
  final x25519 = X25519();
  final alicePrivate = _bytes(32, 0x51);
  final bobPrivate = _bytes(32, 0x91);
  final alicePublic = Uint8List.fromList(
    (await (await x25519.newKeyPairFromSeed(alicePrivate)).extractPublicKey())
        .bytes,
  );
  final bobPublic = Uint8List.fromList(
    (await (await x25519.newKeyPairFromSeed(bobPrivate)).extractPublicKey())
        .bytes,
  );
  final aliceToBobEc = _bytes(32, 0xb1);
  final bobToAliceEc = _bytes(32, 0xd1);
  V3TripleRatchetState? alice;
  V3TripleRatchetState? bob;
  try {
    alice = _snapshot(
      role: V3SessionRole.initiator,
      sessionId: sessionId,
      ecPrivate: alicePrivate,
      ecPublic: alicePublic,
      ecRemote: bobPublic,
      ecSending: aliceToBobEc,
      ecReceiving: null,
      pqRoot: alicePq.rootKey,
      pqEpoch: alicePq.epoch,
    );
    bob = _snapshot(
      role: V3SessionRole.responder,
      sessionId: sessionId,
      ecPrivate: bobPrivate,
      ecPublic: bobPublic,
      ecRemote: alicePublic,
      ecSending: bobToAliceEc,
      ecReceiving: aliceToBobEc,
      pqRoot: bobPq.rootKey,
      pqEpoch: bobPq.epoch,
    );
    final result = (alice: alice, bob: bob);
    alice = null;
    bob = null;
    return result;
  } finally {
    alice?.wipeSecrets();
    bob?.wipeSecrets();
    alicePq.epoch.wipeSecrets();
    bobPq.epoch.wipeSecrets();
    _wipe(alicePq.rootKey);
    _wipe(bobPq.rootKey);
    _wipe(pqSeed);
    _wipe(alicePrivate);
    _wipe(bobPrivate);
    _wipe(aliceToBobEc);
    _wipe(bobToAliceEc);
  }
}

V3TripleRatchetState _snapshot({
  required V3SessionRole role,
  required Uint8List sessionId,
  required Uint8List ecPrivate,
  required Uint8List ecPublic,
  required Uint8List ecRemote,
  required Uint8List ecSending,
  required Uint8List? ecReceiving,
  required Uint8List pqRoot,
  required V3PqEpochState pqEpoch,
}) {
  return V3TripleRatchetState(
    role: role,
    lifecycle: V3RatchetLifecycle.active,
    revision: 0,
    sessionId: sessionId,
    transcriptDigest: _bytes(48, 0x21),
    initiatorRoutingBinding: _bytes(32, 0x31),
    responderRoutingBinding: _bytes(32, 0x71),
    initiatorToResponderAckRootKey: _bytes(32, 0xa1),
    responderToInitiatorAckRootKey: _bytes(32, 0xc1),
    ecRootKey: _bytes(32, 0xe1),
    ecSendingChainKey: ecSending,
    ecReceivingChainKey: ecReceiving,
    ecLocalDhPrivateKey: ecPrivate,
    ecLocalDhPublicKey: ecPublic,
    ecRemoteDhPublicKey: ecRemote,
    ecSendCounter: 0,
    ecReceiveCounter: 0,
    ecPreviousSendingChainLength: 0,
    pqRootKey: pqRoot,
    pqCurrentEpoch: 0,
    pqSendingEpoch: 0,
    pqReceivingEpoch: 0,
    pqEpochStates: <V3PqEpochState>[pqEpoch],
    nativeSckaState: _DeterministicEpochBackend.state(role, sessionId, 0),
  );
}

final class _DeterministicEpochBackend implements V3SckaBackend {
  int sendCalls = 0;

  static Uint8List state(V3SessionRole role, Uint8List sessionId, int epoch) {
    return Uint8List.fromList(<int>[role.wireId, ...sessionId, epoch]);
  }

  Future<void> validateSnapshot(V3TripleRatchetState snapshot) =>
      validateAuthenticatedState(
        role: snapshot.role,
        sessionId: snapshot.sessionId,
        authenticatedState: snapshot.nativeSckaState,
      );

  @override
  Future<Uint8List> initializeAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List sharedSecret,
  }) async =>
      state(role, sessionId, 0);

  @override
  Future<void> validateAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
  }) async {
    if (authenticatedState.length != 18 ||
        authenticatedState[0] != role.wireId ||
        !_bytesEqual(
          Uint8List.sublistView(authenticatedState, 1, 17),
          sessionId,
        )) {
      throw const FormatException('Test SCKA state binding mismatch');
    }
  }

  @override
  Future<V3SckaSendCandidate> sendCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
  }) async {
    sendCalls++;
    final currentEpoch = authenticatedState[17];
    final outputEpoch = currentEpoch == 0 ? 1 : currentEpoch;
    return V3SckaSendCandidate(
      nextAuthenticatedState: state(role, sessionId, outputEpoch),
      sendingEpoch: currentEpoch,
      nativePayload: Uint8List.fromList(<int>[outputEpoch]),
      epochSecret: currentEpoch == outputEpoch
          ? null
          : V3SckaEpochSecret(
              epoch: outputEpoch,
              secret: _epochSecret(sessionId, outputEpoch),
            ),
    );
  }

  @override
  Future<V3SckaReceiveCandidate> receiveCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required V3SckaMessage message,
  }) async {
    final currentEpoch = authenticatedState[17];
    final outputEpoch = message.nativePayload.single;
    return V3SckaReceiveCandidate(
      nextAuthenticatedState: state(role, sessionId, outputEpoch),
      receivingEpoch: message.sendingEpoch,
      epochSecret: outputEpoch == currentEpoch
          ? null
          : V3SckaEpochSecret(
              epoch: outputEpoch,
              secret: _epochSecret(sessionId, outputEpoch),
            ),
    );
  }
}

final class _FaultStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records =
      <String, Map<String, dynamic>>{};
  var _nextId = 0;
  String? durableThenThrowKind;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = 'record-${_nextId++}';
    records[id] = _deepCopy(payload);
    if (payload['kind'] == durableThenThrowKind) {
      durableThenThrowKind = null;
      throw StateError('injected durable-then-throw write');
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
    records.remove(storageId);
  }
}

void _expectExactFrames(List<V3LmfFrame> left, List<V3LmfFrame> right) {
  expect(left, hasLength(right.length));
  for (var index = 0; index < left.length; index++) {
    expect(
      V3LmfFrameCodec.encodeBinary(left[index]),
      V3LmfFrameCodec.encodeBinary(right[index]),
    );
  }
}

Map<String, dynamic> _deepCopy(Map<String, dynamic> value) =>
    (jsonDecode(jsonEncode(value)) as Map).cast<String, dynamic>();

String _encodeBinary(Uint8List value) =>
    base64UrlEncode(value).replaceAll('=', '');

Uint8List _epochSecret(Uint8List sessionId, int epoch) => Uint8List.fromList(
      crypto.sha256.convert(<int>[0x53, ...sessionId, epoch]).bytes,
    );

bool _bytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
