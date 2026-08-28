import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/v3/committed_record_materializer_v3.dart';
import 'package:layergram/core/crypto/v3/committed_record_v3.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_atomic_commit.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_outbox.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/pq_message_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/session_checkpoint_v3.dart';
import 'package:layergram/core/crypto/v3/session_persistence_scope_v3.dart';
import 'package:layergram/core/crypto/v3/session_retirement_journal_v3.dart';
import 'package:layergram/core/crypto/v3/sparse_pq_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_engine_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  late Directory temporaryDirectory;
  late Box<Map> box;
  late SecretKey auxiliaryKey;
  final scopeBackend = _ScopeSckaBackend();
  final messageKey = SecretKeyData(_bytes(32, 0x11));

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    temporaryDirectory =
        await Directory.systemTemp.createTemp('layergram_v3_lmf_aux_');
    Hive.init(temporaryDirectory.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    box = Hive.box<Map>(LocalDatabase.messagesBoxName);
    auxiliaryKey = await AuxRecordCipher.deriveAuxStorageKey(_bytes(32, 0x77));
  });

  tearDownAll(() async {
    await Hive.close();
    await temporaryDirectory.delete(recursive: true);
  });

  setUp(() => box.clear());

  test('inbox frames and commit tombstones stay externally opaque', () async {
    final frames = await _frames(messageKey);
    final firstRepository = _repository(auxiliaryKey, 'primary-scope');
    final first = V3LmfDurableInbox(
      store: V3LmfAuxRecordStore(firstRepository),
    );
    await first.restore(keyResolver: (_) => messageKey);
    await first.receive(frame: frames.first, secretKey: messageKey);

    _expectOnlyOpaqueRecords(box);
    expect(box.values.single.toString(), isNot(contains('v3_lmf_in_v1')));
    expect(box.values.single.toString(), isNot(contains('frame')));
    await first.close();

    final restored = V3LmfDurableInbox(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'primary-scope'),
      ),
    );
    final restoreResult =
        await restored.restore(keyResolver: (_) => messageKey);
    expect(restoreResult.deliveries, isEmpty);
    final complete = await restored.receive(
      frame: frames.last,
      secretKey: messageKey,
    );
    expect(complete.delivery!.plaintext, orderedEquals(_bytes(300, 0x31)));
    await restored.commit(complete.delivery!);

    _expectOnlyOpaqueRecords(box);
    expect(box.values.single.toString(), isNot(contains('v3_lmf_done_v1')));
    await restored.close();

    final afterCommit = V3LmfDurableInbox(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'primary-scope'),
      ),
    );
    final afterCommitResult =
        await afterCommit.restore(keyResolver: (_) => messageKey);
    expect(afterCommitResult.deliveries, isEmpty);
    expect(afterCommit.committedTombstoneCount, 1);
  });

  test('outbox exact bytes restore through encrypted aux records', () async {
    final frames = await _frames(messageKey);
    final original = frames.map(V3LmfFrameCodec.encodeBinary).toList();
    final first = V3LmfDurableOutbox(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'passphrase-scope'),
      ),
    );
    await first.restore();
    final entry = await first.enqueue(frames);
    await first.markExported(
      assemblyId: entry.assemblyId,
      fragmentIndexes: {0},
    );
    _expectOnlyOpaqueRecords(box);
    expect(box.values.single.toString(), isNot(contains('v3_lmf_out_v1')));
    await first.close();

    final restored = V3LmfDurableOutbox(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'passphrase-scope'),
      ),
    );
    final result = await restored.restore();
    expect(result.entries.single.exportAttempts, [1, 0]);
    for (var index = 0; index < original.length; index++) {
      expect(
        V3LmfFrameCodec.encodeBinary(result.entries.single.frames[index]),
        orderedEquals(original[index]),
      );
    }

    // A different identity/passphrase scope cannot enumerate these records.
    final isolated = V3LmfDurableOutbox(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'different-scope'),
      ),
    );
    expect((await isolated.restore()).entries, isEmpty);
  });

  test('atomic application and ratchet effect stays opaque and scoped',
      () async {
    final frames = await _frames(messageKey);
    final repository = _repository(auxiliaryKey, 'atomic-scope');
    final store = V3LmfAuxRecordStore(repository);
    final inbox = V3LmfDurableInbox(store: store);
    final journal = V3LmfAtomicCommitJournal(
      store: store,
      inbox: inbox,
    );
    await inbox.restore(keyResolver: (_) => messageKey);
    await journal.restore();
    V3LmfDurableDelivery? delivery;
    for (final frame in frames) {
      delivery =
          (await inbox.receive(frame: frame, secretKey: messageKey)).delivery ??
              delivery;
    }
    await journal.commit(
      delivery: delivery!,
      builder: (_) => V3LmfAtomicEffect(
        applicationState: _bytes(96, 0x91),
        ratchetState: _bytes(160, 0xc1),
      ),
    );

    _expectOnlyOpaqueRecords(box);
    final external = box.values.join();
    expect(external, isNot(contains(V3LmfAtomicCommitJournal.recordKind)));
    expect(external, isNot(contains('applicationState')));
    expect(external, isNot(contains('ratchetState')));
    await inbox.close();
    await journal.close();

    final restoredRepository = _repository(auxiliaryKey, 'atomic-scope');
    final restoredStore = V3LmfAuxRecordStore(restoredRepository);
    final restoredInbox = V3LmfDurableInbox(store: restoredStore);
    await restoredInbox.restore(keyResolver: (_) => messageKey);
    final restored = V3LmfAtomicCommitJournal(
      store: restoredStore,
      inbox: restoredInbox,
    );
    final result = await restored.restore();
    expect(result.effects, hasLength(1));
    expect(
      result.effects.single.applicationState,
      orderedEquals(_bytes(96, 0x91)),
    );
    expect(
      result.effects.single.ratchetState,
      orderedEquals(_bytes(160, 0xc1)),
    );

    final isolatedRepository = _repository(auxiliaryKey, 'other-atomic-scope');
    final isolatedStore = V3LmfAuxRecordStore(isolatedRepository);
    final isolatedInbox = V3LmfDurableInbox(store: isolatedStore);
    await isolatedInbox.restore(keyResolver: (_) => messageKey);
    final isolated = V3LmfAtomicCommitJournal(
      store: isolatedStore,
      inbox: isolatedInbox,
    );
    expect((await isolated.restore()).effects, isEmpty);
  });

  test('materialized AR3 and TR3 checkpoint stay opaque and scoped', () async {
    final frames = await _frames(messageKey);
    final plaintext = _bytes(300, 0x31);
    final record = V3CommittedRecord.fromDelivery(
      targetFrame: frames.first,
      content: plaintext,
    );
    final application = V3CommittedRecordCodec.encode(record);
    final snapshot = _checkpointSnapshot();
    final ratchet = V3TripleRatchetStateCodec.encode(snapshot);
    final receipt = V3CheckpointReceipt.fromStates(
      direction: V3CheckpointEffectDirection.incoming,
      assemblyId: record.assemblyId,
      applicationState: application,
      ratchetState: ratchet,
    );
    final store = V3LmfAuxRecordStore(
      _repository(auxiliaryKey, 'durable-state-scope'),
    );
    final materializer = V3CommittedRecordMaterializer(store: store);
    final checkpoints = V3SessionCheckpointRepository(store: store);
    await materializer.restore();
    await checkpoints.restore();
    await materializer.materialize(application);
    await checkpoints.persist(
      snapshot: snapshot,
      receipts: <V3CheckpointReceipt>[receipt],
    );

    _expectOnlyOpaqueRecords(box);
    final external = box.values.join();
    expect(
      external,
      isNot(contains(V3CommittedRecordMaterializer.recordKind)),
    );
    expect(
      external,
      isNot(contains(V3SessionCheckpointRepository.recordKind)),
    );
    expect(external, isNot(contains(record.stableRecordId)));
    await materializer.close();
    await checkpoints.close();

    final restoredStore = V3LmfAuxRecordStore(
      _repository(auxiliaryKey, 'durable-state-scope'),
    );
    final restoredMaterializer = V3CommittedRecordMaterializer(
      store: restoredStore,
    );
    final restoredCheckpoints = V3SessionCheckpointRepository(
      store: restoredStore,
    );
    expect((await restoredMaterializer.restore()).records, hasLength(1));
    expect((await restoredCheckpoints.restore()).checkpoints, hasLength(1));

    final isolatedStore = V3LmfAuxRecordStore(
      _repository(auxiliaryKey, 'other-durable-state-scope'),
    );
    final isolatedMaterializer = V3CommittedRecordMaterializer(
      store: isolatedStore,
    );
    final isolatedCheckpoints = V3SessionCheckpointRepository(
      store: isolatedStore,
    );
    expect((await isolatedMaterializer.restore()).records, isEmpty);
    expect((await isolatedCheckpoints.restore()).checkpoints, isEmpty);

    await restoredMaterializer.close();
    await restoredCheckpoints.close();
    await isolatedMaterializer.close();
    await isolatedCheckpoints.close();
    record.wipeContent();
    snapshot.wipeSecrets();
    plaintext.fillRange(0, plaintext.length, 0);
    application.fillRange(0, application.length, 0);
    ratchet.fillRange(0, ratchet.length, 0);
  });

  test('retirement plans stay opaque and identity scoped', () async {
    final assemblyId = _canonicalId(32, 0x31);
    final sessionKey = _canonicalId(16, 0x51);
    final proofRecordedAt = DateTime.utc(2025, 8, 14);
    const lifetime = Duration(days: 365);
    final store = V3LmfAuxRecordStore(
      _repository(auxiliaryKey, 'retirement-scope'),
    );
    final journal = V3SessionRetirementJournal(store: store);
    await journal.restore();
    await journal.prepare(
      direction: V3CheckpointEffectDirection.incoming,
      assemblyId: assemblyId,
      proofDigest: _canonicalId(32, 0x71),
      stableRecordId: 'v3:$assemblyId',
      sessionKey: sessionKey,
      ratchetRevision: 7,
      stateDigest: _canonicalId(32, 0x91),
      sourceCheckpointDigest: _canonicalId(32, 0xb1),
      proofRecordedAt: proofRecordedAt,
      preparedAt: proofRecordedAt.add(lifetime),
      minimumProofLifetimeSeconds: lifetime.inSeconds,
    );

    _expectOnlyOpaqueRecords(box);
    final external = box.values.join();
    expect(
      external,
      isNot(contains(V3SessionRetirementJournal.recordKind)),
    );
    expect(external, isNot(contains(assemblyId)));
    expect(external, isNot(contains(sessionKey)));
    await journal.close();

    final restored = V3SessionRetirementJournal(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'retirement-scope'),
      ),
    );
    expect((await restored.restore()).plans, hasLength(1));
    final isolated = V3SessionRetirementJournal(
      store: V3LmfAuxRecordStore(
        _repository(auxiliaryKey, 'other-retire-scope'),
      ),
    );
    expect((await isolated.restore()).plans, isEmpty);
    await restored.close();
    await isolated.close();
  });

  test(
      'scope owner pins real Aux storage across restart and identity isolation',
      () async {
    final frames = await _frames(messageKey);
    final checkpoint = _checkpointSnapshot();
    final validationCallsBefore = scopeBackend.validationCalls;
    final first = await V3SessionPersistenceScope.open(
      scopeToken: 'v3-runtime-scope',
      auxStorageKey: auxiliaryKey,
      sckaBackend: scopeBackend,
    );
    final firstRestore = await first.restore(
      checkpoints: <V3TripleRatchetState>[checkpoint],
    );
    expect(firstRestore.inbox.deferredFrames, 0);
    expect(firstRestore.handshakes.pendingOutbound, isEmpty);
    expect(firstRestore.handshakes.completionCount, 0);
    expect(firstRestore.handoffs.recoveredHandoffs, isEmpty);
    expect(firstRestore.sessions.sessionRevisions.values, <int>[1]);
    expect(firstRestore.sessions.checkpointCount, 1);
    expect(firstRestore.sessions.retirementPlanCount, 0);
    expect(scopeBackend.validationCalls, greaterThan(validationCallsBefore));

    expect(
      (await first.receiveFrame(frame: frames.last)).status,
      V3LmfInboxStatus.deferred,
    );
    _expectOnlyOpaqueRecords(box);
    final external = box.values.join();
    expect(external, isNot(contains('v3-runtime-scope')));
    expect(external, isNot(contains(V3LmfDurableInbox.inboxRecordKind)));
    expect(
      external,
      isNot(contains(V3SessionCheckpointRepository.recordKind)),
    );
    await first.close();
    await expectLater(
      first.resumeDeferred(),
      throwsStateError,
    );

    // A distinct identity namespace cannot enumerate the pinned scope.
    final isolated = await V3SessionPersistenceScope.open(
      scopeToken: 'other-v3-scope12',
      auxStorageKey: auxiliaryKey,
      sckaBackend: scopeBackend,
    );
    final isolatedRestore = await isolated.restore(
      checkpoints: const <V3TripleRatchetState>[],
    );
    expect(isolatedRestore.inbox.deferredFrames, 0);
    expect(isolatedRestore.handshakes.pendingOutbound, isEmpty);
    expect(isolatedRestore.handoffs.recoveredHandoffs, isEmpty);
    expect(isolatedRestore.sessions.sessionRevisions, isEmpty);
    await isolated.close();

    // The same opaque namespace with another passphrase-derived key can see
    // only ciphertext-shaped records; it cannot restore their v3 meaning.
    final wrongContextKey = await AuxRecordCipher.deriveAuxStorageKey(
      _bytes(32, 0xd7),
    );
    final wrongContext = await V3SessionPersistenceScope.open(
      scopeToken: 'v3-runtime-scope',
      auxStorageKey: wrongContextKey,
      sckaBackend: scopeBackend,
    );
    final wrongRestore = await wrongContext.restore(
      checkpoints: const <V3TripleRatchetState>[],
    );
    expect(wrongRestore.inbox.deferredFrames, 0);
    expect(wrongRestore.handshakes.pendingOutbound, isEmpty);
    expect(wrongRestore.handoffs.recoveredHandoffs, isEmpty);
    expect(wrongRestore.sessions.sessionRevisions, isEmpty);
    await wrongContext.close();

    // The correct identity/passphrase context reconstructs its durable TR3
    // checkpoint before any deferred frame key is requested.
    final restored = await V3SessionPersistenceScope.open(
      scopeToken: 'v3-runtime-scope',
      auxStorageKey: auxiliaryKey,
      sckaBackend: scopeBackend,
    );
    final restoredState = await restored.restore(
      checkpoints: const <V3TripleRatchetState>[],
    );
    expect(restoredState.inbox.deferredFrames, 1);
    expect(restoredState.handshakes.pendingOutbound, isEmpty);
    expect(restoredState.handshakes.completionCount, 0);
    expect(restoredState.handoffs.recoveredHandoffs, isEmpty);
    expect(restoredState.sessions.sessionRevisions.values, <int>[1]);
    expect(restoredState.sessions.checkpointCount, 1);
    expect(restoredState.sessions.retirementPlanCount, 0);

    final resumed = await restored.resumeDeferred();
    expect(resumed.deferredFrames, 1);
    expect(resumed.deliveries, isEmpty);

    await restored.close();
    checkpoint.wipeSecrets();
    expect(await auxiliaryKey.extractBytes(), hasLength(32));
  });

  test('scope lease rejects a second owner and releases after close', () async {
    final first = await V3SessionPersistenceScope.open(
      scopeToken: 'scopeleasetest01',
      auxStorageKey: auxiliaryKey,
      sckaBackend: scopeBackend,
    );
    await expectLater(
      V3SessionPersistenceScope.open(
        scopeToken: 'scopeleasetest01',
        auxStorageKey: auxiliaryKey,
        sckaBackend: scopeBackend,
      ),
      throwsStateError,
    );
    await first.close();

    final reopened = await V3SessionPersistenceScope.open(
      scopeToken: 'scopeleasetest01',
      auxStorageKey: auxiliaryKey,
      sckaBackend: scopeBackend,
    );
    await reopened.close();
  });

  test('scope owns a detached Aux key and fails stopped after restore errors',
      () async {
    final callerKey = SecretKeyData(
      _bytes(32, 0x47),
      overwriteWhenDestroyed: true,
    );
    final scope = await V3SessionPersistenceScope.open(
      scopeToken: 'detached-key-001',
      auxStorageKey: callerKey,
      sckaBackend: scopeBackend,
    );
    callerKey.destroy();

    final invalidCheckpoint = _checkpointSnapshot(
      lifecycle: V3RatchetLifecycle.suspended,
    );
    await expectLater(
      scope.restore(
        checkpoints: <V3TripleRatchetState>[invalidCheckpoint],
      ),
      throwsStateError,
    );
    expect(scope.requiresRecovery, isTrue);
    await expectLater(
      scope.restore(checkpoints: const <V3TripleRatchetState>[]),
      throwsStateError,
    );
    await expectLater(
      scope.resumeDeferred(),
      throwsStateError,
    );
    await scope.close();
    invalidCheckpoint.wipeSecrets();

    final shortKey = SecretKeyData(_bytes(31, 0x71));
    await expectLater(
      V3SessionPersistenceScope.open(
        scopeToken: 'a|x',
        auxStorageKey: shortKey,
        sckaBackend: scopeBackend,
      ),
      throwsArgumentError,
    );
    await expectLater(
      V3SessionPersistenceScope.open(
        scopeToken: 'invalid-key-0001',
        auxStorageKey: shortKey,
        sckaBackend: scopeBackend,
      ),
      throwsArgumentError,
    );
    expect(await shortKey.extractBytes(), orderedEquals(_bytes(31, 0x71)));
  });

  test('scope rejects a backend that fails admission before storage opens',
      () async {
    final rejected = _ScopeSckaBackend(selfTestResult: false);
    await expectLater(
      V3SessionPersistenceScope.open(
        scopeToken: 'backend-gate-001',
        auxStorageKey: auxiliaryKey,
        sckaBackend: rejected,
      ),
      throwsStateError,
    );
    expect(rejected.selfTestCalls, 1);
    expect(box.values, isEmpty);
  });

  test(
      'scope-owned receive restores an out-of-order frame and commits its exact ratchet candidate',
      () async {
    final backend = _ScopeDispatchSckaBackend();
    final pair = await _scopeDispatchPairedSnapshots();
    final plaintext = _bytes(300, 0x45);
    V3TripleRatchetTransition? sent;
    final nonces = <Uint8List>[];
    Uint8List? deliveredPlaintext;
    try {
      sent = await V3TripleRatchetEngine.send(
        snapshot: pair.alice,
        backend: backend,
        kind: V3LmfFrameKind.application,
      );
      final encodedHeader = V3HybridRatchetHeaderCodec.encode(sent.header);
      final fragmentCount = V3LmfFrameCodec.canonicalFragmentCount(
        assembledPlaintextLength: plaintext.length,
        hybridRatchetHeaderLength: encodedHeader.length,
      );
      _wipe(encodedHeader);
      expect(fragmentCount, greaterThan(1));
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

      final first = await V3SessionPersistenceScope.open(
        scopeToken: 'owned-receive-01',
        auxStorageKey: auxiliaryKey,
        sckaBackend: backend,
        testOnlySkippedKeyLifetimeSeconds: 100,
      );
      final firstRestore = await first.restore(
        checkpoints: <V3TripleRatchetState>[pair.bob],
      );
      expect(firstRestore.sessions.sessionRevisions.values, <int>[0]);
      final deferred = await first.receiveFrame(
        frame: frames.last,
        nowUnixSeconds: 7000,
      );
      expect(deferred.status, V3LmfInboxStatus.deferred);
      expect(deferred.delivery, isNull);
      expect(first.pendingReceiveCandidateCount, 0);
      await first.close();

      final restored = await V3SessionPersistenceScope.open(
        scopeToken: 'owned-receive-01',
        auxStorageKey: auxiliaryKey,
        sckaBackend: backend,
        testOnlySkippedKeyLifetimeSeconds: 100,
      );
      final restoredState = await restored.restore(
        checkpoints: const <V3TripleRatchetState>[],
      );
      expect(restoredState.inbox.deferredFrames, 1);
      expect(restoredState.sessions.sessionRevisions.values, <int>[0]);

      final completed = await restored.receiveFrame(
        frame: frames.first,
        nowUnixSeconds: 7000,
      );
      expect(completed.status, V3LmfInboxStatus.complete);
      expect(completed.acknowledgement, isNotNull);
      expect(completed.delivery, isNotNull);
      deliveredPlaintext = completed.delivery!.plaintext;
      expect(deliveredPlaintext, orderedEquals(plaintext));
      expect(restored.pendingReceiveCandidateCount, 1);

      final committed = await restored.commitDelivery(
        delivery: completed.delivery!,
      );
      expect(committed.ratchetRevision, 1);
      expect(restored.pendingReceiveCandidateCount, 0);
      final committedSnapshot =
          await restored.snapshotForSession(pair.bob.sessionId);
      expect(committedSnapshot.revision, 1);
      committedSnapshot.wipeSecrets();
      await restored.close();

      final afterRestart = await V3SessionPersistenceScope.open(
        scopeToken: 'owned-receive-01',
        auxStorageKey: auxiliaryKey,
        sckaBackend: backend,
        testOnlySkippedKeyLifetimeSeconds: 100,
      );
      final afterState = await afterRestart.restore(
        checkpoints: const <V3TripleRatchetState>[],
      );
      expect(afterState.inbox.deferredFrames, 0);
      expect(afterState.sessions.sessionRevisions.values, <int>[1]);
      expect((await afterRestart.resumeDeferred()).deliveries, isEmpty);
      final replay = await afterRestart.receiveFrame(
        frame: frames.first,
        nowUnixSeconds: 7000,
      );
      expect(replay.status, V3LmfInboxStatus.committedReplay);
      expect(replay.delivery, isNull);
      expect(afterRestart.pendingReceiveCandidateCount, 0);
      await afterRestart.close();
    } finally {
      sent?.close();
      pair.alice.wipeSecrets();
      pair.bob.wipeSecrets();
      for (final nonce in nonces) {
        _wipe(nonce);
      }
      if (deliveredPlaintext != null) _wipe(deliveredPlaintext);
      _wipe(plaintext);
    }
  });

  test(
      'automatic fragment-zero resume leaves another session for explicit delivery',
      () async {
    final backend = _ScopeDispatchSckaBackend();
    final firstPair = await _scopeDispatchPairedSnapshots();
    final secondPair = await _scopeDispatchPairedSnapshots(sessionStart: 0x41);
    final firstPlaintext = _bytes(300, 0x25);
    final secondPlaintext = _bytes(300, 0x65);
    Uint8List? firstDelivered;
    Uint8List? secondDelivered;
    try {
      final firstFrames = await _scopeDispatchFrames(
        sender: firstPair.alice,
        backend: backend,
        plaintext: firstPlaintext,
      );
      final secondFrames = await _scopeDispatchFrames(
        sender: secondPair.alice,
        backend: backend,
        plaintext: secondPlaintext,
      );
      expect(firstFrames.length, greaterThan(1));
      expect(secondFrames.length, greaterThan(1));

      // Model an application restart after three exact sealed frames were
      // retained without a session resolver. Their local receive order presents
      // session two's continuation before its fragment zero to the first
      // explicit resume pass, independently from storage enumeration order.
      final preloadRepository = _repository(
        auxiliaryKey,
        'owned-filter-001',
      );
      final preloadInbox = V3LmfDurableInbox(
        store: V3LmfAuxRecordStore(preloadRepository),
      );
      await preloadInbox.restore(keyResolver: (_) => null);
      await preloadInbox.persistDeferred(
        frame: secondFrames.first,
        receivedAt: DateTime.utc(2026, 1, 1, 0, 0, 2),
      );
      await preloadInbox.persistDeferred(
        frame: secondFrames.last,
        receivedAt: DateTime.utc(2026, 1, 1, 0, 0, 1),
      );
      await preloadInbox.persistDeferred(
        frame: firstFrames.last,
        receivedAt: DateTime.utc(2026, 1, 1, 0, 0, 3),
      );
      await preloadInbox.close();
      preloadRepository.setActiveContext(
        scopeToken: null,
        auxStorageKey: null,
      );

      final scope = await V3SessionPersistenceScope.open(
        scopeToken: 'owned-filter-001',
        auxStorageKey: auxiliaryKey,
        sckaBackend: backend,
        testOnlySkippedKeyLifetimeSeconds: 100,
      );
      final restored = await scope.restore(
        checkpoints: <V3TripleRatchetState>[
          firstPair.bob,
          secondPair.bob,
        ],
      );
      expect(restored.inbox.deferredFrames, 3);

      // The first pass encounters session two's continuation before fragment
      // zero. It therefore creates that session's candidate without completing
      // its assembly or consuming the earlier continuation.
      final primed = await scope.resumeDeferred(nowUnixSeconds: 7000);
      expect(primed.deliveries, isEmpty);
      expect(scope.pendingReceiveCandidateCount, 1);

      // Receiving session one's fragment zero may automatically retry only its
      // own continuation. Session two must remain separately observable.
      final first = await scope.receiveFrame(
        frame: firstFrames.first,
        nowUnixSeconds: 7000,
      );
      expect(first.status, V3LmfInboxStatus.complete);
      expect(first.delivery, isNotNull);
      firstDelivered = first.delivery!.plaintext;
      expect(firstDelivered, orderedEquals(firstPlaintext));

      final remaining = await scope.resumeDeferred(nowUnixSeconds: 7000);
      expect(remaining.deliveries, hasLength(1));
      expect(
        remaining.deliveries.single.assemblyId,
        V3LmfFrameCodec.assemblyId(secondFrames.first),
      );
      secondDelivered = remaining.deliveries.single.plaintext;
      expect(secondDelivered, orderedEquals(secondPlaintext));
      await scope.close();
    } finally {
      firstPair.alice.wipeSecrets();
      firstPair.bob.wipeSecrets();
      secondPair.alice.wipeSecrets();
      secondPair.bob.wipeSecrets();
      if (firstDelivered != null) _wipe(firstDelivered);
      if (secondDelivered != null) _wipe(secondDelivered);
      _wipe(firstPlaintext);
      _wipe(secondPlaintext);
    }
  });

  test('fragment-zero capacity is reserved before ratchet candidate work',
      () async {
    final backend = _ScopeDispatchSckaBackend();
    final firstPair = await _scopeDispatchPairedSnapshots();
    final secondPair = await _scopeDispatchPairedSnapshots(sessionStart: 0x41);
    final firstPlaintext = _bytes(300, 0x25);
    final secondPlaintext = _bytes(300, 0x65);
    V3SessionPersistenceScope? scope;
    try {
      final firstFrames = await _scopeDispatchFrames(
        sender: firstPair.alice,
        backend: backend,
        plaintext: firstPlaintext,
      );
      final secondFrames = await _scopeDispatchFrames(
        sender: secondPair.alice,
        backend: backend,
        plaintext: secondPlaintext,
      );
      scope = await V3SessionPersistenceScope.open(
        scopeToken: 'owned-preflight1',
        auxStorageKey: auxiliaryKey,
        sckaBackend: backend,
        testOnlySkippedKeyLifetimeSeconds: 100,
        maxInboxPersistedFrames: 1,
      );
      await scope.restore(
        checkpoints: <V3TripleRatchetState>[
          firstPair.bob,
          secondPair.bob,
        ],
      );
      await scope.receiveFrame(
        frame: firstFrames.first,
        nowUnixSeconds: 7000,
      );
      expect(backend.receiveCandidateCalls, 1);

      await expectLater(
        scope.receiveFrame(
          frame: secondFrames.first,
          nowUnixSeconds: 7000,
        ),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      expect(backend.receiveCandidateCalls, 1);
      expect(scope.pendingReceiveCandidateCount, 1);
    } finally {
      await scope?.close();
      firstPair.alice.wipeSecrets();
      firstPair.bob.wipeSecrets();
      secondPair.alice.wipeSecrets();
      secondPair.bob.wipeSecrets();
      _wipe(firstPlaintext);
      _wipe(secondPlaintext);
    }
  });
}

final class _ScopeSckaBackend implements V3SckaBackend {
  _ScopeSckaBackend({this.selfTestResult = true});

  final bool selfTestResult;
  int selfTestCalls = 0;
  int validationCalls = 0;

  @override
  String get implementationId => 'layergram-test-scope-scka/1';

  @override
  int get protocolRevision => V3SparsePqRatchet.requiredBackendProtocolRevision;

  @override
  Future<bool> selfTest() async {
    selfTestCalls++;
    return selfTestResult;
  }

  @override
  Future<void> validateAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    validationCalls++;
  }

  @override
  Future<Uint8List> initializeAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List sharedSecret,
    required Uint8List stateSealKey,
  }) =>
      throw UnsupportedError('scope storage test backend');

  @override
  Future<V3SckaSendCandidate> sendCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) =>
      throw UnsupportedError('scope storage test backend');

  @override
  Future<V3SckaReceiveCandidate> receiveCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
    required V3SckaMessage message,
  }) =>
      throw UnsupportedError('scope storage test backend');
}

final class _ScopeDispatchSckaBackend implements V3SckaBackend {
  int receiveCandidateCalls = 0;

  @override
  String get implementationId => 'layergram-test-scope-dispatch-scka/1';

  @override
  int get protocolRevision => V3SparsePqRatchet.requiredBackendProtocolRevision;

  @override
  Future<bool> selfTest() async => true;

  static Uint8List state(
    V3SessionRole role,
    Uint8List sessionId,
    int epoch,
    int revision,
  ) {
    final result = Uint8List.fromList(<int>[
      role.wireId,
      ...sessionId,
      epoch,
      ...List<int>.filled(8, 0),
    ]);
    ByteData.sublistView(result).setUint64(18, revision, Endian.big);
    return result;
  }

  @override
  Future<Uint8List> initializeAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List sharedSecret,
    required Uint8List stateSealKey,
  }) async =>
      state(role, sessionId, 0, 0);

  @override
  Future<void> validateAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    if (authenticatedState.length != 26 ||
        authenticatedState[0] != role.wireId ||
        !_constantTimeBytesEqual(
          Uint8List.sublistView(authenticatedState, 1, 17),
          sessionId,
        ) ||
        ByteData.sublistView(authenticatedState).getUint64(18, Endian.big) !=
            expectedStateRevision) {
      throw const FormatException('Test SCKA state binding mismatch');
    }
  }

  @override
  Future<V3SckaSendCandidate> sendCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    final currentEpoch = authenticatedState[17];
    final outputEpoch = currentEpoch == 0 ? 1 : currentEpoch;
    return V3SckaSendCandidate(
      nextAuthenticatedState:
          state(role, sessionId, outputEpoch, expectedStateRevision + 1),
      stateRevision: expectedStateRevision + 1,
      sendingEpoch: currentEpoch,
      nativePayload: Uint8List.fromList(<int>[outputEpoch]),
      epochSecret: currentEpoch == outputEpoch
          ? null
          : V3SckaEpochSecret(
              epoch: outputEpoch,
              secret: _scopeDispatchEpochSecret(sessionId, outputEpoch),
            ),
    );
  }

  @override
  Future<V3SckaReceiveCandidate> receiveCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
    required V3SckaMessage message,
  }) async {
    receiveCandidateCalls++;
    final currentEpoch = authenticatedState[17];
    final payload = message.nativePayload;
    if (payload.length != 1 || payload.single < currentEpoch) {
      throw const FormatException('Test SCKA message is invalid');
    }
    final outputEpoch = payload.single;
    return V3SckaReceiveCandidate(
      nextAuthenticatedState:
          state(role, sessionId, outputEpoch, expectedStateRevision + 1),
      stateRevision: expectedStateRevision + 1,
      receivingEpoch: message.sendingEpoch,
      epochSecret: outputEpoch == currentEpoch
          ? null
          : V3SckaEpochSecret(
              epoch: outputEpoch,
              secret: _scopeDispatchEpochSecret(sessionId, outputEpoch),
            ),
    );
  }
}

AuxRecordRepository _repository(SecretKey key, String scope) {
  final repository = AuxRecordRepository();
  repository.setActiveContext(scopeToken: scope, auxStorageKey: key);
  return repository;
}

void _expectOnlyOpaqueRecords(Box<Map> box) {
  expect(box.values, isNotEmpty);
  for (final raw in box.values) {
    expect(raw.keys, {'encryptedRecord'});
    final encrypted = raw['encryptedRecord'];
    expect(encrypted, isA<String>());
    expect((encrypted! as String).length, greaterThan(100));
  }
}

String _canonicalId(int length, int start) =>
    base64UrlEncode(_bytes(length, start)).replaceAll('=', '');

Future<List<V3LmfFrame>> _frames(SecretKey key) => V3LmfAead.sealFragmented(
      metadata: V3LmfMessageMetadata(
        kind: V3LmfFrameKind.application,
        senderBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 0x01),
        recipientBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 0x41),
        messageId: _bytes(V3LmfFrameCodec.messageIdBytes, 0x81),
        sessionId: _bytes(V3LmfFrameCodec.sessionIdBytes, 0xa1),
        epoch: 7,
        messageCounter: 9,
      ),
      plaintext: _bytes(300, 0x31),
      secretKey: key,
      nonceForFragment: (index) =>
          _bytes(V3LmfFrameCodec.nonceBytes, 0x51 + index),
      hybridRatchetHeader: _hybridHeader(),
    );

V3HybridRatchetHeader _hybridHeader() => V3HybridRatchetHeader(
      ecHeader: V3EcRatchetHeader(
        ratchetPublicKey: _bytes(32, 0x21),
        previousSendingChainLength: 3,
        messageCounter: 5,
      ),
      sckaMessage: V3SckaMessage(
        sendingEpoch: 7,
        messageCounter: 9,
        nativePayload: Uint8List(0),
      ),
    );

V3TripleRatchetState _checkpointSnapshot({
  V3RatchetLifecycle lifecycle = V3RatchetLifecycle.active,
}) =>
    V3TripleRatchetState(
      role: V3SessionRole.initiator,
      lifecycle: lifecycle,
      revision: 1,
      sessionId: _bytes(V3LmfFrameCodec.sessionIdBytes, 0xa1),
      transcriptDigest: _bytes(48, 0x11),
      initiatorRoutingBinding: _bytes(32, 0x21),
      responderRoutingBinding: _bytes(32, 0x61),
      initiatorToResponderAckRootKey: _bytes(32, 0x81),
      responderToInitiatorAckRootKey: _bytes(32, 0xc1),
      ecRootKey: _bytes(32, 0x12),
      ecSendingChainKey: _bytes(32, 0x32),
      ecReceivingChainKey: _bytes(32, 0x52),
      ecLocalDhPrivateKey: _bytes(32, 0x72),
      ecLocalDhPublicKey: _hex(
        '5c117f7fa14c242bc843fd1bac49ad870c37b8e615da1b4fefe64859aff5245d',
      ),
      ecRemoteDhPublicKey: _bytes(32, 0x32),
      ecSendCounter: 1,
      ecReceiveCounter: 1,
      ecPreviousSendingChainLength: 0,
      pqRootKey: _bytes(32, 0x92),
      sckaStateSealKey: _bytes(32, 0xb2),
      pqCurrentEpoch: 0,
      pqSendingEpoch: 0,
      pqReceivingEpoch: 0,
      pqEpochStates: <V3PqEpochState>[
        V3PqEpochState(
          epoch: 0,
          sendingChainKey: _bytes(32, 0xb2),
          sendCounter: 1,
          receivingChainKey: _bytes(32, 0xd2),
          receiveCounter: 1,
        ),
      ],
      nativeSckaState: _bytes(64, 0xe2),
    );

Future<({V3TripleRatchetState alice, V3TripleRatchetState bob})>
    _scopeDispatchPairedSnapshots({int sessionStart = 0x11}) async {
  final sessionId = _bytes(16, sessionStart);
  final pqSeed = _bytes(32, sessionStart + 0x20);
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
    alice = _scopeDispatchSnapshot(
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
    bob = _scopeDispatchSnapshot(
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

Future<List<V3LmfFrame>> _scopeDispatchFrames({
  required V3TripleRatchetState sender,
  required V3SckaBackend backend,
  required Uint8List plaintext,
}) async {
  final transition = await V3TripleRatchetEngine.send(
    snapshot: sender,
    backend: backend,
    kind: V3LmfFrameKind.application,
  );
  final nonces = <Uint8List>[];
  try {
    final encodedHeader = V3HybridRatchetHeaderCodec.encode(transition.header);
    final fragmentCount = V3LmfFrameCodec.canonicalFragmentCount(
      assembledPlaintextLength: plaintext.length,
      hybridRatchetHeaderLength: encodedHeader.length,
    );
    _wipe(encodedHeader);
    for (var index = 0; index < fragmentCount; index++) {
      nonces.add(
        await transition.nonceForFragment(
          fragmentIndex: index,
          fragmentCount: fragmentCount,
          assembledPlaintextLength: plaintext.length,
        ),
      );
    }
    return await V3LmfAead.sealFragmented(
      metadata: transition.metadata,
      plaintext: plaintext,
      secretKey: transition.secretKey,
      nonceForFragment: (index) => Uint8List.fromList(nonces[index]),
      hybridRatchetHeader: transition.header,
    );
  } finally {
    transition.close();
    for (final nonce in nonces) {
      _wipe(nonce);
    }
  }
}

V3TripleRatchetState _scopeDispatchSnapshot({
  required V3SessionRole role,
  required Uint8List sessionId,
  required Uint8List ecPrivate,
  required Uint8List ecPublic,
  required Uint8List ecRemote,
  required Uint8List ecSending,
  required Uint8List? ecReceiving,
  required Uint8List pqRoot,
  required V3PqEpochState pqEpoch,
}) =>
    V3TripleRatchetState(
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
      sckaStateSealKey: _bytes(32, 0xf1),
      pqCurrentEpoch: 0,
      pqSendingEpoch: 0,
      pqReceivingEpoch: 0,
      pqEpochStates: <V3PqEpochState>[pqEpoch],
      nativeSckaState: _ScopeDispatchSckaBackend.state(role, sessionId, 0, 0),
    );

Uint8List _scopeDispatchEpochSecret(Uint8List sessionId, int epoch) =>
    Uint8List.fromList(
      crypto.sha256.convert(<int>[0x53, ...sessionId, epoch]).bytes,
    );

bool _constantTimeBytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

Uint8List _hex(String value) => Uint8List.fromList(
      List<int>.generate(
        value.length ~/ 2,
        (index) =>
            int.parse(value.substring(index * 2, index * 2 + 2), radix: 16),
      ),
    );
