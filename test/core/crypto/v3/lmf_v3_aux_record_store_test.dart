import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/v3/committed_record_materializer_v3.dart';
import 'package:layergram/core/crypto/v3/committed_record_v3.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/hybrid_ratchet_header_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_atomic_commit.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_outbox.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/session_checkpoint_v3.dart';
import 'package:layergram/core/crypto/v3/session_persistence_scope_v3.dart';
import 'package:layergram/core/crypto/v3/session_retirement_journal_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  late Directory temporaryDirectory;
  late Box<Map> box;
  late SecretKey auxiliaryKey;
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
    final first = await V3SessionPersistenceScope.open(
      scopeToken: 'v3-runtime-scope',
      auxStorageKey: auxiliaryKey,
    );
    final firstRestore = await first.restore(
      checkpoints: <V3TripleRatchetState>[checkpoint],
    );
    expect(firstRestore.inbox.deferredFrames, 0);
    expect(firstRestore.handshakes.pendingOutbound, isEmpty);
    expect(firstRestore.handshakes.completionCount, 0);
    expect(firstRestore.sessions.sessionRevisions.values, <int>[1]);
    expect(firstRestore.sessions.checkpointCount, 1);
    expect(firstRestore.sessions.retirementPlanCount, 0);

    for (final frame in frames.reversed) {
      expect(
        (await first.inbox.persistDeferred(frame: frame)).status,
        V3LmfInboxStatus.deferred,
      );
    }
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
      first.resumeDeferred(keyResolver: (_) => messageKey),
      throwsStateError,
    );

    // A distinct identity namespace cannot enumerate the pinned scope.
    final isolated = await V3SessionPersistenceScope.open(
      scopeToken: 'other-v3-scope12',
      auxStorageKey: auxiliaryKey,
    );
    final isolatedRestore = await isolated.restore(
      checkpoints: const <V3TripleRatchetState>[],
    );
    expect(isolatedRestore.inbox.deferredFrames, 0);
    expect(isolatedRestore.handshakes.pendingOutbound, isEmpty);
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
    );
    final wrongRestore = await wrongContext.restore(
      checkpoints: const <V3TripleRatchetState>[],
    );
    expect(wrongRestore.inbox.deferredFrames, 0);
    expect(wrongRestore.handshakes.pendingOutbound, isEmpty);
    expect(wrongRestore.sessions.sessionRevisions, isEmpty);
    await wrongContext.close();

    // The correct identity/passphrase context reconstructs its durable TR3
    // checkpoint before any deferred frame key is requested.
    final restored = await V3SessionPersistenceScope.open(
      scopeToken: 'v3-runtime-scope',
      auxStorageKey: auxiliaryKey,
    );
    final restoredState = await restored.restore(
      checkpoints: const <V3TripleRatchetState>[],
    );
    expect(restoredState.inbox.deferredFrames, frames.length);
    expect(restoredState.handshakes.pendingOutbound, isEmpty);
    expect(restoredState.handshakes.completionCount, 0);
    expect(restoredState.sessions.sessionRevisions.values, <int>[1]);
    expect(restoredState.sessions.checkpointCount, 1);
    expect(restoredState.sessions.retirementPlanCount, 0);

    var resolverCalls = 0;
    final resumed = await restored.resumeDeferred(
      keyResolver: (_) {
        resolverCalls++;
        return messageKey;
      },
    );
    expect(resolverCalls, frames.length);
    expect(resumed.deferredFrames, 0);
    expect(resumed.deliveries, hasLength(1));
    final plaintext = resumed.deliveries.single.plaintext;
    expect(plaintext, orderedEquals(_bytes(300, 0x31)));
    plaintext.fillRange(0, plaintext.length, 0);

    await restored.close();
    checkpoint.wipeSecrets();
    expect(await auxiliaryKey.extractBytes(), hasLength(32));
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
      scope.resumeDeferred(keyResolver: (_) => messageKey),
      throwsStateError,
    );
    await scope.close();
    invalidCheckpoint.wipeSecrets();

    final shortKey = SecretKeyData(_bytes(31, 0x71));
    await expectLater(
      V3SessionPersistenceScope.open(
        scopeToken: 'a|x',
        auxStorageKey: shortKey,
      ),
      throwsArgumentError,
    );
    await expectLater(
      V3SessionPersistenceScope.open(
        scopeToken: 'invalid-key-0001',
        auxStorageKey: shortKey,
      ),
      throwsArgumentError,
    );
    expect(await shortKey.extractBytes(), orderedEquals(_bytes(31, 0x71)));
  });
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
