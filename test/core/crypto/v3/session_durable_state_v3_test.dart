import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/committed_record_materializer_v3.dart';
import 'package:layergram/core/crypto/v3/committed_record_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/session_checkpoint_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';

void main() {
  group('inactive v3 committed-record materializer', () {
    test('materializes exact AR3 bytes once and restores them', () async {
      final store = _Store();
      final bytes = await _applicationRecord(messageStart: 0x21);
      final materializer = V3CommittedRecordMaterializer(store: store);
      expect((await materializer.restore()).records, isEmpty);

      final first = await materializer.materialize(
        bytes,
        persistedAt: DateTime.utc(2026, 8, 14),
      );
      final duplicate = await materializer.materialize(
        bytes,
        persistedAt: DateTime.utc(2026, 8, 15),
      );
      expect(identical(first, duplicate), isTrue);
      expect(first.stableRecordId, 'v3:${first.assemblyId}');
      expect(first.encodedRecord, bytes);
      expect(store.records, hasLength(1));
      await materializer.close();
      expect(first.encodedRecord, everyElement(0));

      final restored = V3CommittedRecordMaterializer(store: store);
      final result = await restored.restore();
      expect(result.records, hasLength(1));
      expect(result.records.single.encodedRecord, bytes);
      final decoded = result.records.single.decodeRecord();
      expect(decoded.stableRecordId, result.records.single.stableRecordId);
      decoded.wipeContent();
      await restored.close();
      _wipe(bytes);
    });

    test('fails closed on divergent content for the same stable ID', () async {
      final store = _Store();
      final materializer = V3CommittedRecordMaterializer(store: store);
      await materializer.restore();
      final first = await _applicationRecord(messageStart: 0x31);
      final divergent = await _applicationRecord(
        messageStart: 0x31,
        plaintextStart: 0xb1,
      );
      await materializer.materialize(first);
      await expectLater(
        materializer.materialize(divergent),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(materializer.recordCount, 1);
      expect(materializer.requiresRecovery, isFalse);
      await materializer.close();
      _wipe(first);
      _wipe(divergent);
    });

    test('recovers an ambiguous durable write without writing twice', () async {
      final store = _Store()..durableThenThrow = true;
      final bytes = await _applicationRecord(messageStart: 0x41);
      final materializer = V3CommittedRecordMaterializer(store: store);
      await materializer.restore();
      await expectLater(materializer.materialize(bytes), throwsStateError);
      expect(materializer.requiresRecovery, isTrue);
      expect(store.records, hasLength(1));
      await expectLater(materializer.materialize(bytes), throwsStateError);
      expect(store.records, hasLength(1));
      await materializer.close();

      store.durableThenThrow = false;
      final recovered = V3CommittedRecordMaterializer(store: store);
      final restored = await recovered.restore();
      expect(restored.records.single.encodedRecord, bytes);
      expect(store.records, hasLength(1));
      await recovered.close();
      _wipe(bytes);
    });

    test('rejects non-canonical envelopes and enforces bounds', () async {
      final bytes = await _applicationRecord(messageStart: 0x51);
      final seedStore = _Store();
      final seed = V3CommittedRecordMaterializer(store: seedStore);
      await seed.restore();
      await seed.materialize(bytes);
      await seed.close();

      final corrupt = _Store()
        ..records['corrupt'] = _deepCopy(seedStore.records.values.single);
      corrupt.records['corrupt']!['record'] =
          '${corrupt.records['corrupt']!['record']}=';
      await expectLater(
        V3CommittedRecordMaterializer(store: corrupt).restore(),
        throwsFormatException,
      );

      expect(
        () => V3CommittedRecordMaterializer(
          store: seedStore,
          maxStoredRecords: 0,
        ),
        throwsArgumentError,
      );
      final physical = _Store()
        ..records['one'] = _deepCopy(seedStore.records.values.single)
        ..records['two'] = _deepCopy(seedStore.records.values.single);
      await expectLater(
        V3CommittedRecordMaterializer(
          store: physical,
          maxStoredRecords: 1,
        ).restore(),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );

      final byteLimited = V3CommittedRecordMaterializer(
        store: _Store(),
        maxTotalRecordBytes: 1,
      );
      await byteLimited.restore();
      await expectLater(
        byteLimited.materialize(bytes),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      expect(byteLimited.recordCount, 0);
      await byteLimited.close();

      final recordLimited = V3CommittedRecordMaterializer(
        store: _Store(),
        maxRecords: 1,
      );
      await recordLimited.restore();
      await recordLimited.materialize(bytes);
      final second = await _applicationRecord(messageStart: 0x52);
      await expectLater(
        recordLimited.materialize(second),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      expect(recordLimited.recordCount, 1);
      await recordLimited.close();
      _wipe(bytes);
      _wipe(second);
    });

    test('authority blocks direct reads and lifecycle calls after claim',
        () async {
      final bytes = await _applicationRecord(messageStart: 0x59);
      final materializer = V3CommittedRecordMaterializer(store: _Store());
      final authority = await materializer.claimSessionCoordinatorAuthority();
      await expectLater(materializer.restore(), throwsStateError);
      await materializer.restore(authority: authority);
      expect(() => materializer.records(), throwsStateError);
      expect(
        () => materializer.recordForStableId('v3:not-a-record'),
        throwsStateError,
      );
      await expectLater(materializer.materialize(bytes), throwsStateError);
      await expectLater(materializer.close(), throwsStateError);
      await materializer.close(authority: authority);
      _wipe(bytes);
    });
  });

  group('inactive v3 session checkpoint repository', () {
    test('persists monotonic checkpoints and restores the highest revision',
        () async {
      final store = _Store()..failDeletes = true;
      final repository = V3SessionCheckpointRepository(store: store);
      await repository.restore();
      final state1 = _snapshot(revision: 1, ratchetStart: 0x11);
      final state2 = _snapshot(revision: 2, ratchetStart: 0x31);
      final effect1 = await _effect(
        snapshot: state1,
        messageStart: 0x61,
        direction: V3CheckpointEffectDirection.incoming,
      );
      final effect2 = await _effect(
        snapshot: state2,
        messageStart: 0x71,
        direction: V3CheckpointEffectDirection.outgoing,
      );
      final first = await repository.persist(
        snapshot: state1,
        receipts: <V3CheckpointReceipt>[effect1.receipt],
        persistedAt: DateTime.utc(2026, 8, 14),
      );
      final second = await repository.persist(
        snapshot: state2,
        receipts: <V3CheckpointReceipt>[effect2.receipt, effect1.receipt],
        persistedAt: DateTime.utc(2026, 8, 14, 1),
      );
      expect(first.encodedSnapshot, everyElement(0));
      expect(second.revision, 2);
      expect(
          second.receipts.map((value) => value.ratchetRevision), <int>[1, 2]);
      expect(store.records, hasLength(2));
      await repository.close();

      store.failDeletes = false;
      final restoredRepository = V3SessionCheckpointRepository(store: store);
      final restored = await restoredRepository.restore();
      expect(restored.checkpoints.single.revision, 2);
      expect(restored.removedSupersededRecords, 1);
      expect(store.records, hasLength(1));
      final decoded = restored.checkpoints.single.decodeSnapshot();
      expect(decoded.revision, 2);
      decoded.wipeSecrets();
      await restoredRepository.close();
      effect1.close();
      effect2.close();
      state1.wipeSecrets();
      state2.wipeSecrets();
    });

    test('rejects stale, forked, and non-monotonic checkpoint histories',
        () async {
      final store = _Store();
      final repository = V3SessionCheckpointRepository(store: store);
      await repository.restore();
      final state1 = _snapshot(revision: 1, ratchetStart: 0x11);
      final fork1 = _snapshot(revision: 1, ratchetStart: 0x41);
      final state2 = _snapshot(revision: 2, ratchetStart: 0x31);
      final effect1 = await _effect(
        snapshot: state1,
        messageStart: 0x81,
        direction: V3CheckpointEffectDirection.incoming,
      );
      final effect2 = await _effect(
        snapshot: state2,
        messageStart: 0x91,
        direction: V3CheckpointEffectDirection.outgoing,
      );
      await repository.persist(
        snapshot: state1,
        receipts: <V3CheckpointReceipt>[effect1.receipt],
      );
      await expectLater(
        repository.persist(
          snapshot: fork1,
          receipts: <V3CheckpointReceipt>[effect1.receipt],
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      await expectLater(
        repository.persist(
          snapshot: state2,
          receipts: <V3CheckpointReceipt>[effect2.receipt],
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      await repository.persist(
        snapshot: state2,
        receipts: <V3CheckpointReceipt>[effect1.receipt, effect2.receipt],
      );
      await expectLater(
        repository.persist(
          snapshot: state1,
          receipts: <V3CheckpointReceipt>[effect1.receipt],
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      final receiptLimited = V3SessionCheckpointRepository(
        store: _Store(),
        maxReceiptsPerSession: 1,
      );
      await receiptLimited.restore();
      await expectLater(
        receiptLimited.persist(
          snapshot: state2,
          receipts: <V3CheckpointReceipt>[effect1.receipt, effect2.receipt],
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      await receiptLimited.close();
      await repository.close();
      effect1.close();
      effect2.close();
      state1.wipeSecrets();
      fork1.wipeSecrets();
      state2.wipeSecrets();
    });

    test('recovers write-new-before-delete after an ambiguous write', () async {
      final store = _Store()..durableThenThrow = true;
      final repository = V3SessionCheckpointRepository(store: store);
      await repository.restore();
      final state = _snapshot(revision: 1, ratchetStart: 0x51);
      final effect = await _effect(
        snapshot: state,
        messageStart: 0xa1,
        direction: V3CheckpointEffectDirection.incoming,
      );
      await expectLater(
        repository.persist(
          snapshot: state,
          receipts: <V3CheckpointReceipt>[effect.receipt],
        ),
        throwsStateError,
      );
      expect(repository.requiresRecovery, isTrue);
      expect(store.records, hasLength(1));
      await expectLater(
        repository.persist(
          snapshot: state,
          receipts: <V3CheckpointReceipt>[effect.receipt],
        ),
        throwsStateError,
      );
      await repository.close();

      store.durableThenThrow = false;
      final recovered = V3SessionCheckpointRepository(store: store);
      expect((await recovered.restore()).checkpoints.single.revision, 1);
      await recovered.close();
      effect.close();
      state.wipeSecrets();
    });

    test('rejects corrupt receipt ordering and physical record overflow',
        () async {
      final store = _Store();
      final repository = V3SessionCheckpointRepository(store: store);
      await repository.restore();
      final state = _snapshot(revision: 1, ratchetStart: 0x61);
      final effect = await _effect(
        snapshot: state,
        messageStart: 0xb1,
        direction: V3CheckpointEffectDirection.incoming,
      );
      await repository.persist(
        snapshot: state,
        receipts: <V3CheckpointReceipt>[effect.receipt],
      );
      await repository.close();

      final corrupt = _Store()
        ..records['corrupt'] = _deepCopy(store.records.values.single);
      final receipt = (corrupt.records['corrupt']!['receipts'] as List).single
          as Map<String, dynamic>;
      receipt['stateDigest'] = '${receipt['stateDigest']}=';
      await expectLater(
        V3SessionCheckpointRepository(store: corrupt).restore(),
        throwsA(anyOf(
            isA<FormatException>(), isA<V3LmfPersistenceConflictException>())),
      );

      final physical = _Store()
        ..records['one'] = _deepCopy(store.records.values.single)
        ..records['two'] = _deepCopy(store.records.values.single);
      await expectLater(
        V3SessionCheckpointRepository(
          store: physical,
          maxStoredRecords: 1,
        ).restore(),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );

      final byteLimited = V3SessionCheckpointRepository(
        store: _Store(),
        maxTotalRetainedBytes: 1,
      );
      await byteLimited.restore();
      await expectLater(
        byteLimited.persist(
          snapshot: state,
          receipts: <V3CheckpointReceipt>[effect.receipt],
        ),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      expect(byteLimited.checkpointCount, 0);
      await byteLimited.close();
      effect.close();
      state.wipeSecrets();
    });

    test('authority blocks direct checkpoint reads and lifecycle calls',
        () async {
      final repository = V3SessionCheckpointRepository(store: _Store());
      final authority = await repository.claimSessionCoordinatorAuthority();
      await expectLater(repository.restore(), throwsStateError);
      await repository.restore(authority: authority);
      expect(() => repository.checkpoints(), throwsStateError);
      expect(
        () => repository.checkpointForSession(_bytes(16, 0x01)),
        throwsStateError,
      );
      final state = _snapshot(revision: 1, ratchetStart: 0x71);
      await expectLater(
        repository.persist(
          snapshot: state,
          receipts: const <V3CheckpointReceipt>[],
        ),
        throwsStateError,
      );
      await expectLater(repository.close(), throwsStateError);
      await repository.close(authority: authority);
      state.wipeSecrets();
    });

    test('rejects a mismatched X25519 private and public checkpoint pair',
        () async {
      final repository = V3SessionCheckpointRepository(store: _Store());
      await repository.restore();
      final state = _snapshot(
        revision: 1,
        ratchetStart: 0x79,
        validEcKeyPair: false,
      );
      await expectLater(
        repository.persist(
          snapshot: state,
          receipts: const <V3CheckpointReceipt>[],
        ),
        throwsA(anyOf(isA<FormatException>(), isA<StateError>())),
      );
      expect(repository.checkpointCount, 0);
      expect(repository.requiresRecovery, isFalse);
      await repository.close();
      state.wipeSecrets();
    });
  });
}

final class _EffectFixture {
  _EffectFixture({
    required this.application,
    required this.ratchet,
    required this.receipt,
  });

  final Uint8List application;
  final Uint8List ratchet;
  final V3CheckpointReceipt receipt;

  void close() {
    _wipe(application);
    _wipe(ratchet);
  }
}

Future<_EffectFixture> _effect({
  required V3TripleRatchetState snapshot,
  required int messageStart,
  required V3CheckpointEffectDirection direction,
}) async {
  final application = await _applicationRecord(messageStart: messageStart);
  final ratchet = V3TripleRatchetStateCodec.encode(snapshot);
  final decoded = V3CommittedRecordCodec.decode(application);
  try {
    return _EffectFixture(
      application: application,
      ratchet: ratchet,
      receipt: V3CheckpointReceipt.fromStates(
        direction: direction,
        assemblyId: decoded.assemblyId,
        applicationState: application,
        ratchetState: ratchet,
      ),
    );
  } finally {
    decoded.wipeContent();
  }
}

Future<Uint8List> _applicationRecord({
  required int messageStart,
  int plaintextStart = 0x91,
}) async {
  final plaintext = _bytes(48, plaintextStart);
  final frame = await V3LmfAead.sealSingle(
    metadata: V3LmfMessageMetadata(
      kind: V3LmfFrameKind.handshake,
      senderBinding: _bytes(32, 0x31),
      recipientBinding: _bytes(32, 0x71),
      messageId: _bytes(16, messageStart),
      sessionId: _bytes(16, 0x01),
      epoch: 0,
      messageCounter: messageStart,
    ),
    plaintext: plaintext,
    secretKey: SecretKeyData(_bytes(32, 0xd1)),
    nonce: _bytes(V3LmfFrameCodec.nonceBytes, messageStart),
  );
  final record = V3CommittedRecord.fromDelivery(
    targetFrame: frame,
    content: plaintext,
  );
  try {
    return V3CommittedRecordCodec.encode(record);
  } finally {
    record.wipeContent();
    _wipe(plaintext);
  }
}

V3TripleRatchetState _snapshot({
  required int revision,
  required int ratchetStart,
  bool validEcKeyPair = true,
}) {
  return V3TripleRatchetState(
    role: V3SessionRole.initiator,
    lifecycle: V3RatchetLifecycle.active,
    revision: revision,
    sessionId: _bytes(16, 0x01),
    transcriptDigest: _bytes(48, 0x21),
    initiatorRoutingBinding: _bytes(32, 0x31),
    responderRoutingBinding: _bytes(32, 0x71),
    initiatorToResponderAckRootKey: _bytes(32, 0xa1),
    responderToInitiatorAckRootKey: _bytes(32, 0xc1),
    ecRootKey: _bytes(32, ratchetStart),
    ecSendingChainKey: _bytes(32, ratchetStart + 1),
    ecReceivingChainKey: _bytes(32, ratchetStart + 2),
    ecLocalDhPrivateKey: _bytes(32, 0x72),
    ecLocalDhPublicKey: validEcKeyPair
        ? _hex(
            '5c117f7fa14c242bc843fd1bac49ad870c37b8e615da1b4fefe64859aff5245d',
          )
        : _bytes(32, 0x01),
    ecRemoteDhPublicKey: _bytes(32, 0x32),
    ecSendCounter: revision,
    ecReceiveCounter: revision,
    ecPreviousSendingChainLength: 0,
    pqRootKey: _bytes(32, ratchetStart + 3),
    sckaStateSealKey: _bytes(32, ratchetStart + 5),
    pqCurrentEpoch: 0,
    pqSendingEpoch: 0,
    pqReceivingEpoch: 0,
    pqEpochStates: <V3PqEpochState>[
      V3PqEpochState(
        epoch: 0,
        sendingChainKey: _bytes(32, ratchetStart + 4),
        sendCounter: revision,
        receivingChainKey: _bytes(32, ratchetStart + 5),
        receiveCounter: revision,
      ),
    ],
    nativeSckaState: _bytes(32, ratchetStart + 6),
  );
}

final class _Store implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records =
      <String, Map<String, dynamic>>{};
  var _nextId = 0;
  bool durableThenThrow = false;
  bool failDeletes = false;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = 'record-${_nextId++}';
    records[id] = _deepCopy(payload);
    if (durableThenThrow) {
      durableThenThrow = false;
      throw StateError('injected durable write ambiguity');
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
    if (failDeletes) throw StateError('injected delete failure');
    records.remove(storageId);
  }
}

Map<String, dynamic> _deepCopy(Map<String, dynamic> value) =>
    (jsonDecode(jsonEncode(value)) as Map).cast<String, dynamic>();

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);

Uint8List _hex(String value) => Uint8List.fromList(
      List<int>.generate(
        value.length ~/ 2,
        (index) =>
            int.parse(value.substring(index * 2, index * 2 + 2), radix: 16),
      ),
    );
