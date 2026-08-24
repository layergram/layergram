import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/committed_record_v3.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/hybrid_ratchet_header_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_atomic_commit.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';

void main() {
  final key = SecretKeyData(_bytes(32, 0x11));

  group('LMF v3 atomic application/ratchet commit', () {
    test('commits concrete application and Triple Ratchet codecs together',
        () async {
      final store = _FaultStore();
      final ready = await _readyDelivery(store: store, key: key);
      final journal = V3LmfAtomicCommitJournal(
        store: store,
        inbox: ready.inbox,
      );
      await journal.restore();

      final committed = await journal.commit(
        delivery: ready.delivery,
        builder: (plaintext) {
          final application = V3CommittedRecord.fromDelivery(
            targetFrame: ready.frames.first,
            content: plaintext,
          );
          final ratchet = _concreteRatchetState(ready.frames.first);
          try {
            return V3LmfAtomicEffect(
              applicationState: V3CommittedRecordCodec.encode(application),
              ratchetState: V3TripleRatchetStateCodec.encode(ratchet),
            );
          } finally {
            application.wipeContent();
            ratchet.wipeSecrets();
          }
        },
      );

      final application = V3CommittedRecordCodec.decode(
        committed.applicationState,
      );
      final ratchet = V3TripleRatchetStateCodec.decode(
        committed.ratchetState,
      );
      expect(application.assemblyId, ready.delivery.assemblyId);
      expect(application.stableRecordId, committed.messageRecordId);
      expect(application.content, _bytes(300, 0x31));
      expect(ratchet.sessionId, ready.frames.first.metadata.sessionId);
      expect(ratchet.pqCurrentEpoch, 0);
      expect(journal.totalStateBytes, 492 + 752);
      application.wipeContent();
      ratchet.wipeSecrets();
    });

    test('does not reissue inbox retirement authority after journal attach',
        () async {
      final store = _FaultStore();
      final ready = await _readyDelivery(store: store, key: key);
      final journal = V3LmfAtomicCommitJournal(
        store: store,
        inbox: ready.inbox,
      );

      await journal.restore();

      await expectLater(
        ready.inbox.attachAtomicCommitJournal(owner: Object()),
        throwsStateError,
      );
    });

    test('persists one effect before the inbox tombstone', () async {
      final store = _FaultStore();
      final ready = await _readyDelivery(store: store, key: key);
      final journal = V3LmfAtomicCommitJournal(
        store: store,
        inbox: ready.inbox,
      );
      await journal.restore();
      var builderCalls = 0;

      final committed = await journal.commit(
        delivery: ready.delivery,
        persistedAt: DateTime.utc(2026, 8, 14),
        builder: (plaintext) {
          builderCalls++;
          expect(plaintext, orderedEquals(_bytes(300, 0x31)));
          return V3LmfAtomicEffect(
            applicationState: _bytes(80, 0x51),
            ratchetState: _bytes(128, 0x91),
          );
        },
      );

      expect(builderCalls, 1);
      expect(committed.messageRecordId, 'v3:${ready.delivery.assemblyId}');
      expect(committed.applicationState, orderedEquals(_bytes(80, 0x51)));
      expect(committed.ratchetState, orderedEquals(_bytes(128, 0x91)));
      expect(journal.committedEffectCount, 1);
      expect(journal.totalStateBytes, 208);
      expect(
        store.records.values.singleWhere(
          (record) => record['kind'] == V3LmfDurableInbox.committedRecordKind,
        )['higherLevelCommitDigest'],
        committed.effectDigest,
      );
      expect(
        store.records.values.map((record) => record['kind']).toSet(),
        {
          V3LmfAtomicCommitJournal.recordKind,
          V3LmfDurableInbox.committedRecordKind,
        },
      );

      final replay = await ready.inbox.receive(
        frame: ready.frames.first,
        secretKey: key,
      );
      expect(replay.status, V3LmfInboxStatus.committedReplay);

      final repeated = await journal.commit(
        delivery: ready.delivery,
        builder: (_) {
          fail('the effect builder must not run for a durable assembly');
        },
      );
      expect(repeated.effectDigest, committed.effectDigest);
      expect(builderCalls, 1);
    });

    test('resumes after effect write succeeds but tombstone write fails',
        () async {
      final store = _FaultStore();
      final ready = await _readyDelivery(store: store, key: key);
      final journal = V3LmfAtomicCommitJournal(
        store: store,
        inbox: ready.inbox,
      );
      await journal.restore();
      store.failKindOnce = V3LmfDurableInbox.committedRecordKind;

      await expectLater(
        journal.commit(
          delivery: ready.delivery,
          builder: (_) => V3LmfAtomicEffect(
            applicationState: _bytes(40, 0x71),
            ratchetState: _bytes(96, 0xb1),
          ),
        ),
        throwsStateError,
      );
      expect(
        store.records.values
            .where(
              (record) => record['kind'] == V3LmfAtomicCommitJournal.recordKind,
            )
            .length,
        1,
      );
      expect(
        store.records.values
            .where(
              (record) => record['kind'] == V3LmfDurableInbox.inboxRecordKind,
            )
            .length,
        ready.frames.length,
      );
      await ready.inbox.close();
      await journal.close();

      final restoredInbox = V3LmfDurableInbox(store: store);
      final inboxRestore = await restoredInbox.restore(keyResolver: (_) => key);
      expect(inboxRestore.deliveries, hasLength(1));
      final restoredJournal = V3LmfAtomicCommitJournal(
        store: store,
        inbox: restoredInbox,
      );
      final journalRestore = await restoredJournal.restore();
      expect(journalRestore.effects, hasLength(1));
      expect(
        journalRestore.pendingInboxCommitAssemblyIds,
        {inboxRestore.deliveries.single.assemblyId},
      );
      expect(
        journalRestore.effects.single.applicationState,
        orderedEquals(_bytes(40, 0x71)),
      );

      final resumed = await restoredJournal.resume(
        delivery: inboxRestore.deliveries.single,
      );
      expect(resumed.ratchetState, orderedEquals(_bytes(96, 0xb1)));
      expect(
        store.records.values.map((record) => record['kind']).toSet(),
        {
          V3LmfAtomicCommitJournal.recordKind,
          V3LmfDurableInbox.committedRecordKind,
        },
      );
    });

    test('ambiguous effect write requires restore before any retry', () async {
      final store = _FaultStore();
      final ready = await _readyDelivery(store: store, key: key);
      final journal = V3LmfAtomicCommitJournal(
        store: store,
        inbox: ready.inbox,
      );
      await journal.restore();
      store.persistAndThrowKindOnce = V3LmfAtomicCommitJournal.recordKind;
      var builderCalls = 0;

      await expectLater(
        journal.commit(
          delivery: ready.delivery,
          builder: (_) {
            builderCalls++;
            return V3LmfAtomicEffect(
              applicationState: _bytes(40, 0x71),
              ratchetState: _bytes(96, 0xb1),
            );
          },
        ),
        throwsStateError,
      );
      expect(builderCalls, 1);
      expect(
        store.records.values
            .where(
              (record) => record['kind'] == V3LmfAtomicCommitJournal.recordKind,
            )
            .length,
        1,
      );
      await expectLater(
        journal.commit(
          delivery: ready.delivery,
          builder: (_) {
            fail('an indeterminate write must fail before rerunning builder');
          },
        ),
        throwsStateError,
      );
      expect(builderCalls, 1);
      await journal.close();

      final recovered = V3LmfAtomicCommitJournal(
        store: store,
        inbox: ready.inbox,
      );
      final restored = await recovered.restore();
      expect(restored.effects, hasLength(1));
      expect(
        restored.pendingInboxCommitAssemblyIds,
        {ready.delivery.assemblyId},
      );
      await recovered.commit(
        delivery: ready.delivery,
        builder: (_) {
          fail('the restored durable effect must bypass builder');
        },
      );
      expect(builderCalls, 1);
    });

    test('builder failure keeps sealed frames eligible for redelivery',
        () async {
      final store = _FaultStore();
      final ready = await _readyDelivery(store: store, key: key);
      final journal = V3LmfAtomicCommitJournal(
        store: store,
        inbox: ready.inbox,
      );
      await journal.restore();

      await expectLater(
        journal.commit(
          delivery: ready.delivery,
          builder: (_) => throw StateError('injected ratchet failure'),
        ),
        throwsStateError,
      );
      expect(journal.committedEffectCount, 0);
      expect(ready.inbox.readyDeliveryCount, 1);
      expect(
        store.records.values.every(
          (record) => record['kind'] == V3LmfDurableInbox.inboxRecordKind,
        ),
        isTrue,
      );
    });

    test('journal rejects transport-only commit paths before builder',
        () async {
      final attachedStore = _FaultStore();
      final attachedReady = await _readyDelivery(
        store: attachedStore,
        key: key,
      );
      final attachedJournal = V3LmfAtomicCommitJournal(
        store: attachedStore,
        inbox: attachedReady.inbox,
      );
      await attachedJournal.restore();
      await expectLater(
        attachedReady.inbox.commit(attachedReady.delivery),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(attachedReady.inbox.readyDeliveryCount, 1);

      final legacyStore = _FaultStore();
      final legacyReady = await _readyDelivery(store: legacyStore, key: key);
      await legacyReady.inbox.commit(legacyReady.delivery);
      final journalAfterLegacyCommit = V3LmfAtomicCommitJournal(
        store: legacyStore,
        inbox: legacyReady.inbox,
      );
      await journalAfterLegacyCommit.restore();
      var builderCalls = 0;
      await expectLater(
        journalAfterLegacyCommit.commit(
          delivery: legacyReady.delivery,
          builder: (_) {
            builderCalls++;
            return V3LmfAtomicEffect(
              applicationState: _bytes(16, 0x31),
              ratchetState: _bytes(32, 0x71),
            );
          },
        ),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(builderCalls, 0);
      expect(journalAfterLegacyCommit.committedEffectCount, 0);
    });

    test('restores exact duplicates but rejects conflicting durable effects',
        () async {
      final firstStore = _FaultStore();
      final firstReady = await _readyDelivery(store: firstStore, key: key);
      final firstJournal = V3LmfAtomicCommitJournal(
        store: firstStore,
        inbox: firstReady.inbox,
      );
      await firstJournal.restore();
      await firstJournal.commit(
        delivery: firstReady.delivery,
        builder: (_) => V3LmfAtomicEffect(
          applicationState: _bytes(32, 0x41),
          ratchetState: _bytes(64, 0x81),
        ),
      );
      final firstEffect = _effectPayload(firstStore);
      firstStore.records['exact-duplicate'] = _deepCopy(firstEffect);
      await firstJournal.close();
      await firstReady.inbox.close();

      final duplicateInbox = V3LmfDurableInbox(store: firstStore);
      await duplicateInbox.restore(keyResolver: (_) => key);
      final duplicateRestored = V3LmfAtomicCommitJournal(
        store: firstStore,
        inbox: duplicateInbox,
      );
      final duplicateResult = await duplicateRestored.restore();
      expect(duplicateResult.effects, hasLength(1));
      expect(duplicateResult.removedExactDuplicates, 1);
      expect(
        firstStore.records.values
            .where(
              (record) => record['kind'] == V3LmfAtomicCommitJournal.recordKind,
            )
            .length,
        1,
      );
      await duplicateRestored.close();

      final conflictingStore = _FaultStore();
      final conflictingReady =
          await _readyDelivery(store: conflictingStore, key: key);
      final conflictingJournal = V3LmfAtomicCommitJournal(
        store: conflictingStore,
        inbox: conflictingReady.inbox,
      );
      await conflictingJournal.restore();
      await conflictingJournal.commit(
        delivery: conflictingReady.delivery,
        builder: (_) => V3LmfAtomicEffect(
          applicationState: _bytes(32, 0xc1),
          ratchetState: _bytes(64, 0xe1),
        ),
      );
      firstStore.records['valid-conflict'] =
          _deepCopy(_effectPayload(conflictingStore));

      final rejected = V3LmfAtomicCommitJournal(
        store: firstStore,
        inbox: duplicateInbox,
      );
      await expectLater(
        rejected.restore(),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(firstStore.records.containsKey('valid-conflict'), isTrue);
    });

    test('malformed effect fails closed and is not deleted', () async {
      final store = _FaultStore();
      store.records['malformed'] = <String, dynamic>{
        'kind': V3LmfAtomicCommitJournal.recordKind,
        'v': 1,
      };
      final inbox = V3LmfDurableInbox(store: store);
      await inbox.restore(keyResolver: (_) => key);
      final journal = V3LmfAtomicCommitJournal(
        store: store,
        inbox: inbox,
      );

      await expectLater(journal.restore(), throwsFormatException);
      expect(store.records.containsKey('malformed'), isTrue);
    });

    test('bound tombstone without its durable effect fails closed on restore',
        () async {
      final store = _FaultStore();
      final ready = await _readyDelivery(store: store, key: key);
      final journal = V3LmfAtomicCommitJournal(
        store: store,
        inbox: ready.inbox,
      );
      await journal.restore();
      await journal.commit(
        delivery: ready.delivery,
        builder: (_) => V3LmfAtomicEffect(
          applicationState: _bytes(24, 0x41),
          ratchetState: _bytes(48, 0x81),
        ),
      );
      final effectStorageId = store.records.entries
          .singleWhere(
            (entry) =>
                entry.value['kind'] == V3LmfAtomicCommitJournal.recordKind,
          )
          .key;
      store.records.remove(effectStorageId);
      await journal.close();
      await ready.inbox.close();

      final restoredInbox = V3LmfDurableInbox(store: store);
      await restoredInbox.restore(keyResolver: (_) => key);
      final restoredJournal = V3LmfAtomicCommitJournal(
        store: store,
        inbox: restoredInbox,
      );
      await expectLater(
        restoredJournal.restore(),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
    });

    test('state limits fail before effect persistence or inbox commit',
        () async {
      final store = _FaultStore();
      final ready = await _readyDelivery(store: store, key: key);
      final journal = V3LmfAtomicCommitJournal(
        store: store,
        inbox: ready.inbox,
        maxRatchetStateBytes: 8,
      );
      await journal.restore();

      await expectLater(
        journal.commit(
          delivery: ready.delivery,
          builder: (_) => V3LmfAtomicEffect(
            applicationState: _bytes(4, 0x31),
            ratchetState: _bytes(9, 0x61),
          ),
        ),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
      expect(journal.committedEffectCount, 0);
      expect(ready.inbox.readyDeliveryCount, 1);
      expect(
        store.records.values.every(
          (record) => record['kind'] == V3LmfDurableInbox.inboxRecordKind,
        ),
        isTrue,
      );
    });
  });
}

Future<
    ({
      V3LmfDurableInbox inbox,
      V3LmfDurableDelivery delivery,
      List<V3LmfFrame> frames,
    })> _readyDelivery({
  required _FaultStore store,
  required SecretKey key,
}) async {
  final frames = await V3LmfAead.sealFragmented(
    metadata: _metadata(),
    plaintext: _bytes(300, 0x31),
    secretKey: key,
    nonceForFragment: (index) =>
        _bytes(V3LmfFrameCodec.nonceBytes, 0x51 + index),
    hybridRatchetHeader: _hybridHeader(),
  );
  final inbox = V3LmfDurableInbox(store: store);
  await inbox.restore(keyResolver: (_) => key);
  V3LmfDurableDelivery? delivery;
  for (final frame in frames) {
    delivery = (await inbox.receive(frame: frame, secretKey: key)).delivery ??
        delivery;
  }
  return (inbox: inbox, delivery: delivery!, frames: frames);
}

V3LmfMessageMetadata _metadata({
  V3LmfFrameKind kind = V3LmfFrameKind.application,
}) =>
    V3LmfMessageMetadata(
      kind: kind,
      senderBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 0x01),
      recipientBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 0x41),
      messageId: _bytes(V3LmfFrameCodec.messageIdBytes, 0x81),
      sessionId: _bytes(V3LmfFrameCodec.sessionIdBytes, 0xa1),
      epoch: 7,
      messageCounter: 9,
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

V3TripleRatchetState _concreteRatchetState(V3LmfFrame frame) {
  final metadata = frame.metadata;
  return V3TripleRatchetState(
    role: V3SessionRole.initiator,
    lifecycle: V3RatchetLifecycle.active,
    revision: 1,
    sessionId: metadata.sessionId,
    transcriptDigest: _bytes(48, 0x21),
    initiatorRoutingBinding: metadata.senderBinding,
    responderRoutingBinding: metadata.recipientBinding,
    initiatorToResponderAckRootKey: _bytes(32, 0x31),
    responderToInitiatorAckRootKey: _bytes(32, 0x51),
    ecRootKey: _bytes(32, 0x71),
    ecSendingChainKey: _bytes(32, 0x91),
    ecReceivingChainKey: _bytes(32, 0xb1),
    ecLocalDhPrivateKey: _bytes(32, 0xd1),
    ecLocalDhPublicKey: _bytes(32, 0x11),
    ecRemoteDhPublicKey: _bytes(32, 0x41),
    ecSendCounter: 0,
    ecReceiveCounter: 0,
    ecPreviousSendingChainLength: 0,
    pqRootKey: _bytes(32, 0x61),
    sckaStateSealKey: _bytes(32, 0x71),
    pqCurrentEpoch: 0,
    pqSendingEpoch: 0,
    pqReceivingEpoch: 0,
    pqEpochStates: <V3PqEpochState>[
      V3PqEpochState(
        epoch: 0,
        sendingChainKey: _bytes(32, 0x81),
        receivingChainKey: _bytes(32, 0xa1),
      ),
    ],
    nativeSckaState: _bytes(128, 0xc1),
  );
}

Map<String, dynamic> _effectPayload(_FaultStore store) => _deepCopy(
      store.records.values.singleWhere(
        (record) => record['kind'] == V3LmfAtomicCommitJournal.recordKind,
      ),
    );

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

Map<String, dynamic> _deepCopy(Map<String, dynamic> value) =>
    (jsonDecode(jsonEncode(value)) as Map).cast<String, dynamic>();

class _FaultStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records =
      <String, Map<String, dynamic>>{};
  var _nextId = 0;
  String? failKindOnce;
  String? persistAndThrowKindOnce;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    if (payload['kind'] == failKindOnce) {
      failKindOnce = null;
      throw StateError('injected write failure');
    }
    final storageId = 'record-${_nextId++}';
    records[storageId] = _deepCopy(payload);
    if (payload['kind'] == persistAndThrowKindOnce) {
      persistAndThrowKindOnce = null;
      throw StateError('injected ambiguous write failure');
    }
    return storageId;
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
