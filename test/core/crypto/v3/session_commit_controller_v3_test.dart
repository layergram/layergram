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
import 'package:layergram/core/crypto/v3/session_commit_controller_v3.dart';
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

V3TripleRatchetState _candidateFrom(
  V3TripleRatchetState current, {
  required int receivingEpoch,
  Uint8List? transcriptOverride,
  int revisionIncrement = 1,
  bool advanceReceiveCounter = true,
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
  final ecSkipped = current.ecSkippedMessageKeys;
  final pqSkipped = current.pqSkippedMessageKeys;
  final nativeState = current.nativeSckaState;
  try {
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
      pqCurrentEpoch: current.pqCurrentEpoch,
      pqSendingEpoch: current.pqSendingEpoch,
      pqReceivingEpoch: receivingEpoch,
      pqEpochStates: epochs,
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

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    if (payload['kind'] == failKindOnce) {
      failKindOnce = null;
      throw StateError('injected write failure');
    }
    final id = 'record-${_nextId++}';
    records[id] = _deepCopy(payload);
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
