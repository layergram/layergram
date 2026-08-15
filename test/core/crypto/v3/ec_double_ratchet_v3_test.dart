import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';

void main() {
  const aliceMnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const bobMnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';

  late _RatchetMlKemBackend backend;
  late V3LocalIdentityHandle alice;
  late V3LocalIdentityHandle bob;
  late V3LocalDeviceHandle aliceDevice;
  late V3LocalDeviceHandle bobDevice;

  setUp(() async {
    backend = _RatchetMlKemBackend();
    final factory = V3LocalIdentityFactory(
      seedService: SeedService(),
      mlKem768Backend: backend,
    );
    alice = await factory.restorePrimary(mnemonic: aliceMnemonic);
    bob = await factory.restorePrimary(mnemonic: bobMnemonic);
    aliceDevice = await V3LocalDeviceHandle.fromSeed(_bytes(32, 0x11));
    bobDevice = await V3LocalDeviceHandle.fromSeed(_bytes(32, 0x51));
  });

  tearDown(() async {
    aliceDevice.close();
    bobDevice.close();
    await alice.close();
    await bob.close();
  });

  group('protocol v3 EC Double Ratchet', () {
    test('encodes one strict fixed-width EC header', () {
      final header = V3EcRatchetHeader(
        ratchetPublicKey: _bytes(32, 0x21),
        previousSendingChainLength: 7,
        messageCounter: 9,
      );
      final encoded = V3EcRatchetHeaderCodec.encode(header);
      expect(V3EcRatchetHeaderCodec.encodedBytes, 56);
      expect(encoded, hasLength(56));
      expect(
        crypto.sha256.convert(encoded).toString(),
        'c4da6a0f0645f7a935960c9e810a6e76cdf935dc26e1a1c87e9a7f82656d2091',
      );

      final decoded = V3EcRatchetHeaderCodec.decode(encoded);
      expect(decoded.ratchetPublicKey, orderedEquals(header.ratchetPublicKey));
      expect(decoded.previousSendingChainLength, 7);
      expect(decoded.messageCounter, 9);

      for (final changed in <Uint8List>[
        Uint8List.fromList(encoded)..[0] ^= 1,
        Uint8List.fromList(encoded)..[3] = 2,
        Uint8List.fromList(encoded)..[4] = 0xff,
        Uint8List.fromList(encoded)..[5] = 1,
        Uint8List.fromList(encoded)..[7] = 55,
        Uint8List.fromList(encoded.sublist(0, encoded.length - 1)),
      ]) {
        expect(
          () => V3EcRatchetHeaderCodec.decode(changed),
          throwsFormatException,
        );
      }
      expect(
        () => V3EcRatchetHeader(
          ratchetPublicKey: Uint8List(32),
          previousSendingChainLength: 0,
          messageCounter: 0,
        ),
        throwsArgumentError,
      );

      for (final invalidPublicKey in <Uint8List>[
        _x25519FieldPrime(),
        Uint8List.fromList(_bytes(32, 0x21))..[31] |= 0x80,
      ]) {
        expect(
          () => V3EcRatchetHeader(
            ratchetPublicKey: invalidPublicKey,
            previousSendingChainLength: 0,
            messageCounter: 0,
          ),
          throwsArgumentError,
        );
        final malformed = Uint8List.fromList(encoded)
          ..setRange(8, 40, invalidPublicKey);
        expect(
          () => V3EcRatchetHeaderCodec.decode(malformed),
          throwsFormatException,
        );
      }
    });

    test('freezes deterministic chain-step vector and candidate semantics',
        () async {
      final snapshot = await _deterministicSnapshot();
      final state = await V3EcDoubleRatchet.restore(snapshot);
      final originalChain = state.sendingChainKey;
      final transition = await V3EcDoubleRatchet.send(state);
      try {
        expect(transition.header.messageCounter, 0);
        expect(transition.header.previousSendingChainLength, 0);
        expect(
          _hex(transition.messageKey),
          '0e65a0e3dd2f7133beb2590eda9f3245107bc4f6c71425c2ff6afc3de34c80cd',
        );
        expect(
          _hex(transition.nextState.sendingChainKey),
          '5dd4c244b5069d2fad5374abcbcc3ee2643a3cfabdb46a35beb9bfd14a733b34',
        );
        expect(state.sendCounter, 0);
        expect(state.sendingChainKey, orderedEquals(originalChain));

        final nextSnapshot = transition.nextState.toTripleRatchetSnapshot(
          snapshot,
        );
        expect(nextSnapshot.revision, 1);
        expect(nextSnapshot.ecSendCounter, 1);
        expect(
          () => transition.nextState.toTripleRatchetSnapshot(nextSnapshot),
          throwsStateError,
        );
        nextSnapshot.wipeSecrets();
      } finally {
        originalChain.fillRange(0, originalChain.length, 0);
        transition.close();
        state.close();
        snapshot.wipeSecrets();
      }
      expect(() => transition.messageKey, throwsStateError);
    });

    test('initializes from authenticated handshake and sends both directions',
        () async {
      final established = await _establish(
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );
      final aliceState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.initiator,
      );
      final bobState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.responder,
      );
      V3EcRatchetTransition? aliceSend;
      V3EcRatchetTransition? bobReceive;
      V3EcRatchetTransition? bobSend;
      V3EcRatchetTransition? aliceReceive;
      V3EcRatchetTransition? aliceNextSend;
      V3EcRatchetTransition? bobNextReceive;
      try {
        expect(aliceState.hasReceivingChain, isFalse);
        expect(bobState.hasReceivingChain, isTrue);

        aliceSend = await V3EcDoubleRatchet.send(aliceState);
        bobReceive = await V3EcDoubleRatchet.receive(
          state: bobState,
          header: aliceSend.header,
          nowUnixSeconds: 1000,
          skippedKeyLifetimeSeconds: 100,
        );
        expect(
          bobReceive.messageKey,
          orderedEquals(aliceSend.messageKey),
        );

        bobSend = await V3EcDoubleRatchet.send(bobReceive.nextState);
        aliceReceive = await V3EcDoubleRatchet.receive(
          state: aliceSend.nextState,
          header: bobSend.header,
          nowUnixSeconds: 1001,
          skippedKeyLifetimeSeconds: 100,
        );
        expect(
          aliceReceive.messageKey,
          orderedEquals(bobSend.messageKey),
        );
        expect(
          bobSend.header.ratchetPublicKey,
          isNot(orderedEquals(
              established.responder.localInitialRatchetPublicKey)),
        );

        aliceNextSend = await V3EcDoubleRatchet.send(aliceReceive.nextState);
        expect(aliceNextSend.header.previousSendingChainLength, 1);
        expect(
          aliceNextSend.header.ratchetPublicKey,
          isNot(orderedEquals(aliceSend.header.ratchetPublicKey)),
        );
        bobNextReceive = await V3EcDoubleRatchet.receive(
          state: bobSend.nextState,
          header: aliceNextSend.header,
          nowUnixSeconds: 1002,
          skippedKeyLifetimeSeconds: 100,
        );
        expect(
          bobNextReceive.messageKey,
          orderedEquals(aliceNextSend.messageKey),
        );
      } finally {
        bobNextReceive?.close();
        aliceNextSend?.close();
        aliceReceive?.close();
        bobSend?.close();
        bobReceive?.close();
        aliceSend?.close();
        aliceState.close();
        bobState.close();
        established.initiator.close();
        established.responder.close();
      }
    });

    test('responder can send immediately after confirmation', () async {
      final established = await _establish(
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );
      final aliceState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.initiator,
      );
      final bobState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.responder,
      );
      final sent = await V3EcDoubleRatchet.send(bobState);
      final received = await V3EcDoubleRatchet.receive(
        state: aliceState,
        header: sent.header,
        nowUnixSeconds: 2000,
        skippedKeyLifetimeSeconds: 100,
      );
      expect(received.messageKey, orderedEquals(sent.messageKey));
      received.close();
      sent.close();
      aliceState.close();
      bobState.close();
      established.initiator.close();
      established.responder.close();
    });

    test('retains bounded skipped keys for out-of-order delivery', () async {
      final established = await _establish(
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );
      final aliceState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.initiator,
      );
      final bobState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.responder,
      );
      final sent0 = await V3EcDoubleRatchet.send(aliceState);
      final sent1 = await V3EcDoubleRatchet.send(sent0.nextState);
      final sent2 = await V3EcDoubleRatchet.send(sent1.nextState);
      final received2 = await V3EcDoubleRatchet.receive(
        state: bobState,
        header: sent2.header,
        nowUnixSeconds: 3000,
        skippedKeyLifetimeSeconds: 10,
      );
      expect(received2.messageKey, orderedEquals(sent2.messageKey));
      expect(received2.nextState.skippedMessageKeys, hasLength(2));

      final received0 = await V3EcDoubleRatchet.receive(
        state: received2.nextState,
        header: sent0.header,
        nowUnixSeconds: 3001,
        skippedKeyLifetimeSeconds: 10,
      );
      expect(received0.messageKey, orderedEquals(sent0.messageKey));
      expect(received0.nextState.skippedMessageKeys, hasLength(1));
      final received1 = await V3EcDoubleRatchet.receive(
        state: received0.nextState,
        header: sent1.header,
        nowUnixSeconds: 3002,
        skippedKeyLifetimeSeconds: 10,
      );
      expect(received1.messageKey, orderedEquals(sent1.messageKey));
      expect(received1.nextState.skippedMessageKeys, isEmpty);

      expect(
        () => V3EcDoubleRatchet.receive(
          state: received1.nextState,
          header: sent0.header,
          nowUnixSeconds: 3003,
          skippedKeyLifetimeSeconds: 10,
        ),
        throwsFormatException,
      );

      received1.close();
      received0.close();
      received2.close();
      sent2.close();
      sent1.close();
      sent0.close();
      aliceState.close();
      bobState.close();
      established.initiator.close();
      established.responder.close();
    });

    test('uses PN to retain losses across a DH ratchet boundary', () async {
      final established = await _establish(
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );
      final aliceState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.initiator,
      );
      final bobState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.responder,
      );
      final alice0 = await V3EcDoubleRatchet.send(aliceState);
      final alice1 = await V3EcDoubleRatchet.send(alice0.nextState);
      final alice2 = await V3EcDoubleRatchet.send(alice1.nextState);
      final bobReceived0 = await V3EcDoubleRatchet.receive(
        state: bobState,
        header: alice0.header,
        nowUnixSeconds: 3500,
        skippedKeyLifetimeSeconds: 100,
      );
      final bob0 = await V3EcDoubleRatchet.send(bobReceived0.nextState);
      final aliceReceivedBob0 = await V3EcDoubleRatchet.receive(
        state: alice2.nextState,
        header: bob0.header,
        nowUnixSeconds: 3501,
        skippedKeyLifetimeSeconds: 100,
      );
      final alice3 = await V3EcDoubleRatchet.send(
        aliceReceivedBob0.nextState,
      );
      expect(alice3.header.previousSendingChainLength, 3);

      final bobReceived3 = await V3EcDoubleRatchet.receive(
        state: bob0.nextState,
        header: alice3.header,
        nowUnixSeconds: 3502,
        skippedKeyLifetimeSeconds: 100,
      );
      expect(bobReceived3.messageKey, orderedEquals(alice3.messageKey));
      expect(bobReceived3.nextState.skippedMessageKeys, hasLength(2));
      final lateAlice2 = await V3EcDoubleRatchet.receive(
        state: bobReceived3.nextState,
        header: alice2.header,
        nowUnixSeconds: 3503,
        skippedKeyLifetimeSeconds: 100,
      );
      expect(lateAlice2.messageKey, orderedEquals(alice2.messageKey));

      final backwardsPn = V3EcRatchetHeader(
        ratchetPublicKey: alice3.header.ratchetPublicKey,
        previousSendingChainLength: 0,
        messageCounter: alice3.header.messageCounter,
      );
      await expectLater(
        V3EcDoubleRatchet.receive(
          state: bob0.nextState,
          header: backwardsPn,
          nowUnixSeconds: 3504,
          skippedKeyLifetimeSeconds: 100,
        ),
        throwsFormatException,
      );

      lateAlice2.close();
      bobReceived3.close();
      alice3.close();
      aliceReceivedBob0.close();
      bob0.close();
      bobReceived0.close();
      alice2.close();
      alice1.close();
      alice0.close();
      aliceState.close();
      bobState.close();
      established.initiator.close();
      established.responder.close();
    });

    test('fails closed on expired or over-limit skipped keys', () async {
      final established = await _establish(
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );
      final aliceState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.initiator,
      );
      final bobState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.responder,
      );
      final sent0 = await V3EcDoubleRatchet.send(aliceState);
      final sent1 = await V3EcDoubleRatchet.send(sent0.nextState);
      final sent2 = await V3EcDoubleRatchet.send(sent1.nextState);
      final received2 = await V3EcDoubleRatchet.receive(
        state: bobState,
        header: sent2.header,
        nowUnixSeconds: 4000,
        skippedKeyLifetimeSeconds: 10,
      );
      await expectLater(
        V3EcDoubleRatchet.receive(
          state: received2.nextState,
          header: sent0.header,
          nowUnixSeconds: 4011,
          skippedKeyLifetimeSeconds: 10,
        ),
        throwsFormatException,
      );

      final excessive = V3EcRatchetHeader(
        ratchetPublicKey: aliceState.localDhPublicKey,
        previousSendingChainLength: 0,
        messageCounter: 51,
      );
      await expectLater(
        V3EcDoubleRatchet.receive(
          state: bobState,
          header: excessive,
          nowUnixSeconds: 5000,
          skippedKeyLifetimeSeconds: 10,
        ),
        throwsFormatException,
      );
      expect(bobState.receiveCounter, 0);
      expect(bobState.skippedMessageKeys, isEmpty);

      final lowOrderPublicKey = Uint8List(32)..[0] = 1;
      await expectLater(
        V3EcDoubleRatchet.receive(
          state: aliceState,
          header: V3EcRatchetHeader(
            ratchetPublicKey: lowOrderPublicKey,
            previousSendingChainLength: 0,
            messageCounter: 0,
          ),
          nowUnixSeconds: 5000,
          skippedKeyLifetimeSeconds: 10,
        ),
        throwsFormatException,
      );
      expect(aliceState.receiveCounter, 0);
      expect(aliceState.hasReceivingChain, isFalse);

      received2.close();
      sent2.close();
      sent1.close();
      sent0.close();
      aliceState.close();
      bobState.close();
      established.initiator.close();
      established.responder.close();
    });

    test('round-trips candidate state through canonical TR3 restart', () async {
      final established = await _establish(
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );
      final aliceState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.initiator,
      );
      final initialSnapshot = _snapshot(
        established.initiator,
        aliceState,
      );
      final sent = await V3EcDoubleRatchet.send(aliceState);
      final committed = sent.nextState.toTripleRatchetSnapshot(initialSnapshot);
      final encoded = V3TripleRatchetStateCodec.encode(committed);
      final decoded = V3TripleRatchetStateCodec.decode(encoded);
      final restored = await V3EcDoubleRatchet.restore(decoded);
      expect(restored.snapshotRevision, 1);
      expect(restored.sendCounter, 1);
      expect(restored.rootKey, orderedEquals(sent.nextState.rootKey));
      expect(
        restored.sendingChainKey,
        orderedEquals(sent.nextState.sendingChainKey),
      );
      expect(restored.hasReceivingChain, isFalse);

      restored.close();
      decoded.wipeSecrets();
      committed.wipeSecrets();
      sent.close();
      initialSnapshot.wipeSecrets();
      aliceState.close();
      established.initiator.close();
      established.responder.close();
    });

    test('restores skipped keys exactly after a durable restart', () async {
      final established = await _establish(
        alice: alice,
        aliceDevice: aliceDevice,
        bob: bob,
        bobDevice: bobDevice,
      );
      final aliceState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.initiator,
      );
      final bobState = await V3EcDoubleRatchet.initializeFromHandshake(
        established.responder,
      );
      final bobSnapshot = _snapshot(established.responder, bobState);
      final sent0 = await V3EcDoubleRatchet.send(aliceState);
      final sent1 = await V3EcDoubleRatchet.send(sent0.nextState);
      final sent2 = await V3EcDoubleRatchet.send(sent1.nextState);
      final received2 = await V3EcDoubleRatchet.receive(
        state: bobState,
        header: sent2.header,
        nowUnixSeconds: 6000,
        skippedKeyLifetimeSeconds: 100,
      );
      final committed = received2.nextState.toTripleRatchetSnapshot(
        bobSnapshot,
      );
      final decoded = V3TripleRatchetStateCodec.decode(
        V3TripleRatchetStateCodec.encode(committed),
      );
      final restored = await V3EcDoubleRatchet.restore(decoded);
      expect(restored.skippedMessageKeys, hasLength(2));
      final late0 = await V3EcDoubleRatchet.receive(
        state: restored,
        header: sent0.header,
        nowUnixSeconds: 6001,
        skippedKeyLifetimeSeconds: 100,
      );
      expect(late0.messageKey, orderedEquals(sent0.messageKey));
      expect(late0.nextState.skippedMessageKeys, hasLength(1));

      late0.close();
      restored.close();
      decoded.wipeSecrets();
      committed.wipeSecrets();
      received2.close();
      sent2.close();
      sent1.close();
      sent0.close();
      bobSnapshot.wipeSecrets();
      aliceState.close();
      bobState.close();
      established.initiator.close();
      established.responder.close();
    });

    test('restore rejects a mismatched local private/public pair', () async {
      final snapshot = await _deterministicSnapshot(mismatchPublic: true);
      await expectLater(
        V3EcDoubleRatchet.restore(snapshot),
        throwsFormatException,
      );
      snapshot.wipeSecrets();
    });

    test('wiping invalidates state and transition secret access', () async {
      final snapshot = await _deterministicSnapshot();
      final state = await V3EcDoubleRatchet.restore(snapshot);
      final transition = await V3EcDoubleRatchet.send(state);
      state.close();
      expect(state.isClosed, isTrue);
      expect(() => state.rootKey, throwsStateError);
      transition.close();
      expect(transition.isClosed, isTrue);
      expect(() => transition.messageKey, throwsStateError);
      expect(() => transition.nextState, throwsStateError);
      snapshot.wipeSecrets();
    });
  });
}

Future<
    ({
      V3HandshakeEstablishedMaterial initiator,
      V3HandshakeEstablishedMaterial responder,
    })> _establish({
  required V3LocalIdentityHandle alice,
  required V3LocalDeviceHandle aliceDevice,
  required V3LocalIdentityHandle bob,
  required V3LocalDeviceHandle bobDevice,
}) async {
  final offer = await V3HybridHandshake.createOffer(
    localIdentity: alice,
    localDevice: aliceDevice,
    remoteIdentity: bob.publicIdentity,
    mode: V3HandshakeMode.normal,
  );
  final reply = await V3HybridHandshake.createReply(
    localIdentity: bob,
    localDevice: bobDevice,
    initiatorIdentity: alice.publicIdentity,
    offer: offer.offer,
    expectedMode: V3HandshakeMode.normal,
  );
  final initiator = await V3HybridHandshake.acceptReply(
    pending: offer,
    localIdentity: alice,
    localDevice: aliceDevice,
    responderIdentity: bob.publicIdentity,
    reply: reply.reply,
  );
  final responder = await V3HybridHandshake.acceptConfirmation(
    pending: reply,
    initiatorIdentity: alice.publicIdentity,
    responderIdentity: bob.publicIdentity,
    confirmation: initiator.confirmation,
  );
  return (initiator: initiator.established, responder: responder);
}

Future<V3TripleRatchetState> _deterministicSnapshot({
  bool mismatchPublic = false,
}) async {
  final x25519 = X25519();
  final localPrivate = _bytes(32, 0x11);
  final localPair = await x25519.newKeyPairFromSeed(localPrivate);
  final localPublic = Uint8List.fromList(
    (await localPair.extractPublicKey()).bytes,
  );
  final remotePair = await x25519.newKeyPairFromSeed(_bytes(32, 0x61));
  final remotePublic = Uint8List.fromList(
    (await remotePair.extractPublicKey()).bytes,
  );
  final wrongPair = await x25519.newKeyPairFromSeed(_bytes(32, 0x31));
  final wrongPublic = Uint8List.fromList(
    (await wrongPair.extractPublicKey()).bytes,
  );
  return V3TripleRatchetState(
    role: V3SessionRole.initiator,
    lifecycle: V3RatchetLifecycle.active,
    revision: 0,
    sessionId: _bytes(16, 1),
    transcriptDigest: _bytes(48, 0x11),
    initiatorRoutingBinding: _bytes(32, 0x21),
    responderRoutingBinding: _bytes(32, 0x41),
    initiatorToResponderAckRootKey: _bytes(32, 0x61),
    responderToInitiatorAckRootKey: _bytes(32, 0x81),
    ecRootKey: _bytes(32, 0xa1),
    ecSendingChainKey: _bytes(32, 0xc1),
    ecReceivingChainKey: null,
    ecLocalDhPrivateKey: localPrivate,
    ecLocalDhPublicKey: mismatchPublic ? wrongPublic : localPublic,
    ecRemoteDhPublicKey: remotePublic,
    ecSendCounter: 0,
    ecReceiveCounter: 0,
    ecPreviousSendingChainLength: 0,
    pqRootKey: _bytes(32, 0x31),
    sckaStateSealKey: _bytes(32, 0x51),
    pqCurrentEpoch: 0,
    pqSendingEpoch: 0,
    pqReceivingEpoch: 0,
    pqEpochStates: <V3PqEpochState>[
      V3PqEpochState(
        epoch: 0,
        sendingChainKey: _bytes(32, 0x51),
        receivingChainKey: _bytes(32, 0x71),
      ),
    ],
    ecSkippedMessageKeys: const <V3EcSkippedMessageKey>[],
    pqSkippedMessageKeys: const <V3PqSkippedMessageKey>[],
    nativeSckaState: _bytes(64, 0x91),
  );
}

V3TripleRatchetState _snapshot(
  V3HandshakeEstablishedMaterial established,
  V3EcDoubleRatchetState ec,
) {
  final session = established.sessionKeys;
  final pqEpoch = V3PqEpochState(
    epoch: 0,
    sendingChainKey: _bytes(32, 0x51),
    receivingChainKey: _bytes(32, 0x71),
  );
  final skipped = ec.skippedMessageKeys;
  final result = V3TripleRatchetState(
    role: established.role,
    lifecycle: V3RatchetLifecycle.active,
    revision: ec.snapshotRevision,
    sessionId: session.sessionId,
    transcriptDigest: session.transcriptDigest,
    initiatorRoutingBinding: session.initiatorRoutingBinding,
    responderRoutingBinding: session.responderRoutingBinding,
    initiatorToResponderAckRootKey: session.initiatorToResponderAckRootKey,
    responderToInitiatorAckRootKey: session.responderToInitiatorAckRootKey,
    ecRootKey: ec.rootKey,
    ecSendingChainKey: ec.sendingChainKey,
    ecReceivingChainKey: ec.receivingChainKey,
    ecLocalDhPrivateKey: ec.localDhPrivateKey,
    ecLocalDhPublicKey: ec.localDhPublicKey,
    ecRemoteDhPublicKey: ec.remoteDhPublicKey,
    ecSendCounter: ec.sendCounter,
    ecReceiveCounter: ec.receiveCounter,
    ecPreviousSendingChainLength: ec.previousSendingChainLength,
    pqRootKey: session.pqRatchetRootKey,
    sckaStateSealKey: session.sckaStateSealKey,
    pqCurrentEpoch: 0,
    pqSendingEpoch: 0,
    pqReceivingEpoch: 0,
    pqEpochStates: <V3PqEpochState>[pqEpoch],
    ecSkippedMessageKeys: skipped,
    pqSkippedMessageKeys: const <V3PqSkippedMessageKey>[],
    nativeSckaState: _bytes(64, 0x91),
  );
  pqEpoch.wipeSecrets();
  for (final value in skipped) {
    value.wipeSecret();
  }
  return result;
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

Uint8List _x25519FieldPrime() => Uint8List.fromList(
      <int>[0xed, ...List<int>.filled(30, 0xff), 0x7f],
    );

String _hex(List<int> value) =>
    value.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

final class _RatchetMlKemPrivateKeyHandle implements MlKem768PrivateKeyHandle {
  _RatchetMlKemPrivateKeyHandle(this.publicKey);

  final Uint8List publicKey;

  @override
  bool isClosed = false;

  @override
  Future<void> close() async {
    isClosed = true;
  }
}

final class _RatchetMlKemBackend implements MlKem768Backend {
  var _encapsulationCounter = 0;

  @override
  String get implementationId => 'test-only-ratchet-ml-kem';

  @override
  Future<bool> selfTest() async => true;

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) async {
    final digest = crypto.sha512.convert(seed).bytes;
    final publicKey = Uint8List.fromList(
      List<int>.generate(
        MlKem768.publicKeyBytes,
        (index) => digest[index % digest.length],
      ),
    );
    return MlKem768KeyPair(
      publicKey: publicKey,
      privateKeyHandle: _RatchetMlKemPrivateKeyHandle(publicKey),
    );
  }

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async =>
      publicKey.length == MlKem768.publicKeyBytes &&
      publicKey.any((byte) => byte != 0);

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) async {
    final counter = _encapsulationCounter++;
    final block = crypto.sha512.convert(<int>[
      ...publicKey,
      counter & 0xff,
      (counter >> 8) & 0xff,
    ]).bytes;
    final ciphertext = Uint8List.fromList(
      List<int>.generate(
        MlKem768.ciphertextBytes,
        (index) => block[index % block.length] ^ (index & 0xff),
      ),
    );
    return MlKem768Encapsulation(
      ciphertext: ciphertext,
      sharedSecret: _sharedSecret(publicKey, ciphertext),
    );
  }

  @override
  Future<Uint8List> decapsulate(
    MlKem768PrivateKeyHandle privateKeyHandle,
    Uint8List ciphertext,
  ) async {
    final handle = privateKeyHandle as _RatchetMlKemPrivateKeyHandle;
    if (handle.isClosed || ciphertext.length != MlKem768.ciphertextBytes) {
      throw StateError('invalid test ML-KEM handle or ciphertext');
    }
    return _sharedSecret(handle.publicKey, ciphertext);
  }

  Uint8List _sharedSecret(Uint8List publicKey, Uint8List ciphertext) =>
      Uint8List.fromList(
        crypto.sha256.convert(<int>[
          ...'test-only-ratchet-shared\x00'.codeUnits,
          ...publicKey,
          ...ciphertext,
        ]).bytes,
      );
}
