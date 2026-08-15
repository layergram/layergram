import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/committed_record_v3.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/hybrid_ratchet_header_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_acknowledgement.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_atomic_commit.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_outbox.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768_ffi.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3_validator.dart';
import 'package:layergram/core/crypto/v3/session_commit_controller_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('packaged production ML-KEM ABI traverses FFI', (tester) async {
    final backend = MlKem768FfiBackend.openPackaged();
    expect(backend.implementationId, contains('mlkem-native-v2.0.0'));
    expect(backend.hasTestHooks, isFalse);
    expect(await backend.selfTest(), isTrue);

    final seed = Uint8List.fromList(
      List<int>.generate(MlKem768.keyGenerationSeedBytes, (index) => index),
    );
    MlKem768KeyPair? keyPair;
    MlKem768Encapsulation? encapsulation;
    Uint8List? decapsulated;
    try {
      keyPair = await backend.keyPairFromSeed(seed);
      encapsulation = await backend.encapsulate(keyPair.publicKey);
      decapsulated = await backend.decapsulate(
        keyPair.privateKeyHandle,
        encapsulation.ciphertext,
      );

      expect(decapsulated, orderedEquals(encapsulation.sharedSecret));
    } finally {
      seed.fillRange(0, seed.length, 0);
      encapsulation?.wipeSharedSecret();
      decapsulated?.fillRange(0, decapsulated.length, 0);
      await keyPair?.privateKeyHandle.close();
    }
  });

  testWidgets('packaged backend restores the complete v3 identity vector',
      (tester) async {
    const mnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon abandon abandon art';
    final backend = MlKem768FfiBackend.openPackaged();
    final factory = V3LocalIdentityFactory(
      seedService: SeedService(),
      mlKem768Backend: backend,
    );
    final identity = await factory.restorePrimary(mnemonic: mnemonic);
    try {
      expect(
        _toHex(identity.publicIdentity.x25519PublicKey),
        '63714c686580e067c811207fee91fe01101b62f4c4ce409c88d6b0f83c883a2a',
      );
      expect(
        sha256.convert(identity.publicIdentity.mlKem768PublicKey).toString(),
        '23c3e86da0aca0b264a8fce803fc300a3f3be12336f6fb3df06067f2a0b29ef4',
      );
      expect(
        identity.publicIdentity.identityId,
        'YJACJCAEX3JH7QSS6ESDJCSBNGOBRTVIZDHK3GQIWDXFL4YJSUPW43QEVE5PEJSYTHMVYHYC4LBOE',
      );
      expect(
        identity.publicIdentity.fingerprint,
        'C240-2488-04BE-D27F-C252-F124-348A-4169',
      );
      final imported = await V3PublicIdentityValidator(
        mlKem768Backend: backend,
      ).decodeBinary(
        V3PublicIdentityCodec.encodeBinary(identity.publicIdentity),
      );
      expect(
        imported.publicIdentity.identityId,
        identity.publicIdentity.identityId,
      );
    } finally {
      await identity.close();
    }
  });

  testWidgets('inactive hybrid handshake traverses packaged ML-KEM and restart',
      (tester) async {
    const aliceMnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon abandon abandon art';
    const bobMnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
    final backend = MlKem768FfiBackend.openPackaged();
    final factory = V3LocalIdentityFactory(
      seedService: SeedService(),
      mlKem768Backend: backend,
    );
    final alice = await factory.restorePrimary(mnemonic: aliceMnemonic);
    final bob = await factory.restorePrimary(mnemonic: bobMnemonic);
    final aliceDevice =
        await V3LocalDeviceHandle.fromSeed(_rangeBytes(32, 0x11));
    final bobDevice = await V3LocalDeviceHandle.fromSeed(_rangeBytes(32, 0x51));
    V3InitiatorPendingHandshake? originalInitiator;
    V3InitiatorPendingHandshake? restoredInitiator;
    V3ResponderPendingHandshake? originalResponder;
    V3ResponderPendingHandshake? restoredResponder;
    V3HandshakeEstablishedMaterial? initiatorEstablished;
    V3HandshakeEstablishedMaterial? responderEstablished;
    try {
      originalInitiator = await V3HybridHandshake.createOffer(
        localIdentity: alice,
        localDevice: aliceDevice,
        remoteIdentity: bob.publicIdentity,
        mode: V3HandshakeMode.normal,
      );
      restoredInitiator = V3HandshakePendingStateCodec.decodeInitiator(
        V3HandshakePendingStateCodec.encodeInitiator(originalInitiator),
      );
      originalInitiator.close();

      originalResponder = await V3HybridHandshake.createReply(
        localIdentity: bob,
        localDevice: bobDevice,
        initiatorIdentity: alice.publicIdentity,
        offer: V3HandshakeCodec.decodeOffer(
          V3HandshakeCodec.encodeOffer(restoredInitiator.offer),
        ),
        expectedMode: V3HandshakeMode.normal,
      );
      restoredResponder = V3HandshakePendingStateCodec.decodeResponder(
        V3HandshakePendingStateCodec.encodeResponder(originalResponder),
      );
      originalResponder.close();

      final initiator = await V3HybridHandshake.acceptReply(
        pending: restoredInitiator,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: V3HandshakeCodec.decodeReply(
          V3HandshakeCodec.encodeReply(restoredResponder.reply),
        ),
      );
      initiatorEstablished = initiator.established;
      responderEstablished = await V3HybridHandshake.acceptConfirmation(
        pending: restoredResponder,
        initiatorIdentity: alice.publicIdentity,
        responderIdentity: bob.publicIdentity,
        confirmation: V3HandshakeCodec.decodeConfirmation(
          V3HandshakeCodec.encodeConfirmation(initiator.confirmation),
        ),
      );

      expect(
        initiatorEstablished.sessionKeys.sessionId,
        orderedEquals(responderEstablished.sessionKeys.sessionId),
      );
      expect(
        initiatorEstablished.sessionKeys.transcriptDigest,
        orderedEquals(responderEstablished.sessionKeys.transcriptDigest),
      );
      expect(
        initiatorEstablished.sessionKeys.ecRatchetRootKey,
        orderedEquals(responderEstablished.sessionKeys.ecRatchetRootKey),
      );
      expect(
        initiatorEstablished.sessionKeys.pqRatchetRootKey,
        orderedEquals(responderEstablished.sessionKeys.pqRatchetRootKey),
      );
    } finally {
      originalInitiator?.close();
      restoredInitiator?.close();
      originalResponder?.close();
      restoredResponder?.close();
      initiatorEstablished?.close();
      responderEstablished?.close();
      aliceDevice.close();
      bobDevice.close();
      await alice.close();
      await bob.close();
    }
  });

  testWidgets('inactive LMF v3 framing traverses the packaged platform',
      (tester) async {
    final key = SecretKeyData(_rangeBytes(32, 0));
    final metadata = V3LmfMessageMetadata(
      kind: V3LmfFrameKind.handshake,
      senderBinding: _rangeBytes(V3LmfFrameCodec.routingBindingBytes, 1),
      recipientBinding: _rangeBytes(V3LmfFrameCodec.routingBindingBytes, 0x41),
      messageId: _rangeBytes(V3LmfFrameCodec.messageIdBytes, 0x81),
      sessionId: _rangeBytes(V3LmfFrameCodec.sessionIdBytes, 0xa1),
      epoch: 7,
      messageCounter: 9,
      expiresAtUnixSeconds: 2000000000,
    );
    final golden = await V3LmfAead.sealSingle(
      metadata: metadata,
      plaintext: Uint8List.fromList('Layergram v3 golden frame'.codeUnits),
      secretKey: key,
      nonce: _rangeBytes(V3LmfFrameCodec.nonceBytes, 0xa0),
    );
    final goldenBytes = V3LmfFrameCodec.encodeBinary(golden);

    expect(
      _toHex(goldenBytes),
      '4c4d3303010100b400190102030405060708090a0b0c0d0e0f10111213141516'
      '1718191a1b1c1d1e1f204142434445464748494a4b4c4d4e4f50515253545556'
      '5758595a5b5c5d5e5f608182838485868788898a8b8c8d8e8f90a1a2a3a4a5'
      'a6a7a8a9aaabacadaeafb0000000000000000700000000000000097735940000'
      '00000100000019a0a1a2a3a4a5a6a7a8a9aaab000000000000000000000000'
      '00000000000000000000000000000000000000000000aa79054837ac70de0f45f1e0'
      '271dafb214c93730f4c52301f9cd648176ad87cc84dc532cbecb164569',
    );
    final token = V3LmfFrameCodec.encodeToken(golden);
    final link = V3LmfFrameCodec.encodeLink(golden);
    final cover = 'A' * StegoEncoder.minCoverLengthForBytes(goldenBytes.length);
    final stego = V3LmfFrameCodec.encodeStego(
      frame: golden,
      coverText: cover,
      maxTotalCharacters: V3LmfFrameCodec.portableShareCharacterLimit,
    );
    expect(
      V3LmfFrameCodec.encodeBinary(V3LmfFrameCodec.decodeToken(token)),
      orderedEquals(goldenBytes),
    );
    expect(
      V3LmfFrameCodec.encodeBinary(V3LmfFrameCodec.decodeLink(link)),
      orderedEquals(goldenBytes),
    );
    expect(
      V3LmfFrameCodec.encodeBinary(V3LmfFrameCodec.decodeStego(stego)),
      orderedEquals(goldenBytes),
    );

    final plaintext = _rangeBytes(MlKem768.ciphertextBytes, 0x31);
    final frames = await V3LmfAead.sealFragmented(
      metadata: metadata,
      plaintext: plaintext,
      secretKey: key,
      nonceForFragment: (index) =>
          _rangeBytes(V3LmfFrameCodec.nonceBytes, 0x30 + index),
    );
    expect(frames, hasLength(5));
    final reassembler = V3LmfReassembler();
    V3LmfReassemblyOutcome? completed;
    for (final index in <int>[4, 1, 3, 0, 2]) {
      final outcome = await reassembler.accept(
        frame: frames[index],
        secretKey: key,
      );
      if (outcome.isComplete) completed = outcome;
    }
    expect(completed?.plaintext, orderedEquals(plaintext));
    expect(reassembler.pendingAssemblyCount, 0);
    reassembler.close();
  });

  testWidgets('inactive v3 schedule and state codecs traverse packaged Dart',
      (tester) async {
    final session = await V3KeySchedule.deriveSession(
      classicalHandshakeSecret: _rangeBytes(32, 0),
      postQuantumHandshakeSecret: _rangeBytes(32, 0x20),
      transcriptDigest: _rangeBytes(48, 0x40),
    );
    final message = await V3KeySchedule.deriveMessage(
      ecMessageKey: _rangeBytes(32, 0x80),
      pqMessageKey: _rangeBytes(32, 0xa0),
      sessionId: session.sessionId,
      direction: V3TrafficDirection.initiatorToResponder,
      kind: V3LmfFrameKind.application,
      epoch: 7,
      messageCounter: 9,
    );
    final bindings = session.bindingsFor(
      V3TrafficDirection.initiatorToResponder,
    );
    final plaintext = Uint8List.fromList('packaged hybrid schedule'.codeUnits);
    final metadata = V3LmfMessageMetadata(
      kind: V3LmfFrameKind.application,
      senderBinding: bindings.senderBinding,
      recipientBinding: bindings.recipientBinding,
      messageId: message.messageId,
      sessionId: session.sessionId,
      epoch: 7,
      messageCounter: 9,
    );
    final hybridHeader = _hybridHeader();
    final hybridHeaderLength =
        V3HybridRatchetHeaderCodec.encode(hybridHeader).length;
    final hybridHeaderDigest =
        V3LmfFrameCodec.digestHybridRatchetHeader(hybridHeader);
    final nonce = await message.nonceForFragment(
      fragmentIndex: 0,
      fragmentCount: 1,
      assembledPlaintextLength: plaintext.length,
      hybridRatchetHeaderLength: hybridHeaderLength,
      hybridRatchetHeaderDigest: hybridHeaderDigest,
    );
    final frame = await V3LmfAead.sealSingle(
      metadata: metadata,
      plaintext: plaintext,
      secretKey: message.secretKey,
      nonce: nonce,
      hybridRatchetHeader: hybridHeader,
    );
    final application = V3CommittedRecord.fromDelivery(
      targetFrame: frame,
      content: plaintext,
    );
    final ratchet = V3TripleRatchetState(
      role: V3SessionRole.initiator,
      lifecycle: V3RatchetLifecycle.active,
      revision: 1,
      sessionId: session.sessionId,
      transcriptDigest: session.transcriptDigest,
      initiatorRoutingBinding: session.initiatorRoutingBinding,
      responderRoutingBinding: session.responderRoutingBinding,
      initiatorToResponderAckRootKey: session.initiatorToResponderAckRootKey,
      responderToInitiatorAckRootKey: session.responderToInitiatorAckRootKey,
      ecRootKey: session.ecRatchetRootKey,
      ecSendingChainKey: _rangeBytes(32, 0x11),
      ecReceivingChainKey: _rangeBytes(32, 0x31),
      ecLocalDhPrivateKey: _rangeBytes(32, 0x51),
      ecLocalDhPublicKey: _rangeBytes(32, 0x11),
      ecRemoteDhPublicKey: _rangeBytes(32, 0x31),
      ecSendCounter: 0,
      ecReceiveCounter: 0,
      ecPreviousSendingChainLength: 0,
      pqRootKey: session.pqRatchetRootKey,
      sckaStateSealKey: session.sckaStateSealKey,
      pqCurrentEpoch: 0,
      pqSendingEpoch: 0,
      pqReceivingEpoch: 0,
      pqEpochStates: <V3PqEpochState>[
        V3PqEpochState(
          epoch: 0,
          sendingChainKey: _rangeBytes(32, 0xb1),
          receivingChainKey: _rangeBytes(32, 0xd1),
        ),
      ],
      nativeSckaState: _rangeBytes(128, 0x21),
    );
    final encodedApplication = V3CommittedRecordCodec.encode(application);
    final encodedRatchet = V3TripleRatchetStateCodec.encode(ratchet);
    final decodedApplication =
        V3CommittedRecordCodec.decode(encodedApplication);
    final decodedRatchet = V3TripleRatchetStateCodec.decode(encodedRatchet);
    expect(decodedApplication.content, plaintext);
    expect(decodedApplication.assemblyId, V3LmfFrameCodec.assemblyId(frame));
    expect(decodedRatchet.sessionId, session.sessionId);
    expect(_toHex(message.messageId), '044aaf313888fab0f9caa64f00a93eb5');

    decodedApplication.wipeContent();
    decodedRatchet.wipeSecrets();
    application.wipeContent();
    ratchet.wipeSecrets();
    message.close();
    session.close();
  });

  testWidgets('inactive durable LMF v3 state survives a packaged restart',
      (tester) async {
    final key = SecretKeyData(_rangeBytes(32, 0x11));
    final metadata = V3LmfMessageMetadata(
      kind: V3LmfFrameKind.application,
      senderBinding: _rangeBytes(V3LmfFrameCodec.routingBindingBytes, 1),
      recipientBinding: _rangeBytes(V3LmfFrameCodec.routingBindingBytes, 0x41),
      messageId: _rangeBytes(V3LmfFrameCodec.messageIdBytes, 0x81),
      sessionId: _rangeBytes(V3LmfFrameCodec.sessionIdBytes, 0xa1),
      epoch: 7,
      messageCounter: 9,
    );
    final plaintext = _rangeBytes(600, 0x31);
    final frames = await V3LmfAead.sealFragmented(
      metadata: metadata,
      plaintext: plaintext,
      secretKey: key,
      nonceForFragment: (index) =>
          _rangeBytes(V3LmfFrameCodec.nonceBytes, 0x51 + index),
      hybridRatchetHeader: _hybridHeader(),
    );

    final inboxStore = _PackagingRecordStore();
    final firstInbox = V3LmfDurableInbox(store: inboxStore);
    await firstInbox.restore(keyResolver: (_) => key);
    await firstInbox.receive(frame: frames.last, secretKey: key);
    await firstInbox.receive(frame: frames.first, secretKey: key);
    await firstInbox.close();

    final restoredInbox = V3LmfDurableInbox(store: inboxStore);
    final restoredState =
        await restoredInbox.restore(keyResolver: (_) async => key);
    expect(restoredState.deliveries, isEmpty);
    final complete = await restoredInbox.receive(
      frame: frames[1],
      secretKey: key,
    );
    expect(complete.delivery!.plaintext, orderedEquals(plaintext));
    final firstJournal = V3LmfAtomicCommitJournal(
      store: inboxStore,
      inbox: restoredInbox,
    );
    await firstJournal.restore();
    final committedEffect = await firstJournal.commit(
      delivery: complete.delivery!,
      builder: (_) => V3LmfAtomicEffect(
        applicationState: _rangeBytes(96, 0x91),
        ratchetState: _rangeBytes(192, 0xc1),
      ),
    );
    expect(
      restoredInbox.committedHigherLevelBindings[complete.delivery!.assemblyId],
      committedEffect.effectDigest,
    );
    await firstJournal.close();
    await restoredInbox.close();

    final afterCommitInbox = V3LmfDurableInbox(store: inboxStore);
    final afterCommitState =
        await afterCommitInbox.restore(keyResolver: (_) => key);
    expect(afterCommitState.deliveries, isEmpty);
    final restoredJournal = V3LmfAtomicCommitJournal(
      store: inboxStore,
      inbox: afterCommitInbox,
    );
    final restoredEffects = await restoredJournal.restore();
    expect(restoredEffects.effects, hasLength(1));
    expect(
      restoredEffects.effects.single.applicationState,
      orderedEquals(_rangeBytes(96, 0x91)),
    );
    expect(
      restoredEffects.effects.single.ratchetState,
      orderedEquals(_rangeBytes(192, 0xc1)),
    );
    expect(
      (await afterCommitInbox.receive(frame: frames.first, secretKey: key))
          .status,
      V3LmfInboxStatus.committedReplay,
    );

    final outboxStore = _PackagingRecordStore();
    final firstOutbox = V3LmfDurableOutbox(store: outboxStore);
    await firstOutbox.restore();
    final queued = await firstOutbox.enqueue(frames);
    await firstOutbox.markExported(
      assemblyId: queued.assemblyId,
      fragmentIndexes: {0, 2},
    );
    await firstOutbox.close();

    final restoredOutbox = V3LmfDurableOutbox(store: outboxStore);
    final outboxState = await restoredOutbox.restore();
    expect(outboxState.entries.single.exportAttempts, [1, 0, 1]);
    for (var index = 0; index < frames.length; index++) {
      expect(
        V3LmfFrameCodec.encodeBinary(
          outboxState.entries.single.frames[index],
        ),
        orderedEquals(V3LmfFrameCodec.encodeBinary(frames[index])),
      );
    }

    final acknowledgement = V3LmfAcknowledgementCodec.forReceivedFrames(frames);
    final ackFrame = await V3LmfAead.sealSingle(
      metadata: V3LmfMessageMetadata(
        kind: V3LmfFrameKind.acknowledgement,
        senderBinding: metadata.recipientBinding,
        recipientBinding: metadata.senderBinding,
        messageId: _rangeBytes(V3LmfFrameCodec.messageIdBytes, 0xc1),
        sessionId: metadata.sessionId,
        epoch: metadata.epoch,
        messageCounter: metadata.messageCounter + 1,
      ),
      plaintext: V3LmfAcknowledgementCodec.encode(acknowledgement),
      secretKey: key,
      nonce: _rangeBytes(V3LmfFrameCodec.nonceBytes, 0xd1),
    );
    expect(
      await restoredOutbox.applyAcknowledgement(
        acknowledgementFrame: ackFrame,
        secretKey: key,
      ),
      V3LmfOutboxAckStatus.complete,
    );
  });

  testWidgets('inactive v3 session controller restores a committed revision',
      (tester) async {
    final transportKey = SecretKeyData(_rangeBytes(32, 0x31));
    final localPair = await X25519().newKeyPairFromSeed(_rangeBytes(32, 0x51));
    final remotePair = await X25519().newKeyPairFromSeed(_rangeBytes(32, 0x91));
    final localPrivate =
        Uint8List.fromList(await localPair.extractPrivateKeyBytes());
    final localPublic =
        Uint8List.fromList((await localPair.extractPublicKey()).bytes);
    final remotePublic =
        Uint8List.fromList((await remotePair.extractPublicKey()).bytes);
    final sessionId = _rangeBytes(V3LmfFrameCodec.sessionIdBytes, 0x11);
    final initiatorBinding =
        _rangeBytes(V3LmfFrameCodec.routingBindingBytes, 0x21);
    final responderBinding =
        _rangeBytes(V3LmfFrameCodec.routingBindingBytes, 0x61);
    final checkpoint = V3TripleRatchetState(
      role: V3SessionRole.initiator,
      lifecycle: V3RatchetLifecycle.active,
      revision: 0,
      sessionId: sessionId,
      transcriptDigest: _rangeBytes(48, 0xa1),
      initiatorRoutingBinding: initiatorBinding,
      responderRoutingBinding: responderBinding,
      initiatorToResponderAckRootKey: _rangeBytes(32, 0x41),
      responderToInitiatorAckRootKey: _rangeBytes(32, 0x81),
      ecRootKey: _rangeBytes(32, 0x12),
      ecSendingChainKey: _rangeBytes(32, 0x32),
      ecReceivingChainKey: _rangeBytes(32, 0x52),
      ecLocalDhPrivateKey: localPrivate,
      ecLocalDhPublicKey: localPublic,
      ecRemoteDhPublicKey: remotePublic,
      ecSendCounter: 0,
      ecReceiveCounter: 0,
      ecPreviousSendingChainLength: 0,
      pqRootKey: _rangeBytes(32, 0x72),
      sckaStateSealKey: _rangeBytes(32, 0x82),
      pqCurrentEpoch: 0,
      pqSendingEpoch: 0,
      pqReceivingEpoch: 0,
      pqEpochStates: <V3PqEpochState>[
        V3PqEpochState(
          epoch: 0,
          sendingChainKey: _rangeBytes(32, 0x92),
          receivingChainKey: _rangeBytes(32, 0xb2),
        ),
      ],
      nativeSckaState: _rangeBytes(128, 0xd2),
    );
    localPrivate.fillRange(0, localPrivate.length, 0);

    final plaintext = _rangeBytes(80, 0x31);
    final frame = await V3LmfAead.sealSingle(
      metadata: V3LmfMessageMetadata(
        kind: V3LmfFrameKind.application,
        senderBinding: responderBinding,
        recipientBinding: initiatorBinding,
        messageId: _rangeBytes(V3LmfFrameCodec.messageIdBytes, 0xc1),
        sessionId: sessionId,
        epoch: 0,
        messageCounter: 0,
      ),
      plaintext: plaintext,
      secretKey: transportKey,
      nonce: _rangeBytes(V3LmfFrameCodec.nonceBytes, 0x71),
      hybridRatchetHeader: V3HybridRatchetHeader(
        ecHeader: V3EcRatchetHeader(
          ratchetPublicKey: remotePublic,
          previousSendingChainLength: 0,
          messageCounter: 0,
        ),
        sckaMessage: V3SckaMessage(
          sendingEpoch: 0,
          messageCounter: 0,
          nativePayload: _rangeBytes(24, 0xe1),
        ),
      ),
    );
    final store = _PackagingRecordStore();
    final inbox = V3LmfDurableInbox(store: store);
    await inbox.restore(keyResolver: (_) => transportKey);
    final received = await inbox.receive(
      frame: frame,
      secretKey: transportKey,
    );
    final controller = V3SessionCommitController(
      journal: V3LmfAtomicCommitJournal(store: store, inbox: inbox),
    );
    await controller.restore(
      checkpoints: <V3TripleRatchetState>[checkpoint],
    );
    expect(
      (await controller.commitDelivery(
        delivery: received.delivery!,
        expectedRevision: 0,
        transitionBuilder: (_, current, __) =>
            _packagedControllerCandidate(current),
      ))
          .ratchetRevision,
      1,
    );
    await controller.close();
    await inbox.close();

    final restoredInbox = V3LmfDurableInbox(store: store);
    final inboxRestore = await restoredInbox.restore(
      keyResolver: (_) => transportKey,
    );
    expect(inboxRestore.deliveries, isEmpty);
    final restoredController = V3SessionCommitController(
      journal: V3LmfAtomicCommitJournal(
        store: store,
        inbox: restoredInbox,
      ),
    );
    final controllerRestore = await restoredController.restore(
      checkpoints: <V3TripleRatchetState>[checkpoint],
    );
    expect(controllerRestore.sessionRevisions.values, <int>[1]);
    final restoredSnapshot = await restoredController.snapshotForSession(
      sessionId,
    );
    expect(restoredSnapshot.revision, 1);
    expect(restoredSnapshot.ecReceiveCounter, 1);

    restoredSnapshot.wipeSecrets();
    await restoredController.close();
    await restoredInbox.close();
    checkpoint.wipeSecrets();
  });
}

String _toHex(Uint8List value) =>
    value.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

Uint8List _rangeBytes(int length, int start) {
  return Uint8List.fromList(
    List<int>.generate(length, (index) => (start + index) & 0xff),
  );
}

V3HybridRatchetHeader _hybridHeader() => V3HybridRatchetHeader(
      ecHeader: V3EcRatchetHeader(
        ratchetPublicKey: _rangeBytes(32, 0x21),
        previousSendingChainLength: 3,
        messageCounter: 5,
      ),
      sckaMessage: V3SckaMessage(
        sendingEpoch: 7,
        messageCounter: 9,
        nativePayload: Uint8List(0),
      ),
    );

V3TripleRatchetState _packagedControllerCandidate(
  V3TripleRatchetState current,
) {
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
    return current.replaceHybridState(
      expectedRevision: current.revision,
      ecRootKey: ecRoot,
      ecSendingChainKey: ecSending,
      ecReceivingChainKey: ecReceiving,
      ecLocalDhPrivateKey: ecPrivate,
      ecLocalDhPublicKey: ecPublic,
      ecRemoteDhPublicKey: ecRemote,
      ecSendCounter: current.ecSendCounter,
      ecReceiveCounter: current.ecReceiveCounter + 1,
      ecPreviousSendingChainLength: current.ecPreviousSendingChainLength,
      ecSkippedMessageKeys: ecSkipped,
      pqRootKey: pqRoot,
      pqCurrentEpoch: current.pqCurrentEpoch,
      pqSendingEpoch: current.pqSendingEpoch,
      pqReceivingEpoch: current.pqReceivingEpoch,
      pqEpochStates: epochs,
      pqSkippedMessageKeys: pqSkipped,
      nativeSckaState: nativeState,
    );
  } finally {
    for (final value in <Uint8List?>[
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

class _PackagingRecordStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> _records =
      <String, Map<String, dynamic>>{};
  var _nextId = 0;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final storageId = 'record-${_nextId++}';
    _records[storageId] = _copyMap(payload);
    return storageId;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async => _records.entries
      .map(
        (entry) => V3LmfStoredRecord(
          storageId: entry.key,
          payload: _copyMap(entry.value),
        ),
      )
      .toList(growable: false);

  @override
  Future<void> delete(String storageId) async {
    _records.remove(storageId);
  }
}

Map<String, dynamic> _copyMap(Map<String, dynamic> value) =>
    (jsonDecode(jsonEncode(value)) as Map).cast<String, dynamic>();
