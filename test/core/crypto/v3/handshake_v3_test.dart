import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';

void main() {
  const aliceMnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const bobMnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';

  late _HandshakeMlKemBackend backend;
  late V3LocalIdentityHandle alice;
  late V3LocalIdentityHandle bob;
  late V3LocalDeviceHandle aliceDevice;
  late V3LocalDeviceHandle bobDevice;

  setUp(() async {
    backend = _HandshakeMlKemBackend();
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

  test('mutually authenticates both EC and ML-KEM branches', () async {
    final offerState = await V3HybridHandshake.createOffer(
      localIdentity: alice,
      localDevice: aliceDevice,
      remoteIdentity: bob.publicIdentity,
      mode: V3HandshakeMode.normal,
    );
    final offer = V3HandshakeCodec.decodeOffer(
      V3HandshakeCodec.encodeOffer(offerState.offer),
    );
    final replyState = await V3HybridHandshake.createReply(
      localIdentity: bob,
      localDevice: bobDevice,
      initiatorIdentity: alice.publicIdentity,
      offer: offer,
      expectedMode: V3HandshakeMode.normal,
    );
    final reply = V3HandshakeCodec.decodeReply(
      V3HandshakeCodec.encodeReply(replyState.reply),
    );
    final initiatorResult = await V3HybridHandshake.acceptReply(
      pending: offerState,
      localIdentity: alice,
      localDevice: aliceDevice,
      responderIdentity: bob.publicIdentity,
      reply: reply,
    );
    final confirmation = V3HandshakeCodec.decodeConfirmation(
      V3HandshakeCodec.encodeConfirmation(initiatorResult.confirmation),
    );
    final responderResult = await V3HybridHandshake.acceptConfirmation(
      pending: replyState,
      initiatorIdentity: alice.publicIdentity,
      responderIdentity: bob.publicIdentity,
      confirmation: confirmation,
    );

    expect(offerState.isClosed, isTrue);
    expect(replyState.isClosed, isTrue);
    expect(
      initiatorResult.established.sessionKeys.sessionId,
      orderedEquals(responderResult.sessionKeys.sessionId),
    );
    expect(
      initiatorResult.established.sessionKeys.transcriptDigest,
      orderedEquals(responderResult.sessionKeys.transcriptDigest),
    );
    expect(
      initiatorResult.established.sessionKeys.ecRatchetRootKey,
      orderedEquals(responderResult.sessionKeys.ecRatchetRootKey),
    );
    expect(
      initiatorResult.established.sessionKeys.pqRatchetRootKey,
      orderedEquals(responderResult.sessionKeys.pqRatchetRootKey),
    );
    expect(
      initiatorResult.established.remoteDeviceId,
      orderedEquals(bobDevice.deviceId),
    );
    expect(
      responderResult.remoteDeviceId,
      orderedEquals(aliceDevice.deviceId),
    );
    expect(
      initiatorResult.established.remoteInitialRatchetPublicKey,
      orderedEquals(responderResult.localInitialRatchetPublicKey),
    );
    expect(
      responderResult.remoteInitialRatchetPublicKey,
      orderedEquals(
        initiatorResult.established.localInitialRatchetPublicKey,
      ),
    );

    initiatorResult.established.close();
    responderResult.close();
  });

  test('pending states survive canonical encrypted-record restart', () async {
    final originalInitiator = await V3HybridHandshake.createOffer(
      localIdentity: alice,
      localDevice: aliceDevice,
      remoteIdentity: bob.publicIdentity,
      mode: V3HandshakeMode.maximum,
    );
    final initiatorRecord =
        V3HandshakePendingStateCodec.encodeInitiator(originalInitiator);
    final restoredInitiator =
        V3HandshakePendingStateCodec.decodeInitiator(initiatorRecord);
    originalInitiator.close();

    final originalResponder = await V3HybridHandshake.createReply(
      localIdentity: bob,
      localDevice: bobDevice,
      initiatorIdentity: alice.publicIdentity,
      offer: restoredInitiator.offer,
      expectedMode: V3HandshakeMode.maximum,
    );
    final responderRecord =
        V3HandshakePendingStateCodec.encodeResponder(originalResponder);
    final restoredResponder =
        V3HandshakePendingStateCodec.decodeResponder(responderRecord);
    originalResponder.close();

    final initiatorResult = await V3HybridHandshake.acceptReply(
      pending: restoredInitiator,
      localIdentity: alice,
      localDevice: aliceDevice,
      responderIdentity: bob.publicIdentity,
      reply: restoredResponder.reply,
    );
    final responderResult = await V3HybridHandshake.acceptConfirmation(
      pending: restoredResponder,
      initiatorIdentity: alice.publicIdentity,
      responderIdentity: bob.publicIdentity,
      confirmation: initiatorResult.confirmation,
    );

    expect(initiatorResult.established.mode, V3HandshakeMode.maximum);
    expect(responderResult.mode, V3HandshakeMode.maximum);
    expect(
      initiatorResult.established.sessionKeys.sessionId,
      orderedEquals(responderResult.sessionKeys.sessionId),
    );
    initiatorResult.established.close();
    responderResult.close();
  });

  test('responder proof tamper fails before session material exists', () async {
    final offerState = await V3HybridHandshake.createOffer(
      localIdentity: alice,
      localDevice: aliceDevice,
      remoteIdentity: bob.publicIdentity,
      mode: V3HandshakeMode.normal,
    );
    final replyState = await V3HybridHandshake.createReply(
      localIdentity: bob,
      localDevice: bobDevice,
      initiatorIdentity: alice.publicIdentity,
      offer: offerState.offer,
      expectedMode: V3HandshakeMode.normal,
    );
    final tampered = V3HandshakeCodec.encodeReply(replyState.reply)
      ..[V3HandshakeCodec.replyBytes - 1] ^= 1;
    final parsed = V3HandshakeCodec.decodeReply(tampered);

    await expectLater(
      V3HybridHandshake.acceptReply(
        pending: offerState,
        localIdentity: alice,
        localDevice: aliceDevice,
        responderIdentity: bob.publicIdentity,
        reply: parsed,
      ),
      throwsFormatException,
    );
    expect(offerState.isClosed, isFalse);
    offerState.close();
    replyState.close();
  });

  test('initiator proof tamper is rejected without consuming responder state',
      () async {
    final offerState = await V3HybridHandshake.createOffer(
      localIdentity: alice,
      localDevice: aliceDevice,
      remoteIdentity: bob.publicIdentity,
      mode: V3HandshakeMode.normal,
    );
    final replyState = await V3HybridHandshake.createReply(
      localIdentity: bob,
      localDevice: bobDevice,
      initiatorIdentity: alice.publicIdentity,
      offer: offerState.offer,
      expectedMode: V3HandshakeMode.normal,
    );
    final initiatorResult = await V3HybridHandshake.acceptReply(
      pending: offerState,
      localIdentity: alice,
      localDevice: aliceDevice,
      responderIdentity: bob.publicIdentity,
      reply: replyState.reply,
    );
    final tampered =
        V3HandshakeCodec.encodeConfirmation(initiatorResult.confirmation)
          ..[V3HandshakeCodec.confirmationBytes - 1] ^= 1;
    final parsed = V3HandshakeCodec.decodeConfirmation(tampered);

    await expectLater(
      V3HybridHandshake.acceptConfirmation(
        pending: replyState,
        initiatorIdentity: alice.publicIdentity,
        responderIdentity: bob.publicIdentity,
        confirmation: parsed,
      ),
      throwsFormatException,
    );
    expect(replyState.isClosed, isFalse);
    replyState.close();
    initiatorResult.established.close();
  });

  test('mode, identity, device, and ciphertext changes fail closed', () async {
    final offerState = await V3HybridHandshake.createOffer(
      localIdentity: alice,
      localDevice: aliceDevice,
      remoteIdentity: bob.publicIdentity,
      mode: V3HandshakeMode.normal,
    );
    final encoded = V3HandshakeCodec.encodeOffer(offerState.offer);

    expect(
      () => V3HandshakeCodec.decodeOffer(Uint8List.fromList(encoded)..[7] = 2),
      throwsFormatException,
    );
    expect(
      () => V3HandshakeCodec.decodeOffer(
        Uint8List.fromList(encoded)..[V3HandshakeCodec.offerBytes - 1] ^= 1,
      ),
      throwsFormatException,
    );
    await expectLater(
      V3HybridHandshake.createReply(
        localIdentity: alice,
        localDevice: aliceDevice,
        initiatorIdentity: bob.publicIdentity,
        offer: offerState.offer,
        expectedMode: V3HandshakeMode.normal,
      ),
      throwsFormatException,
    );
    await expectLater(
      V3HybridHandshake.createReply(
        localIdentity: bob,
        localDevice: bobDevice,
        initiatorIdentity: alice.publicIdentity,
        offer: offerState.offer,
        expectedMode: V3HandshakeMode.maximum,
      ),
      throwsFormatException,
    );
    offerState.close();
  });

  test('simultaneous offers resolve identically without arrival-order trust',
      () async {
    final aliceOffer = await V3HybridHandshake.createOffer(
      localIdentity: alice,
      localDevice: aliceDevice,
      remoteIdentity: bob.publicIdentity,
      mode: V3HandshakeMode.normal,
    );
    final bobOffer = await V3HybridHandshake.createOffer(
      localIdentity: bob,
      localDevice: bobDevice,
      remoteIdentity: alice.publicIdentity,
      mode: V3HandshakeMode.normal,
    );

    final firstDecision = V3HybridHandshake.resolveSimultaneousOffers(
      aliceOffer.offer,
      bobOffer.offer,
    );
    final secondDecision = V3HybridHandshake.resolveSimultaneousOffers(
      bobOffer.offer,
      aliceOffer.offer,
    );
    expect(
      V3HandshakeCodec.encodeOffer(firstDecision),
      orderedEquals(V3HandshakeCodec.encodeOffer(secondDecision)),
    );

    aliceOffer.close();
    bobOffer.close();
  });

  test('pending state rejects truncation, corruption, and role confusion',
      () async {
    final state = await V3HybridHandshake.createOffer(
      localIdentity: alice,
      localDevice: aliceDevice,
      remoteIdentity: bob.publicIdentity,
      mode: V3HandshakeMode.normal,
    );
    final encoded = V3HandshakePendingStateCodec.encodeInitiator(state);

    expect(
      () => V3HandshakePendingStateCodec.decodeInitiator(
        Uint8List.fromList(encoded)..[encoded.length - 1] ^= 1,
      ),
      throwsFormatException,
    );
    expect(
      () => V3HandshakePendingStateCodec.decodeInitiator(
        Uint8List.sublistView(encoded, 0, encoded.length - 1),
      ),
      throwsFormatException,
    );
    expect(
      () => V3HandshakePendingStateCodec.decodeResponder(encoded),
      throwsFormatException,
    );
    state.close();
  });

  test('all three logical records stay under portable text/link target',
      () async {
    final offerState = await V3HybridHandshake.createOffer(
      localIdentity: alice,
      localDevice: aliceDevice,
      remoteIdentity: bob.publicIdentity,
      mode: V3HandshakeMode.normal,
    );
    final replyState = await V3HybridHandshake.createReply(
      localIdentity: bob,
      localDevice: bobDevice,
      initiatorIdentity: alice.publicIdentity,
      offer: offerState.offer,
      expectedMode: V3HandshakeMode.normal,
    );
    final initiator = await V3HybridHandshake.acceptReply(
      pending: offerState,
      localIdentity: alice,
      localDevice: aliceDevice,
      responderIdentity: bob.publicIdentity,
      reply: replyState.reply,
    );
    final records = <(Uint8List, Uint8List)>[
      (
        V3HandshakeCodec.encodeOffer(replyState.offer),
        replyState.offer.messageId,
      ),
      (
        V3HandshakeCodec.encodeReply(replyState.reply),
        replyState.reply.messageId,
      ),
      (
        V3HandshakeCodec.encodeConfirmation(initiator.confirmation),
        initiator.confirmation.messageId,
      ),
    ];
    final key = SecretKeyData(_bytes(32, 0x31));
    final fragmentCounts = <int>[];
    for (var recordIndex = 0; recordIndex < records.length; recordIndex++) {
      final record = records[recordIndex];
      final frames = await V3LmfAead.sealFragmented(
        metadata: V3LmfMessageMetadata(
          kind: V3LmfFrameKind.handshake,
          senderBinding: _bytes(32, 0x01),
          recipientBinding: _bytes(32, 0x41),
          messageId: record.$2,
          sessionId: replyState.offer.handshakeId,
          epoch: 0,
          messageCounter: recordIndex,
        ),
        plaintext: record.$1,
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(12, 0x80 + recordIndex * 16 + index),
      );
      fragmentCounts.add(frames.length);
      final tokenExport = frames.map(V3LmfFrameCodec.encodeToken).join('\n');
      final linkExport = frames.map(V3LmfFrameCodec.encodeLink).join('\n');
      expect(
        tokenExport.length,
        lessThanOrEqualTo(V3LmfFrameCodec.portableShareCharacterLimit),
      );
      expect(
        linkExport.length,
        lessThanOrEqualTo(V3LmfFrameCodec.portableShareCharacterLimit),
      );
    }
    expect(fragmentCounts, <int>[6, 6, 2]);

    replyState.close();
    initiator.established.close();
  });

  test('offer codec has a frozen independently-built vector', () {
    final encoded = _independentOfferVector();
    final decoded = V3HandshakeCodec.decodeOffer(encoded);

    expect(V3HandshakeCodec.encodeOffer(decoded), orderedEquals(encoded));
    expect(
      sha256.convert(encoded).toString(),
      '556b4b5c3f44ef12532d4b4860617d67ca368413012bc490cad2865f8a4d9f79',
    );
  });
}

Uint8List _independentOfferVector() {
  final mode = V3HandshakeMode.normal.wireId;
  const capabilities = V3HandshakeCodec.requiredCapabilities;
  final initiatorIdentityDigest = _bytes(48, 0x01);
  final responderIdentityDigest = _bytes(48, 0x41);
  final devicePublic = _bytes(32, 0x81);
  final ephemeralPublic = _bytes(32, 0xa1);
  final ciphertext = _bytes(MlKem768.ciphertextBytes, 0xc1);
  final deviceId = _hashPrefix(
    <List<int>>[
      'layergram/v3/device/id\x00'.codeUnits,
      devicePublic,
    ],
    16,
  );
  final handshakeId = _hashPrefix(
    <List<int>>[
      'layergram/v3/handshake/id\x00'.codeUnits,
      <int>[mode],
      _u32Test(capabilities),
      initiatorIdentityDigest,
      responderIdentityDigest,
      deviceId,
      devicePublic,
      ephemeralPublic,
      ciphertext,
    ],
    16,
  );
  final messageId = _hashPrefix(
    <List<int>>[
      'layergram/v3/handshake/offer-message-id\x00'.codeUnits,
      handshakeId,
      ephemeralPublic,
      ciphertext,
    ],
    16,
  );
  final output = Uint8List(V3HandshakeCodec.offerBytes);
  output.setRange(0, 3, V3HandshakeCodec.magic);
  output[3] = V3HandshakeCodec.formatVersion;
  output[4] = 3;
  output[5] = 1;
  output[6] = V3HandshakeRecordKind.offer.wireId;
  output[7] = mode;
  final data = ByteData.sublistView(output)
    ..setUint16(10, V3HandshakeCodec.commonHeaderBytes, Endian.big)
    ..setUint32(12, V3HandshakeCodec.offerBytes, Endian.big)
    ..setUint32(16, capabilities, Endian.big);
  var offset = 20;
  for (final field in <Uint8List>[
    handshakeId,
    messageId,
    initiatorIdentityDigest,
    responderIdentityDigest,
    deviceId,
    devicePublic,
    ephemeralPublic,
    ciphertext,
  ]) {
    output.setRange(offset, offset + field.length, field);
    offset += field.length;
  }
  expect(data.lengthInBytes, output.length);
  expect(offset, output.length);
  return output;
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

Uint8List _hashPrefix(List<List<int>> chunks, int length) => Uint8List.fromList(
      sha256
          .convert(chunks.expand((chunk) => chunk).toList(growable: false))
          .bytes
          .take(length)
          .toList(growable: false),
    );

Uint8List _u32Test(int value) {
  final result = Uint8List(4);
  ByteData.sublistView(result).setUint32(0, value, Endian.big);
  return result;
}

final class _HandshakeMlKemPrivateKeyHandle
    implements MlKem768PrivateKeyHandle {
  _HandshakeMlKemPrivateKeyHandle(this.publicKey);

  final Uint8List publicKey;

  @override
  bool isClosed = false;

  @override
  Future<void> close() async {
    isClosed = true;
  }
}

final class _HandshakeMlKemBackend implements MlKem768Backend {
  var _encapsulationCounter = 0;

  @override
  String get implementationId => 'test-only-handshake-ml-kem';

  @override
  Future<bool> selfTest() async => true;

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) async {
    final digest = sha512.convert(seed).bytes;
    final publicKey = Uint8List.fromList(
      List<int>.generate(
        MlKem768.publicKeyBytes,
        (index) => digest[index % digest.length],
      ),
    );
    return MlKem768KeyPair(
      publicKey: publicKey,
      privateKeyHandle: _HandshakeMlKemPrivateKeyHandle(publicKey),
    );
  }

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async =>
      publicKey.length == MlKem768.publicKeyBytes &&
      publicKey.any((byte) => byte != 0);

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) async {
    _encapsulationCounter++;
    final counter = _u32Test(_encapsulationCounter);
    final block = sha512.convert(<int>[...publicKey, ...counter]).bytes;
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
    final handle = privateKeyHandle as _HandshakeMlKemPrivateKeyHandle;
    if (handle.isClosed || ciphertext.length != MlKem768.ciphertextBytes) {
      throw StateError('invalid test ML-KEM handle or ciphertext');
    }
    return _sharedSecret(handle.publicKey, ciphertext);
  }

  Uint8List _sharedSecret(Uint8List publicKey, Uint8List ciphertext) =>
      Uint8List.fromList(
        sha256.convert(<int>[
          ...'test-only-handshake-shared\x00'.codeUnits,
          ...publicKey,
          ...ciphertext,
        ]).bytes,
      );
}
