import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';
import 'package:layergram/core/crypto/v3/handshake_transport_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';

void main() {
  const aliceMnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const bobMnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';

  late _TransportMlKemBackend backend;
  late V3LocalIdentityHandle alice;
  late V3LocalIdentityHandle bob;
  late V3LocalDeviceHandle aliceDevice;
  late V3LocalDeviceHandle bobDevice;

  setUp(() async {
    backend = _TransportMlKemBackend();
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

  test('offer reply and confirmation round-trip in every carrier mode',
      () async {
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
    final accepted = await V3HybridHandshake.acceptReply(
      pending: offer,
      localIdentity: alice,
      localDevice: aliceDevice,
      responderIdentity: bob.publicIdentity,
      reply: reply.reply,
    );
    final records = <Uint8List>[
      V3HandshakeCodec.encodeOffer(offer.offer),
      V3HandshakeCodec.encodeReply(reply.reply),
      V3HandshakeCodec.encodeConfirmation(accepted.confirmation),
    ];
    try {
      final counts = <int>[];
      for (final record in records) {
        final frames = await V3HandshakeTransport.seal(
          record: record,
          initiatorIdentity: alice.publicIdentity,
          responderIdentity: bob.publicIdentity,
        );
        final repeated = await V3HandshakeTransport.seal(
          record: record,
          initiatorIdentity: alice.publicIdentity,
          responderIdentity: bob.publicIdentity,
        );
        counts.add(frames.length);
        expect(repeated, hasLength(frames.length));
        for (var index = 0; index < frames.length; index++) {
          expect(
            V3LmfFrameCodec.encodeBinary(repeated[index]),
            orderedEquals(V3LmfFrameCodec.encodeBinary(frames[index])),
          );
        }

        final textFrames = V3HandshakeTransport.decodeText(
          V3HandshakeTransport.encodeText(frames),
        );
        final linkFrames = V3HandshakeTransport.decodeLinks(
          V3HandshakeTransport.encodeLinks(frames),
        );
        final covers = frames
            .map(
              (frame) =>
                  'A' *
                  StegoEncoder.minCoverLengthForBytes(
                    V3LmfFrameCodec.encodeBinary(frame).length,
                  ),
            )
            .toList(growable: false);
        final stegoFrames = V3HandshakeTransport.decodeStego(
          V3HandshakeTransport.encodeStego(
            frames: frames,
            coverTexts: covers,
          ),
        );

        for (final decodedFrames in [textFrames, linkFrames, stegoFrames]) {
          final opened = await V3HandshakeTransport.open(
            frames: decodedFrames.reversed,
            initiatorIdentity: alice.publicIdentity,
            responderIdentity: bob.publicIdentity,
          );
          try {
            expect(opened.record, orderedEquals(record));
          } finally {
            opened.close();
          }
        }
      }
      expect(counts, <int>[6, 6, 2]);
    } finally {
      for (final record in records) {
        record.fillRange(0, record.length, 0);
      }
      accepted.established.close();
      reply.close();
    }
  });

  test('wrong identity and modified frame fail closed', () async {
    final offer = await V3HybridHandshake.createOffer(
      localIdentity: alice,
      localDevice: aliceDevice,
      remoteIdentity: bob.publicIdentity,
      mode: V3HandshakeMode.maximum,
    );
    final record = V3HandshakeCodec.encodeOffer(offer.offer);
    try {
      final frames = await V3HandshakeTransport.seal(
        record: record,
        initiatorIdentity: alice.publicIdentity,
        responderIdentity: bob.publicIdentity,
      );
      await expectLater(
        V3HandshakeTransport.open(
          frames: frames,
          initiatorIdentity: bob.publicIdentity,
          responderIdentity: alice.publicIdentity,
        ),
        throwsFormatException,
      );

      final encoded = V3LmfFrameCodec.encodeBinary(frames.first)..last ^= 1;
      final modified = <V3LmfFrame>[
        V3LmfFrameCodec.decodeBinary(encoded),
        ...frames.skip(1),
      ];
      await expectLater(
        V3HandshakeTransport.open(
          frames: modified,
          initiatorIdentity: alice.publicIdentity,
          responderIdentity: bob.publicIdentity,
        ),
        throwsA(anything),
      );
    } finally {
      record.fillRange(0, record.length, 0);
      offer.close();
    }
  });
}

Uint8List _bytes(int length, int seed) {
  return Uint8List.fromList(
    List<int>.generate(length, (index) => (seed + index) & 0xff),
  );
}

final class _TransportPrivateKeyHandle implements MlKem768PrivateKeyHandle {
  _TransportPrivateKeyHandle(this.publicKey);

  final Uint8List publicKey;

  @override
  bool isClosed = false;

  @override
  Future<void> close() async {
    publicKey.fillRange(0, publicKey.length, 0);
    isClosed = true;
  }
}

final class _TransportMlKemBackend implements MlKem768Backend {
  int _encapsulationCounter = 0;

  @override
  String get implementationId => 'handshake-transport-test';

  @override
  Future<bool> selfTest() async => true;

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) async {
    final publicKey = Uint8List.fromList(
      List<int>.generate(
        MlKem768.publicKeyBytes,
        (index) => (seed[index % seed.length] + index) & 0xff,
      ),
    );
    if (publicKey.every((byte) => byte == 0)) publicKey[0] = 1;
    return MlKem768KeyPair(
      publicKey: publicKey,
      privateKeyHandle: _TransportPrivateKeyHandle(
        Uint8List.fromList(publicKey),
      ),
    );
  }

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async {
    return publicKey.length == MlKem768.publicKeyBytes &&
        publicKey.any((byte) => byte != 0);
  }

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) async {
    final counter = _encapsulationCounter++;
    final seed = sha256.convert(<int>[...publicKey, counter]).bytes;
    final ciphertext = Uint8List.fromList(
      List<int>.generate(
        MlKem768.ciphertextBytes,
        (index) => seed[index % seed.length] ^ (index & 0xff),
      ),
    );
    return MlKem768Encapsulation(
      ciphertext: ciphertext,
      sharedSecret: Uint8List.fromList(sha256.convert(ciphertext).bytes),
    );
  }

  @override
  Future<Uint8List> decapsulate(
    MlKem768PrivateKeyHandle privateKeyHandle,
    Uint8List ciphertext,
  ) async {
    if (privateKeyHandle is! _TransportPrivateKeyHandle ||
        privateKeyHandle.isClosed) {
      throw StateError('invalid test ML-KEM handle');
    }
    return Uint8List.fromList(sha256.convert(ciphertext).bytes);
  }
}
