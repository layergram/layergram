import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768_ffi.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3_validator.dart';

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
      '4c4d33030101008e00190102030405060708090a0b0c0d0e0f10111213141516'
      '1718191a1b1c1d1e1f204142434445464748494a4b4c4d4e4f50515253545556'
      '5758595a5b5c5d5e5f608182838485868788898a8b8c8d8e8f90a1a2a3a4a5'
      'a6a7a8a9aaabacadaeafb0000000070000000000000009773594000000000100'
      '000019a0a1a2a3a4a5a6a7a8a9aaabaa79054837ac70de0f45f1e0271dafb21'
      '4c93730f4c52301f987ccf30812a75a51aea46274d3f1ac72',
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
}

String _toHex(Uint8List value) =>
    value.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

Uint8List _rangeBytes(int length, int start) {
  return Uint8List.fromList(
    List<int>.generate(length, (index) => (start + index) & 0xff),
  );
}
