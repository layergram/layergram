import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';
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
}

String _toHex(Uint8List value) =>
    value.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
