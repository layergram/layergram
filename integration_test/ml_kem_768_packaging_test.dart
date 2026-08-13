import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768_ffi.dart';

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
}
