import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';

void main() {
  test('ML-KEM-768 protocol sizes match FIPS 203', () {
    expect(MlKem768.publicKeyBytes, 1184);
    expect(MlKem768.privateKeyBytes, 2400);
    expect(MlKem768.ciphertextBytes, 1088);
    expect(MlKem768.sharedSecretBytes, 32);
    expect(MlKem768.keyGenerationSeedBytes, 64);
    expect(MlKem768.encapsulationSeedBytes, 32);
  });

  test('value objects reject truncated cryptographic material', () {
    expect(
      () => MlKem768Encapsulation(
        ciphertext: Uint8List(MlKem768.ciphertextBytes - 1),
        sharedSecret: Uint8List(MlKem768.sharedSecretBytes),
      ),
      throwsArgumentError,
    );
    expect(
      () => MlKem768Encapsulation(
        ciphertext: Uint8List(MlKem768.ciphertextBytes),
        sharedSecret: Uint8List(MlKem768.sharedSecretBytes - 1),
      ),
      throwsArgumentError,
    );
  });
}
