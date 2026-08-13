// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:typed_data';

/// FIPS 203 ML-KEM-768 sizes.
///
/// These constants are protocol invariants. Identity and transport codecs must
/// never truncate them to reduce QR, link, or steganographic payload size.
abstract final class MlKem768 {
  static const int publicKeyBytes = 1184;
  static const int privateKeyBytes = 2400;
  static const int ciphertextBytes = 1088;
  static const int sharedSecretBytes = 32;
  static const int keyGenerationSeedBytes = 64;
  static const int encapsulationSeedBytes = 32;
}

/// Opaque ownership boundary for a native ML-KEM-768 decapsulation key.
///
/// Implementations must keep the 2,400-byte private key outside ordinary Dart
/// objects and destroy it when this handle is closed.
abstract interface class MlKem768PrivateKeyHandle {
  bool get isClosed;

  Future<void> close();
}

class MlKem768KeyPair {
  MlKem768KeyPair({
    required Uint8List publicKey,
    required this.privateKeyHandle,
  }) : publicKey = _copyWithLength(
          publicKey,
          MlKem768.publicKeyBytes,
          'publicKey',
        );

  final Uint8List publicKey;
  final MlKem768PrivateKeyHandle privateKeyHandle;
}

class MlKem768Encapsulation {
  MlKem768Encapsulation({
    required Uint8List ciphertext,
    required Uint8List sharedSecret,
  })  : ciphertext = _copyWithLength(
          ciphertext,
          MlKem768.ciphertextBytes,
          'ciphertext',
        ),
        sharedSecret = _copyWithLength(
          sharedSecret,
          MlKem768.sharedSecretBytes,
          'sharedSecret',
        );

  final Uint8List ciphertext;
  final Uint8List sharedSecret;

  void wipeSharedSecret() {
    sharedSecret.fillRange(0, sharedSecret.length, 0);
  }
}

/// Backend contract for the production native ML-KEM-768 implementation.
///
/// No pure-Dart or fallback implementation is supplied intentionally. Protocol
/// v3 must fail closed until a reviewed backend is wired on every release ABI.
abstract interface class MlKem768Backend {
  String get implementationId;

  Future<bool> selfTest();

  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed);

  Future<bool> validatePublicKey(Uint8List publicKey);

  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey);

  Future<Uint8List> decapsulate(
    MlKem768PrivateKeyHandle privateKeyHandle,
    Uint8List ciphertext,
  );
}

Uint8List _copyWithLength(
  Uint8List value,
  int expectedLength,
  String name,
) {
  if (value.length != expectedLength) {
    throw ArgumentError.value(
      value.length,
      '$name.length',
      'must be exactly $expectedLength bytes',
    );
  }
  return Uint8List.fromList(value);
}
