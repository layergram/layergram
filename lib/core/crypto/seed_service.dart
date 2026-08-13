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

import 'dart:convert';
import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

enum IdentityDerivationVersion {
  v1('v1', 'sha256-seed'),
  v2('v2', 'hkdf-sha256'),
  v3('v3', 'hkdf-sha256-hybrid-x25519-ml-kem-768');

  const IdentityDerivationVersion(this.storageValue, this.algorithm);

  final String storageValue;
  final String algorithm;

  static IdentityDerivationVersion fromStorageValue(String? value) {
    for (final candidate in values) {
      if (candidate.storageValue == value) {
        return candidate;
      }
    }
    return IdentityDerivationVersion.v1;
  }
}

enum IdentityDerivationPurpose {
  identity(
    'layergram-identity-x25519-v2',
    'layergram/v3/identity/x25519-seed',
    'layergram/v3/identity/ml-kem-768-keygen-seed',
  ),
  passphraseIdentity(
    'layergram-passphrase-identity-x25519-v2',
    'layergram/v3/passphrase-identity/x25519-seed',
    'layergram/v3/passphrase-identity/ml-kem-768-keygen-seed',
  );

  const IdentityDerivationPurpose(
    this.v2Info,
    this.v3X25519Info,
    this.v3MlKem768Info,
  );

  final String v2Info;
  final String v3X25519Info;
  final String v3MlKem768Info;
}

/// Deterministic v3 seeds derived from one BIP39 seed.
///
/// These values are inputs to the X25519 and ML-KEM-768 key-generation
/// algorithms. They are not public keys and must be treated as secret material.
/// The ML-KEM seed is exactly the 64-byte `d || z` input required by FIPS 203
/// `ML-KEM.KeyGen_Internal`.
class V3IdentityKeySeeds {
  V3IdentityKeySeeds({
    required Uint8List x25519Seed,
    required Uint8List mlKem768KeyGenerationSeed,
  })  : x25519Seed = Uint8List.fromList(x25519Seed),
        mlKem768KeyGenerationSeed =
            Uint8List.fromList(mlKem768KeyGenerationSeed) {
    if (this.x25519Seed.length != 32) {
      throw ArgumentError.value(
        this.x25519Seed.length,
        'x25519Seed.length',
        'must be exactly 32 bytes',
      );
    }
    if (this.mlKem768KeyGenerationSeed.length != 64) {
      throw ArgumentError.value(
        this.mlKem768KeyGenerationSeed.length,
        'mlKem768KeyGenerationSeed.length',
        'must be exactly 64 bytes',
      );
    }
  }

  final Uint8List x25519Seed;
  final Uint8List mlKem768KeyGenerationSeed;

  /// Best-effort overwrite for managed-memory buffers.
  ///
  /// Dart does not guarantee perfect zeroization; production ML-KEM private
  /// material will be held behind native opaque handles instead.
  void wipe() {
    x25519Seed.fillRange(0, x25519Seed.length, 0);
    mlKem768KeyGenerationSeed.fillRange(
      0,
      mlKem768KeyGenerationSeed.length,
      0,
    );
  }
}

class SeedService {
  static const preferredIdentityDerivationVersion =
      IdentityDerivationVersion.v2;
  static const legacyIdentityDerivationVersion = IdentityDerivationVersion.v1;
  static const derivationSalt = 'layergram';
  static const v3DerivationSalt = 'layergram/protocol-v3/identity-derivation';

  static final _hkdf32 = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  static final _hkdf64 = Hkdf(hmac: Hmac.sha256(), outputLength: 64);

  String generateMnemonic({int words = 24}) {
    final strength = words == 24 ? 256 : 128;
    return bip39.generateMnemonic(strength: strength);
  }

  bool validateMnemonic(String mnemonic) {
    return bip39.validateMnemonic(mnemonic.trim());
  }

  Uint8List mnemonicToSeed(String mnemonic) {
    final seedHex = bip39.mnemonicToSeedHex(mnemonic.trim());
    return Uint8List.fromList(_hexToBytes(seedHex));
  }

  Future<Uint8List> deriveIdentityPrivateKey(
    Uint8List seed, {
    IdentityDerivationVersion version = preferredIdentityDerivationVersion,
  }) {
    return derivePrivateKey(
      seed,
      version: version,
      purpose: IdentityDerivationPurpose.identity,
    );
  }

  Future<Uint8List> derivePassphraseIdentityPrivateKey(
    Uint8List seed, {
    IdentityDerivationVersion version = preferredIdentityDerivationVersion,
  }) {
    return derivePrivateKey(
      seed,
      version: version,
      purpose: IdentityDerivationPurpose.passphraseIdentity,
    );
  }

  Future<Uint8List> derivePrivateKey(
    Uint8List seed, {
    required IdentityDerivationVersion version,
    IdentityDerivationPurpose purpose = IdentityDerivationPurpose.identity,
  }) async {
    switch (version) {
      case IdentityDerivationVersion.v1:
        return derivePrivateKeyV1(seed);
      case IdentityDerivationVersion.v2:
        return derivePrivateKeyV2(seed, purpose: purpose);
      case IdentityDerivationVersion.v3:
        throw UnsupportedError(
          'Protocol v3 identities require both X25519 and ML-KEM-768; '
          'use deriveV3IdentityKeySeeds while the v3 runtime is gated',
        );
    }
  }

  Uint8List derivePrivateKeyV1(Uint8List seed) {
    final digest = crypto.sha256.convert(seed).bytes;
    return Uint8List.fromList(digest);
  }

  Future<Uint8List> derivePrivateKeyV2(
    Uint8List seed, {
    IdentityDerivationPurpose purpose = IdentityDerivationPurpose.identity,
  }) async {
    final derived = await _hkdf32.deriveKey(
      secretKey: SecretKey(seed),
      nonce: utf8.encode(derivationSalt),
      info: utf8.encode(purpose.v2Info),
    );
    return Uint8List.fromList(await derived.extractBytes());
  }

  /// Derives only the X25519 seed used by a v3 hybrid identity.
  ///
  /// Runtime identity creation must use [deriveV3IdentityKeySeeds] so that a
  /// partial, classical-only identity can never be mistaken for protocol v3.
  Future<Uint8List> derivePrivateKeyV3(
    Uint8List seed, {
    IdentityDerivationPurpose purpose = IdentityDerivationPurpose.identity,
  }) {
    return _deriveV3(
      seed,
      outputLength: 32,
      info: purpose.v3X25519Info,
    );
  }

  /// Derives the full 64-byte ML-KEM-768 key-generation seed (`d || z`).
  ///
  /// No part of this value may be truncated to make a QR or link smaller.
  Future<Uint8List> deriveMlKem768KeyGenerationSeedV3(
    Uint8List seed, {
    IdentityDerivationPurpose purpose = IdentityDerivationPurpose.identity,
  }) {
    return _deriveV3(
      seed,
      outputLength: 64,
      info: purpose.v3MlKem768Info,
    );
  }

  Future<V3IdentityKeySeeds> deriveV3IdentityKeySeeds(
    Uint8List seed, {
    IdentityDerivationPurpose purpose = IdentityDerivationPurpose.identity,
  }) async {
    final x25519Seed = await derivePrivateKeyV3(seed, purpose: purpose);
    final mlKemSeed = await deriveMlKem768KeyGenerationSeedV3(
      seed,
      purpose: purpose,
    );
    return V3IdentityKeySeeds(
      x25519Seed: x25519Seed,
      mlKem768KeyGenerationSeed: mlKemSeed,
    );
  }

  Future<Uint8List> _deriveV3(
    Uint8List seed, {
    required int outputLength,
    required String info,
  }) async {
    final hkdf = outputLength == 32 ? _hkdf32 : _hkdf64;
    final derived = await hkdf.deriveKey(
      secretKey: SecretKey(seed),
      nonce: utf8.encode(v3DerivationSalt),
      info: utf8.encode(info),
    );
    return Uint8List.fromList(await derived.extractBytes());
  }

  List<int> _hexToBytes(String hex) {
    final out = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      out.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return out;
  }
}
