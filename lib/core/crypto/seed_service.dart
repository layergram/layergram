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
  v2('v2', 'hkdf-sha256');

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
  identity('layergram-identity-x25519-v2'),
  passphraseIdentity('layergram-passphrase-identity-x25519-v2');

  const IdentityDerivationPurpose(this.v2Info);

  final String v2Info;
}

class SeedService {
  static const preferredIdentityDerivationVersion = IdentityDerivationVersion.v2;
  static const legacyIdentityDerivationVersion = IdentityDerivationVersion.v1;
  static const derivationSalt = 'layergram';

  static final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

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
    final derived = await _hkdf.deriveKey(
      secretKey: SecretKey(seed),
      nonce: utf8.encode(derivationSalt),
      info: utf8.encode(purpose.v2Info),
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
