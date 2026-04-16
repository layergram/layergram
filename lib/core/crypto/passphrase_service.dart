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
import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'seed_service.dart';

/// Ephemeral passphrase-derived key state.
///
/// Keys are held **in memory only** and are destroyed when the app is killed
/// or the user explicitly deactivates the passphrase.  Backgrounding the app
/// does NOT destroy them.
class PassphraseState {
  const PassphraseState._({
    required this.isActive,
    this.privateKeyBase64,
    this.publicKeyBase64,
    this.keyTag,
    this.derivationVersion,
    this.derivationAlgorithm,
  });

  const PassphraseState.inactive()
      : isActive = false,
        privateKeyBase64 = null,
        publicKeyBase64 = null,
        keyTag = null,
        derivationVersion = null,
        derivationAlgorithm = null;

  final bool isActive;
  final String? privateKeyBase64;
  final String? publicKeyBase64;

  /// Short opaque tag derived from the active public key.
  /// Used to efficiently filter messages without attempting decryption.
  /// `null` when passphrase is inactive.
  final String? keyTag;

  final IdentityDerivationVersion? derivationVersion;
  final String? derivationAlgorithm;
}

class PassphraseNotifier extends StateNotifier<PassphraseState> {
  PassphraseNotifier({required SeedService seedService})
      : _seedService = seedService,
        super(const PassphraseState.inactive());

  final SeedService _seedService;
  static final _x25519 = X25519();

  Future<void> activate(
    String mnemonic,
    String passphrase, {
    IdentityDerivationVersion derivationVersion =
        SeedService.preferredIdentityDerivationVersion,
  }) async {
    final seedHex =
        bip39.mnemonicToSeedHex(mnemonic.trim(), passphrase: passphrase);
    final seed = Uint8List.fromList(_hexToBytes(seedHex));
    final privateKey = await _seedService.derivePassphraseIdentityPrivateKey(
      seed,
      version: derivationVersion,
    );
    final pair = await _x25519.newKeyPairFromSeed(privateKey);
    final publicKey = await pair.extractPublicKey();
    final pubBytes = Uint8List.fromList(publicKey.bytes);

    state = PassphraseState._(
      isActive: true,
      privateKeyBase64: base64Encode(privateKey),
      publicKeyBase64: base64Encode(pubBytes),
      keyTag: computeKeyTag(pubBytes),
      derivationVersion: derivationVersion,
      derivationAlgorithm: derivationVersion.algorithm,
    );
  }

  /// Destroy the passphrase-derived keys and revert to the original identity.
  void deactivate() {
    state = const PassphraseState.inactive();
  }

  /// Compute a short opaque tag from a public key's raw bytes.
  ///
  /// The tag is `base64url(sha256(pubBytes)[0:6])` without padding (8 chars).
  /// An adversary cannot compute this without knowing the public key.
  static String computeKeyTag(Uint8List publicKeyBytes) {
    final hash = sha256.convert(publicKeyBytes).bytes;
    return base64Url.encode(hash.sublist(0, 6)).replaceAll('=', '');
  }

  /// Convenience: compute keyTag from a base64-encoded public key string.
  static String computeKeyTagFromBase64(String publicKeyBase64) {
    return computeKeyTag(Uint8List.fromList(base64Decode(publicKeyBase64)));
  }

  static List<int> _hexToBytes(String hex) {
    final out = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      out.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return out;
  }
}
