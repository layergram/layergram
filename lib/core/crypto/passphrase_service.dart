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
import 'v3/identity_runtime_v3.dart';
import 'v3/identity_v3_adapter.dart';
import 'v3/public_identity_v3.dart';

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
    this.v3IdentityId,
    this.v3Fingerprint,
    this.v3PublicIdentityBase64,
  });

  const PassphraseState.inactive()
      : isActive = false,
        privateKeyBase64 = null,
        publicKeyBase64 = null,
        keyTag = null,
        derivationVersion = null,
        derivationAlgorithm = null,
        v3IdentityId = null,
        v3Fingerprint = null,
        v3PublicIdentityBase64 = null;

  final bool isActive;
  final String? privateKeyBase64;
  final String? publicKeyBase64;

  /// Short opaque tag derived from the active public key.
  /// Used to efficiently filter messages without attempting decryption.
  /// `null` when passphrase is inactive.
  final String? keyTag;

  final IdentityDerivationVersion? derivationVersion;
  final String? derivationAlgorithm;
  final String? v3IdentityId;
  final String? v3Fingerprint;
  final String? v3PublicIdentityBase64;
}

class PassphraseNotifier extends StateNotifier<PassphraseState> {
  PassphraseNotifier({
    required SeedService seedService,
    V3IdentityRuntime? v3IdentityRuntime,
    bool enableProtocolV3 = false,
  })  : _seedService = seedService,
        _v3IdentityRuntime = v3IdentityRuntime,
        _enableProtocolV3 = enableProtocolV3,
        super(const PassphraseState.inactive());

  final SeedService _seedService;
  final V3IdentityRuntime? _v3IdentityRuntime;
  final bool _enableProtocolV3;
  static final _x25519 = X25519();

  Future<void> activate(
    String mnemonic,
    String passphrase, {
    IdentityDerivationVersion derivationVersion =
        SeedService.preferredIdentityDerivationVersion,
    String displayName = '',
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

    V3PublicIdentity? v3Identity;
    if (_enableProtocolV3) {
      final runtime = _v3IdentityRuntime;
      if (runtime == null) {
        throw StateError('Layergram v3 identity runtime is unavailable');
      }
      try {
        v3Identity = await runtime.activatePassphrase(
          mnemonic: mnemonic,
          passphrase: passphrase,
          displayName: displayName,
        );
      } catch (_) {
        await runtime.deactivatePassphrase();
        rethrow;
      }
    }

    state = PassphraseState._(
      isActive: true,
      privateKeyBase64: base64Encode(privateKey),
      publicKeyBase64: base64Encode(pubBytes),
      keyTag: computeKeyTag(pubBytes),
      derivationVersion: derivationVersion,
      derivationAlgorithm: derivationVersion.algorithm,
      v3IdentityId: v3Identity?.identityId,
      v3Fingerprint: v3Identity?.fingerprint,
      v3PublicIdentityBase64: v3Identity == null
          ? null
          : V3IdentityAdapter.encodePublicBundle(v3Identity),
    );
  }

  /// Destroy the passphrase-derived keys and revert to the original identity.
  Future<void> deactivate() async {
    state = const PassphraseState.inactive();
    await _v3IdentityRuntime?.deactivatePassphrase();
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
