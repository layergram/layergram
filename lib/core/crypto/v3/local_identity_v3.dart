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

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

import '../seed_service.dart';
import 'key_schedule_v3.dart';
import 'ml_kem_768.dart';
import 'public_identity_v3.dart';

part 'handshake_v3.dart';

/// In-memory ownership boundary for one complete protocol-v3 local identity.
///
/// This type is deliberately not serializable. The ML-KEM decapsulation key is
/// retained only by the native opaque handle. The X25519 seed is held in a
/// private managed-memory buffer and overwritten on [close] as a best effort.
/// Dart cannot guarantee perfect managed-memory zeroization.
final class V3LocalIdentityHandle {
  V3LocalIdentityHandle._({
    required this.publicIdentity,
    required Uint8List x25519PrivateSeed,
    required MlKem768PrivateKeyHandle mlKem768PrivateKeyHandle,
    required MlKem768Backend mlKem768Backend,
  })  : _x25519PrivateSeed = Uint8List.fromList(x25519PrivateSeed),
        _mlKem768PrivateKeyHandle = mlKem768PrivateKeyHandle,
        _mlKem768Backend = mlKem768Backend;

  final V3PublicIdentity publicIdentity;
  final Uint8List _x25519PrivateSeed;
  final MlKem768PrivateKeyHandle _mlKem768PrivateKeyHandle;
  final MlKem768Backend _mlKem768Backend;

  bool _isClosed = false;

  bool get isClosed => _isClosed;

  /// Destroys the private material owned by this identity handle.
  ///
  /// The operation is idempotent. The only consumer of the private fields is
  /// the still-inactive authenticated handshake part of this library; no
  /// active identity, provider, messaging, storage, or UI seam can reach it.
  Future<void> close() async {
    if (_isClosed) return;
    _x25519PrivateSeed.fillRange(0, _x25519PrivateSeed.length, 0);
    await _mlKem768PrivateKeyHandle.close();
    _isClosed = true;
  }
}

/// Creates complete, but still inactive, protocol-v3 local identities.
///
/// Callers must explicitly provide the native ML-KEM backend. This factory is
/// not wired into the current identity manager, storage, providers, or UI, so
/// protocol v2 remains the only active application protocol.
final class V3LocalIdentityFactory {
  V3LocalIdentityFactory({
    required SeedService seedService,
    required MlKem768Backend mlKem768Backend,
  })  : _seedService = seedService,
        _mlKem768Backend = mlKem768Backend;

  final SeedService _seedService;
  final MlKem768Backend _mlKem768Backend;
  final X25519 _x25519 = X25519();

  /// Restores the primary v3 identity from the existing recovery phrase.
  Future<V3LocalIdentityHandle> restorePrimary({
    required String mnemonic,
    String displayName = '',
  }) {
    return _restore(
      mnemonic: mnemonic,
      bip39Passphrase: '',
      purpose: IdentityDerivationPurpose.identity,
      displayName: displayName,
    );
  }

  /// Restores an ephemeral passphrase-scoped v3 identity.
  ///
  /// The passphrase is used by BIP39 and the resulting seed is additionally
  /// isolated under Layergram's v3 passphrase-identity HKDF labels.
  Future<V3LocalIdentityHandle> restorePassphrase({
    required String mnemonic,
    required String passphrase,
    String displayName = '',
  }) {
    if (passphrase.isEmpty) {
      throw ArgumentError(
        'must not be empty for a passphrase-scoped identity',
        'passphrase',
      );
    }
    return _restore(
      mnemonic: mnemonic,
      bip39Passphrase: passphrase,
      purpose: IdentityDerivationPurpose.passphraseIdentity,
      displayName: displayName,
    );
  }

  Future<V3LocalIdentityHandle> _restore({
    required String mnemonic,
    required String bip39Passphrase,
    required IdentityDerivationPurpose purpose,
    required String displayName,
  }) async {
    if (!_seedService.validateMnemonic(mnemonic)) {
      throw ArgumentError('invalid BIP39 mnemonic', 'mnemonic');
    }
    if (!await _mlKem768Backend.selfTest()) {
      throw StateError('ML-KEM-768 backend self-test failed');
    }

    final bip39Seed = _seedService.mnemonicToSeed(
      mnemonic,
      passphrase: bip39Passphrase,
    );
    V3IdentityKeySeeds? keySeeds;
    MlKem768KeyPair? mlKemKeyPair;
    var transferredPrivateHandle = false;
    try {
      keySeeds = await _seedService.deriveV3IdentityKeySeeds(
        bip39Seed,
        purpose: purpose,
      );
      final x25519KeyPair = await _x25519.newKeyPairFromSeed(
        keySeeds.x25519Seed,
      );
      final x25519PublicKey = await x25519KeyPair.extractPublicKey();

      mlKemKeyPair = await _mlKem768Backend.keyPairFromSeed(
        keySeeds.mlKem768KeyGenerationSeed,
      );
      if (!await _mlKem768Backend.validatePublicKey(mlKemKeyPair.publicKey)) {
        throw StateError('ML-KEM-768 backend produced an invalid public key');
      }

      final publicIdentity = V3PublicIdentity(
        x25519PublicKey: Uint8List.fromList(x25519PublicKey.bytes),
        mlKem768PublicKey: mlKemKeyPair.publicKey,
        displayName: displayName,
      );
      final identity = V3LocalIdentityHandle._(
        publicIdentity: publicIdentity,
        x25519PrivateSeed: keySeeds.x25519Seed,
        mlKem768PrivateKeyHandle: mlKemKeyPair.privateKeyHandle,
        mlKem768Backend: _mlKem768Backend,
      );
      transferredPrivateHandle = true;
      return identity;
    } finally {
      bip39Seed.fillRange(0, bip39Seed.length, 0);
      keySeeds?.wipe();
      if (!transferredPrivateHandle) {
        await mlKemKeyPair?.privateKeyHandle.close();
      }
    }
  }
}
