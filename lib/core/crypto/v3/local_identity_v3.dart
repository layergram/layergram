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
import '../aux_record_cipher.dart';
import 'key_schedule_v3.dart';
import 'ml_kem_768.dart';
import 'public_identity_v3.dart';

part 'handshake_v3.dart';

/// In-memory ownership boundary for one complete protocol-v3 local identity.
///
/// This type is deliberately not serializable. The ML-KEM decapsulation key is
/// retained by the native opaque handle. A private copy of its deterministic
/// generation seed is held only in an app-owned handle for an explicitly
/// authorized keyboard grant; keyboard handles do not retain that copy. The
/// X25519 seed and optional generation seed are wiped on [close] as a best
/// effort. Dart cannot guarantee perfect managed-memory zeroization.
final class V3LocalIdentityHandle {
  V3LocalIdentityHandle._({
    required this.publicIdentity,
    required Uint8List x25519PrivateSeed,
    required Uint8List? localStorageRoot,
    required Uint8List? keyboardMlKemGenerationSeed,
    required MlKem768PrivateKeyHandle mlKem768PrivateKeyHandle,
    required MlKem768Backend mlKem768Backend,
  })  : _x25519PrivateSeed = Uint8List.fromList(x25519PrivateSeed),
        _localStorageRoot = localStorageRoot == null
            ? null
            : Uint8List.fromList(localStorageRoot),
        _keyboardMlKemGenerationSeed = keyboardMlKemGenerationSeed == null
            ? null
            : Uint8List.fromList(keyboardMlKemGenerationSeed),
        _mlKem768PrivateKeyHandle = mlKem768PrivateKeyHandle,
        _mlKem768Backend = mlKem768Backend;

  final V3PublicIdentity publicIdentity;
  final Uint8List _x25519PrivateSeed;
  final Uint8List? _localStorageRoot;
  Uint8List? _keyboardMlKemGenerationSeed;
  final MlKem768PrivateKeyHandle _mlKem768PrivateKeyHandle;
  final MlKem768Backend _mlKem768Backend;

  bool _isClosed = false;

  bool get isClosed => _isClosed;

  /// Destroys the private material owned by this identity handle.
  ///
  /// The operation is idempotent. The only consumer of the private fields is
  /// the authenticated handshake part of this library; no
  /// active identity, provider, messaging, storage, or UI seam can reach it.
  Future<void> close() async {
    if (_isClosed) return;
    _isClosed = true;
    _x25519PrivateSeed.fillRange(0, _x25519PrivateSeed.length, 0);
    final root = _localStorageRoot;
    root?.fillRange(0, root.length, 0);
    _keyboardMlKemGenerationSeed?.fillRange(
        0, _keyboardMlKemGenerationSeed!.length, 0);
    _keyboardMlKemGenerationSeed = null;
    await _mlKem768PrivateKeyHandle.close();
  }

  /// Derives the scoped Aux-record key without exposing its root material.
  Future<SecretKey> deriveAuxStorageKey() {
    final root = _localStorageRoot;
    if (_isClosed || root == null) {
      throw StateError('Layergram v3 identity storage key is unavailable');
    }
    return AuxRecordCipher.deriveAuxStorageKey(root);
  }

  /// Creates a volatile, versioned capability for one autonomous keyboard
  /// session. It contains only the X25519 and ML-KEM generation seeds, never
  /// the mnemonic or Aux storage root. The caller must put the returned bytes
  /// into an authenticated, encrypted, one-shot grant and wipe them afterwards.
  /// No method here writes the capability to disk. The app may issue another
  /// grant after the prior custody session has been reclaimed; a restored
  /// keyboard handle cannot issue grants.
  Uint8List exportKeyboardKeyMaterial() {
    final mlKemSeed = _keyboardMlKemGenerationSeed;
    if (_isClosed || _localStorageRoot == null || mlKemSeed == null) {
      throw StateError('Layergram v3 keyboard key export is unavailable');
    }
    final result = Uint8List(V3LocalIdentityFactory.keyboardKeyMaterialBytes);
    result[0] = V3LocalIdentityFactory.keyboardKeyMaterialVersion;
    result.setRange(1, 33, _x25519PrivateSeed);
    result.setRange(33, result.length, mlKemSeed);
    return result;
  }

  /// Derives the classical preFs bootstrap key for one direction.
  ///
  /// The preFs bootstrap is an explicitly labelled, pre-session compatibility
  /// exception: it authenticates with the long-term identity X25519 key only.
  /// It is **not** forward secret and **not** post-quantum, and it is therefore
  /// never labelled as an established v3 session. Only the derived AEAD key is
  /// returned; the raw X25519 private seed and the raw DH output never leave
  /// this library. [salt] and [info] carry the preFs version, suite, direction
  /// and envelope-kind domain separation supplied by the envelope codec.
  Future<SecretKey> derivePreFsBootstrapKey({
    required V3PublicIdentity remoteIdentity,
    required Uint8List salt,
    required Uint8List info,
  }) async {
    if (_isClosed) {
      throw StateError('Layergram v3 identity handle is closed');
    }
    if (salt.isEmpty || info.isEmpty) {
      throw ArgumentError('preFs key derivation requires a salt and info');
    }
    final shared = await _V3HandshakePrimitives._dh(
      _x25519PrivateSeed,
      remoteIdentity.x25519PublicKey,
    );
    try {
      final derived = await _V3HandshakePrimitives._hkdf(
        ikm: shared,
        salt: salt,
        info: info,
        length: 32,
      );
      try {
        return SecretKey(Uint8List.fromList(derived));
      } finally {
        _wipeV3HandshakeBytes(derived);
      }
    } finally {
      _wipeV3HandshakeBytes(shared);
    }
  }
}

/// Creates complete protocol-v3 local identities.
///
/// Callers must explicitly provide the native ML-KEM backend. This factory is
/// not wired into the current identity manager, storage, providers, or UI, so
/// protocol v2 remains the only active application protocol.
final class V3LocalIdentityFactory {
  static const int keyboardKeyMaterialVersion = 1;
  static const int keyboardKeyMaterialBytes = 1 + 32 + 64;

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

  /// Reconstitutes only the identity operations needed by one delegated
  /// keyboard session. The input buffer is consumed and wiped even on failure.
  /// Both public keys must match the app-approved public identity. This handle
  /// has no Aux storage root and cannot derive an app storage key.
  Future<V3LocalIdentityHandle> restoreKeyboardSession({
    required Uint8List keyMaterial,
    required V3PublicIdentity expectedPublicIdentity,
  }) async {
    Uint8List? xSeed;
    Uint8List? mlKemSeed;
    MlKem768KeyPair? mlKemKeyPair;
    var transferredPrivateHandle = false;
    try {
      if (keyMaterial.length != keyboardKeyMaterialBytes ||
          keyMaterial[0] != keyboardKeyMaterialVersion) {
        throw const FormatException('Invalid keyboard identity capability');
      }
      xSeed = Uint8List.fromList(keyMaterial.sublist(1, 33));
      mlKemSeed = Uint8List.fromList(keyMaterial.sublist(33));
      if (!await _mlKem768Backend.selfTest()) {
        throw StateError('ML-KEM-768 backend self-test failed');
      }
      final xKeyPair = await _x25519.newKeyPairFromSeed(xSeed);
      final xPublic = await xKeyPair.extractPublicKey();
      mlKemKeyPair = await _mlKem768Backend.keyPairFromSeed(mlKemSeed);
      if (!await _mlKem768Backend.validatePublicKey(mlKemKeyPair.publicKey) ||
          !_sameBytes(xPublic.bytes, expectedPublicIdentity.x25519PublicKey) ||
          !_sameBytes(mlKemKeyPair.publicKey,
              expectedPublicIdentity.mlKem768PublicKey)) {
        throw const FormatException('Keyboard identity capability mismatch');
      }
      final identity = V3LocalIdentityHandle._(
        publicIdentity: expectedPublicIdentity,
        x25519PrivateSeed: xSeed,
        localStorageRoot: null,
        keyboardMlKemGenerationSeed: null,
        mlKem768PrivateKeyHandle: mlKemKeyPair.privateKeyHandle,
        mlKem768Backend: _mlKem768Backend,
      );
      transferredPrivateHandle = true;
      return identity;
    } finally {
      keyMaterial.fillRange(0, keyMaterial.length, 0);
      xSeed?.fillRange(0, xSeed.length, 0);
      mlKemSeed?.fillRange(0, mlKemSeed.length, 0);
      if (!transferredPrivateHandle) {
        await mlKemKeyPair?.privateKeyHandle.close();
      }
    }
  }

  static bool _sameBytes(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    var difference = 0;
    for (var index = 0; index < left.length; index++) {
      difference |= left[index] ^ right[index];
    }
    return difference == 0;
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
        localStorageRoot: keySeeds.localStorageRoot,
        keyboardMlKemGenerationSeed: keySeeds.mlKem768KeyGenerationSeed,
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
