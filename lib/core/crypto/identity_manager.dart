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

import 'package:base32/base32.dart';
import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';

import '../storage/local_identity_vault.dart';
import 'models.dart';
import 'seed_service.dart';

class IdentityManager {
  IdentityManager({
    required SeedService seedService,
    required LocalIdentityVault localIdentityVault,
  })  : _seedService = seedService,
        _localIdentityVault = localIdentityVault;

  final SeedService _seedService;
  final LocalIdentityVault _localIdentityVault;
  final _x25519 = X25519();

  Future<LocalIdentity> createNewIdentity({String? displayName}) async {
    final mnemonic = _seedService.generateMnemonic();
    return _persistFromMnemonic(mnemonic, displayName: displayName);
  }

  Future<LocalIdentity> restoreIdentityFromMnemonic(
    String mnemonic, {
    String? displayName,
  }) async {
    if (!_seedService.validateMnemonic(mnemonic)) {
      throw ArgumentError('Invalid mnemonic');
    }
    return _persistFromMnemonic(mnemonic, displayName: displayName);
  }

  Future<LocalIdentity?> getLocalIdentity() {
    return _localIdentityVault.read();
  }

  Future<void> updateDisplayName(String displayName) async {
    final current = await _localIdentityVault.read();
    if (current == null) return;
    final updated = LocalIdentity(
      identityId: current.identityId,
      publicKeyBase64: current.publicKeyBase64,
      fingerprint: current.fingerprint,
      displayName: displayName,
      mnemonic: current.mnemonic,
    );
    await _localIdentityVault.save(updated);
  }

  Future<String?> getRecoveryPhrase() async {
    final current = await _localIdentityVault.read();
    return current?.mnemonic;
  }

  Future<String?> getLocalPrivateKeyBase64() {
    return _deriveLocalPrivateKeyBase64();
  }

  Future<void> clearLocalIdentity() {
    return _localIdentityVault.clear();
  }

  Future<String?> _deriveLocalPrivateKeyBase64() async {
    final local = await _localIdentityVault.read();
    if (local == null) return null;
    final seed = _seedService.mnemonicToSeed(local.mnemonic);
    final privateKey = _seedService.derivePrivateKey(seed);
    return base64Encode(privateKey);
  }

  Future<LocalIdentity> _persistFromMnemonic(
    String mnemonic, {
    String? displayName,
  }) async {
    final seed = _seedService.mnemonicToSeed(mnemonic);
    final privateKey = _seedService.derivePrivateKey(seed);
    final publicKey = await _publicFromPrivate(privateKey);
    final hash = sha256.convert(publicKey).bytes;
    final identityId =
        base32.encode(Uint8List.fromList(hash)).replaceAll('=', '');
    final fingerprint = hash
        .take(8)
        .map((e) => e.toRadixString(16).padLeft(2, '0'))
        .join('-')
        .toUpperCase();

    final identity = LocalIdentity(
      identityId: identityId,
      publicKeyBase64: base64Encode(publicKey),
      fingerprint: fingerprint,
      displayName: displayName ?? 'Me',
      mnemonic: mnemonic,
    );

    await _localIdentityVault.save(identity);
    return identity;
  }

  Future<List<int>> _publicFromPrivate(List<int> privateKey) async {
    final pair = await _x25519.newKeyPairFromSeed(privateKey);
    final public = await pair.extractPublicKey();
    return public.bytes;
  }
}
