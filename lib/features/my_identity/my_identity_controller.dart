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
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/crypto/identity_link_codec.dart';
import '../../core/crypto/models.dart';
import '../../core/providers.dart';

class MyIdentityController {
  MyIdentityController(this.ref);

  final Ref ref;

  Future<LocalIdentity?> getActiveIdentity() async {
    final local = await ref.read(identityManagerProvider).getLocalIdentity();
    if (local == null) return null;

    final pp = ref.read(passphraseProvider);
    if (pp.isActive && pp.publicKeyBase64 != null) {
      final publicKeyBytes = base64Decode(pp.publicKeyBase64!);
      final hash = sha256.convert(publicKeyBytes).bytes;
      final identityId =
          base32.encode(Uint8List.fromList(hash)).replaceAll('=', '');
      final fingerprint = hash
          .take(8)
          .map((e) => e.toRadixString(16).padLeft(2, '0'))
          .join('-')
          .toUpperCase();
      
      return LocalIdentity(
        identityId: identityId,
        publicKeyBase64: pp.publicKeyBase64!,
        fingerprint: fingerprint,
        displayName: local.displayName,
        mnemonic: local.mnemonic,
        derivationVersion: pp.derivationVersion ?? local.derivationVersion,
        derivationAlgorithm:
            pp.derivationAlgorithm ?? local.derivationAlgorithm,
      );
    }
    return local;
  }

  Future<String> identityShareBlock() async {
    final local = await getActiveIdentity();
    if (local == null) return '';
    return '[Layergram Identity]\n'
        'Protocol: layergram/1\n'
        'Name: ${local.displayName}\n'
        'Identity ID: ${local.identityId}\n'
        'Fingerprint: ${local.fingerprint}\n'
        'Public Key (Base64):\n'
        '${local.publicKeyBase64}\n'
        '[/Layergram Identity]';
  }

  Future<String> identityShareLink() async {
    final local = await getActiveIdentity();
    if (local == null) return '';
    return IdentityLinkCodec.encode(local);
  }

  Future<String?> recoveryPhrase() async {
    final local = await ref.read(identityManagerProvider).getLocalIdentity();
    return local?.mnemonic;
  }

  Future<Map<String, dynamic>?> identityQrPayload() async {
    final local = await getActiveIdentity();
    if (local == null) return null;
    return {
      'v': 1,
      'protocol': 'layergram/1',
      'type': 'identity',
      'identityId': local.identityId,
      'publicKey': local.publicKeyBase64,
      'displayName': local.displayName,
      'fingerprint': local.fingerprint,
    };
  }

  Future<void> updateDisplayName(String name) async {
    await ref.read(identityManagerProvider).updateDisplayName(name);
    ref.read(identityReloadTokenProvider.notifier).state++;
  }
}

final myIdentityControllerProvider =
    Provider((ref) => MyIdentityController(ref));
