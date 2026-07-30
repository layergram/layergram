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

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'dart:convert';

import '../../core/crypto/identity_link_codec.dart';
import '../../core/crypto/models.dart';
import '../../core/providers.dart';
import '../home/home_controller.dart';

class IdentitiesController {
  IdentitiesController(this.ref);

  final Ref ref;

  Stream<List<RemoteIdentity>> watchAll() {
    return ref.read(identitiesRepositoryProvider).watchRemote();
  }

  RemoteIdentity parseIdentityFromLink(String link) {
    final identity = IdentityLinkCodec.decode(link);
    if (identity.identityId.isEmpty || identity.publicKeyBase64.isEmpty) {
      throw ArgumentError('Invalid identity link');
    }
    return identity;
  }

  Future<void> importIdentityFromLink(String link) async {
    final identity = parseIdentityFromLink(link);
    await saveIdentity(identity);
  }

  RemoteIdentity parseIdentityFromText(String text) {
    final identity = ref.read(homeControllerProvider).parseIdentityBlock(text);
    if (identity.identityId.isEmpty || identity.publicKeyBase64.isEmpty) {
      throw ArgumentError('Invalid identity text block');
    }
    return identity;
  }

  RemoteIdentity parseIdentityImport(String input) {
    final normalized = input.trim();
    if (normalized.toLowerCase().startsWith('layergram://i/')) {
      return parseIdentityFromLink(normalized);
    }
    return parseIdentityFromText(normalized);
  }

  Future<void> importIdentityFromText(String text) async {
    final identity = parseIdentityFromText(text);
    await saveIdentity(identity);
  }

  RemoteIdentity parseIdentityFromQrPayload(String data) {
    final parsed = jsonDecode(data) as Map<String, dynamic>;
    if (parsed['type'] != 'identity') {
      throw ArgumentError('Invalid QR payload type');
    }
    final protocol = parsed['protocol'] as String?;
    if (protocol != null && !protocol.startsWith('layergram/')) {
      throw ArgumentError('Invalid protocol marker');
    }
    final identity = RemoteIdentity(
      identityId: (parsed['identityId'] as String?) ?? '',
      publicKeyBase64: (parsed['publicKey'] as String?) ?? '',
      fingerprint: (parsed['fingerprint'] as String?) ?? '',
      displayName: (parsed['displayName'] as String?) ?? 'Unknown',
    );
    if (identity.identityId.isEmpty || identity.publicKeyBase64.isEmpty) {
      throw ArgumentError('Invalid QR identity payload');
    }
    return identity;
  }

  Future<void> importIdentityFromQrPayload(String data) async {
    final identity = parseIdentityFromQrPayload(data);
    await saveIdentity(identity);
  }

  Future<void> saveIdentity(RemoteIdentity identity) async {
    await ref.read(identitiesRepositoryProvider).upsertRemoteIdentity(identity);
  }

  /// Mark a contact as verified.
  ///
  /// This API is intentionally named after the user-visible ceremony and
  /// must only be called after a successful SAS comparison. The repository
  /// path is kept private so the UI cannot flip `verified = true` without
  /// going through the verification flow.
  Future<void> markContactVerified(RemoteIdentity identity) {
    return _writeVerified(identity, true);
  }

  /// Revoke an existing verification so the contact goes back to the
  /// default unverified state. Used by the "Revoke verification" action
  /// when the user no longer trusts a previously verified key.
  Future<void> revokeContactVerification(RemoteIdentity identity) {
    return _writeVerified(identity, false);
  }

  Future<void> _writeVerified(RemoteIdentity identity, bool verified) {
    return ref
        .read(identitiesRepositoryProvider)
        .upsertRemoteIdentity(identity.copyWith(verified: verified));
  }

  Future<void> setDisplayName(RemoteIdentity identity, String displayName) {
    return ref
        .read(identitiesRepositoryProvider)
        .upsertRemoteIdentity(identity.copyWith(displayName: displayName));
  }

  Future<void> delete(String identityId) async {
    await ref.read(identitiesRepositoryProvider).deleteRemoteIdentity(identityId);
    final effectiveTag = ref.read(effectiveKeyTagProvider);
    await ref.read(messagesRepositoryProvider).deleteForContactByKeyFilter(
          identityId,
          effectiveTag: effectiveTag,
        );
  }
}

final identitiesControllerProvider =
    Provider((ref) => IdentitiesController(ref));
