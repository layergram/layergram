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
import 'dart:typed_data';

import '../../core/crypto/identity_link_codec.dart';
import '../../core/crypto/models.dart';
import '../../core/crypto/v3/identity_v3_adapter.dart';
import '../../core/crypto/v3/public_identity_v3.dart';
import '../../core/providers.dart';
import '../home/home_controller.dart';

class ProtocolV3IdentityRequiredException implements Exception {
  const ProtocolV3IdentityRequiredException();
}

class ProtocolV3IdentityUnavailableException implements Exception {
  const ProtocolV3IdentityUnavailableException();
}

class IdentitiesController {
  IdentitiesController(this.ref);

  final Ref ref;
  static const int maxIdentityImportCharacters = 4096;

  Stream<List<RemoteIdentity>> watchAll() {
    return ref.read(identitiesRepositoryProvider).watchRemote();
  }

  RemoteIdentity parseIdentityFromLink(String link) {
    if (link.isEmpty || link.length > maxIdentityImportCharacters) {
      throw ArgumentError('Invalid identity link');
    }
    if (link.trim().startsWith('layergram://i/v3.')) {
      _ensureProtocolV3ImportEnabled();
      return _validateImportedProtocol(
        V3IdentityAdapter.toRemoteIdentity(
          V3PublicIdentityCodec.decodeLink(link),
        ),
      );
    }
    final identity = IdentityLinkCodec.decode(link);
    if (identity.identityId.isEmpty || identity.publicKeyBase64.isEmpty) {
      throw ArgumentError('Invalid identity link');
    }
    return _validateImportedProtocol(identity);
  }

  Future<void> importIdentityFromLink(String link) async {
    final identity = parseIdentityFromLink(link);
    await saveIdentity(identity);
  }

  RemoteIdentity parseIdentityFromText(String text) {
    if (text.isEmpty || text.length > maxIdentityImportCharacters) {
      throw ArgumentError('Invalid identity text block');
    }
    if (text.contains('Protocol: layergram/3')) {
      _ensureProtocolV3ImportEnabled();
      return _validateImportedProtocol(
        V3IdentityAdapter.toRemoteIdentity(
          V3IdentityAdapter.decodeShareBlock(text),
        ),
      );
    }
    final trimmed = text.trim();
    if (trimmed.startsWith(V3PublicIdentityCodec.tokenPrefix)) {
      _ensureProtocolV3ImportEnabled();
      return _validateImportedProtocol(
        V3IdentityAdapter.toRemoteIdentity(
          V3PublicIdentityCodec.decodeToken(trimmed),
        ),
      );
    }
    final identity = ref.read(homeControllerProvider).parseIdentityBlock(text);
    if (identity.identityId.isEmpty || identity.publicKeyBase64.isEmpty) {
      throw ArgumentError('Invalid identity text block');
    }
    return _validateImportedProtocol(identity);
  }

  RemoteIdentity parseIdentityImport(String input) {
    if (input.isEmpty || input.length > maxIdentityImportCharacters) {
      throw ArgumentError('Invalid identity import');
    }
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

  RemoteIdentity parseIdentityFromQrPayload(Object data) {
    if (data is Uint8List) {
      if (data.length > V3PublicIdentityCodec.maxBinaryBytes) {
        throw ArgumentError('Invalid QR identity payload');
      }
      final isV3Binary = data.length >= V3PublicIdentityCodec.magic.length &&
          List<int>.generate(
            V3PublicIdentityCodec.magic.length,
            (index) => index,
          ).every((index) => data[index] == V3PublicIdentityCodec.magic[index]);
      if (isV3Binary) {
        _ensureProtocolV3ImportEnabled();
        return _validateImportedProtocol(
          V3IdentityAdapter.toRemoteIdentity(
            V3PublicIdentityCodec.decodeBinary(data),
          ),
        );
      }
      try {
        return parseIdentityFromQrPayload(
          utf8.decode(data, allowMalformed: false),
        );
      } on FormatException {
        throw ArgumentError('Invalid QR identity payload');
      }
    }
    if (data is! String) {
      throw ArgumentError('Invalid QR payload type');
    }
    if (data.isEmpty || data.length > maxIdentityImportCharacters) {
      throw ArgumentError('Invalid QR identity payload');
    }
    final normalized = data.trim();
    if (normalized.startsWith(V3PublicIdentityCodec.tokenPrefix)) {
      _ensureProtocolV3ImportEnabled();
      return _validateImportedProtocol(
        V3IdentityAdapter.toRemoteIdentity(
          V3PublicIdentityCodec.decodeToken(normalized),
        ),
      );
    }
    if (normalized.startsWith('layergram://i/v3.')) {
      _ensureProtocolV3ImportEnabled();
      return _validateImportedProtocol(
        V3IdentityAdapter.toRemoteIdentity(
          V3PublicIdentityCodec.decodeLink(normalized),
        ),
      );
    }
    final Object? decoded;
    try {
      decoded = jsonDecode(data);
    } on FormatException {
      throw ArgumentError('Invalid QR identity payload');
    }
    if (decoded is! Map<String, dynamic>) {
      throw ArgumentError('Invalid QR identity payload');
    }
    final parsed = decoded;
    if (parsed['type'] != 'identity') {
      throw ArgumentError('Invalid QR payload type');
    }
    final protocol = parsed['protocol'] as String?;
    if (protocol != null && !protocol.startsWith('layergram/')) {
      throw ArgumentError('Invalid protocol marker');
    }
    final identity = IdentityLinkCodec.validateLegacyIdentity(RemoteIdentity(
      identityId: (parsed['identityId'] as String?) ?? '',
      publicKeyBase64: (parsed['publicKey'] as String?) ?? '',
      fingerprint: (parsed['fingerprint'] as String?) ?? '',
      displayName: (parsed['displayName'] as String?) ?? 'Unknown',
    ));
    if (identity.identityId.isEmpty || identity.publicKeyBase64.isEmpty) {
      throw ArgumentError('Invalid QR identity payload');
    }
    return _validateImportedProtocol(identity);
  }

  Future<void> importIdentityFromQrPayload(String data) async {
    final identity = parseIdentityFromQrPayload(data);
    await saveIdentity(identity);
  }

  Future<void> saveIdentity(RemoteIdentity identity) async {
    identity = _validateImportedProtocol(identity);
    if (identity.protocolVersion == V3PublicIdentityCodec.protocolVersion) {
      final publicIdentity = V3IdentityAdapter.fromRemoteIdentity(identity);
      await ref
          .read(v3IdentityRuntimeProvider)
          .validateRemotePublicIdentity(publicIdentity);
    } else {
      identity = IdentityLinkCodec.validateLegacyIdentity(identity);
    }
    final repository = ref.read(identitiesRepositoryProvider);
    final existing = await repository.getRemoteById(identity.identityId);
    if (existing != null) {
      if (existing.publicKeyBase64 != identity.publicKeyBase64 ||
          existing.protocolVersion != identity.protocolVersion ||
          existing.publicIdentityBase64 != identity.publicIdentityBase64) {
        throw StateError('Identity key change requires explicit verification');
      }
      identity = identity.copyWith(verified: existing.verified);
    }
    await repository.upsertRemoteIdentity(identity);
  }

  RemoteIdentity _validateImportedProtocol(RemoteIdentity identity) {
    final enabled = ref.read(protocolV3IdentityEnabledProvider);
    if (!enabled &&
        identity.protocolVersion == V3PublicIdentityCodec.protocolVersion) {
      throw const ProtocolV3IdentityUnavailableException();
    }
    if (enabled &&
        identity.protocolVersion != V3PublicIdentityCodec.protocolVersion) {
      throw const ProtocolV3IdentityRequiredException();
    }
    return identity;
  }

  void _ensureProtocolV3ImportEnabled() {
    if (!ref.read(protocolV3IdentityEnabledProvider)) {
      throw const ProtocolV3IdentityUnavailableException();
    }
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
    await ref
        .read(identitiesRepositoryProvider)
        .deleteRemoteIdentity(identityId);
    final effectiveTag = ref.read(effectiveKeyTagProvider);
    await ref.read(messagesRepositoryProvider).deleteForContactByKeyFilter(
          identityId,
          effectiveTag: effectiveTag,
        );
  }
}

final identitiesControllerProvider =
    Provider((ref) => IdentitiesController(ref));
