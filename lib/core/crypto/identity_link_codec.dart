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

import 'models.dart';

class IdentityLinkCodec {
  static const scheme = 'layergram';
  static const _host = 'i';
  static const _version = 1;
  static const int publicKeyBytes = 32;
  static const int maxLinkCharacters = 2048;

  static String encode(LocalIdentity identity) {
    final validated = validateLegacyIdentity(
      RemoteIdentity(
        identityId: identity.identityId,
        publicKeyBase64: identity.publicKeyBase64,
        fingerprint: identity.fingerprint,
        displayName: identity.displayName,
        protocolVersion: identity.protocolVersion,
        publicIdentityBase64: identity.publicIdentityBase64,
      ),
    );
    final payload = <String, dynamic>{
      'v': _version,
      'id': validated.identityId,
      'pk': validated.publicKeyBase64,
      'fp': validated.fingerprint,
      'n': validated.displayName,
    };

    final bytes = utf8.encode(jsonEncode(payload));
    final hash = sha256.convert(bytes).bytes;
    final checksum = base64UrlEncode(hash.sublist(0, 6)).replaceAll('=', '');
    final data = base64UrlEncode(bytes).replaceAll('=', '');
    final token = '$data.$checksum';

    return Uri(
      scheme: scheme,
      host: _host,
      pathSegments: [token],
    ).toString();
  }

  static RemoteIdentity decode(String link) {
    final normalized = link.trim();
    if (normalized.isEmpty || normalized.length > maxLinkCharacters) {
      throw ArgumentError('Invalid identity link');
    }
    final uri = Uri.tryParse(normalized);
    if (uri == null ||
        uri.scheme != scheme ||
        uri.host != _host ||
        uri.userInfo.isNotEmpty ||
        uri.hasPort ||
        uri.hasQuery ||
        uri.hasFragment) {
      throw ArgumentError('Invalid identity link');
    }

    if (uri.pathSegments.length != 1) {
      throw ArgumentError('Invalid identity link');
    }

    final token = uri.pathSegments.first;
    final dot = token.lastIndexOf('.');
    if (dot <= 0 || dot >= token.length - 1) {
      throw ArgumentError('Invalid identity link');
    }

    final data = token.substring(0, dot);
    final checksum = token.substring(dot + 1);

    if (!_isCanonicalBase64Url(data) ||
        checksum.length != 8 ||
        !_isCanonicalBase64Url(checksum)) {
      throw ArgumentError('Invalid identity link');
    }
    final bytes = base64Url.decode(base64Url.normalize(data));
    final hash = sha256.convert(bytes).bytes;
    final expected = base64UrlEncode(hash.sublist(0, 6)).replaceAll('=', '');
    if (checksum != expected) {
      throw ArgumentError('Invalid identity link');
    }

    final decoded = jsonDecode(utf8.decode(bytes));
    if (decoded is! Map<String, dynamic>) {
      throw ArgumentError('Invalid identity link');
    }

    final v = decoded['v'];
    if (v != _version) {
      throw ArgumentError('Invalid identity link');
    }

    final identity = validateLegacyIdentity(RemoteIdentity(
      identityId: (decoded['id'] as String?) ?? '',
      publicKeyBase64: (decoded['pk'] as String?) ?? '',
      fingerprint: (decoded['fp'] as String?) ?? '',
      displayName: (decoded['n'] as String?) ?? 'Unknown',
    ));

    if (identity.identityId.isEmpty || identity.publicKeyBase64.isEmpty) {
      throw ArgumentError('Invalid identity link');
    }

    return identity;
  }

  /// Enforces the v2 invariant that the public key uniquely determines both
  /// the identity ID and the human fingerprint.
  static RemoteIdentity validateLegacyIdentity(RemoteIdentity identity) {
    if (identity.protocolVersion != 2 ||
        identity.publicIdentityBase64 != null) {
      throw ArgumentError('Invalid legacy identity');
    }
    final encodedKey = identity.publicKeyBase64.trim();
    late final Uint8List publicKey;
    try {
      publicKey = Uint8List.fromList(base64Decode(encodedKey));
    } on FormatException {
      throw ArgumentError('Invalid legacy identity public key');
    }
    if (publicKey.length != publicKeyBytes ||
        base64Encode(publicKey) != encodedKey ||
        publicKey.every((byte) => byte == 0)) {
      throw ArgumentError('Invalid legacy identity public key');
    }
    final hash = sha256.convert(publicKey).bytes;
    final expectedId =
        base32.encode(Uint8List.fromList(hash)).replaceAll('=', '');
    final expectedFingerprint = hash
        .take(8)
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join('-')
        .toUpperCase();
    if (identity.identityId != expectedId ||
        identity.fingerprint != expectedFingerprint) {
      throw ArgumentError('Legacy identity binding mismatch');
    }
    return RemoteIdentity(
      identityId: expectedId,
      publicKeyBase64: encodedKey,
      fingerprint: expectedFingerprint,
      displayName: identity.displayName,
      verified: identity.verified,
    );
  }

  static bool _isCanonicalBase64Url(String value) {
    if (value.isEmpty) return false;
    for (final unit in value.codeUnits) {
      final upper = unit >= 0x41 && unit <= 0x5a;
      final lower = unit >= 0x61 && unit <= 0x7a;
      final digit = unit >= 0x30 && unit <= 0x39;
      if (!upper && !lower && !digit && unit != 0x2d && unit != 0x5f) {
        return false;
      }
    }
    return true;
  }
}
