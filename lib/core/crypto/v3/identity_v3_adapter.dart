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

import '../models.dart';
import 'public_identity_v3.dart';

/// Bridges the canonical v3 identity codec to the application identity model.
///
/// The complete hybrid identity is always retained. [publicKeyBase64] remains
/// the X25519 component for narrow legacy UI/capability seams; protocol-v3
/// cryptography must resolve [publicIdentityBase64] instead.
abstract final class V3IdentityAdapter {
  static String encodePublicBundle(V3PublicIdentity identity) {
    return base64UrlEncode(V3PublicIdentityCodec.encodeBinary(identity))
        .replaceAll('=', '');
  }

  static V3PublicIdentity decodePublicBundle(String encoded) {
    if (encoded.isEmpty || encoded.length > 2048) {
      throw const FormatException('Invalid Layergram v3 public identity');
    }
    late final Uint8List bytes;
    try {
      bytes = Uint8List.fromList(
        base64Url.decode(base64Url.normalize(encoded)),
      );
    } on FormatException {
      throw const FormatException('Invalid Layergram v3 public identity');
    }
    final identity = V3PublicIdentityCodec.decodeBinary(bytes);
    if (encodePublicBundle(identity) != encoded) {
      throw const FormatException(
        'Non-canonical Layergram v3 public identity',
      );
    }
    return identity;
  }

  static RemoteIdentity toRemoteIdentity(
    V3PublicIdentity identity, {
    bool verified = false,
  }) {
    return RemoteIdentity(
      identityId: identity.identityId,
      publicKeyBase64: base64Encode(identity.x25519PublicKey),
      fingerprint: identity.fingerprint,
      displayName:
          identity.displayName.isEmpty ? 'Unknown' : identity.displayName,
      verified: verified,
      protocolVersion: V3PublicIdentityCodec.protocolVersion,
      publicIdentityBase64: encodePublicBundle(identity),
    );
  }

  static V3PublicIdentity fromRemoteIdentity(RemoteIdentity identity) {
    if (identity.protocolVersion != V3PublicIdentityCodec.protocolVersion ||
        identity.publicIdentityBase64 == null) {
      throw const FormatException('Contact is not a Layergram v3 identity');
    }
    final decoded = decodePublicBundle(identity.publicIdentityBase64!);
    final expectedX25519 = base64Encode(decoded.x25519PublicKey);
    if (decoded.identityId != identity.identityId ||
        decoded.fingerprint != identity.fingerprint ||
        expectedX25519 != identity.publicKeyBase64) {
      throw const FormatException('Layergram v3 contact binding mismatch');
    }
    return decoded;
  }

  static String encodeShareBlock(V3PublicIdentity identity) {
    return '[Layergram Identity]\n'
        'Protocol: layergram/3\n'
        'Name: ${identity.displayName}\n'
        'Identity ID: ${identity.identityId}\n'
        'Fingerprint: ${identity.fingerprint}\n'
        'Public Identity:\n'
        '${V3PublicIdentityCodec.encodeToken(identity)}\n'
        '[/Layergram Identity]';
  }

  static V3PublicIdentity decodeShareBlock(String text) {
    const start = '[Layergram Identity]';
    const end = '[/Layergram Identity]';
    final startIndex = text.indexOf(start);
    final endIndex = text.indexOf(end);
    if (startIndex < 0 || endIndex <= startIndex) {
      throw const FormatException('Invalid Layergram v3 identity block');
    }
    final scoped = text.substring(startIndex + start.length, endIndex);
    final protocol = RegExp(
      r'^Protocol:\s*layergram/3\s*$',
      multiLine: true,
    );
    if (!protocol.hasMatch(scoped)) {
      throw const FormatException('Invalid Layergram v3 identity protocol');
    }
    final tokenMatch = RegExp(
      r'(?:^|\s)(v3\.[A-Za-z0-9_-]+)(?:\s|$)',
      multiLine: true,
    ).firstMatch(scoped);
    if (tokenMatch == null) {
      throw const FormatException('Missing Layergram v3 public identity');
    }
    final identity = V3PublicIdentityCodec.decodeToken(tokenMatch.group(1)!);
    final encoded = encodeShareBlock(identity);
    if (!_sameBindingFields(scoped, encoded)) {
      throw const FormatException('Layergram v3 identity block mismatch');
    }
    return identity;
  }

  static bool _sameBindingFields(String supplied, String canonical) {
    for (final label in const ['Identity ID:', 'Fingerprint:']) {
      if (_field(supplied, label) != _field(canonical, label)) return false;
    }
    return true;
  }

  static String? _field(String value, String label) {
    for (final line in const LineSplitter().convert(value)) {
      if (line.trimLeft().startsWith(label)) {
        return line.substring(line.indexOf(label) + label.length).trim();
      }
    }
    return null;
  }
}
