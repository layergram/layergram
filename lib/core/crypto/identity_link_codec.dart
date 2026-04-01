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

import 'package:crypto/crypto.dart';

import 'models.dart';

class IdentityLinkCodec {
  static const scheme = 'layergram';
  static const _host = 'i';
  static const _version = 1;

  static String encode(LocalIdentity identity) {
    final payload = <String, dynamic>{
      'v': _version,
      'id': identity.identityId,
      'pk': identity.publicKeyBase64,
      'fp': identity.fingerprint,
      'n': identity.displayName,
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
    final uri = Uri.tryParse(link.trim());
    if (uri == null || uri.scheme != scheme || uri.host != _host) {
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

    final identity = RemoteIdentity(
      identityId: (decoded['id'] as String?) ?? '',
      publicKeyBase64: (decoded['pk'] as String?) ?? '',
      fingerprint: (decoded['fp'] as String?) ?? '',
      displayName: (decoded['n'] as String?) ?? 'Unknown',
    );

    if (identity.identityId.isEmpty || identity.publicKeyBase64.isEmpty) {
      throw ArgumentError('Invalid identity link');
    }

    return identity;
  }
}
