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

import 'ml_kem_768.dart';

enum V3IdentitySuite {
  hybridX25519MlKem768(1);

  const V3IdentitySuite(this.wireId);

  final int wireId;

  static V3IdentitySuite fromWireId(int wireId) {
    for (final suite in values) {
      if (suite.wireId == wireId) return suite;
    }
    throw const FormatException('Unsupported Layergram v3 identity suite');
  }
}

/// The complete public identity used by Layergram protocol v3.
///
/// It contains public material only. A mnemonic or private key must never be
/// added to this type or its codec.
class V3PublicIdentity {
  factory V3PublicIdentity({
    required Uint8List x25519PublicKey,
    required Uint8List mlKem768PublicKey,
    String displayName = '',
    V3IdentitySuite suite = V3IdentitySuite.hybridX25519MlKem768,
    int flags = 0,
  }) {
    final x25519 = _validatedKey(
      x25519PublicKey,
      V3PublicIdentityCodec.x25519PublicKeyBytes,
      'x25519PublicKey',
    );
    final mlKem = _validatedKey(
      mlKem768PublicKey,
      MlKem768.publicKeyBytes,
      'mlKem768PublicKey',
    );
    final nameBytes = _validatedDisplayName(displayName);
    if (flags != 0) {
      throw ArgumentError.value(flags, 'flags', 'no v3 flags are assigned yet');
    }
    return V3PublicIdentity._(
      x25519PublicKey: x25519,
      mlKem768PublicKey: mlKem,
      displayName: utf8.decode(nameBytes),
      suite: suite,
      flags: flags,
    );
  }

  const V3PublicIdentity._({
    required Uint8List x25519PublicKey,
    required Uint8List mlKem768PublicKey,
    required this.displayName,
    required this.suite,
    required this.flags,
  })  : _x25519PublicKey = x25519PublicKey,
        _mlKem768PublicKey = mlKem768PublicKey;

  final Uint8List _x25519PublicKey;
  final Uint8List _mlKem768PublicKey;
  final String displayName;
  final V3IdentitySuite suite;
  final int flags;

  Uint8List get x25519PublicKey => Uint8List.fromList(_x25519PublicKey);

  Uint8List get mlKem768PublicKey => Uint8List.fromList(_mlKem768PublicKey);

  /// Stable identifier derived from all cryptographic public components.
  String get identityId {
    final digest = sha384.convert(identityBindingBytes).bytes;
    return base32.encode(Uint8List.fromList(digest)).replaceAll('=', '');
  }

  /// 128-bit display fingerprint; the full 384-bit digest remains in
  /// [identityId] and in protocol transcript bindings.
  String get fingerprint {
    final digest = sha384.convert(identityBindingBytes).bytes;
    final bytes = digest.take(16).toList(growable: false);
    final groups = <String>[];
    for (var index = 0; index < bytes.length; index += 2) {
      groups.add(
        bytes
            .sublist(index, index + 2)
            .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
            .join()
            .toUpperCase(),
      );
    }
    return groups.join('-');
  }

  /// Canonical bytes authenticated by identity IDs, fingerprints and future
  /// session transcripts. The mutable display label is deliberately excluded.
  Uint8List get identityBindingBytes => Uint8List.fromList([
        ...V3PublicIdentityCodec.magic,
        suite.wireId,
        flags,
        ..._x25519PublicKey,
        ..._mlKem768PublicKey,
      ]);
}

abstract final class V3PublicIdentityCodec {
  static const int protocolVersion = 3;
  static const int x25519PublicKeyBytes = 32;
  static const int maxDisplayNameBytes = 32;
  static const int checksumBytes = 16;
  static const int _headerBytes = 6;
  static const int _fixedBytes = _headerBytes +
      x25519PublicKeyBytes +
      MlKem768.publicKeyBytes +
      checksumBytes;
  static const int maxBinaryBytes = _fixedBytes + maxDisplayNameBytes;
  static const int maxTokenCharacters =
      3 + ((maxBinaryBytes * 4 + 2) ~/ 3); // `v3.` + unpadded Base64URL
  static const String tokenPrefix = 'v3.';
  static const String scheme = 'layergram';
  static const String host = 'i';
  static const List<int> magic = <int>[0x4c, 0x47, 0x33]; // "LG3"

  static Uint8List encodeBinary(V3PublicIdentity identity) {
    final nameBytes = _validatedDisplayName(identity.displayName);
    final body = Uint8List(
      _headerBytes +
          x25519PublicKeyBytes +
          MlKem768.publicKeyBytes +
          nameBytes.length,
    );
    var offset = 0;
    body.setRange(offset, offset + magic.length, magic);
    offset += magic.length;
    body[offset++] = identity.suite.wireId;
    body[offset++] = identity.flags;
    body[offset++] = nameBytes.length;
    body.setRange(
      offset,
      offset + x25519PublicKeyBytes,
      identity._x25519PublicKey,
    );
    offset += x25519PublicKeyBytes;
    body.setRange(
      offset,
      offset + MlKem768.publicKeyBytes,
      identity._mlKem768PublicKey,
    );
    offset += MlKem768.publicKeyBytes;
    body.setRange(offset, offset + nameBytes.length, nameBytes);

    final checksum = sha384.convert(body).bytes.take(checksumBytes);
    return Uint8List.fromList([...body, ...checksum]);
  }

  static V3PublicIdentity decodeBinary(Uint8List encoded) {
    if (encoded.length < _fixedBytes || encoded.length > maxBinaryBytes) {
      throw const FormatException('Invalid Layergram v3 identity length');
    }
    var offset = 0;
    for (final expected in magic) {
      if (encoded[offset++] != expected) {
        throw const FormatException('Invalid Layergram v3 identity magic');
      }
    }
    final suite = V3IdentitySuite.fromWireId(encoded[offset++]);
    final flags = encoded[offset++];
    if (flags != 0) {
      throw const FormatException('Unsupported Layergram v3 identity flags');
    }
    final nameLength = encoded[offset++];
    if (nameLength > maxDisplayNameBytes) {
      throw const FormatException('Invalid Layergram v3 display name length');
    }
    final expectedLength = _fixedBytes + nameLength;
    if (encoded.length != expectedLength) {
      throw const FormatException('Non-canonical Layergram v3 identity length');
    }

    final checksumOffset = encoded.length - checksumBytes;
    final body = Uint8List.sublistView(encoded, 0, checksumOffset);
    final suppliedChecksum =
        Uint8List.sublistView(encoded, checksumOffset, encoded.length);
    final expectedChecksum = Uint8List.fromList(
      sha384.convert(body).bytes.take(checksumBytes).toList(growable: false),
    );
    if (!_constantTimeEquals(suppliedChecksum, expectedChecksum)) {
      throw const FormatException('Invalid Layergram v3 identity checksum');
    }

    final x25519 = Uint8List.sublistView(
      encoded,
      offset,
      offset + x25519PublicKeyBytes,
    );
    offset += x25519PublicKeyBytes;
    final mlKem = Uint8List.sublistView(
      encoded,
      offset,
      offset + MlKem768.publicKeyBytes,
    );
    offset += MlKem768.publicKeyBytes;
    final nameBytes =
        Uint8List.sublistView(encoded, offset, offset + nameLength);
    late final String displayName;
    try {
      displayName = utf8.decode(nameBytes, allowMalformed: false);
    } on FormatException {
      throw const FormatException('Invalid Layergram v3 display name encoding');
    }

    return V3PublicIdentity(
      x25519PublicKey: x25519,
      mlKem768PublicKey: mlKem,
      displayName: displayName,
      suite: suite,
      flags: flags,
    );
  }

  static String encodeToken(V3PublicIdentity identity) {
    final armored = base64UrlEncode(encodeBinary(identity)).replaceAll('=', '');
    final token = '$tokenPrefix$armored';
    if (token.length > maxTokenCharacters) {
      throw StateError('Layergram v3 identity token exceeds its wire limit');
    }
    return token;
  }

  static V3PublicIdentity decodeToken(String token) {
    final normalized = token.trim();
    if (!normalized.startsWith(tokenPrefix) ||
        normalized.length > maxTokenCharacters) {
      throw const FormatException('Invalid Layergram v3 identity token');
    }
    final armored = normalized.substring(tokenPrefix.length);
    if (armored.isEmpty || !_isCanonicalBase64Url(armored)) {
      throw const FormatException('Invalid Layergram v3 identity token');
    }
    late final Uint8List bytes;
    try {
      bytes = Uint8List.fromList(
        base64Url.decode(base64Url.normalize(armored)),
      );
    } on FormatException {
      throw const FormatException('Invalid Layergram v3 identity armor');
    }
    final identity = decodeBinary(bytes);
    if (encodeToken(identity) != normalized) {
      throw const FormatException('Non-canonical Layergram v3 identity token');
    }
    return identity;
  }

  static String encodeLink(V3PublicIdentity identity) {
    return Uri(
      scheme: scheme,
      host: host,
      pathSegments: [encodeToken(identity)],
    ).toString();
  }

  static V3PublicIdentity decodeLink(String link) {
    final uri = Uri.tryParse(link.trim());
    if (uri == null ||
        uri.scheme != scheme ||
        uri.host != host ||
        uri.pathSegments.length != 1 ||
        uri.userInfo.isNotEmpty ||
        uri.hasPort ||
        uri.hasQuery ||
        uri.hasFragment) {
      throw const FormatException('Invalid Layergram v3 identity link');
    }
    final identity = decodeToken(uri.pathSegments.single);
    if (encodeLink(identity) != link.trim()) {
      throw const FormatException('Non-canonical Layergram v3 identity link');
    }
    return identity;
  }
}

bool _isCanonicalBase64Url(String value) {
  for (final codeUnit in value.codeUnits) {
    final isUppercase = codeUnit >= 0x41 && codeUnit <= 0x5a;
    final isLowercase = codeUnit >= 0x61 && codeUnit <= 0x7a;
    final isDigit = codeUnit >= 0x30 && codeUnit <= 0x39;
    if (!isUppercase &&
        !isLowercase &&
        !isDigit &&
        codeUnit != 0x2d &&
        codeUnit != 0x5f) {
      return false;
    }
  }
  return true;
}

Uint8List _validatedKey(Uint8List key, int expectedLength, String name) {
  if (key.length != expectedLength) {
    throw ArgumentError.value(
      key.length,
      '$name.length',
      'must be exactly $expectedLength bytes',
    );
  }
  var anyNonZero = false;
  for (final byte in key) {
    anyNonZero |= byte != 0;
  }
  if (!anyNonZero) {
    throw ArgumentError.value(key, name, 'must not be all zero');
  }
  return Uint8List.fromList(key);
}

Uint8List _validatedDisplayName(String displayName) {
  if (displayName != displayName.trim()) {
    throw ArgumentError.value(
      displayName,
      'displayName',
      'must already be trimmed',
    );
  }
  for (final rune in displayName.runes) {
    if (rune < 0x20 || rune == 0x7f) {
      throw ArgumentError.value(
        displayName,
        'displayName',
        'must not contain control characters',
      );
    }
  }
  final bytes = Uint8List.fromList(utf8.encode(displayName));
  if (bytes.length > V3PublicIdentityCodec.maxDisplayNameBytes) {
    throw ArgumentError.value(
      bytes.length,
      'displayName UTF-8 length',
      'must not exceed ${V3PublicIdentityCodec.maxDisplayNameBytes} bytes',
    );
  }
  return bytes;
}

bool _constantTimeEquals(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
