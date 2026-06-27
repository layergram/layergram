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

/// Canonical encoding/decoding for FS public keys.
///
/// Wire format: 0x01 || 32-byte X25519 public key  → base64url (no padding).
///
/// The curve identifier byte (0x01 = X25519) is always present to allow
/// future curve agility and to prevent silent cross-type confusion.
///
/// Spec reference: §8.3.1, §8.3.3, §8.3.5.
class FsKeyCodec {
  FsKeyCodec._();

  static const int _curveX25519 = 0x01;
  static const int _rawKeyLength = 32;
  static const int _encodedLength = 33; // 1 byte curve + 32 bytes key

  /// Encodes a 32-byte X25519 public key to the canonical wire format.
  ///
  /// Throws [ArgumentError] if [rawPublicKey] is not exactly 32 bytes.
  static String encodeKey(Uint8List rawPublicKey) {
    if (rawPublicKey.length != _rawKeyLength) {
      throw ArgumentError(
        'FsKeyCodec.encodeKey: key must be 32 bytes, got ${rawPublicKey.length}',
      );
    }
    final encoded = Uint8List(_encodedLength);
    encoded[0] = _curveX25519;
    encoded.setRange(1, _encodedLength, rawPublicKey);
    return base64Url.encode(encoded).replaceAll('=', '');
  }

  /// Decodes a canonical-encoded public key back to its 32-byte raw form.
  ///
  /// Returns the decoded bytes on success.
  ///
  /// Throws [FsKeyCodecException] if:
  /// - the input is null or empty;
  /// - the base64url decode fails;
  /// - the encoded length is wrong;
  /// - the curve identifier is unsupported;
  /// - the key bytes are all-zero (degenerate / identity point);
  /// - the key bytes consist of a known low-order X25519 point.
  static Uint8List decodeKey(String? encoded) {
    if (encoded == null || encoded.isEmpty) {
      throw const FsKeyCodecException('FsKeyCodec.decodeKey: empty input');
    }

    final Uint8List blob;
    try {
      blob = Uint8List.fromList(
        base64Url.decode(_padBase64Url(encoded)),
      );
    } catch (_) {
      throw const FsKeyCodecException(
        'FsKeyCodec.decodeKey: invalid base64url',
      );
    }

    if (blob.length != _encodedLength) {
      throw FsKeyCodecException(
        'FsKeyCodec.decodeKey: wrong encoded length ${blob.length}, expected $_encodedLength',
      );
    }

    if (blob[0] != _curveX25519) {
      throw FsKeyCodecException(
        'FsKeyCodec.decodeKey: unsupported curve identifier 0x${blob[0].toRadixString(16)}',
      );
    }

    final raw = Uint8List.fromList(blob.sublist(1));
    _validateKeyBytes(raw);
    return raw;
  }

  /// Validates that [keyBytes] is a safe X25519 public key.
  ///
  /// Rejects:
  /// - all-zero keys (output of DH with the identity point);
  /// - known low-order X25519 points that produce an all-zero or degenerate
  ///   DH output regardless of the other party's key.
  ///
  /// Note: the `cryptography` package may also reject low-order points at the
  /// DH level. This check provides defence in depth before any DH operation.
  static void _validateKeyBytes(Uint8List keyBytes) {
    assert(keyBytes.length == _rawKeyLength);

    // Reject all-zero key.
    if (_isAllZero(keyBytes)) {
      throw const FsKeyCodecException(
        'FsKeyCodec: all-zero X25519 public key rejected',
      );
    }

    // Reject known low-order X25519 points.
    // These are points of small order whose DH output is always all-zero
    // or a fixed small set of values, regardless of the scalar.
    // Reference: https://cr.yp.to/ecdh/curve25519-20060209.pdf §3,
    //            https://github.com/golang/go/issues/19374
    for (final lowOrder in _lowOrderPoints) {
      if (_bytesEqual(keyBytes, Uint8List.fromList(lowOrder))) {
        throw const FsKeyCodecException(
          'FsKeyCodec: low-order X25519 public key rejected',
        );
      }
    }
  }

  /// Validates the output of a DH computation.
  ///
  /// Throws [FsKeyCodecException] if [dhOutput] is all-zero, which indicates
  /// a low-order input key or a degenerate computation.
  static void validateDhOutput(Uint8List dhOutput) {
    if (dhOutput.length < 32 || _isAllZero(dhOutput.sublist(0, 32))) {
      throw const FsKeyCodecException(
        'FsKeyCodec: DH output is all-zero (degenerate/low-order key)',
      );
    }
  }

  static bool _isAllZero(Uint8List bytes) {
    for (final b in bytes) {
      if (b != 0) return false;
    }
    return true;
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static String _padBase64Url(String s) {
    final rem = s.length % 4;
    if (rem == 0) return s;
    return s.padRight(s.length + (4 - rem), '=');
  }

  /// Known low-order X25519 points (little-endian byte representation).
  ///
  /// These are the small-subgroup points of Curve25519 that produce
  /// degenerate DH outputs. Sourced from RFC 8422 / curve25519-20060209 /
  /// libsodium check_group_size tests.
  static const List<List<int>> _lowOrderPoints = [
    // 0 (the identity/neutral element)
    [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0],
    // 1
    [1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0],
    // p - 1  (= 2^255 - 20, little-endian)
    [0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f],
    // p  (= 2^255 - 19, little-endian) — maps to 0 in the field
    [0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f],
    // p + 1  (field element 1, same as 1 after reduction)
    [0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f],
    // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order-4 point)
    [0xe0,0xeb,0x7a,0x72,0x9b,0x27,0x3a,0x10,
     0x34,0x7a,0x96,0x14,0x20,0x40,0x9f,0xc1,
     0x25,0x36,0x6d,0x3b,0x3d,0x28,0xf6,0x3f,
     0x5d,0xf3,0x3e,0xd4,0xf2,0x95,0x4b,0x39],
    // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order-8 point)
    [0x5f,0x9c,0x95,0xbc,0xa3,0x50,0x8c,0x24,
     0xb1,0xd0,0xb1,0x55,0x9c,0x83,0xef,0x5b,
     0x04,0x44,0x5c,0xc4,0x58,0x1c,0x8e,0x86,
     0xd8,0x22,0x4e,0xdd,0xd0,0x9f,0x11,0x57],
  ];
}

/// Thrown when a public key fails validation in [FsKeyCodec].
class FsKeyCodecException implements Exception {
  const FsKeyCodecException(this.message);
  final String message;

  @override
  String toString() => 'FsKeyCodecException: $message';
}
