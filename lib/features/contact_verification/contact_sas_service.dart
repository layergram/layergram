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

import 'package:cryptography/cryptography.dart';

import '../../core/crypto/v3/public_identity_v3.dart';

/// Short Authentication String representation used to verify a contact.
///
/// The value is derived deterministically from the two long-term identity
/// public keys and is independent of who is looking: Alice and Bob compute
/// the same [ContactSasCode] as long as they hold each other's genuine keys.
class ContactSasCode {
  const ContactSasCode({
    required this.digits,
    required this.emojiIndices,
    required this.emojiGlyphs,
  });

  /// Six decimal digits (e.g. `"039281"`), always zero-padded.
  final String digits;

  /// Four indices into [ContactSasService.emojiPalette], each in `0..63`.
  final List<int> emojiIndices;

  /// Four emoji glyphs corresponding to [emojiIndices], resolved against the
  /// fixed palette at derivation time so the UI never needs to.
  final List<String> emojiGlyphs;
}

/// Derives a user-comparable SAS from two Layergram identity public keys.
///
/// The derivation is intentionally symmetric on the key pair: both users
/// obtain the same SAS regardless of which of them plays the "local" role.
/// A tampering MITM that swaps one of the keys will, with overwhelming
/// probability, change every visible digit and emoji.
class ContactSasService {
  const ContactSasService();

  /// Versioned HKDF `info` string. Bumping the suffix invalidates previously
  /// displayed SAS values and is a deliberate breaking change at the UX
  /// level, not a cryptographic one.
  static const sasInfoLabel = 'layergram-sas-v1';

  /// Fixed HKDF salt. Keeping it stable across devices is required so that
  /// two peers derive the same SAS.
  static const sasSaltLabel = 'layergram-sas-salt-v1';
  static const v3SasInfoLabel = 'layergram-sas-v3-hybrid';
  static const v3SasSaltLabel = 'layergram-sas-salt-v3';

  /// Exactly 64 visually distinct, widely-rendered emoji glyphs.
  /// Keep this list append-only and never reorder: changing it would
  /// change every previously displayed SAS without touching any key.
  static const List<String> emojiPalette = <String>[
    '🐶',
    '🐱',
    '🦊',
    '🐻',
    '🐼',
    '🐨',
    '🐯',
    '🦁',
    '🐮',
    '🐷',
    '🐸',
    '🐵',
    '🐔',
    '🐧',
    '🦅',
    '🦉',
    '🐝',
    '🐢',
    '🐠',
    '🐬',
    '🐳',
    '🦋',
    '🌵',
    '🌲',
    '🌴',
    '🌻',
    '🌹',
    '🌈',
    '🍎',
    '🍋',
    '🍒',
    '🍉',
    '🍇',
    '🍍',
    '🥕',
    '🌽',
    '🍕',
    '🍔',
    '🚗',
    '🚲',
    '🚀',
    '🏠',
    '🌊',
    '⚽',
    '🎸',
    '🎹',
    '🎨',
    '📱',
    '💻',
    '📷',
    '💡',
    '🔑',
    '🔒',
    '🎁',
    '🎈',
    '🎂',
    '💎',
    '🎯',
    '🧩',
    '🌟',
    '⭐',
    '🔥',
    '🌙',
    '☀',
  ];

  /// Derives the SAS for the [localPublicKeyBase64] / [peerPublicKeyBase64]
  /// pair. The inputs are base64 encodings of the raw X25519 public keys,
  /// which is the format stored by Layergram contacts.
  Future<ContactSasCode> derive({
    required String localPublicKeyBase64,
    required String peerPublicKeyBase64,
  }) async {
    final local = base64Decode(_sanitizeBase64(localPublicKeyBase64));
    final peer = base64Decode(_sanitizeBase64(peerPublicKeyBase64));
    if (local.isEmpty || peer.isEmpty) {
      throw ArgumentError('Public key inputs must not be empty');
    }
    return _deriveFromKeyBytes(
      Uint8List.fromList(local),
      Uint8List.fromList(peer),
      saltLabel: sasSaltLabel,
      infoLabel: sasInfoLabel,
    );
  }

  /// Derives a symmetric SAS over the complete canonical protocol-v3 identity
  /// bindings, including suite, flags, X25519, and ML-KEM public material.
  Future<ContactSasCode> deriveV3({
    required V3PublicIdentity localIdentity,
    required V3PublicIdentity peerIdentity,
  }) {
    return _deriveFromKeyBytes(
      localIdentity.identityBindingBytes,
      peerIdentity.identityBindingBytes,
      saltLabel: v3SasSaltLabel,
      infoLabel: v3SasInfoLabel,
    );
  }

  Future<ContactSasCode> _deriveFromKeyBytes(
    Uint8List a,
    Uint8List b, {
    required String saltLabel,
    required String infoLabel,
  }) async {
    final ordered = _canonicalOrder(a, b);
    final material = _concat(ordered.$1, ordered.$2);

    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 8);
    final derived = await hkdf.deriveKey(
      secretKey: SecretKey(material),
      nonce: utf8.encode(saltLabel),
      info: utf8.encode(infoLabel),
    );
    final out = Uint8List.fromList(await derived.extractBytes());

    final digits = _digitsFromBytes(out);
    final emojiIndices = _emojiIndicesFromBytes(out);
    final emojiGlyphs = [
      for (final idx in emojiIndices) emojiPalette[idx],
    ];

    return ContactSasCode(
      digits: digits,
      emojiIndices: emojiIndices,
      emojiGlyphs: emojiGlyphs,
    );
  }

  (Uint8List, Uint8List) _canonicalOrder(Uint8List a, Uint8List b) {
    final cmp = _lexCompare(a, b);
    if (cmp <= 0) return (a, b);
    return (b, a);
  }

  int _lexCompare(Uint8List a, Uint8List b) {
    final n = a.length < b.length ? a.length : b.length;
    for (var i = 0; i < n; i++) {
      final diff = a[i] - b[i];
      if (diff != 0) return diff;
    }
    return a.length - b.length;
  }

  Uint8List _concat(Uint8List a, Uint8List b) {
    final out = Uint8List(a.length + b.length);
    out.setRange(0, a.length, a);
    out.setRange(a.length, a.length + b.length, b);
    return out;
  }

  String _digitsFromBytes(Uint8List bytes) {
    // Use the top 32 bits of the HKDF output; any 20+ bits suffice for 6
    // decimal digits, 32 makes the modulo bias negligible at 10^6.
    final value =
        (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    final sixDigits = value % 1000000;
    return sixDigits.toString().padLeft(6, '0');
  }

  List<int> _emojiIndicesFromBytes(Uint8List bytes) {
    // Use bytes[4..7]: pack into a 32-bit word and extract 4 x 6-bit indices.
    final packed =
        (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
    return <int>[
      (packed >> 26) & 0x3F,
      (packed >> 20) & 0x3F,
      (packed >> 14) & 0x3F,
      (packed >> 8) & 0x3F,
    ];
  }

  String _sanitizeBase64(String input) {
    final normalized = input.replaceAll('-', '+').replaceAll('_', '/');
    final cleaned = normalized.replaceAll(RegExp(r'[^A-Za-z0-9+/=]'), '');
    final mod = cleaned.length % 4;
    if (mod == 0) return cleaned;
    return cleaned.padRight(cleaned.length + (4 - mod), '=');
  }
}
