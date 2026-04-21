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

/// LMF v1 legacy decoder.
///
/// This decoder exists ONLY for backward compatibility with old messages.
/// DO NOT use this for new encoding - LMF v2 should be used for all new messages.
///
/// Differences from v2:
/// - Accepts 2060/2062 as aliases for 2061 (payload alphabet)
/// - No LMFv2Inner container (raw JSON is encrypted)
/// - No compression
/// - json.v == 1 (or no version field)
class LmfV1LegacyDecoder {
  static final _algo = AesGcm.with256bits();

  /// Minimum expected encrypted payload size:
  /// 12 (nonce) + 16 (tag) = 28 bytes minimum (could be just {})
  static const int minEncryptedPayloadBytes = 28;

  // ── V1 payload alphabet (with aliases) ───────────────────────────────────

  /// V1 alphabet accepts aliases 2060/2062 as equivalent to 2061.
  static const Map<int, int> _runeToVal = {
    0x200B: 0, // 00 - ZERO WIDTH SPACE
    0x200C: 1, // 01 - ZERO WIDTH NON-JOINER
    0x200D: 2, // 10 - ZERO WIDTH JOINER
    0x2061: 3, // 11 - FUNCTION APPLICATION
    0x2060: 3, // alias to 11 - WORD JOINER
    0x2062: 3, // alias to 11 - INVISIBLE TIMES
  };

  // ── Legacy decoding entry point ─────────────────────────────────────────

  /// Attempt to decode an LMF v1 legacy message from [stegoText].
  ///
  /// [key] is the AES-GCM-256 key (derived from X25519 + HKDF-SHA256).
  ///
  /// Returns the decoded JSON envelope if successful, or null if decoding fails.
  /// This is a legacy fallback - try v2 first before calling this.
  static Future<Map<String, dynamic>?> decode({
    required String stegoText,
    required SecretKey key,
  }) async {
    // Extract payload runes from text (accepting v1 aliases)
    final payloadRunes = _extractPayloadRunes(stegoText);

    // Convert runes to bytes
    final encryptedBytes = _payloadRunesToBytes(payloadRunes);
    if (encryptedBytes == null ||
        encryptedBytes.length < minEncryptedPayloadBytes) {
      return null;
    }

    // Try decrypt with different byte alignments (0-7)
    for (var alignment = 0; alignment < 8; alignment++) {
      final adjustedBytes = _adjustAlignment(encryptedBytes, alignment);
      if (adjustedBytes == null) continue;

      final jsonMap = await _decryptToJson(adjustedBytes, key);
      if (jsonMap != null) {
        // Validate this is v1 (no v field or v == 1)
        final version = jsonMap['v'];
        if (version == null || version == 1) {
          return jsonMap;
        }
      }
    }

    return null;
  }

  // ── Steganographic extraction (v1 with aliases) ────────────────────────────

  /// Extract payload runes from text, accepting v1 alphabet with aliases.
  static List<int> _extractPayloadRunes(String text) {
    final runes = <int>[];
    for (final r in text.runes) {
      if (_runeToVal.containsKey(r)) {
        runes.add(r);
      }
      // All other runes (including noise) are silently skipped
    }
    return runes;
  }

  /// Convert payload runes back to bytes (base-4 decoding).
  static Uint8List? _payloadRunesToBytes(List<int> runes) {
    if (runes.length % 4 != 0) return null;
    final byteCount = runes.length ~/ 4;
    final bytes = Uint8List(byteCount);
    for (var i = 0; i < byteCount; i++) {
      final r0 = _runeToVal[runes[i * 4]];
      final r1 = _runeToVal[runes[i * 4 + 1]];
      final r2 = _runeToVal[runes[i * 4 + 2]];
      final r3 = _runeToVal[runes[i * 4 + 3]];
      if (r0 == null || r1 == null || r2 == null || r3 == null) {
        return null;
      }
      bytes[i] = (r0 << 6) | (r1 << 4) | (r2 << 2) | r3;
    }
    return bytes;
  }

  // ── Byte alignment handling ─────────────────────────────────────────────

  static Uint8List? _adjustAlignment(Uint8List bytes, int alignment) {
    if (alignment == 0) return bytes;
    if (alignment < 0 || alignment > 7) return null;

    final bits = <int>[];
    for (final b in bytes) {
      for (var i = 7; i >= 0; i--) {
        bits.add((b >> i) & 1);
      }
    }

    if (bits.length < alignment + 8) return null;
    final shiftedBits = bits.sublist(alignment);

    final byteCount = shiftedBits.length ~/ 8;
    if (byteCount < minEncryptedPayloadBytes) return null;

    final result = Uint8List(byteCount);
    for (var b = 0; b < byteCount; b++) {
      var val = 0;
      for (var i = 0; i < 8; i++) {
        val = (val << 1) | shiftedBits[b * 8 + i];
      }
      result[b] = val;
    }

    return result;
  }

  // ── Decryption to JSON ─────────────────────────────────────────────────

  static Future<Map<String, dynamic>?> _decryptToJson(
    Uint8List encrypted,
    SecretKey key,
  ) async {
    if (encrypted.length < 28) return null;

    final nonce = encrypted.sublist(0, 12);
    final mac = Mac(encrypted.sublist(encrypted.length - 16));
    final cipher = encrypted.sublist(12, encrypted.length - 16);

    final box = SecretBox(cipher, nonce: nonce, mac: mac);

    try {
      final clear = await _algo.decrypt(box, secretKey: key);
      final jsonString = utf8.decode(clear);
      final map = jsonDecode(jsonString) as Map<String, dynamic>;
      return map;
    } catch (_) {
      return null;
    }
  }
}
