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

import 'dart:math';
import 'dart:typed_data';

/// LMF v2 steganographic alphabet definitions.
///
/// The payload alphabet maps 2 bits per Unicode character.
/// The noise alphabet characters are filtered out during decoding.
class StegoAlphabetV2 {
  // ── Payload alphabet (2 bits per rune) ─────────────────────────────────────
  /// 00 → U+200B (ZERO WIDTH SPACE)
  static const int sym00 = 0x200B;

  /// 01 → U+200C (ZERO WIDTH NON-JOINER)
  static const int sym01 = 0x200C;

  /// 10 → U+200D (ZERO WIDTH JOINER)
  static const int sym10 = 0x200D;

  /// 11 → U+2061 (FUNCTION APPLICATION)
  static const int sym11 = 0x2061;

  /// Payload symbols in order of their 2-bit value (0-3).
  static const List<int> payloadRunes = [sym00, sym01, sym10, sym11];

  /// Map from rune to 2-bit value for decoding.
  /// Accepts only the exact v2 payload alphabet (no aliases).
  static const Map<int, int> payloadRuneToValue = {
    sym00: 0, // 00
    sym01: 1, // 01
    sym10: 2, // 10
    sym11: 3, // 11
  };

  /// Map from 2-bit value (0-3) to payload rune.
  static const List<int> valueToPayloadRune = [sym00, sym01, sym10, sym11];

  // ── Noise alphabet (ignored during decoding) ─────────────────────────────
  /// U+2063 (INVISIBLE SEPARATOR)
  static const int noise1 = 0x2063;

  /// U+2064 (INVISIBLE PLUS)
  static const int noise2 = 0x2064;

  /// U+FEFF (ZERO WIDTH NO-BREAK SPACE / BOM)
  static const int noise3 = 0xFEFF;

  /// Noise symbols for v2 (discarded during extraction).
  static const List<int> noiseRunes = [noise1, noise2, noise3];

  /// Set of all noise runes for O(1) membership testing.
  static const Set<int> noiseRunesSet = {noise1, noise2, noise3};

  // ── Forbidden characters (must never appear in v2 output) ─────────────────
  /// U+200E (LEFT-TO-RIGHT MARK) - forbidden, normalizes to U+200C on some platforms
  static const int forbiddenLrm = 0x200E;

  /// U+200F (RIGHT-TO-LEFT MARK) - forbidden, normalizes to U+200C on some platforms
  static const int forbiddenRlm = 0x200F;

  /// All forbidden runes that must never be emitted in v2 output.
  static const Set<int> forbiddenRunes = {forbiddenLrm, forbiddenRlm};

  // ── Recommended noise distribution ───────────────────────────────────────
  /// Recommended distribution for noise generation:
  /// - U+2063: 45%
  /// - U+2064: 45%
  /// - U+FEFF: 10%
  ///
  /// This keeps U+FEFF rarer because it is historically more "special".
  static final List<(int rune, int weight)> recommendedNoiseDistribution = [
    (noise1, 45), // U+2063
    (noise2, 45), // U+2064
    (noise3, 10), // U+FEFF
  ];

  // ── Encoding helpers ─────────────────────────────────────────────────────

  /// Convert raw bytes to a list of payload runes (base-4 encoding).
  /// Each byte produces 4 payload symbols (2 bits each).
  static List<int> bytesToPayloadRunes(Uint8List bytes) {
    final runes = <int>[];
    for (final b in bytes) {
      runes.add(valueToPayloadRune[(b >> 6) & 0x03]);
      runes.add(valueToPayloadRune[(b >> 4) & 0x03]);
      runes.add(valueToPayloadRune[(b >> 2) & 0x03]);
      runes.add(valueToPayloadRune[b & 0x03]);
    }
    return runes;
  }

  /// Extract payload runes from text, ignoring noise.
  /// Returns only valid v2 payload runes in the order encountered.
  static List<int> extractPayloadRunes(String text) {
    final runes = <int>[];
    for (final r in text.runes) {
      if (payloadRuneToValue.containsKey(r)) {
        runes.add(r);
      }
      // Noise and all other runes are silently skipped
    }
    return runes;
  }

  /// Convert payload runes back to bytes (base-4 decoding).
  /// Returns null if rune count is not a multiple of 4.
  static Uint8List? payloadRunesToBytes(List<int> runes) {
    if (runes.length % 4 != 0) return null;
    final byteCount = runes.length ~/ 4;
    final bytes = Uint8List(byteCount);
    for (var i = 0; i < byteCount; i++) {
      final r0 = payloadRuneToValue[runes[i * 4]];
      final r1 = payloadRuneToValue[runes[i * 4 + 1]];
      final r2 = payloadRuneToValue[runes[i * 4 + 2]];
      final r3 = payloadRuneToValue[runes[i * 4 + 3]];
      if (r0 == null || r1 == null || r2 == null || r3 == null) {
        return null; // Invalid rune in payload
      }
      bytes[i] = (r0 << 6) | (r1 << 4) | (r2 << 2) | r3;
    }
    return bytes;
  }

  /// Generate a random noise rune using the recommended distribution.
  static int randomNoiseRune(Random rng) {
    final totalWeight = recommendedNoiseDistribution.fold<int>(
      0,
      (sum, item) => sum + item.$2,
    );
    var roll = rng.nextInt(totalWeight);
    for (final (rune, weight) in recommendedNoiseDistribution) {
      if (roll < weight) return rune;
      roll -= weight;
    }
    return noise1; // Fallback
  }

  /// Check if a rune is a valid v2 payload symbol.
  static bool isPayloadRune(int rune) => payloadRuneToValue.containsKey(rune);

  /// Check if a rune is a v2 noise symbol.
  static bool isNoiseRune(int rune) => noiseRunesSet.contains(rune);

  /// Check if a rune is forbidden in v2 output.
  static bool isForbiddenRune(int rune) => forbiddenRunes.contains(rune);

  /// Number of payload runes needed to encode [byteCount] bytes.
  /// Each byte = 4 payload runes (2 bits each).
  static int payloadRuneCountForBytes(int byteCount) => byteCount * 4;

  /// Number of bytes produced from [runeCount] payload runes.
  /// Each 4 runes = 1 byte.
  static int? byteCountForPayloadRunes(int runeCount) {
    if (runeCount % 4 != 0) return null;
    return runeCount ~/ 4;
  }
}
