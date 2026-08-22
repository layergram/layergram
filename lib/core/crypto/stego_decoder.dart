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

import 'dart:typed_data';

import 'stego_alphabet_v2.dart';

/// LMF v2 steganographic decoder.
///
/// Uses the exact v2 payload alphabet (U+200B, U+200C, U+200D, U+2061).
/// Noise characters (U+2063, U+2064, U+FEFF) are ignored.
/// V1 aliases (2060, 2062) are NOT accepted in v2 mode.
class StegoDecoder {
  /// Hard application-ingress ceiling checked before rune enumeration.
  static const int maxCarrierCodeUnits = 262144;
  static const int maxPayloadRunes = 196608;
  static const int maxDecodedBytes = 49152;

  /// V2 payload alphabet: exact runes only, no aliases.
  static const Map<int, int> _runeToVal = StegoAlphabetV2.payloadRuneToValue;

  // ── V2 binary decode ────────────────────────────────────────────────────────

  /// Extract raw bytes from zero-width characters in [text].
  ///
  /// Noise runes (U+2063, U+2064, U+FEFF) are automatically ignored.
  /// Returns candidate byte arrays for each byte alignment (0-7) that
  /// produces at least [minBytes] bytes. Alignment 0 is the most likely
  /// correct one (encoding always starts byte-aligned).
  ///
  /// Minimum 28 bytes expected: 12 (nonce) + 16 (AES-GCM MAC).
  List<Uint8List> decodeByteCandidates(String text, {int minBytes = 28}) {
    if (text.length > maxCarrierCodeUnits ||
        minBytes < 0 ||
        minBytes > maxDecodedBytes) {
      throw const FormatException('Invalid Layergram steganographic carrier');
    }
    final runes = <int>[];
    for (final rune in text.runes) {
      if (_runeToVal.containsKey(rune)) {
        if (runes.length >= maxPayloadRunes) {
          throw const FormatException(
              'Invalid Layergram steganographic carrier');
        }
        runes.add(rune);
      }
    }
    final bits = _symsToBits(runes);
    if (bits.length < minBytes * 8) return const [];

    final candidates = <Uint8List>[];
    for (var offset = 0; offset < 8; offset++) {
      final available = bits.length - offset;
      if (available < minBytes * 8) continue;
      final byteCount = available ~/ 8;
      if (byteCount > maxDecodedBytes) {
        throw const FormatException('Invalid Layergram steganographic carrier');
      }
      final bytes = Uint8List(byteCount);
      for (var b = 0; b < byteCount; b++) {
        var val = 0;
        final base = offset + b * 8;
        for (var bit = 0; bit < 8; bit++) {
          val = (val << 1) | bits[base + bit];
        }
        bytes[b] = val;
      }
      candidates.add(bytes);
    }
    return candidates;
  }

  /// Extract payload runes from text (for LMF v2 decoding).
  /// Returns only valid v2 payload runes in order encountered.
  List<int> extractPayloadRunes(String text) {
    return StegoAlphabetV2.extractPayloadRunes(text);
  }

  // ── Base-4 helpers ──────────────────────────────────────────────────────────

  List<int> _symsToBits(List<int> runes) {
    final bits = <int>[];
    for (final r in runes) {
      final val = _runeToVal[r];
      if (val == null) {
        // Noise runes (U+2063, U+2064, U+FEFF) and all other runes are skipped
        continue;
      }
      bits.add((val >> 1) & 1);
      bits.add(val & 1);
    }
    return bits;
  }
}
