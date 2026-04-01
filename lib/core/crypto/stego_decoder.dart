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

class StegoDecoder {
  // Must match encoder exactly, but decoder accepts extra aliases seen in WA.
  // Primary alphabet (2 bits per rune): 200B=00, 200C=01, 200D=10, 2061=11.
  // Aliases: 2060/2062 occasionally survive and are treated as '11'.
  static const Map<int, int> _runeToVal = {
    0x200B: 0, // 00
    0x200C: 1, // 01
    0x200D: 2, // 10
    0x2061: 3, // 11
    0x2060: 3, // alias to 11
    0x2062: 3, // alias to 11
  };

  // ── V2 binary decode ────────────────────────────────────────────────────────

  /// Extract raw bytes from zero-width characters in [text].
  ///
  /// Noise runes (not in the encoding alphabet) are automatically ignored.
  /// Returns candidate byte arrays for each byte alignment (0-7) that
  /// produces at least [minBytes] bytes. Alignment 0 is the most likely
  /// correct one (encoding always starts byte-aligned).
  ///
  /// Minimum 28 bytes expected: 12 (nonce) + 16 (AES-GCM MAC).
  List<Uint8List> decodeByteCandidates(String text, {int minBytes = 28}) {
    final runes = text.runes.toList(growable: false);
    final bits = _symsToBits(runes);
    if (bits.length < minBytes * 8) return const [];

    final candidates = <Uint8List>[];
    for (var offset = 0; offset < 8; offset++) {
      final available = bits.length - offset;
      if (available < minBytes * 8) continue;
      final byteCount = available ~/ 8;
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

  // ── Base-4 helpers ──────────────────────────────────────────────────────────

  List<int> _symsToBits(List<int> runes) {
    final bits = <int>[];
    for (final r in runes) {
      final val = _runeToVal[r];
      if (val == null) continue; // noise runes are automatically skipped
      bits.add((val >> 1) & 1);
      bits.add(val & 1);
    }
    return bits;
  }
}
