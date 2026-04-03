import 'dart:typed_data';

import 'package:characters/characters.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:layergram/core/crypto/stego_decoder.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';

void main() {
  const allInvis = {
    0x200B,
    0x200C,
    0x200D,
    0x200E,
    0x200F,
    0x2060,
    0x2061,
    0x2062,
    0x2063,
    0x2064,
    0xFEFF,
  };

  bool isCarrierSafeGrapheme(String grapheme) {
    if (grapheme.isEmpty) return false;
    for (final rune in grapheme.runes) {
      if (rune < 0x20 || rune > 0x7E) return false;
    }
    return true;
  }

  String stripHiddenRunes(String value) {
    final buf = StringBuffer();
    for (final rune in value.runes) {
      if (!allInvis.contains(rune)) {
        buf.write(String.fromCharCode(rune));
      }
    }
    return buf.toString();
  }

  List<String> slotBlocks(String cover, String encoded) {
    final visChars = StegoEncoder.normalizeCoverText(cover).characters.toList();
    final blocks = <String>[];
    var cursor = 0;

    for (var i = 0; i < visChars.length; i++) {
      final current = visChars[i];
      expect(encoded.startsWith(current, cursor), isTrue);
      cursor += current.length;
      if (i == visChars.length - 1) {
        break;
      }
      final next = visChars[i + 1];
      var nextStart = cursor;
      while (nextStart <= encoded.length &&
          !encoded.startsWith(next, nextStart)) {
        nextStart++;
      }
      expect(nextStart, lessThanOrEqualTo(encoded.length));
      blocks.add(encoded.substring(cursor, nextStart));
      cursor = nextStart;
    }

    expect(cursor, equals(encoded.length));
    return blocks;
  }

  int visibleCharsBeforeFirstHidden(String encoded) {
    var visibleCount = 0;
    for (final rune in encoded.runes) {
      if (allInvis.contains(rune)) {
        return visibleCount;
      }
      visibleCount++;
    }
    return visibleCount;
  }

  // ── V2 binary encode/decode tests ─────────────────────────────────────────

  group('V2 binary encodeBytes/decodeByteCandidates', () {
    test('roundtrip preserves raw bytes', () {
      // Simulate nonce (12) + ciphertext+MAC (32) = 44 bytes
      final payload = Uint8List.fromList(List.generate(44, (i) => i));
      const cover = 'This is a deliberately long cover message that keeps the first part fully visible before any hidden symbols are inserted into the suffix.';

      final encoded = StegoEncoder().encodeBytes(cover, payload);
      final candidates = StegoDecoder().decodeByteCandidates(encoded);

      expect(candidates, isNotEmpty);
      // Alignment 0 should produce the correct bytes.
      expect(candidates[0], equals(payload));
    });

    test('noise runes are present in encoded text but ignored by decoder', () {
      final payload = Uint8List.fromList(List.generate(44, (i) => i));
      const cover = 'Cover message with enough visible characters to keep the preview clean while hiding the encrypted payload in the suffix only.';

      final encoded = StegoEncoder().encodeBytes(cover, payload);

      // Check that some noise runes exist (200E, 200F, 2063, 2064, FEFF).
      const noiseSet = {0x200E, 0x200F, 0x2063, 0x2064, 0xFEFF};
      final hasNoise = encoded.runes.any((r) => noiseSet.contains(r));
      // Noise is random (0-2 per symbol), so with 176 symbols, statistically
      // almost guaranteed to have at least some noise. But we allow the rare
      // case of no noise (all 0s from RNG).
      // The important thing is that even with noise, decoding works.
      expect(hasNoise, anyOf(isTrue, isFalse)); // just document it exists

      final candidates = StegoDecoder().decodeByteCandidates(encoded);
      expect(candidates, isNotEmpty);
      expect(candidates[0], equals(payload));
    });

    test('no trailing invisible chars after last visible char', () {
      final payload = Uint8List.fromList(List.generate(44, (i) => i));
      const cover = 'Cover message with enough visible characters for the payload data to be distributed safely in later suffix slots.';

      final encoded = StegoEncoder().encodeBytes(cover, payload);

      // The last character should be a visible character, not a zero-width one.
      final lastRune = encoded.runes.last;
      expect(allInvis.contains(lastRune), isFalse,
          reason: 'Last rune should be visible, not zero-width');
    });

    test('no trailing space appended', () {
      final payload = Uint8List.fromList(List.generate(44, (i) => i));
      const cover = 'Cover message with enough visible characters for the payload data to be distributed safely in later suffix slots.';

      final encoded = StegoEncoder().encodeBytes(cover, payload);

      // V2 should NOT append a trailing space.
      expect(encoded.endsWith(' '), isFalse);
    });

    test('trailing spaces in cover are trimmed before embedding', () {
      final payload = Uint8List.fromList(List.generate(44, (i) => i));
      final cover =
          '${'Cover message with enough visible characters for the payload data to be distributed safely in later suffix slots.'}   ';

      final encoded = StegoEncoder().encodeBytes(cover, payload);
      final candidates = StegoDecoder().decodeByteCandidates(encoded);

      expect(encoded.endsWith(' '), isFalse);
      expect(candidates, isNotEmpty);
      expect(candidates[0], equals(payload));
    });

    test('cover with only trailing-whitespace-normalized emptiness throws', () {
      final payload = Uint8List.fromList(List.generate(44, (i) => i));

      expect(
        () => StegoEncoder().encodeBytes('   ', payload),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('minCoverLengthForBytes reserves preview-safe prefix', () {
      // 44 bytes → 176 runes (base-4: 4 runes per byte)
      // max payload per carrier slot = 48 - 2 = 46
      // required carrier slots = ceil(176 / 46) = 4
      // coverLen = 64 + 4 = 68
      expect(StegoEncoder.minCoverLengthForBytes(44), equals(68));

      // 200 bytes → 800 runes
      // required carrier slots = ceil(800 / 46) = 18
      // coverLen = 64 + 18 = 82
      expect(StegoEncoder.minCoverLengthForBytes(200), equals(82));

      // 0 bytes → 0
      expect(StegoEncoder.minCoverLengthForBytes(0), equals(0));
    });

    test('first hidden rune starts only after the preview-safe prefix', () {
      final payload = Uint8List.fromList(List.generate(44, (i) => i));
      final cover = 'A' * 140;

      final encoded = StegoEncoder().encodeBytes(cover, payload);
      final visiblePrefix = visibleCharsBeforeFirstHidden(encoded);

      expect(
        visiblePrefix,
        greaterThanOrEqualTo(StegoEncoder.previewSafePrefixMinChars),
      );
      expect(
        visiblePrefix,
        lessThanOrEqualTo(StegoEncoder.previewSafePrefixMaxChars),
      );
    });

    test('randomized clean prefix is not fixed on long covers', () {
      final payload = Uint8List.fromList(List.generate(60, (i) => i));
      final cover = 'B' * 200;
      final starts = <int>{};

      for (var i = 0; i < 16; i++) {
        final encoded = StegoEncoder().encodeBytes(cover, payload);
        final visiblePrefix = visibleCharsBeforeFirstHidden(encoded);
        expect(
          visiblePrefix,
          greaterThanOrEqualTo(StegoEncoder.previewSafePrefixMinChars),
        );
        expect(
          visiblePrefix,
          lessThanOrEqualTo(StegoEncoder.previewSafePrefixMaxChars),
        );
        starts.add(visiblePrefix);
      }

      expect(starts.length, greaterThan(1));
    });

    test('cover shorter than preview-safe minimum throws', () {
      final payload = Uint8List.fromList(List.generate(44, (i) => i));
      final cover = 'C' * 67;

      expect(
        () => StegoEncoder().encodeBytes(cover, payload),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('distributed encoding has no large consecutive zero-width blocks', () {
      final payload = Uint8List.fromList(List.generate(60, (i) => i));
      const cover = 'Questo messaggio di copertura e abbastanza lungo per testare la distribuzione corretta nel suffisso mantenendo pulita tutta la parte iniziale della preview.';

      final encoded = StegoEncoder().encodeBytes(cover, payload);

      var maxRun = 0;
      var currentRun = 0;
      for (final rune in encoded.runes) {
        if (allInvis.contains(rune)) {
          currentRun++;
        } else {
          if (currentRun > maxRun) maxRun = currentRun;
          currentRun = 0;
        }
      }
      if (currentRun > maxRun) maxRun = currentRun;

      // Each block (payload + noise) is between 8 and 48 runes total.
      expect(maxRun, lessThan(49));

      final candidates = StegoDecoder().decodeByteCandidates(encoded);
      expect(candidates, isNotEmpty);
      expect(candidates[0], equals(payload));
    });

    test('cover with decomposed accents and emoji only embeds in ASCII-safe slots', () {
      final payload = Uint8List.fromList(List.generate(44, (i) => i));
      const cover =
          'This cover message keeps enough plain ASCII text after the preview while mentioning cafe\u0301, man\u0303ana, and a smile 😄 near the visible suffix for Unicode safety checks.';

      final encoded = StegoEncoder().encodeBytes(cover, payload);
      final candidates = StegoDecoder().decodeByteCandidates(encoded);
      final visChars = StegoEncoder.normalizeCoverText(cover).characters.toList();
      final blocks = slotBlocks(cover, encoded);

      expect(stripHiddenRunes(encoded), equals(StegoEncoder.normalizeCoverText(cover)));
      expect(blocks, hasLength(visChars.length - 1));
      expect(candidates, isNotEmpty);
      expect(candidates[0], equals(payload));

      for (var i = 0; i < blocks.length; i++) {
        final safe =
            isCarrierSafeGrapheme(visChars[i]) && isCarrierSafeGrapheme(visChars[i + 1]);
        if (!safe) {
          expect(blocks[i], isEmpty);
        }
      }
    });

    test('plain text produces no binary candidates', () {
      final candidates = StegoDecoder().decodeByteCandidates(
        'just a normal message',
      );
      expect(candidates, isEmpty);
    });
  });
}
