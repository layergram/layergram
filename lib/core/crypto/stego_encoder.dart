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
import 'dart:math';
import 'dart:typed_data';

import 'package:characters/characters.dart';

class StegoEncoder {
  // Max payload runes assigned to a mixed carrier slot.
  static const int maxPayloadRunesPerCarrierSlot = 16;

  // Max total runes (payload + noise) per mixed visible-char slot.
  static const int maxRunesPerSlot = 22;
  static const int maxRunesPerNoiseOnlySlot = 12;

  // Min total runes per slot. Also used for conservative cover-length
  // calculation: we assume each slot holds at most minRunesPerSlot payload
  // symbols so the cover text is always generously long.
  static const int minRunesPerSlot = 8;

  static const int previewSafePrefixMinChars = 64;
  static const int previewSafePrefixMaxChars = 96;
  static const int minNoiseRunesPerMixedSlot = 2;
  static const int maxNoiseRunesPerMixedSlot = 6;

  // Base-4 (2 bits per rune). Alphabet restricted to runes che WA preserva:
  // 200B, 200C, 200D, 2061 (2060/2062 vengono rimossi).
  static const List<String> _syms = [
    '\u200B', // 00
    '\u200C', // 01
    '\u200D', // 10
    '\u2061', // 11
  ];

  // Noise zero-width characters (NOT in the encoding alphabet).
  // These are inserted randomly to increase deniability and are discarded
  // by the decoder (which only recognises _syms).
  static const List<String> _noise = [
    '\u200E', // LEFT-TO-RIGHT MARK
    '\u200F', // RIGHT-TO-LEFT MARK
    '\u2063', // INVISIBLE SEPARATOR
    '\u2064', // INVISIBLE PLUS
    '\uFEFF', // ZERO WIDTH NO-BREAK SPACE (BOM)
  ];

  static final _rng = Random.secure();

  // ── Capacity helpers ──────────────────────────────────────────────────────

  /// Number of hidden runes needed for [byteCount] raw bytes.
  static int hiddenRuneCount(int byteCount) {
    final bits = byteCount * 8;
    final padded = bits.isEven ? bits : bits + 1;
    return padded ~/ 2; // base-4: 2 bits per rune
  }

  static int estimatedEncryptedPayloadBytes(
    String secretText, {
    int jsonEnvelopeBytes = 256,
  }) {
    final encodedSecret = jsonEncode(secretText);
    final secretJsonBytes = max(0, utf8.encode(encodedSecret).length - 2);
    return 12 + jsonEnvelopeBytes + secretJsonBytes + 16;
  }

  static String normalizeCoverText(String coverText) {
    return coverText.trimRight();
  }

  static int visibleCharacterCount(String coverText) {
    return normalizeCoverText(coverText).characters.length;
  }

  /// Minimum number of visible characters needed in the cover text
  /// so that no slot exceeds [maxRunesPerSlot].
  ///
  /// V2: hidden runes are distributed only *between* visible characters
  /// (N-1 slots for N chars). No trailing or leading invisible block.
  ///
  /// Reserves a clean preview-safe prefix and then ensures the suffix has
  /// enough carrier slots for the payload.
  static int minCoverLengthForBytes(int byteCount) {
    final runes = hiddenRuneCount(byteCount);
    if (runes == 0) return 0;
    final minSlots = _requiredCarrierSlots(runes);
    return previewSafePrefixMinChars + minSlots;
  }

  static int requiredCarrierSlotsForBytes(int byteCount) {
    return _requiredCarrierSlots(hiddenRuneCount(byteCount));
  }

  static int minimumHiddenLengthForBytes(int byteCount) {
    return _minimumHiddenRuneCountForPayloadSymbols(hiddenRuneCount(byteCount));
  }

  static int minimumEncodedLengthForBytes(String coverText, int byteCount) {
    return visibleCharacterCount(coverText) + minimumHiddenLengthForBytes(byteCount);
  }

  static bool canEncodeBytesWithinCharacterLimit(
    String coverText,
    int byteCount,
    int maxTotalCharacters,
  ) {
    if (maxTotalCharacters < 0) return false;
    final visibleChars = visibleCharacterCount(coverText);
    if (visibleChars > maxTotalCharacters) return false;
    if (byteCount <= 0) return true;
    if (!canEmbedBytes(coverText, byteCount)) return false;
    return minimumEncodedLengthForBytes(coverText, byteCount) <=
        maxTotalCharacters;
  }

  static bool canEmbedBytes(String coverText, int byteCount) {
    if (byteCount <= 0) return true;
    final visChars = normalizeCoverText(coverText).characters.toList();
    if (visChars.length < minCoverLengthForBytes(byteCount)) return false;
    final requiredCarrierSlots = requiredCarrierSlotsForBytes(byteCount);
    final baseEligibleSlotIndexes = _eligibleCarrierSlotIndexes(visChars);
    if (baseEligibleSlotIndexes.length < requiredCarrierSlots) return false;
    return true;
  }

  static int missingCoverCapacityForBytes(String coverText, int byteCount) {
    if (byteCount <= 0) return 0;
    final visChars = normalizeCoverText(coverText).characters.toList();
    final minCoverLength = minCoverLengthForBytes(byteCount);
    final visibleDeficit = minCoverLength - visChars.length;
    if (visibleDeficit > 0) return visibleDeficit;
    final requiredCarrierSlots = requiredCarrierSlotsForBytes(byteCount);
    final carrierDeficit =
        requiredCarrierSlots - _eligibleCarrierSlotIndexes(visChars).length;
    return carrierDeficit > 0 ? carrierDeficit : 0;
  }

  // ── V2 binary encoder ─────────────────────────────────────────────────────

  /// Encode raw [payload] bytes into invisible zero-width characters
  /// distributed between visible characters of [coverText].
  ///
  /// Each slot (between two consecutive visible characters) receives a block
  /// of random total length between [minRunesPerSlot] and [maxRunesPerSlot],
  /// containing payload symbols interleaved with noise at random positions.
  /// No hidden runes are placed before the first or after the last visible
  /// character.
  String encodeBytes(
    String coverText,
    Uint8List payload, {
    int? maxTotalCharacters,
  }) {
    final normalizedCoverText = normalizeCoverText(coverText);
    final payloadSymbols = _bytesToSymbols(payload);
    final visChars = normalizedCoverText.characters.toList();

    if (maxTotalCharacters != null && maxTotalCharacters < 0) {
      throw ArgumentError.value(
        maxTotalCharacters,
        'maxTotalCharacters',
        'Maximum total characters must be zero or greater',
      );
    }

    if (maxTotalCharacters != null && visChars.length > maxTotalCharacters) {
      throw ArgumentError.value(
        coverText,
        'coverText',
        'Cover text exceeds the configured total character limit.',
      );
    }

    if (payloadSymbols.isEmpty) {
      return normalizedCoverText;
    }

    if (normalizedCoverText.isEmpty) {
      throw ArgumentError.value(
        coverText,
        'coverText',
        'Cover text must contain at least one visible character for embedding',
      );
    }

    final minCoverLength = minCoverLengthForBytes(payload.length);
    final requiredCarrierSlots = requiredCarrierSlotsForBytes(payload.length);
    if (visChars.length < minCoverLength) {
      throw ArgumentError.value(
        coverText,
        'coverText',
        'Cover text too short for preview-safe embedding. Minimum visible characters: $minCoverLength',
      );
    }

    final baseEligibleSlotIndexes = _eligibleCarrierSlotIndexes(visChars);
    if (baseEligibleSlotIndexes.length < requiredCarrierSlots) {
      throw ArgumentError.value(
        coverText,
        'coverText',
        'Cover text cannot safely carry the payload. Add more plain visible text.',
      );
    }

    final slots = visChars.length - 1;
    final cleanPrefixChars = _chooseCleanPrefixChars(
      visibleCharCount: visChars.length,
      requiredCarrierSlots: requiredCarrierSlots,
      eligibleSlotIndexes: baseEligibleSlotIndexes,
    );
    final firstEligibleSlot = cleanPrefixChars - 1;
    final eligibleSlotIndexes = baseEligibleSlotIndexes
        .where((slotIndex) => slotIndex >= firstEligibleSlot)
        .toList(growable: false);
    final enforceTotalCharacterLimit = maxTotalCharacters != null;
    final totalCharacterLimit = maxTotalCharacters;
    final carrierSlotIndexes = _pickCarrierSlotIndexes(
      eligibleSlotIndexes,
      requiredCarrierSlots,
      payloadSymbols.length,
      exactRequiredCount: enforceTotalCharacterLimit,
    );
    final payloadCounts = enforceTotalCharacterLimit
        ? _allocateBalancedPayloadCounts(
            payloadSymbols.length,
            carrierSlotIndexes.length,
          )
        : _allocatePayloadCounts(
            payloadSymbols.length,
            carrierSlotIndexes.length,
          );
    final payloadCountsBySlot = <int, int>{
      for (var i = 0; i < carrierSlotIndexes.length; i++)
        carrierSlotIndexes[i]: payloadCounts[i],
    };
    final blockSizesBySlot = <int, int>{};
    final noiseOnlySizesBySlot = <int, int>{};

    if (enforceTotalCharacterLimit) {
      final hiddenBudget = totalCharacterLimit! - visChars.length;
      final extraMixedCapacityBySlot = <int, int>{};
      var minHiddenTotal = 0;

      for (var i = 0; i < carrierSlotIndexes.length; i++) {
        final slotIndex = carrierSlotIndexes[i];
        final payloadCount = payloadCounts[i];
        final minSize = max(
          minRunesPerSlot,
          payloadCount + minNoiseRunesPerMixedSlot,
        );
        final maxSize = max(
          minSize,
          min(
            maxRunesPerSlot,
            payloadCount + maxNoiseRunesPerMixedSlot,
          ),
        );
        blockSizesBySlot[slotIndex] = minSize;
        extraMixedCapacityBySlot[slotIndex] = maxSize - minSize;
        minHiddenTotal += minSize;
      }

      if (minHiddenTotal > hiddenBudget) {
        throw ArgumentError.value(
          coverText,
          'coverText',
          'Cover text and hidden payload exceed the configured total character limit.',
        );
      }

      var remainingHiddenBudget = hiddenBudget - minHiddenTotal;
      final mixedSlotsForExtra = carrierSlotIndexes.toList()..shuffle(_rng);
      for (final slotIndex in mixedSlotsForExtra) {
        if (remainingHiddenBudget <= 0) break;
        final room = extraMixedCapacityBySlot[slotIndex] ?? 0;
        if (room <= 0) continue;
        final extra = _randomBetween(0, min(room, remainingHiddenBudget));
        blockSizesBySlot[slotIndex] = blockSizesBySlot[slotIndex]! + extra;
        remainingHiddenBudget -= extra;
      }

      final decoyCandidates = eligibleSlotIndexes
          .where((slotIndex) => !payloadCountsBySlot.containsKey(slotIndex))
          .toList()
        ..shuffle(_rng);
      final maxDecoys = min(
        decoyCandidates.length,
        max(1, carrierSlotIndexes.length ~/ 3),
      );
      for (final slotIndex in decoyCandidates) {
        if (noiseOnlySizesBySlot.length >= maxDecoys ||
            remainingHiddenBudget < minRunesPerSlot) {
          break;
        }
        final maxSize = min(
          maxRunesPerNoiseOnlySlot,
          remainingHiddenBudget,
        );
        if (maxSize < minRunesPerSlot) break;
        final blockSize = _randomBetween(minRunesPerSlot, maxSize);
        noiseOnlySizesBySlot[slotIndex] = blockSize;
        remainingHiddenBudget -= blockSize;
      }
    } else {
      final noiseOnlySlotIndexes = _pickNoiseOnlySlotIndexes(
        eligibleSlotIndexes: eligibleSlotIndexes,
        carrierSlotIndexes: carrierSlotIndexes,
      ).toSet()
        ..addAll(
          carrierSlotIndexes.contains(firstEligibleSlot) ||
                  !eligibleSlotIndexes.contains(firstEligibleSlot)
              ? const <int>{}
              : <int>{firstEligibleSlot},
        );

      for (var i = 0; i < carrierSlotIndexes.length; i++) {
        final slotIndex = carrierSlotIndexes[i];
        final payloadCount = payloadCounts[i];
        final minSize = max(
          minRunesPerSlot,
          payloadCount + minNoiseRunesPerMixedSlot,
        );
        final maxSize = max(
          minSize,
          min(
            maxRunesPerSlot,
            payloadCount + maxNoiseRunesPerMixedSlot,
          ),
        );
        blockSizesBySlot[slotIndex] = _randomBetween(minSize, maxSize);
      }

      for (final slotIndex in noiseOnlySlotIndexes) {
        noiseOnlySizesBySlot[slotIndex] = _randomBetween(
          minRunesPerSlot,
          maxRunesPerNoiseOnlySlot,
        );
      }
    }

    final buf = StringBuffer();
    var payloadIdx = 0;

    for (var i = 0; i < visChars.length; i++) {
      buf.write(visChars[i]);
      if (i < slots) {
        final payloadCount = payloadCountsBySlot[i];
        if (payloadCount != null) {
          final slotPayload = payloadSymbols.sublist(
            payloadIdx,
            payloadIdx + payloadCount,
          );
          payloadIdx += payloadCount;
          final blockSize = blockSizesBySlot[i]!;
          buf.writeAll(_buildBlock(slotPayload, blockSize));
        } else if (noiseOnlySizesBySlot.containsKey(i)) {
          final blockSize = noiseOnlySizesBySlot[i]!;
          buf.writeAll(_buildBlock(const [], blockSize));
        }
      }
    }

    return buf.toString();
  }

  // ── Internal helpers ──────────────────────────────────────────────────────

  /// Convert raw bytes to a list of base-4 symbol strings.
  List<String> _bytesToSymbols(Uint8List bytes) {
    final syms = <String>[];
    for (final b in bytes) {
      syms.add(_syms[(b >> 6) & 0x03]);
      syms.add(_syms[(b >> 4) & 0x03]);
      syms.add(_syms[(b >> 2) & 0x03]);
      syms.add(_syms[b & 0x03]);
    }
    return syms;
  }

  static int _requiredCarrierSlots(int payloadSymbolCount) {
    if (payloadSymbolCount <= 0) return 0;
    final maxPayloadPerSlot = maxPayloadRunesPerCarrierSlot;
    return (payloadSymbolCount / maxPayloadPerSlot).ceil();
  }

  static int _minimumHiddenRuneCountForPayloadSymbols(int payloadSymbolCount) {
    if (payloadSymbolCount <= 0) return 0;
    final carrierSlots = _requiredCarrierSlots(payloadSymbolCount);
    final baseCount = payloadSymbolCount ~/ carrierSlots;
    final extraCount = payloadSymbolCount % carrierSlots;
    var total = 0;
    for (var i = 0; i < carrierSlots; i++) {
      final payloadCount = baseCount + (i < extraCount ? 1 : 0);
      total += max(
        minRunesPerSlot,
        payloadCount + minNoiseRunesPerMixedSlot,
      );
    }
    return total;
  }

  int _chooseCleanPrefixChars({
    required int visibleCharCount,
    required int requiredCarrierSlots,
    required List<int> eligibleSlotIndexes,
  }) {
    final latestAllowedPrefixByLength = visibleCharCount - requiredCarrierSlots;
    final latestAllowedPrefixBySlots =
        eligibleSlotIndexes[eligibleSlotIndexes.length - requiredCarrierSlots] +
            1;
    final maxPrefix = min(
      previewSafePrefixMaxChars,
      min(latestAllowedPrefixByLength, latestAllowedPrefixBySlots),
    );
    return _randomBetween(previewSafePrefixMinChars, maxPrefix);
  }

  static List<int> _eligibleCarrierSlotIndexes(List<String> visChars) {
    if (visChars.length <= previewSafePrefixMinChars) return const [];
    final firstEligibleSlot = previewSafePrefixMinChars - 1;
    return _carrierSafeSlotIndexes(visChars)
        .where((slotIndex) => slotIndex >= firstEligibleSlot)
        .toList(growable: false);
  }

  static List<int> _carrierSafeSlotIndexes(List<String> visChars) {
    final slots = visChars.length - 1;
    if (slots <= 0) return const [];
    final safeSlots = <int>[];
    for (var i = 0; i < slots; i++) {
      if (_isCarrierSafeGrapheme(visChars[i]) &&
          _isCarrierSafeGrapheme(visChars[i + 1])) {
        safeSlots.add(i);
      }
    }
    return safeSlots;
  }

  static bool _isCarrierSafeGrapheme(String grapheme) {
    if (grapheme.isEmpty) return false;
    for (final rune in grapheme.runes) {
      if (rune < 0x20 || rune > 0x7E) return false;
    }
    return true;
  }

  List<int> _pickCarrierSlotIndexes(
    List<int> eligibleSlotIndexes,
    int requiredCarrierSlots,
    int payloadSymbolCount,
    {bool exactRequiredCount = false}
  ) {
    if (requiredCarrierSlots <= 0) return const [];
    final maxCarrierSlots = min(eligibleSlotIndexes.length, payloadSymbolCount);
    final remainingFlex = maxCarrierSlots - requiredCarrierSlots;
    final maxExtraSlots = min(
      remainingFlex,
      max(1, requiredCarrierSlots ~/ 2),
    );
    final carrierCount = exactRequiredCount
        ? requiredCarrierSlots
        : requiredCarrierSlots +
            (maxExtraSlots > 0 ? _rng.nextInt(maxExtraSlots + 1) : 0);
    final picked = eligibleSlotIndexes.toList()..shuffle(_rng);
    return (picked.take(carrierCount).toList()..sort());
  }

  Set<int> _pickNoiseOnlySlotIndexes({
    required List<int> eligibleSlotIndexes,
    required List<int> carrierSlotIndexes,
  }) {
    if (eligibleSlotIndexes.isEmpty) return const <int>{};
    final carrierSet = carrierSlotIndexes.toSet();
    final decoyCandidates = eligibleSlotIndexes
        .where((slotIndex) => !carrierSet.contains(slotIndex))
        .toList();
    if (decoyCandidates.isEmpty) return const <int>{};
    final maxDecoys = min(
      decoyCandidates.length,
      max(1, carrierSlotIndexes.length ~/ 3),
    );
    final decoyCount = _rng.nextInt(maxDecoys + 1);
    if (decoyCount == 0) return const <int>{};
    decoyCandidates.shuffle(_rng);
    return decoyCandidates.take(decoyCount).toSet();
  }

  List<int> _allocatePayloadCounts(int payloadSymbolCount, int carrierCount) {
    if (payloadSymbolCount <= 0 || carrierCount <= 0) return const [];
    final counts = <int>[];
    final maxPayloadPerSlot = maxPayloadRunesPerCarrierSlot;
    var remainingSymbols = payloadSymbolCount;
    for (var i = 0; i < carrierCount; i++) {
      final remainingSlots = carrierCount - i;
      if (remainingSlots == 1) {
        counts.add(remainingSymbols);
        break;
      }
      final minForThis = max(
        1,
        remainingSymbols - ((remainingSlots - 1) * maxPayloadPerSlot),
      );
      final maxForThis = min(
        maxPayloadPerSlot,
        remainingSymbols - (remainingSlots - 1),
      );
      final targetForThis = (remainingSymbols / remainingSlots).ceil();
      final jitter = min(3, maxForThis - minForThis);
      final lower = max(minForThis, targetForThis - jitter);
      final upper = min(maxForThis, targetForThis + jitter);
      final chosen = _randomBetween(lower, upper);
      counts.add(chosen);
      remainingSymbols -= chosen;
    }
    return counts;
  }

  List<int> _allocateBalancedPayloadCounts(int payloadSymbolCount, int carrierCount) {
    if (payloadSymbolCount <= 0 || carrierCount <= 0) return const [];
    final baseCount = payloadSymbolCount ~/ carrierCount;
    final extraCount = payloadSymbolCount % carrierCount;
    return List<int>.generate(
      carrierCount,
      (index) => baseCount + (index < extraCount ? 1 : 0),
      growable: false,
    );
  }

  int _randomBetween(int minInclusive, int maxInclusive) {
    if (maxInclusive <= minInclusive) return minInclusive;
    return minInclusive + _rng.nextInt(maxInclusive - minInclusive + 1);
  }

  /// Build a block of [totalSize] runes containing [payloadSymbols] at
  /// random positions (preserving their relative order) with the remaining
  /// positions filled by random noise characters.
  List<String> _buildBlock(List<String> payloadSymbols, int totalSize) {
    if (totalSize <= 0) return const [];

    final block = List<String>.filled(totalSize, '');

    if (payloadSymbols.isEmpty) {
      // Pure noise block.
      for (var i = 0; i < totalSize; i++) {
        block[i] = _noise[_rng.nextInt(_noise.length)];
      }
      return block;
    }

    // Choose random positions for payload symbols (maintaining order).
    final available = List<int>.generate(totalSize, (i) => i);
    available.shuffle(_rng);
    final positions = available.take(payloadSymbols.length).toList()..sort();

    for (var i = 0; i < payloadSymbols.length; i++) {
      block[positions[i]] = payloadSymbols[i];
    }

    // Fill remaining positions with noise.
    for (var i = 0; i < totalSize; i++) {
      if (block[i].isEmpty) {
        block[i] = _noise[_rng.nextInt(_noise.length)];
      }
    }

    return block;
  }
}
