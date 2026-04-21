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
import 'package:cryptography/cryptography.dart';

import 'compression_zstd.dart';
import 'stego_alphabet_v2.dart';

/// LMF v2 message encoder.
///
/// Encoding flow:
/// 1. Build v2 JSON with required fields
/// 2. UTF-8 encode JSON
/// 3. Optionally compress with zstd (policy-based)
/// 4. Wrap into LMFv2Inner container (formatVersion=0x02, flags, reserved, payloadBytes)
/// 5. Encrypt with AES-GCM-256 (12-byte nonce || ciphertext || 16-byte tag)
/// 6. Map encrypted bytes to v2 payload alphabet
/// 7. Embed into cover text with noise injection
class LmfV2Encoder {
  static final _rng = Random.secure();
  static final _algo = AesGcm.with256bits();

  // ── LMFv2Inner container structure ────────────────────────────────────────

  /// formatVersion = 0x02 for LMF v2
  static const int formatVersion = 0x02;

  /// Flags bitmask:
  /// - bit 0 = 1 if payloadBytes is zstd-compressed
  /// - bit 0 = 0 if payloadBytes is plain UTF-8 JSON
  static const int flagCompressed = 0x01;

  /// Reserved bytes must be zero
  static const int reserved = 0x0000;

  // ── JSON envelope fields ────────────────────────────────────────────────

  /// Build the v2 JSON envelope with required fields.
  static Map<String, dynamic> buildJsonEnvelope({
    required String senderId,
    required String recipientId,
    required int timestampMillis,
    required String text,
    String? senderDisplayName,
    int? expireAfter,
    bool deleteAfterRead = false,
  }) {
    return {
      'v': 2,
      'senderId': senderId,
      'recipientId': recipientId,
      'timestamp': timestampMillis,
      'text': text,
      if (senderDisplayName != null) 'senderDisplayName': senderDisplayName,
      if (expireAfter != null) 'expireAfter': expireAfter,
      'deleteAfterRead': deleteAfterRead,
    };
  }

  // ── Main encoding entry point ───────────────────────────────────────────

  /// Encode a message into LMF v2 format.
  ///
  /// [jsonEnvelope] is the v2 JSON object to encrypt.
  /// [key] is the AES-GCM-256 key (derived from X25519 + HKDF-SHA256).
  /// [coverText] is the visible text to hide the payload within.
  ///
  /// Returns the steganographic output: cover text with hidden payload.
  static Future<String> encode({
    required Map<String, dynamic> jsonEnvelope,
    required SecretKey key,
    required String coverText,
  }) async {
    // 1. UTF-8 encode JSON
    final jsonBytes = utf8.encode(jsonEncode(jsonEnvelope));

    // 2. Optionally compress with zstd
    final (compressedBytes, wasCompressed) = CompressionZstd.compress(
      Uint8List.fromList(jsonBytes),
    );

    // 3. Build LMFv2Inner container
    final innerContainer = _buildInnerContainer(
      payloadBytes: compressedBytes,
      isCompressed: wasCompressed,
    );

    // 4. Encrypt with AES-GCM-256
    final encrypted = await _encrypt(innerContainer, key);

    // 5. Encode to steganographic text
    return _embedInCover(coverText, encrypted);
  }

  // ── LMFv2Inner container builder ────────────────────────────────────────

  /// Build the LMFv2Inner binary structure:
  /// - 1 byte: formatVersion (0x02)
  /// - 1 byte: flags (bit 0 = compressed)
  /// - 2 bytes: reserved (0x0000)
  /// - N bytes: payloadBytes
  static Uint8List _buildInnerContainer({
    required Uint8List payloadBytes,
    required bool isCompressed,
  }) {
    final flags = isCompressed ? flagCompressed : 0;
    final header = Uint8List(4);
    header[0] = formatVersion;
    header[1] = flags;
    header[2] = (reserved >> 8) & 0xFF;
    header[3] = reserved & 0xFF;

    final result = Uint8List(header.length + payloadBytes.length);
    result.setAll(0, header);
    result.setAll(header.length, payloadBytes);
    return result;
  }

  // ── Encryption ──────────────────────────────────────────────────────────

  static Future<Uint8List> _encrypt(Uint8List plaintext, SecretKey key) async {
    final nonce = _algo.newNonce();
    final box = await _algo.encrypt(plaintext, secretKey: key, nonce: nonce);

    // Layout: 12-byte nonce || ciphertext || 16-byte tag
    final result = Uint8List(12 + box.cipherText.length + 16);
    result.setAll(0, nonce);
    result.setAll(12, box.cipherText);
    result.setAll(12 + box.cipherText.length, box.mac.bytes);
    return result;
  }

  // ── Steganographic embedding ────────────────────────────────────────────

  /// Embed encrypted bytes into cover text using v2 alphabet and constraints.
  static String _embedInCover(String coverText, Uint8List encryptedBytes) {
    // Convert bytes to payload runes (base-4 encoding)
    final payloadRunes = StegoAlphabetV2.bytesToPayloadRunes(encryptedBytes);

    // Normalize cover text
    final normalizedCover = coverText.trimRight();
    final visChars = Characters(normalizedCover).toList();

    if (visChars.isEmpty) {
      throw ArgumentError('Cover text must contain at least one visible character');
    }

    if (payloadRunes.isEmpty) {
      return normalizedCover;
    }

    // Simple distribution: spread payload evenly across slots
    final slots = visChars.length - 1;
    if (slots <= 0) {
      // Single character cover - cannot embed between characters
      throw ArgumentError(
        'Cover text must contain at least two visible characters for embedding',
      );
    }

    // Calculate how many payload runes per slot
    final baseCount = payloadRunes.length ~/ slots;
    final extraCount = payloadRunes.length % slots;

    final buf = StringBuffer();
    var payloadIdx = 0;

    for (var i = 0; i < visChars.length; i++) {
      buf.write(visChars[i]);

      if (i < slots) {
        // Determine how many payload runes for this slot
        final slotPayloadCount = baseCount + (i < extraCount ? 1 : 0);

        if (slotPayloadCount > 0) {
          final slotPayload = payloadRunes.sublist(
            payloadIdx,
            payloadIdx + slotPayloadCount,
          );
          payloadIdx += slotPayloadCount;

          // Build block with noise
          buf.write(_buildBlock(slotPayload));
        } else {
          // Noise-only block for slots without payload
          buf.write(_buildBlock([]));
        }
      }
    }

    return buf.toString();
  }

  /// Build a block containing [payloadRunes] with noise padding.
  /// Ensures minimum block size and proper noise distribution.
  static String _buildBlock(List<int> payloadRunes) {
    const minBlockSize = 4;
    const maxBlockSize = 12;

    final targetSize = max(
      minBlockSize,
      min(maxBlockSize, payloadRunes.length + _rng.nextInt(4) + 2),
    );

    if (payloadRunes.isEmpty) {
      // Pure noise block
      final runes = List.generate(targetSize, (_) {
        return String.fromCharCode(StegoAlphabetV2.randomNoiseRune(_rng));
      });
      return runes.join();
    }

    // Mixed block: payload at random positions, noise elsewhere
    final positions = List.generate(targetSize, (i) => i)..shuffle(_rng);
    final payloadPositions = positions.take(payloadRunes.length).toList()..sort();

    final block = List<String>.filled(targetSize, '');

    // Place payload runes
    for (var i = 0; i < payloadRunes.length; i++) {
      block[payloadPositions[i]] = String.fromCharCode(payloadRunes[i]);
    }

    // Fill with noise
    for (var i = 0; i < targetSize; i++) {
      if (block[i].isEmpty) {
        block[i] = String.fromCharCode(StegoAlphabetV2.randomNoiseRune(_rng));
      }
    }

    return block.join();
  }
}
