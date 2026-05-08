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

import 'compression_zstd.dart';
import 'stego_alphabet_v2.dart';

/// LMF v2 message decoder.
///
/// Decoding flow:
/// 1. Extract payload runes from text (ignore noise)
/// 2. Convert runes to bytes (base-4 decoding)
/// 3. Decrypt with AES-GCM-256 (generate byte-alignment candidates)
/// 4. Parse LMFv2Inner container
/// 5. Validate header (formatVersion, reserved, flags)
/// 6. Decompress if needed
/// 7. Parse JSON and validate v=2
class LmfV2Decoder {
  static final _algo = AesGcm.with256bits();

  /// Minimum expected encrypted payload size:
  /// 12 (nonce) + 4 (minimum inner container) + 16 (tag) = 32 bytes
  static const int minEncryptedPayloadBytes = 32;

  // ── Main decoding entry point ───────────────────────────────────────────

  /// Attempt to decode an LMF v2 message from [stegoText].
  ///
  /// [key] is the AES-GCM-256 key (derived from X25519 + HKDF-SHA256).
  ///
  /// Returns the decoded JSON envelope if successful, or null if decoding fails.
  static Future<Map<String, dynamic>?> decode({
    required String stegoText,
    required SecretKey key,
  }) async {
    // 1. Extract payload runes from text
    final payloadRunes = StegoAlphabetV2.extractPayloadRunes(stegoText);

    // 2. Convert runes to bytes
    final encryptedBytes = StegoAlphabetV2.payloadRunesToBytes(payloadRunes);
    if (encryptedBytes == null ||
        encryptedBytes.length < minEncryptedPayloadBytes) {
      return null;
    }

    // 3. Try decrypt with different byte alignments (0-7)
    // LMF v2 always starts at alignment 0, but we check all for robustness
    for (var alignment = 0; alignment < 8; alignment++) {
      final adjustedBytes = _adjustAlignment(encryptedBytes, alignment);
      if (adjustedBytes == null) continue;

      final innerContainer = await _decrypt(adjustedBytes, key);
      if (innerContainer == null) continue;

      // 4. Parse LMFv2Inner container
      final result = _parseInnerContainer(innerContainer);
      if (result != null) return result;
    }

    return null;
  }

  // ── Byte alignment handling ─────────────────────────────────────────────

  /// Adjust bytes for alignment offset.
  /// alignment=0 returns original, alignment=1-7 shifts by that many bits.
  static Uint8List? _adjustAlignment(Uint8List bytes, int alignment) {
    if (alignment == 0) return bytes;
    if (alignment < 0 || alignment > 7) return null;

    // Convert to bits
    final bits = <int>[];
    for (final b in bytes) {
      for (var i = 7; i >= 0; i--) {
        bits.add((b >> i) & 1);
      }
    }

    // Shift by alignment bits
    if (bits.length < alignment + 8) return null;
    final shiftedBits = bits.sublist(alignment);

    // Convert back to bytes
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

  // ── Decryption ──────────────────────────────────────────────────────────

  static Future<Uint8List?> _decrypt(Uint8List encrypted, SecretKey key) async {
    if (encrypted.length < 28) return null; // 12 + 16 = minimum

    final nonce = encrypted.sublist(0, 12);
    final mac = Mac(encrypted.sublist(encrypted.length - 16));
    final cipher = encrypted.sublist(12, encrypted.length - 16);

    final box = SecretBox(cipher, nonce: nonce, mac: mac);

    try {
      final clear = await _algo.decrypt(box, secretKey: key);
      return Uint8List.fromList(clear);
    } catch (_) {
      return null;
    }
  }

  // ── LMFv2Inner container parsing ────────────────────────────────────────

  /// Parse the LMFv2Inner container structure.
  ///
  /// Returns the decoded JSON envelope if valid, or null if invalid.
  static Map<String, dynamic>? _parseInnerContainer(Uint8List inner) {
    // Minimum size: 4 byte header
    if (inner.length < 4) return null;

    // Parse header
    final formatVersion = inner[0];
    final flags = inner[1];
    final reserved = (inner[2] << 8) | inner[3];

    // Validate header
    if (formatVersion != 0x02) return null;
    if (reserved != 0x0000) return null;
    if (flags & ~0x01 != 0) return null; // Only bit 0 is allowed

    final isCompressed = (flags & 0x01) != 0;
    final payloadBytes = inner.sublist(4);

    if (payloadBytes.isEmpty) return null;

    // Decompress if needed
    Uint8List jsonBytes;
    if (isCompressed) {
      final decompressed = CompressionZstd.decompress(payloadBytes);
      if (decompressed == null) return null;
      jsonBytes = decompressed;
    } else {
      jsonBytes = payloadBytes;
    }

    // Parse JSON
    try {
      final jsonString = utf8.decode(jsonBytes);
      final map = jsonDecode(jsonString) as Map<String, dynamic>;

      // Validate JSON version
      if (map['v'] != 2) return null;

      // Required fields check
      if (map['senderId'] == null ||
          map['recipientId'] == null ||
          map['timestamp'] == null ||
          map['text'] == null) {
        return null;
      }

      return map;
    } catch (_) {
      return null;
    }
  }

  // ── x.fs extension helpers ──────────────────────────────────────────────

  /// Extracts the `x.fs` Forward Secrecy extension from a decoded [envelope].
  ///
  /// Returns the raw JSON map under `envelope['x']['fs']`, or null if absent
  /// or malformed.  Callers should check the `type` field to dispatch to the
  /// correct [FsInitMessage.fromJson] / [FsReplyMessage.fromJson] /
  /// [FsConfirmMessage.fromJson] parser.
  static Map<String, dynamic>? extractFsExtension(
    Map<String, dynamic> envelope,
  ) {
    final x = envelope['x'];
    if (x is! Map<String, dynamic>) return null;
    final fs = x['fs'];
    if (fs is! Map<String, dynamic>) return null;
    return fs;
  }

  /// Returns the `type` string from the `x.fs` extension, or null if absent.
  static String? fsMsgType(Map<String, dynamic> envelope) {
    return extractFsExtension(envelope)?['type'] as String?;
  }
}
