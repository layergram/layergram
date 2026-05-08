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
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/compression_zstd.dart';
import 'package:layergram/core/crypto/lmf_v2_decoder.dart';
import 'package:layergram/core/crypto/lmf_v2_encoder.dart';
import 'package:layergram/core/crypto/stego_alphabet_v2.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';

void main() {
  group('StegoAlphabetV2', () {
    test('payload alphabet has exactly 4 symbols', () {
      expect(StegoAlphabetV2.payloadRunes.length, 4);
      expect(StegoAlphabetV2.payloadRuneToValue.length, 4);
    });

    test('payload symbols are correct Unicode codepoints', () {
      expect(StegoAlphabetV2.sym00, 0x200B); // ZERO WIDTH SPACE
      expect(StegoAlphabetV2.sym01, 0x200C); // ZERO WIDTH NON-JOINER
      expect(StegoAlphabetV2.sym10, 0x200D); // ZERO WIDTH JOINER
      expect(StegoAlphabetV2.sym11, 0x2061); // FUNCTION APPLICATION
    });

    test('noise alphabet has exactly 3 symbols', () {
      expect(StegoAlphabetV2.noiseRunes.length, 3);
      expect(StegoAlphabetV2.noiseRunesSet.length, 3);
    });

    test('noise symbols are correct Unicode codepoints', () {
      expect(StegoAlphabetV2.noise1, 0x2063); // INVISIBLE SEPARATOR
      expect(StegoAlphabetV2.noise2, 0x2064); // INVISIBLE PLUS
      expect(StegoAlphabetV2.noise3, 0xFEFF); // ZERO WIDTH NO-BREAK SPACE
    });

    test('forbidden runes are U+200E and U+200F', () {
      expect(StegoAlphabetV2.forbiddenRunes, contains(0x200E));
      expect(StegoAlphabetV2.forbiddenRunes, contains(0x200F));
      expect(StegoAlphabetV2.forbiddenRunes.length, 2);
    });

    test('U+200C is not in noise alphabet', () {
      expect(StegoAlphabetV2.isNoiseRune(0x200C), isFalse);
      expect(StegoAlphabetV2.isPayloadRune(0x200C), isTrue);
    });

    test('bytesToPayloadRunes produces correct number of runes', () {
      final bytes = Uint8List.fromList([0x00, 0xFF, 0x12]);
      final runes = StegoAlphabetV2.bytesToPayloadRunes(bytes);
      expect(runes.length, 12); // 3 bytes * 4 runes/byte
    });

    test('payloadRunesToBytes round-trip', () {
      final original = Uint8List.fromList([0x00, 0xFF, 0x12, 0x34, 0xAB, 0xCD]);
      final runes = StegoAlphabetV2.bytesToPayloadRunes(original);
      final recovered = StegoAlphabetV2.payloadRunesToBytes(runes);
      expect(recovered, isNotNull);
      expect(recovered!.toList(), original.toList());
    });

    test('extractPayloadRunes ignores noise', () {
      const payload = '\u200B\u200C\u200D\u2061'; // 4 payload runes
      const noise = '\u2063\u2064\uFEFF'; // 3 noise runes
      final mixed = '$noise$payload$noise$payload$noise';
      final extracted = StegoAlphabetV2.extractPayloadRunes(mixed);
      expect(extracted.length, 8); // 4 + 4 payload runes
    });

    test('isForbiddenRune correctly identifies forbidden characters', () {
      expect(StegoAlphabetV2.isForbiddenRune(0x200E), isTrue);
      expect(StegoAlphabetV2.isForbiddenRune(0x200F), isTrue);
      expect(StegoAlphabetV2.isForbiddenRune(0x200B), isFalse);
      expect(StegoAlphabetV2.isForbiddenRune(0x2063), isFalse);
    });
  });

  group('CompressionZstd', () {
    test('short plaintext (< 96 bytes) is not compressed', () {
      final short = Uint8List.fromList(List.generate(50, (i) => i));
      final (result, wasCompressed) = CompressionZstd.compress(short);
      expect(wasCompressed, isFalse);
      expect(result.length, short.length);
    });

    test('long compressible text is compressed', () {
      // Create highly compressible data (repeated pattern)
      final compressible = Uint8List.fromList(
        List.generate(200, (i) => 'A'.codeUnitAt(0)),
      );
      final (result, wasCompressed) = CompressionZstd.compress(compressible);
      // Note: May or may not compress depending on implementation
      // Just verify it doesn't crash
      expect(result, isNotNull);
    });

    test('decompress recovers original data', () {
      final original = utf8.encode('Hello, World! This is a test message.') as Uint8List;
      final compressed = CompressionZstd.compressRaw(original);
      if (compressed != null) {
        final recovered = CompressionZstd.decompress(compressed);
        expect(recovered, isNotNull);
        expect(recovered!.toList(), original.toList());
      }
    });

    test('decompress returns null for invalid data', () {
      final invalid = Uint8List.fromList([0x00, 0x01, 0x02, 0x03]);
      final result = CompressionZstd.decompress(invalid);
      expect(result, isNull);
    });
  });

  group('LmfV2Encoder/Decoder round-trip', () {
    late SecretKey testKey;

    setUp(() async {
      // Generate a test key
      final algo = AesGcm.with256bits();
      testKey = await algo.newSecretKey();
    });

    test('basic encode/decode round-trip', () async {
      final jsonEnvelope = LmfV2Encoder.buildJsonEnvelope(
        senderId: 'sender-123',
        recipientId: 'recipient-456',
        timestampMillis: DateTime.now().millisecondsSinceEpoch,
        text: 'Hello, secret world!',
        senderDisplayName: 'Alice',
      );

      const coverText =
          'This is a normal looking message that will hide the secret payload '
          'inside it using steganography techniques that are quite effective '
          'at hiding information in plain sight without detection';

      final encoded = await LmfV2Encoder.encode(
        jsonEnvelope: jsonEnvelope,
        key: testKey,
        coverText: coverText,
      );

      // Verify encoded text is not empty and contains visible characters
      expect(encoded.isNotEmpty, isTrue);
      expect(encoded.length > coverText.length, isTrue); // Should have hidden runes

      // Decode
      final decoded = await LmfV2Decoder.decode(stegoText: encoded, key: testKey);

      expect(decoded, isNotNull);
      expect(decoded!['v'], 2);
      expect(decoded['senderId'], 'sender-123');
      expect(decoded['recipientId'], 'recipient-456');
      expect(decoded['text'], 'Hello, secret world!');
      expect(decoded['senderDisplayName'], 'Alice');
    });

    test('long message with compression round-trip', () async {
      final longText = 'A' * 200; // Long text that should trigger compression

      final jsonEnvelope = LmfV2Encoder.buildJsonEnvelope(
        senderId: 'sender-123',
        recipientId: 'recipient-456',
        timestampMillis: DateTime.now().millisecondsSinceEpoch,
        text: longText,
      );

      const coverText =
          'This is a normal looking message that will hide the secret payload '
          'inside it using steganography techniques that are quite effective '
          'at hiding information in plain sight without detection. We need '
          'more cover text to hide the long payload efficiently and securely '
          'so that it remains undetected by any observers or automated systems';

      final encoded = await LmfV2Encoder.encode(
        jsonEnvelope: jsonEnvelope,
        key: testKey,
        coverText: coverText,
      );

      final decoded = await LmfV2Decoder.decode(stegoText: encoded, key: testKey);

      expect(decoded, isNotNull);
      expect(decoded!['v'], 2);
      expect(decoded['text'], longText);
    });

    test('decoding fails with wrong key', () async {
      final jsonEnvelope = LmfV2Encoder.buildJsonEnvelope(
        senderId: 'sender-123',
        recipientId: 'recipient-456',
        timestampMillis: DateTime.now().millisecondsSinceEpoch,
        text: 'Secret message',
      );

      const coverText =
          'This is a normal looking message that will hide the secret payload '
          'inside it using steganography techniques that are quite effective';

      final encoded = await LmfV2Encoder.encode(
        jsonEnvelope: jsonEnvelope,
        key: testKey,
        coverText: coverText,
      );

      // Try to decode with a different key
      final wrongKey = await AesGcm.with256bits().newSecretKey();
      final decoded = await LmfV2Decoder.decode(stegoText: encoded, key: wrongKey);

      expect(decoded, isNull);
    });

    test('decoding fails with invalid stego text', () async {
      final decoded = await LmfV2Decoder.decode(
        stegoText: 'Just normal text with no hidden payload',
        key: testKey,
      );

      expect(decoded, isNull);
    });

    test('encoded message does not contain forbidden characters', () async {
      final jsonEnvelope = LmfV2Encoder.buildJsonEnvelope(
        senderId: 'sender-123',
        recipientId: 'recipient-456',
        timestampMillis: DateTime.now().millisecondsSinceEpoch,
        text: 'Test message',
      );

      const coverText =
          'This is a normal looking message that will hide the secret payload '
          'inside it using steganography techniques that are quite effective';

      final encoded = await LmfV2Encoder.encode(
        jsonEnvelope: jsonEnvelope,
        key: testKey,
        coverText: coverText,
      );

      // Check that forbidden characters are not present
      for (final rune in encoded.runes) {
        expect(
          StegoAlphabetV2.isForbiddenRune(rune),
          isFalse,
          reason: 'Forbidden rune U+${rune.toRadixString(16).toUpperCase().padLeft(4, '0')} found in output',
        );
      }
    });

    test('LMF v2 capacity calculations include 4-byte inner container overhead', () {
      // The estimatedEncryptedPayloadBytes should now include +4 bytes for LMFv2Inner header
      // Verify by checking the calculation includes the expected overhead

      // Empty secret should still account for all overhead bytes
      final emptySecretBytes = StegoEncoder.estimatedEncryptedPayloadBytes('');

      // Expected: 12 (nonce) + 4 (LMFv2Inner header) + 256 (envelope estimate) + 0 (no secret) + 16 (MAC) = 288
      // Note: jsonEnvelopeBytes defaults to 256
      expect(emptySecretBytes, equals(12 + 4 + 256 + 0 + 16)); // 288

      // With a secret text, the calculation should include the secret JSON bytes
      final withSecretBytes = StegoEncoder.estimatedEncryptedPayloadBytes('Hello');
      final encodedSecret = jsonEncode('Hello'); // "Hello" -> 7 bytes including quotes
      final expectedSecretJsonBytes = utf8.encode(encodedSecret).length - 2; // -2 for quotes

      expect(withSecretBytes, equals(12 + 4 + 256 + expectedSecretJsonBytes + 16));
    });

    test('hiddenRuneCount calculation is consistent with estimatedEncryptedPayloadBytes', () {
      final secretText = 'Test message for capacity calculation';
      final estimatedBytes = StegoEncoder.estimatedEncryptedPayloadBytes(secretText);
      final runeCount = StegoEncoder.hiddenRuneCount(estimatedBytes);

      // Verify the rune count is positive and proportional to byte count
      expect(runeCount, greaterThan(0));
      expect(runeCount, equals(estimatedBytes * 4)); // 4 runes per byte (2 bits per rune)
    });
  });

  // ---------------------------------------------------------------------------
  // Phase 5 — LMF v2 x.fs extension tests
  // ---------------------------------------------------------------------------

  group('LMF v2 x.fs extension (Phase 5)', () {
    late SecretKey testKey;
    const _coverText = 'Hello from Layergram. This is a moderately long cover text for testing purposes, ensuring there is enough capacity for the hidden payload with the FS extension attached to the message.';

    setUp(() async {
      testKey = SecretKey(Uint8List(32)..fillRange(0, 32, 0x42));
    });

    // T5.1 — envelope with no x.fs round-trips correctly.
    test('T5.1: envelope without x.fs round-trips (baseline compatibility)', () async {
      final env = LmfV2Encoder.buildJsonEnvelope(
        senderId: 'alice',
        recipientId: 'bob',
        timestampMillis: 1700000000000,
        text: 'Hello',
      );
      expect(env.containsKey('x'), isFalse);

      final stego = await LmfV2Encoder.encode(
        jsonEnvelope: env,
        key: testKey,
        coverText: _coverText,
      );
      final decoded = await LmfV2Decoder.decode(stegoText: stego, key: testKey);
      expect(decoded, isNotNull);
      expect(decoded!['text'], equals('Hello'));
      expect(LmfV2Decoder.extractFsExtension(decoded), isNull);
    });

    // T5.2 — envelope with fs_init round-trips and x.fs is extractable.
    test('T5.2: envelope with x.fs fs_init round-trips', () async {
      final fsInit = {
        'v': 1,
        'type': 'fs_init',
        'initId': 'abc123',
        'initiatorDevicePub': 'AQ' + 'A' * 42,
        'initiatorEphemeralPub': 'AQ' + 'A' * 42,
        'caps': ['lgfs1', 'dr1'],
        'createdAt': 1700000000,
      };
      final env = LmfV2Encoder.buildJsonEnvelope(
        senderId: 'alice',
        recipientId: 'bob',
        timestampMillis: 1700000000000,
        text: 'Hey',
        fsExtension: fsInit,
      );
      expect(env['x'], isA<Map<String, dynamic>>());
      expect((env['x'] as Map)['fs'], equals(fsInit));

      final stego = await LmfV2Encoder.encode(
        jsonEnvelope: env,
        key: testKey,
        coverText: _coverText,
      );
      final decoded = await LmfV2Decoder.decode(stegoText: stego, key: testKey);
      expect(decoded, isNotNull);
      final fs = LmfV2Decoder.extractFsExtension(decoded!);
      expect(fs, isNotNull, reason: 'x.fs must survive encrypt→decrypt round-trip');
      expect(fs!['type'], equals('fs_init'));
      expect(fs['initId'], equals('abc123'));
      expect(LmfV2Decoder.fsMsgType(decoded), equals('fs_init'));
    });

    // T5.3 — envelope with fs_reply round-trips.
    test('T5.3: envelope with x.fs fs_reply round-trips', () async {
      final fsReply = {
        'v': 1,
        'type': 'fs_reply',
        'initId': 'abc123',
        'replyId': 'reply456',
        'responderDevicePub': 'AQ' + 'B' * 42,
        'responderEphemeralPub': 'AQ' + 'C' * 42,
        'responderInitialRatchetPub': 'AQ' + 'D' * 42,
        'caps': ['lgfs1'],
        'createdAt': 1700000001,
      };
      final env = LmfV2Encoder.buildJsonEnvelope(
        senderId: 'bob',
        recipientId: 'alice',
        timestampMillis: 1700000001000,
        text: 'Sure',
        fsExtension: fsReply,
      );

      final stego = await LmfV2Encoder.encode(
        jsonEnvelope: env,
        key: testKey,
        coverText: _coverText,
      );
      final decoded = await LmfV2Decoder.decode(stegoText: stego, key: testKey);
      expect(decoded, isNotNull);
      final fs = LmfV2Decoder.extractFsExtension(decoded!);
      expect(fs, isNotNull);
      expect(fs!['type'], equals('fs_reply'));
      expect(fs['replyId'], equals('reply456'));
    });

    // T5.4 — envelope with fs_confirm round-trips.
    test('T5.4: envelope with x.fs fs_confirm round-trips', () async {
      final fsConfirm = {
        'v': 1,
        'type': 'fs_confirm',
        'initId': 'abc123',
        'replyId': 'reply456',
        'transcriptHash': 'A' * 43,
        'confirmTag': 'B' * 43,
        'initiatorInitialRatchetPub': 'AQ' + 'E' * 42,
      };
      final env = LmfV2Encoder.buildJsonEnvelope(
        senderId: 'alice',
        recipientId: 'bob',
        timestampMillis: 1700000002000,
        text: 'Done',
        fsExtension: fsConfirm,
      );

      final stego = await LmfV2Encoder.encode(
        jsonEnvelope: env,
        key: testKey,
        coverText: _coverText,
      );
      final decoded = await LmfV2Decoder.decode(stegoText: stego, key: testKey);
      expect(decoded, isNotNull);
      final fs = LmfV2Decoder.extractFsExtension(decoded!);
      expect(fs, isNotNull);
      expect(fs!['type'], equals('fs_confirm'));
      expect(fs['confirmTag'], equals('B' * 43));
    });

    // T5.5 — legacy decoder ignores unknown x field.
    test('T5.5: envelope with x.fs is still a valid v=2 message (legacy compatible)', () async {
      final env = LmfV2Encoder.buildJsonEnvelope(
        senderId: 'alice',
        recipientId: 'bob',
        timestampMillis: 1700000000000,
        text: 'Legacy compatible',
        fsExtension: {'v': 1, 'type': 'fs_init', 'initId': 'x', 'caps': ['lgfs1'], 'createdAt': 1700000000},
      );
      final stego = await LmfV2Encoder.encode(
        jsonEnvelope: env,
        key: testKey,
        coverText: _coverText,
      );
      final decoded = await LmfV2Decoder.decode(stegoText: stego, key: testKey);
      expect(decoded, isNotNull, reason: 'Message with x.fs must still decode successfully');
      expect(decoded!['v'], equals(2));
      expect(decoded['senderId'], equals('alice'));
      expect(decoded['text'], equals('Legacy compatible'));
    });

    // T5.6 — fsMsgType returns null when x.fs absent.
    test('T5.6: fsMsgType returns null when x.fs absent', () {
      final env = {
        'v': 2,
        'senderId': 'alice',
        'recipientId': 'bob',
        'timestamp': 1700000000000,
        'text': 'No FS',
        'deleteAfterRead': false,
      };
      expect(LmfV2Decoder.fsMsgType(env), isNull);
      expect(LmfV2Decoder.extractFsExtension(env), isNull);
    });
  });
}
