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
import 'package:layergram/features/contact_verification/contact_sas_service.dart';

// Canonical base64 encodings of 32-byte vectors. These are only used as
// opaque input to SAS derivation; they do not need to be valid X25519
// public keys, but they must round-trip through `base64Decode` in strict
// mode, so we generate them from fixed byte arrays.
final _aliceKey = base64Encode(List<int>.filled(32, 0x01));
final _bobKey = base64Encode(List<int>.filled(32, 0x02));
final _carolKey = base64Encode(List<int>.filled(32, 0x03));

void main() {
  late ContactSasService service;

  setUp(() {
    service = const ContactSasService();
  });

  group('ContactSasService.derive', () {
    test('produces exactly 6 decimal digits zero-padded on the left', () async {
      final code = await service.derive(
        localPublicKeyBase64: _aliceKey,
        peerPublicKeyBase64: _bobKey,
      );

      expect(code.digits, hasLength(6));
      expect(RegExp(r'^[0-9]{6}$').hasMatch(code.digits), isTrue);
    });

    test('produces exactly 4 emoji indices inside the palette range', () async {
      final code = await service.derive(
        localPublicKeyBase64: _aliceKey,
        peerPublicKeyBase64: _bobKey,
      );

      expect(code.emojiIndices, hasLength(4));
      for (final idx in code.emojiIndices) {
        expect(idx, greaterThanOrEqualTo(0));
        expect(idx, lessThan(ContactSasService.emojiPalette.length));
      }
    });

    test('resolves emoji glyphs deterministically from the palette', () async {
      final code = await service.derive(
        localPublicKeyBase64: _aliceKey,
        peerPublicKeyBase64: _bobKey,
      );

      expect(code.emojiGlyphs, hasLength(4));
      for (var i = 0; i < code.emojiGlyphs.length; i++) {
        expect(
          code.emojiGlyphs[i],
          ContactSasService.emojiPalette[code.emojiIndices[i]],
        );
      }
    });

    test('is deterministic for the same public-key pair', () async {
      final first = await service.derive(
        localPublicKeyBase64: _aliceKey,
        peerPublicKeyBase64: _bobKey,
      );
      final second = await service.derive(
        localPublicKeyBase64: _aliceKey,
        peerPublicKeyBase64: _bobKey,
      );

      expect(first.digits, second.digits);
      expect(first.emojiIndices, second.emojiIndices);
    });

    test('is symmetric: Alice viewing Bob derives the same SAS as Bob viewing Alice',
        () async {
      final aliceView = await service.derive(
        localPublicKeyBase64: _aliceKey,
        peerPublicKeyBase64: _bobKey,
      );
      final bobView = await service.derive(
        localPublicKeyBase64: _bobKey,
        peerPublicKeyBase64: _aliceKey,
      );

      expect(aliceView.digits, bobView.digits);
      expect(aliceView.emojiIndices, bobView.emojiIndices);
    });

    test('differs when a key is swapped for a different one (MITM sanity)',
        () async {
      final genuine = await service.derive(
        localPublicKeyBase64: _aliceKey,
        peerPublicKeyBase64: _bobKey,
      );
      final mitm = await service.derive(
        localPublicKeyBase64: _aliceKey,
        peerPublicKeyBase64: _carolKey,
      );

      final sameDigits = genuine.digits == mitm.digits;
      final sameEmoji = const ListEquality<int>()
          .equals(genuine.emojiIndices, mitm.emojiIndices);
      expect(sameDigits && sameEmoji, isFalse);
    });

    test('differs across many random key pairs (probabilistic uniqueness)',
        () async {
      final seenDigits = <String>{};
      for (var i = 0; i < 32; i++) {
        final a = await _freshX25519PublicKeyBase64();
        final b = await _freshX25519PublicKeyBase64();
        final code = await service.derive(
          localPublicKeyBase64: a,
          peerPublicKeyBase64: b,
        );
        seenDigits.add(code.digits);
      }

      expect(seenDigits.length, greaterThan(28));
    });

    test('accepts base64url-encoded public keys equivalently to standard base64',
        () async {
      final standard = await service.derive(
        localPublicKeyBase64: _aliceKey,
        peerPublicKeyBase64: _bobKey,
      );
      final url = await service.derive(
        localPublicKeyBase64: _aliceKey.replaceAll('+', '-').replaceAll('/', '_'),
        peerPublicKeyBase64: _bobKey.replaceAll('+', '-').replaceAll('/', '_'),
      );

      expect(standard.digits, url.digits);
      expect(standard.emojiIndices, url.emojiIndices);
    });

    test('rejects empty public-key inputs', () async {
      expect(
        () => service.derive(
          localPublicKeyBase64: '',
          peerPublicKeyBase64: _bobKey,
        ),
        throwsArgumentError,
      );
      expect(
        () => service.derive(
          localPublicKeyBase64: _aliceKey,
          peerPublicKeyBase64: '',
        ),
        throwsArgumentError,
      );
    });
  });

  group('ContactSasService.emojiPalette', () {
    test('has exactly 64 entries, as the derivation relies on 6-bit indices', () {
      expect(ContactSasService.emojiPalette, hasLength(64));
    });

    test('contains unique glyphs so different indices map to different emoji', () {
      final asSet = ContactSasService.emojiPalette.toSet();
      expect(asSet.length, ContactSasService.emojiPalette.length);
    });
  });
}

Future<String> _freshX25519PublicKeyBase64() async {
  final algo = X25519();
  final pair = await algo.newKeyPair();
  final pub = await pair.extractPublicKey();
  return base64Encode(Uint8List.fromList(pub.bytes));
}

class ListEquality<T> {
  const ListEquality();

  bool equals(List<T>? a, List<T>? b) {
    if (identical(a, b)) return true;
    if (a == null || b == null) return false;
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
