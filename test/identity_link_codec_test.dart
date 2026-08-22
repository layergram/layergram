import 'dart:convert';
import 'dart:typed_data';

import 'package:base32/base32.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/identity_link_codec.dart';
import 'package:layergram/core/crypto/models.dart';

void main() {
  group('IdentityLinkCodec', () {
    final testIdentity = _identityFor(
      Uint8List.fromList(List<int>.generate(32, (index) => index + 1)),
    );

    test('encode and decode works correctly', () {
      final link = IdentityLinkCodec.encode(testIdentity);
      expect(link, startsWith('layergram://i/'));
      final decoded = IdentityLinkCodec.decode(link);
      expect(decoded.identityId, equals(testIdentity.identityId));
      expect(decoded.publicKeyBase64, equals(testIdentity.publicKeyBase64));
      expect(decoded.fingerprint, equals(testIdentity.fingerprint));
      expect(decoded.displayName, equals(testIdentity.displayName));
    });

    test('decode throws ArgumentError or FormatException on invalid input', () {
      expect(
        () => IdentityLinkCodec.decode('http://i/sometoken.checksum'),
        throwsA(anything),
      );
      expect(
        () => IdentityLinkCodec.decode('layergram://x/sometoken.checksum'),
        throwsA(anything),
      );
      expect(
        () => IdentityLinkCodec.decode('layergram://i/sometokenwithoutdot'),
        throwsA(anything),
      );

      final link = IdentityLinkCodec.encode(testIdentity);
      final corrupted1 = '${link.substring(0, link.length - 2)}XX';
      expect(() => IdentityLinkCodec.decode(corrupted1), throwsA(anything));

      final parts = link.split('.');
      final corruptedData = '${parts[0].substring(0, parts[0].length - 1)}X';
      final corrupted2 = '$corruptedData.${parts[1]}';
      expect(() => IdentityLinkCodec.decode(corrupted2), throwsA(anything));
    });

    test('rejects a legacy identity whose ID or fingerprint is not key-bound',
        () {
      expect(
        () => IdentityLinkCodec.validateLegacyIdentity(
          RemoteIdentity(
            identityId: '${testIdentity.identityId}X',
            publicKeyBase64: testIdentity.publicKeyBase64,
            fingerprint: testIdentity.fingerprint,
            displayName: testIdentity.displayName,
          ),
        ),
        throwsArgumentError,
      );
      expect(
        () => IdentityLinkCodec.validateLegacyIdentity(
          RemoteIdentity(
            identityId: testIdentity.identityId,
            publicKeyBase64: testIdentity.publicKeyBase64,
            fingerprint: '${testIdentity.fingerprint}-00',
            displayName: testIdentity.displayName,
          ),
        ),
        throwsArgumentError,
      );
    });

    test('rejects oversized links before parsing', () {
      expect(
        () => IdentityLinkCodec.decode(
          'layergram://i/${'A' * IdentityLinkCodec.maxLinkCharacters}',
        ),
        throwsArgumentError,
      );
    });
  });
}

LocalIdentity _identityFor(Uint8List publicKey) {
  final hash = sha256.convert(publicKey).bytes;
  final identityId =
      base32.encode(Uint8List.fromList(hash)).replaceAll('=', '');
  final fingerprint = hash
      .take(8)
      .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join('-')
      .toUpperCase();
  return LocalIdentity(
    identityId: identityId,
    publicKeyBase64: base64Encode(publicKey),
    fingerprint: fingerprint,
    displayName: 'Alice',
    mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  );
}
