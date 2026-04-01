import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/identity_link_codec.dart';
import 'package:layergram/core/crypto/models.dart';

void main() {
  group('IdentityLinkCodec', () {
    final testIdentity = LocalIdentity(
      identityId: 'test-id-12345',
      publicKeyBase64: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...',
      fingerprint: 'A1B2:C3D4:E5F6',
      displayName: 'Alice',
      mnemonic: 'test mnemonic phrase here',
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
      expect(() => IdentityLinkCodec.decode('http://i/sometoken.checksum'), throwsA(anything));
      expect(() => IdentityLinkCodec.decode('layergram://x/sometoken.checksum'), throwsA(anything));
      expect(() => IdentityLinkCodec.decode('layergram://i/sometokenwithoutdot'), throwsA(anything));
      
      final link = IdentityLinkCodec.encode(testIdentity);
      final corrupted1 = '${link.substring(0, link.length - 2)}XX';
      expect(() => IdentityLinkCodec.decode(corrupted1), throwsA(anything));
      
      final parts = link.split('.');
      final corruptedData = '${parts[0].substring(0, parts[0].length - 1)}X';
      final corrupted2 = '$corruptedData.${parts[1]}';
      expect(() => IdentityLinkCodec.decode(corrupted2), throwsA(anything));
    });
  });
}
