import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:qr/qr.dart';

void main() {
  V3PublicIdentity identity({
    String displayName = 'Alice',
    int xOffset = 0,
    int pqOffset = 0,
  }) {
    return V3PublicIdentity(
      x25519PublicKey: Uint8List.fromList(
        List<int>.generate(
          V3PublicIdentityCodec.x25519PublicKeyBytes,
          (index) => ((index + xOffset) % 255) + 1,
        ),
      ),
      mlKem768PublicKey: Uint8List.fromList(
        List<int>.generate(
          MlKem768.publicKeyBytes,
          (index) => ((index + pqOffset) % 255) + 1,
        ),
      ),
      displayName: displayName,
    );
  }

  test('binary round-trip preserves every public-key byte', () {
    final original = identity();
    final encoded = V3PublicIdentityCodec.encodeBinary(original);
    final decoded = V3PublicIdentityCodec.decodeBinary(encoded);

    expect(decoded.x25519PublicKey, orderedEquals(original.x25519PublicKey));
    expect(
      decoded.mlKem768PublicKey,
      orderedEquals(original.mlKem768PublicKey),
    );
    expect(decoded.mlKem768PublicKey, hasLength(MlKem768.publicKeyBytes));
    expect(decoded.displayName, 'Alice');
    expect(decoded.identityId, original.identityId);
    expect(decoded.fingerprint, original.fingerprint);
  });

  test('text token and deep link carry the complete same identity', () {
    final original = identity();
    final token = V3PublicIdentityCodec.encodeToken(original);
    final link = V3PublicIdentityCodec.encodeLink(original);

    expect(token, startsWith(V3PublicIdentityCodec.tokenPrefix));
    expect(
      token.length,
      lessThanOrEqualTo(V3PublicIdentityCodec.maxTokenCharacters),
    );
    expect(link, startsWith('layergram://i/v3.'));
    expect(link.length, lessThan(4096));
    expect(
      V3PublicIdentityCodec.decodeToken(token).mlKem768PublicKey,
      orderedEquals(original.mlKem768PublicKey),
    );
    expect(
      V3PublicIdentityCodec.decodeLink(link).identityId,
      original.identityId,
    );
  });

  test('maximum-size full identity fits one static QR at level H', () {
    final original = identity(displayName: 'A' * 32);
    final bytes = V3PublicIdentityCodec.encodeBinary(original);

    expect(bytes, hasLength(V3PublicIdentityCodec.maxBinaryBytes));
    expect(bytes, hasLength(1270));

    final qr = QrCode.fromUint8List(
      data: bytes,
      errorCorrectLevel: QrErrorCorrectLevel.H,
    );
    final rendered = QrImage(qr);
    final token = V3PublicIdentityCodec.encodeToken(original);

    expect(qr.typeNumber, 40);
    expect(rendered.moduleCount, 177);
    expect(token, hasLength(V3PublicIdentityCodec.maxTokenCharacters));
    expect(V3PublicIdentityCodec.maxTokenCharacters, 1697);
  });

  test('both key components are bound to the identity ID', () {
    final baseline = identity();
    final changedX = identity(xOffset: 1);
    final changedPq = identity(pqOffset: 1);

    expect(changedX.identityId, isNot(baseline.identityId));
    expect(changedPq.identityId, isNot(baseline.identityId));
  });

  test('renaming does not rotate the cryptographic identity', () {
    final alice = identity(displayName: 'Alice');
    final renamed = identity(displayName: 'Alice Smith');

    expect(renamed.identityId, alice.identityId);
    expect(renamed.fingerprint, alice.fingerprint);
  });

  test('tampering and non-canonical encodings fail closed', () {
    final encoded = V3PublicIdentityCodec.encodeBinary(identity());
    final tampered = Uint8List.fromList(encoded)..[100] ^= 0x01;
    expect(
      () => V3PublicIdentityCodec.decodeBinary(tampered),
      throwsFormatException,
    );

    final unknownSuite = Uint8List.fromList(encoded)..[3] = 0xff;
    expect(
      () => V3PublicIdentityCodec.decodeBinary(unknownSuite),
      throwsFormatException,
    );

    final unknownFlags = Uint8List.fromList(encoded)..[4] = 0x01;
    expect(
      () => V3PublicIdentityCodec.decodeBinary(unknownFlags),
      throwsFormatException,
    );

    final withTrailingByte = Uint8List.fromList([...encoded, 0]);
    expect(
      () => V3PublicIdentityCodec.decodeBinary(withTrailingByte),
      throwsFormatException,
    );

    final token = V3PublicIdentityCodec.encodeToken(identity());
    expect(
      () => V3PublicIdentityCodec.decodeToken('$token='),
      throwsFormatException,
    );

    final link = V3PublicIdentityCodec.encodeLink(identity());
    expect(
      () => V3PublicIdentityCodec.decodeLink('$link?source=profile'),
      throwsFormatException,
    );
    expect(
      () => V3PublicIdentityCodec.decodeLink('$link#identity'),
      throwsFormatException,
    );
  });

  test('constructors reject shortened or all-zero keys and oversized names',
      () {
    expect(
      () => V3PublicIdentity(
        x25519PublicKey:
            Uint8List(V3PublicIdentityCodec.x25519PublicKeyBytes - 1),
        mlKem768PublicKey: Uint8List(MlKem768.publicKeyBytes),
      ),
      throwsArgumentError,
    );
    expect(
      () => V3PublicIdentity(
        x25519PublicKey: Uint8List(V3PublicIdentityCodec.x25519PublicKeyBytes),
        mlKem768PublicKey: Uint8List(MlKem768.publicKeyBytes),
      ),
      throwsArgumentError,
    );
    expect(
      () => identity(displayName: 'A' * 33),
      throwsArgumentError,
    );
  });
}
