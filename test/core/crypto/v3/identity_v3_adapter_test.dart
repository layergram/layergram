import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/v3/identity_v3_adapter.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';

void main() {
  V3PublicIdentity identity({String displayName = 'Alice'}) {
    return V3PublicIdentity(
      x25519PublicKey: Uint8List.fromList(
        List<int>.generate(32, (index) => index + 1),
      ),
      mlKem768PublicKey: Uint8List.fromList(
        List<int>.generate(
          MlKem768.publicKeyBytes,
          (index) => (index % 251) + 1,
        ),
      ),
      displayName: displayName,
    );
  }

  test('application record retains and verifies the complete v3 identity', () {
    final original = identity();
    final remote = V3IdentityAdapter.toRemoteIdentity(original);

    expect(remote.protocolVersion, V3PublicIdentityCodec.protocolVersion);
    expect(remote.publicKeyBase64, base64Encode(original.x25519PublicKey));
    expect(remote.publicIdentityBase64, isNotEmpty);

    final decoded = V3IdentityAdapter.fromRemoteIdentity(remote);
    expect(decoded.identityId, original.identityId);
    expect(
      decoded.mlKem768PublicKey,
      orderedEquals(original.mlKem768PublicKey),
    );

    final restored = RemoteIdentity.fromMap(remote.toMap());
    expect(
      V3IdentityAdapter.fromRemoteIdentity(restored).identityId,
      original.identityId,
    );
  });

  test('plain text block carries and binds the same complete identity', () {
    final original = identity();
    final block = V3IdentityAdapter.encodeShareBlock(original);
    final decoded = V3IdentityAdapter.decodeShareBlock(block);

    expect(block, contains('Protocol: layergram/3'));
    expect(block, contains(V3PublicIdentityCodec.encodeToken(original)));
    expect(decoded.identityId, original.identityId);
    expect(
      decoded.mlKem768PublicKey,
      orderedEquals(original.mlKem768PublicKey),
    );

    final mismatched = block.replaceFirst(
      'Identity ID: ${original.identityId}',
      'Identity ID: WRONG',
    );
    expect(
      () => V3IdentityAdapter.decodeShareBlock(mismatched),
      throwsFormatException,
    );
  });

  test('bundle armor is canonical and contact aliases fail closed', () {
    final original = identity();
    final encoded = V3IdentityAdapter.encodePublicBundle(original);
    expect(
      V3IdentityAdapter.decodePublicBundle(encoded).identityId,
      original.identityId,
    );
    expect(
      () => V3IdentityAdapter.decodePublicBundle('$encoded='),
      throwsFormatException,
    );

    final remote = V3IdentityAdapter.toRemoteIdentity(original);
    final aliased = RemoteIdentity(
      identityId: remote.identityId,
      publicKeyBase64: base64Encode(Uint8List(32)..fillRange(0, 32, 7)),
      fingerprint: remote.fingerprint,
      displayName: remote.displayName,
      protocolVersion: remote.protocolVersion,
      publicIdentityBase64: remote.publicIdentityBase64,
    );
    expect(
      () => V3IdentityAdapter.fromRemoteIdentity(aliased),
      throwsFormatException,
    );
  });

  test('old identity maps remain protocol-v2 compatible', () {
    final legacy = RemoteIdentity.fromMap(const {
      'identityId': 'legacy-id',
      'publicKeyBase64': 'legacy-key',
      'fingerprint': 'legacy-fingerprint',
      'displayName': 'Legacy',
    });
    expect(legacy.protocolVersion, 2);
    expect(legacy.publicIdentityBase64, isNull);
  });
}
