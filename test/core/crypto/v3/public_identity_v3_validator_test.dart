import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3_validator.dart';

void main() {
  late _ValidationBackend backend;
  late V3PublicIdentityValidator validator;
  late V3PublicIdentity identity;

  setUp(() {
    backend = _ValidationBackend();
    validator = V3PublicIdentityValidator(mlKem768Backend: backend);
    identity = V3PublicIdentity(
      x25519PublicKey: Uint8List.fromList(
        List<int>.generate(
          V3PublicIdentityCodec.x25519PublicKeyBytes,
          (index) => index + 1,
        ),
      ),
      mlKem768PublicKey: Uint8List.fromList(
        List<int>.generate(
          MlKem768.publicKeyBytes,
          (index) => (index % 251) + 1,
        ),
      ),
      displayName: 'Alice',
    );
  });

  test('strict binary, token, and link imports return validated identities',
      () async {
    final binary = await validator.decodeBinary(
      V3PublicIdentityCodec.encodeBinary(identity),
    );
    final token = await validator.decodeToken(
      V3PublicIdentityCodec.encodeToken(identity),
    );
    final link = await validator.decodeLink(
      V3PublicIdentityCodec.encodeLink(identity),
    );

    expect(binary.publicIdentity.identityId, identity.identityId);
    expect(token.publicIdentity.identityId, identity.identityId);
    expect(link.publicIdentity.identityId, identity.identityId);
    expect(backend.selfTestCalls, 3);
    expect(backend.validationCalls, 3);
  });

  test('malformed encoding fails before invoking the native backend', () async {
    final tampered = V3PublicIdentityCodec.encodeBinary(identity)..[0] ^= 1;

    await expectLater(validator.decodeBinary(tampered), throwsFormatException);
    expect(backend.selfTestCalls, 0);
    expect(backend.validationCalls, 0);
  });

  test('backend self-test failure blocks identity use', () async {
    backend.selfTestResult = false;

    await expectLater(validator.validate(identity), throwsStateError);
    expect(backend.selfTestCalls, 1);
    expect(backend.validationCalls, 0);
  });

  test('invalid ML-KEM public key fails closed', () async {
    backend.validationResult = false;

    await expectLater(validator.validate(identity), throwsFormatException);
    expect(backend.validationCalls, 1);
  });
}

final class _ValidationBackend implements MlKem768Backend {
  bool selfTestResult = true;
  bool validationResult = true;
  int selfTestCalls = 0;
  int validationCalls = 0;

  @override
  String get implementationId => 'test-only-validation-backend';

  @override
  Future<bool> selfTest() async {
    selfTestCalls++;
    return selfTestResult;
  }

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async {
    validationCalls++;
    expect(publicKey, hasLength(MlKem768.publicKeyBytes));
    return validationResult;
  }

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) {
    throw UnsupportedError('not needed by public identity validation tests');
  }

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) {
    throw UnsupportedError('not needed by public identity validation tests');
  }

  @override
  Future<Uint8List> decapsulate(
    MlKem768PrivateKeyHandle privateKeyHandle,
    Uint8List ciphertext,
  ) {
    throw UnsupportedError('not needed by public identity validation tests');
  }
}
