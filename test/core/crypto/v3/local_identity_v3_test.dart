import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';

void main() {
  const mnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  late SeedService seedService;
  late _FakeMlKem768Backend backend;
  late V3LocalIdentityFactory factory;

  setUp(() {
    seedService = SeedService();
    backend = _FakeMlKem768Backend();
    factory = V3LocalIdentityFactory(
      seedService: seedService,
      mlKem768Backend: backend,
    );
  });

  test('same mnemonic restores the same complete v3 public identity', () async {
    final first = await factory.restorePrimary(
      mnemonic: mnemonic,
      displayName: 'Alice',
    );
    final second = await factory.restorePrimary(
      mnemonic: mnemonic,
      displayName: 'Alice on another device',
    );

    expect(first.publicIdentity.identityId, second.publicIdentity.identityId);
    expect(first.publicIdentity.fingerprint, second.publicIdentity.fingerprint);
    expect(
      first.publicIdentity.x25519PublicKey,
      orderedEquals(second.publicIdentity.x25519PublicKey),
    );
    expect(
      first.publicIdentity.mlKem768PublicKey,
      orderedEquals(second.publicIdentity.mlKem768PublicKey),
    );
    expect(
      V3PublicIdentityCodec.encodeBinary(first.publicIdentity),
      hasLength(1238 + 'Alice'.length),
    );

    await first.close();
    await second.close();
  });

  test('passphrase identity is isolated from the primary identity', () async {
    final primary = await factory.restorePrimary(mnemonic: mnemonic);
    final passphrase = await factory.restorePassphrase(
      mnemonic: mnemonic,
      passphrase: 'correct horse battery staple',
    );
    final restoredPassphrase = await factory.restorePassphrase(
      mnemonic: mnemonic,
      passphrase: 'correct horse battery staple',
      displayName: 'Renamed passphrase identity',
    );

    expect(
      passphrase.publicIdentity.identityId,
      isNot(primary.publicIdentity.identityId),
    );
    expect(
      passphrase.publicIdentity.x25519PublicKey,
      isNot(orderedEquals(primary.publicIdentity.x25519PublicKey)),
    );
    expect(
      passphrase.publicIdentity.mlKem768PublicKey,
      isNot(orderedEquals(primary.publicIdentity.mlKem768PublicKey)),
    );
    expect(
      restoredPassphrase.publicIdentity.identityId,
      passphrase.publicIdentity.identityId,
    );

    await primary.close();
    await passphrase.close();
    await restoredPassphrase.close();
  });

  test('secret derivation buffers are wiped after successful restoration',
      () async {
    final identity = await factory.restorePrimary(mnemonic: mnemonic);

    expect(backend.lastKeyGenerationSeedReference, isNotNull);
    expect(backend.lastKeyGenerationSeedReference, everyElement(0));

    await identity.close();
  });

  test('backend self-test failure stops before private-key generation',
      () async {
    backend.selfTestResult = false;

    await expectLater(
      factory.restorePrimary(mnemonic: mnemonic),
      throwsStateError,
    );
    expect(backend.selfTestCalls, 1);
    expect(backend.keyPairCalls, 0);
  });

  test('invalid backend public key closes the native private handle', () async {
    backend.validatePublicKeyResult = false;

    await expectLater(
      factory.restorePrimary(mnemonic: mnemonic),
      throwsStateError,
    );
    expect(backend.createdHandles, hasLength(1));
    expect(backend.createdHandles.single.isClosed, isTrue);
    expect(backend.lastKeyGenerationSeedReference, everyElement(0));
  });

  test('identity construction failure closes the native private handle',
      () async {
    await expectLater(
      factory.restorePrimary(
        mnemonic: mnemonic,
        displayName: ' not canonical',
      ),
      throwsArgumentError,
    );
    expect(backend.createdHandles.single.isClosed, isTrue);
    expect(backend.lastKeyGenerationSeedReference, everyElement(0));
  });

  test('local identity close is idempotent', () async {
    final identity = await factory.restorePrimary(mnemonic: mnemonic);
    final privateHandle = backend.createdHandles.single;

    expect(identity.isClosed, isFalse);
    await identity.close();
    await identity.close();

    expect(identity.isClosed, isTrue);
    expect(privateHandle.closeCalls, 1);
  });

  test('scoped Aux key is deterministic, isolated and unavailable after close',
      () async {
    final primary = await factory.restorePrimary(mnemonic: mnemonic);
    final passphrase = await factory.restorePassphrase(
      mnemonic: mnemonic,
      passphrase: 'hidden context',
    );
    final primaryKey = await (await primary.deriveAuxStorageKey()).extract();
    final primaryAgain = await (await primary.deriveAuxStorageKey()).extract();
    final passphraseKey =
        await (await passphrase.deriveAuxStorageKey()).extract();
    try {
      expect(primaryKey.bytes, orderedEquals(primaryAgain.bytes));
      expect(primaryKey.bytes, isNot(orderedEquals(passphraseKey.bytes)));
    } finally {
      primaryKey.destroy();
      primaryAgain.destroy();
      passphraseKey.destroy();
    }

    await primary.close();
    expect(() => primary.deriveAuxStorageKey(), throwsStateError);
    await passphrase.close();
  });

  test('invalid mnemonic and empty passphrase fail before the backend',
      () async {
    const invalidMnemonic = 'secret words must never appear in an error';
    Object? mnemonicError;
    try {
      await factory.restorePrimary(mnemonic: invalidMnemonic);
    } catch (error) {
      mnemonicError = error;
    }
    expect(mnemonicError, isA<ArgumentError>());
    expect(mnemonicError.toString(), isNot(contains(invalidMnemonic)));
    expect(
      () => factory.restorePassphrase(
        mnemonic: mnemonic,
        passphrase: '',
      ),
      throwsArgumentError,
    );
    expect(backend.selfTestCalls, 0);
  });
}

final class _FakeMlKem768PrivateKeyHandle implements MlKem768PrivateKeyHandle {
  @override
  bool isClosed = false;

  int closeCalls = 0;

  @override
  Future<void> close() async {
    if (isClosed) return;
    isClosed = true;
    closeCalls++;
  }
}

final class _FakeMlKem768Backend implements MlKem768Backend {
  bool selfTestResult = true;
  bool validatePublicKeyResult = true;
  int selfTestCalls = 0;
  int keyPairCalls = 0;
  Uint8List? lastKeyGenerationSeedReference;
  final List<_FakeMlKem768PrivateKeyHandle> createdHandles = [];

  @override
  String get implementationId => 'test-only-ml-kem-768';

  @override
  Future<bool> selfTest() async {
    selfTestCalls++;
    return selfTestResult;
  }

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) async {
    keyPairCalls++;
    lastKeyGenerationSeedReference = seed;
    final digest = sha512.convert(seed).bytes;
    final publicKey = Uint8List(MlKem768.publicKeyBytes);
    for (var index = 0; index < publicKey.length; index++) {
      publicKey[index] = digest[index % digest.length];
    }
    final handle = _FakeMlKem768PrivateKeyHandle();
    createdHandles.add(handle);
    return MlKem768KeyPair(
      publicKey: publicKey,
      privateKeyHandle: handle,
    );
  }

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async {
    expect(publicKey, hasLength(MlKem768.publicKeyBytes));
    return validatePublicKeyResult;
  }

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) {
    throw UnsupportedError('not needed by identity factory tests');
  }

  @override
  Future<Uint8List> decapsulate(
    MlKem768PrivateKeyHandle privateKeyHandle,
    Uint8List ciphertext,
  ) {
    throw UnsupportedError('not needed by identity factory tests');
  }
}
