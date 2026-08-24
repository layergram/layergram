import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/identity_runtime_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';

void main() {
  const mnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  LocalIdentity local({String name = 'Alice'}) {
    return LocalIdentity(
      identityId: 'legacy-identity',
      publicKeyBase64: 'legacy-public-key',
      fingerprint: 'legacy-fingerprint',
      displayName: name,
      mnemonic: mnemonic,
    );
  }

  test('runtime lazily owns one native identity handle and closes it',
      () async {
    final backend = _RuntimeMlKemBackend();
    var loaderCalls = 0;
    final runtime = V3IdentityRuntime(
      seedService: SeedService(),
      backendLoader: () {
        loaderCalls++;
        return backend;
      },
    );

    final first = await runtime.primaryPublicIdentity(local());
    final renamed = await runtime.primaryPublicIdentity(local(name: 'Renamed'));

    expect(loaderCalls, 1);
    expect(backend.keyPairCalls, 1);
    expect(first.identityId, renamed.identityId);
    expect(renamed.displayName, 'Renamed');
    expect(backend.handle?.isClosed, isFalse);

    await runtime.close();
    expect(backend.handle?.isClosed, isTrue);
    await expectLater(
      runtime.primaryPublicIdentity(local()),
      throwsStateError,
    );
  });

  test('passphrase handle is isolated, replaceable and expellable', () async {
    final backend = _RuntimeMlKemBackend();
    final runtime = V3IdentityRuntime(
      seedService: SeedService(),
      backendLoader: () => backend,
    );

    final primary = await runtime.primaryPublicIdentity(local());
    final first = await runtime.activatePassphrase(
      mnemonic: mnemonic,
      passphrase: 'first secret context',
      displayName: 'Hidden Alice',
    );
    final firstHandle = backend.handles.last;
    final second = await runtime.activatePassphrase(
      mnemonic: mnemonic,
      passphrase: 'second secret context',
      displayName: 'Other Alice',
    );

    expect(first.identityId, isNot(primary.identityId));
    expect(second.identityId, isNot(first.identityId));
    expect(firstHandle.isClosed, isTrue);
    expect(runtime.activePassphraseHandle.isClosed, isFalse);

    await runtime.deactivatePassphrase();
    expect(backend.handles.last.isClosed, isTrue);
    expect(() => runtime.activePassphraseHandle, throwsStateError);
    await runtime.close();
  });

  test('registered session owner drains before identity handle destruction',
      () async {
    final backend = _RuntimeMlKemBackend();
    final runtime = V3IdentityRuntime(
      seedService: SeedService(),
      backendLoader: () => backend,
    );
    await runtime.activatePassphrase(
      mnemonic: mnemonic,
      passphrase: 'hidden context',
      displayName: 'Hidden Alice',
    );
    final identity = runtime.activePassphraseHandle;
    var evictionCalls = 0;
    final registration = runtime.registerHandleEvictionHandler((handle) async {
      evictionCalls++;
      expect(identical(handle, identity), isTrue);
      expect(handle.isClosed, isFalse);
    });

    await runtime.deactivatePassphrase();
    expect(evictionCalls, 1);
    expect(identity.isClosed, isTrue);

    runtime.unregisterHandleEvictionHandler(registration);
    await runtime.close();
  });
}

final class _RuntimePrivateKeyHandle implements MlKem768PrivateKeyHandle {
  @override
  bool isClosed = false;

  @override
  Future<void> close() async {
    isClosed = true;
  }
}

final class _RuntimeMlKemBackend implements MlKem768Backend {
  int keyPairCalls = 0;
  _RuntimePrivateKeyHandle? handle;
  final List<_RuntimePrivateKeyHandle> handles = [];

  @override
  String get implementationId => 'runtime-test-ml-kem';

  @override
  Future<bool> selfTest() async => true;

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) async {
    keyPairCalls++;
    final nextHandle = _RuntimePrivateKeyHandle();
    handle = nextHandle;
    handles.add(nextHandle);
    return MlKem768KeyPair(
      publicKey: Uint8List.fromList(
        List<int>.generate(
          MlKem768.publicKeyBytes,
          (index) => (seed[index % seed.length] + index) % 255 + 1,
        ),
      ),
      privateKeyHandle: nextHandle,
    );
  }

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async => true;

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) {
    throw UnimplementedError();
  }

  @override
  Future<Uint8List> decapsulate(
    MlKem768PrivateKeyHandle privateKeyHandle,
    Uint8List ciphertext,
  ) {
    throw UnimplementedError();
  }
}
