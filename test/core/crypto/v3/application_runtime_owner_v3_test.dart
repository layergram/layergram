import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/application_runtime_owner_v3.dart';
import 'package:layergram/core/crypto/v3/identity_runtime_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';

void main() {
  const mnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  LocalIdentity local(String identityId) => LocalIdentity(
        identityId: identityId,
        publicKeyBase64: 'legacy-public-$identityId',
        fingerprint: 'legacy-fingerprint-$identityId',
        displayName: 'Alice',
        mnemonic: mnemonic,
      );

  test('owner reuses one context and drains it before passphrase expulsion',
      () async {
    final identityRuntime = V3IdentityRuntime(
      seedService: SeedService(),
      backendLoader: _OwnerMlKemBackend.new,
    );
    final opened = <_FakeApplicationRuntime>[];
    final owner = V3ApplicationRuntimeOwner<_FakeApplicationRuntime>(
      identityRuntime: identityRuntime,
      runtimeFactory: ({required localIdentity, required scopeToken}) async {
        final runtime = _FakeApplicationRuntime(localIdentity);
        opened.add(runtime);
        return runtime;
      },
    );

    final primary = await owner.open(
      recoveryIdentity: local('legacy-a'),
      scopeToken: 'primary-scope001',
      contextId: 'primary|legacy-a|primary-scope001',
      usePassphraseIdentity: false,
    );
    final reused = await owner.open(
      recoveryIdentity: local('legacy-a'),
      scopeToken: 'primary-scope001',
      contextId: 'primary|legacy-a|primary-scope001',
      usePassphraseIdentity: false,
    );
    expect(identical(primary, reused), isTrue);
    expect(opened, hasLength(1));

    await identityRuntime.activatePassphrase(
      mnemonic: mnemonic,
      passphrase: 'hidden context',
      displayName: 'Hidden Alice',
    );
    final passphrase = await owner.open(
      recoveryIdentity: local('legacy-a'),
      scopeToken: 'primary-scope001',
      contextId: 'passphrase|hidden|primary-scope001',
      usePassphraseIdentity: true,
    );
    expect(primary.isClosed, isTrue);
    expect(primary.identityWasOpenWhenClosed, isTrue);
    expect(opened, hasLength(2));

    final passphraseIdentity = passphrase.identity;
    await identityRuntime.deactivatePassphrase();
    expect(passphrase.isClosed, isTrue);
    expect(passphrase.identityWasOpenWhenClosed, isTrue);
    expect(passphraseIdentity.isClosed, isTrue);
    expect(owner.current, isNull);

    await owner.close();
    await identityRuntime.close();
  });

  test('replacing a primary identity evicts its session before key close',
      () async {
    final identityRuntime = V3IdentityRuntime(
      seedService: SeedService(),
      backendLoader: _OwnerMlKemBackend.new,
    );
    late _FakeApplicationRuntime session;
    final owner = V3ApplicationRuntimeOwner<_FakeApplicationRuntime>(
      identityRuntime: identityRuntime,
      runtimeFactory: ({required localIdentity, required scopeToken}) async {
        return session = _FakeApplicationRuntime(localIdentity);
      },
    );

    await owner.open(
      recoveryIdentity: local('legacy-a'),
      scopeToken: 'primary-scope001',
      contextId: 'primary|legacy-a|primary-scope001',
      usePassphraseIdentity: false,
    );
    final oldIdentity = session.identity;

    await identityRuntime.primaryPublicIdentity(local('legacy-b'));
    expect(session.isClosed, isTrue);
    expect(session.identityWasOpenWhenClosed, isTrue);
    expect(oldIdentity.isClosed, isTrue);
    expect(owner.current, isNull);

    await owner.close();
    await identityRuntime.close();
  });

  test('concurrent expulsion prevents an opening runtime from escaping',
      () async {
    final identityRuntime = V3IdentityRuntime(
      seedService: SeedService(),
      backendLoader: _OwnerMlKemBackend.new,
    );
    await identityRuntime.activatePassphrase(
      mnemonic: mnemonic,
      passphrase: 'hidden context',
      displayName: 'Hidden Alice',
    );
    final factoryStarted = Completer<void>();
    final allowFactory = Completer<void>();
    late _FakeApplicationRuntime session;
    final owner = V3ApplicationRuntimeOwner<_FakeApplicationRuntime>(
      identityRuntime: identityRuntime,
      runtimeFactory: ({required localIdentity, required scopeToken}) async {
        session = _FakeApplicationRuntime(localIdentity);
        factoryStarted.complete();
        await allowFactory.future;
        return session;
      },
    );

    final opening = owner.open(
      recoveryIdentity: local('legacy-a'),
      scopeToken: 'primary-scope001',
      contextId: 'passphrase|hidden|primary-scope001',
      usePassphraseIdentity: true,
    );
    await factoryStarted.future;
    final expulsion = identityRuntime.deactivatePassphrase();
    await Future<void>.delayed(Duration.zero);
    expect(session.isClosed, isFalse);
    expect(session.identity.isClosed, isFalse);

    allowFactory.complete();
    await expectLater(
      opening,
      throwsA(isA<V3ApplicationRuntimeContextSuperseded>()),
    );
    await expulsion;
    expect(session.isClosed, isTrue);
    expect(session.identityWasOpenWhenClosed, isTrue);
    expect(session.identity.isClosed, isTrue);

    await owner.close();
    await identityRuntime.close();
  });

  test('a newer context request prevents a stale runtime from reopening',
      () async {
    final identityRuntime = V3IdentityRuntime(
      seedService: SeedService(),
      backendLoader: _OwnerMlKemBackend.new,
    );
    final firstStarted = Completer<void>();
    final allowFirst = Completer<void>();
    final opened = <_FakeApplicationRuntime>[];
    var factoryCalls = 0;
    final owner = V3ApplicationRuntimeOwner<_FakeApplicationRuntime>(
      identityRuntime: identityRuntime,
      runtimeFactory: ({required localIdentity, required scopeToken}) async {
        final runtime = _FakeApplicationRuntime(localIdentity);
        opened.add(runtime);
        if (factoryCalls++ == 0) {
          firstStarted.complete();
          await allowFirst.future;
        }
        return runtime;
      },
    );

    final stale = owner.open(
      recoveryIdentity: local('legacy-a'),
      scopeToken: 'primary-scope001',
      contextId: 'primary|legacy-a|primary-scope001',
      usePassphraseIdentity: false,
    );
    await firstStarted.future;
    final latest = owner.open(
      recoveryIdentity: local('legacy-a'),
      scopeToken: 'primary-scope002',
      contextId: 'primary|legacy-a|primary-scope002',
      usePassphraseIdentity: false,
    );
    allowFirst.complete();

    await expectLater(
      stale,
      throwsA(isA<V3ApplicationRuntimeContextSuperseded>()),
    );
    final active = await latest;
    expect(opened, hasLength(2));
    expect(opened.first.isClosed, isTrue);
    expect(active, same(opened.last));
    expect(owner.current, same(active));

    await owner.close();
    await identityRuntime.close();
  });
}

final class _FakeApplicationRuntime implements V3ApplicationRuntimeSession {
  _FakeApplicationRuntime(this.identity);

  final V3LocalIdentityHandle identity;
  bool isClosed = false;
  bool? identityWasOpenWhenClosed;

  @override
  Future<void> close() async {
    if (isClosed) return;
    identityWasOpenWhenClosed = !identity.isClosed;
    isClosed = true;
  }
}

final class _OwnerPrivateKeyHandle implements MlKem768PrivateKeyHandle {
  @override
  bool isClosed = false;

  @override
  Future<void> close() async {
    isClosed = true;
  }
}

final class _OwnerMlKemBackend implements MlKem768Backend {
  @override
  String get implementationId => 'runtime-owner-test-ml-kem';

  @override
  Future<bool> selfTest() async => true;

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) async {
    return MlKem768KeyPair(
      publicKey: Uint8List.fromList(
        List<int>.generate(
          MlKem768.publicKeyBytes,
          (index) => (seed[index % seed.length] + index) % 255 + 1,
        ),
      ),
      privateKeyHandle: _OwnerPrivateKeyHandle(),
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
