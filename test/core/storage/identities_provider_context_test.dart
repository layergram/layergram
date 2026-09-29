import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/identity_manager.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/identities_repository.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/local_identity_vault.dart';
import 'package:layergram/core/storage/local_storage_security_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';

class _DelayedContext extends LocalStorageSecurityService {
  _DelayedContext(this.pending)
      : super(
          secureStorage: SecureStorageService(),
          localIdentityVault:
              LocalIdentityVault(secureStorage: SecureStorageService()),
        );
  final Completer<LocalStorageContext?> pending;
  @override
  Future<LocalStorageContext?> contextForIdentity(String identityId) =>
      pending.future;
}

class _NoLocalIdentity extends IdentityManager {
  _NoLocalIdentity()
      : super(
          seedService: SeedService(),
          localIdentityVault:
              LocalIdentityVault(secureStorage: SecureStorageService()),
        );
  @override
  Future<LocalIdentity?> getLocalIdentity() async => null;
}

void main() {
  late Directory temporary;
  final keyBytes = Uint8List(32)..fillRange(0, 32, 0x42);
  setUp(() async {
    temporary = await Directory.systemTemp.createTemp('lg-contact-context-');
    Hive.init(temporary.path);
    await Hive.openBox<Map>(LocalDatabase.identitiesBoxName);
  });
  tearDown(() async {
    await Hive.close();
    await temporary.delete(recursive: true);
  });

  ProviderContainer open(Completer<LocalStorageContext?> pending) {
    final container = ProviderContainer(overrides: [
      localStorageSecurityProvider.overrideWithValue(_DelayedContext(pending)),
      identityManagerProvider.overrideWithValue(_NoLocalIdentity()),
    ]);
    container.read(activeIdentityIdProvider.notifier).state = 'local-owner';
    return container;
  }

  LocalStorageContext context() => LocalStorageContext(
        scopeToken: 'contacts-test-scope',
        contactsKey: SecretKey(keyBytes),
        chatMetaKey: SecretKey(Uint8List(32)),
      );

  test('cold contact provider waits for its asynchronous encryption context',
      () async {
    final contact = RemoteIdentity(
      identityId: 'remote-contact',
      publicKeyBase64: 'public-test-key',
      fingerprint: 'contact-test-fingerprint',
      displayName: 'Contact',
      verified: false,
    );
    final seed = IdentitiesRepository(ownerIdentityId: 'local-owner');
    await seed.setActiveContext(
        scopeToken: 'contacts-test-scope',
        encryptionKey: SecretKey(keyBytes),
        selfIdentity: null);
    await seed.upsertRemoteIdentity(contact);
    seed.dispose();

    final barrier = Completer<LocalStorageContext?>();
    final container = open(barrier);
    try {
      final repository = container.read(identitiesRepositoryProvider);
      var settledBeforeContext = false;
      final ready = repository.waitForReadyContext();
      unawaited(ready.then<void>((_) => settledBeforeContext = true,
          onError: (Object _) => settledBeforeContext = true));
      await Future<void>.delayed(Duration.zero);
      expect(settledBeforeContext, isFalse,
          reason: 'A cold keyboard handoff must wait instead of refusing it');
      barrier.complete(context());
      await ready;
      expect((await repository.watchRemote().first).single.identityId,
          contact.identityId);
    } finally {
      if (!barrier.isCompleted) barrier.complete(null);
      await Future<void>.delayed(Duration.zero);
      container.dispose();
    }
  });

  test('missing contact context still fails closed after the provider settles',
      () async {
    final barrier = Completer<LocalStorageContext?>();
    final container = open(barrier);
    try {
      final ready =
          container.read(identitiesRepositoryProvider).waitForReadyContext();
      final failure = expectLater(ready, throwsStateError);
      barrier.complete(null);
      await failure;
    } finally {
      container.dispose();
    }
  });

  test('changing identity during context loading never admits the old owner',
      () async {
    final barrier = Completer<LocalStorageContext?>();
    final container = open(barrier);
    try {
      final repository = container.read(identitiesRepositoryProvider);
      final ready = repository.waitForReadyContext();
      final failure = expectLater(ready, throwsStateError);
      container.read(activeIdentityIdProvider.notifier).state = 'other-owner';
      await container.pump();
      barrier.complete(context());
      await failure;
    } finally {
      if (!barrier.isCompleted) barrier.complete(null);
      container.dispose();
    }
  });
}
