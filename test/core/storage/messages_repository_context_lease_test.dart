import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/message_record_cipher.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';

void main() {
  late Directory temporaryDirectory;
  final keyMaterial = Uint8List.fromList(List<int>.generate(32, (i) => i));

  Future<SecretKey> deriveKey(String keyTag) =>
      MessageRecordCipher.deriveKey(keyMaterial, keyTag: keyTag);

  MessageRecord message(String id, {int timestamp = 1}) => MessageRecord(
        id: id,
        senderId: 'me',
        recipientId: 'contact',
        direction: 'outgoing',
        timestamp: timestamp,
        text: 'body-$id',
        keyTag: 'primary',
      );

  Future<MessagesRepository> activeRepository({
    required String scopeToken,
    required SecretKey storageKey,
  }) async {
    final repository = MessagesRepository();
    await repository.setActiveContext(
      scopeToken: scopeToken,
      storageKey: storageKey,
    );
    return repository;
  }

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    temporaryDirectory =
        await Directory.systemTemp.createTemp('layergram_messages_lease_');
    Hive.init(temporaryDirectory.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await temporaryDirectory.delete(recursive: true);
  });

  setUp(() async {
    await Hive.box<Map>(LocalDatabase.messagesBoxName).clear();
  });

  group('MessagesRepositoryContextLease', () {
    test('valid lease can add, read and delete within its context', () async {
      final repository = await activeRepository(
        scopeToken: 'opaque-scope-alpha',
        storageKey: await deriveKey('primary'),
      );
      final lease = await repository.acquireContextLease();

      await repository.addInContext(lease, message('lease-1'));
      expect(
        (await repository.getAllMessagesInContext(lease))
            .map((m) => m.id)
            .toList(),
        ['lease-1'],
      );

      await repository.deleteInContext(lease, 'lease-1');
      expect(await repository.getAllMessagesInContext(lease), isEmpty);
      expect(await repository.getAllMessages(), isEmpty);
      repository.dispose();
    });

    test('a lease from another repository instance is rejected', () async {
      final repositoryA = await activeRepository(
        scopeToken: 'opaque-scope-alpha',
        storageKey: await deriveKey('primary'),
      );
      final repositoryB = await activeRepository(
        scopeToken: 'opaque-scope-beta',
        storageKey: await deriveKey('primary'),
      );
      final leaseA = await repositoryA.acquireContextLease();

      await expectLater(
        repositoryB.addInContext(leaseA, message('foreign')),
        throwsStateError,
      );
      await expectLater(
        repositoryB.getAllMessagesInContext(leaseA),
        throwsStateError,
      );
      await expectLater(
        repositoryB.deleteInContext(leaseA, 'foreign'),
        throwsStateError,
      );
      expect(await repositoryB.getAllMessages(), isEmpty);

      repositoryA.dispose();
      repositoryB.dispose();
    });

    test(
        'synchronous invalidation blocks acquisition while a context key load would be pending',
        () async {
      final storageKey = await deriveKey('primary');
      final repository = await activeRepository(
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );
      final firstLease = await repository.acquireContextLease();

      // Mirrors messagesRepositoryProvider.scheduleStorageContextUpdate():
      // revoke synchronously, before awaiting replacement key material.
      repository.invalidateContextLeases();
      await expectLater(repository.acquireContextLease(), throwsStateError);
      await expectLater(
        repository.getAllMessagesInContext(firstLease),
        throwsStateError,
      );

      // Admission also stays closed for scope-only contexts without a key.
      await repository.setActiveContext(
        scopeToken: 'opaque-scope-alpha',
        storageKey: null,
      );
      await expectLater(repository.acquireContextLease(), throwsStateError);

      // A complete load of the replacement context reopens admission.
      await repository.setActiveContext(
        scopeToken: 'opaque-scope-beta',
        storageKey: storageKey,
      );
      final renewed = await repository.acquireContextLease();
      expect(await repository.getAllMessagesInContext(renewed), isEmpty);
      repository.dispose();
    });

    test('a queued context switch invalidates the old lease before completing',
        () async {
      final keyA = await deriveKey('identity-a');
      final keyB = await deriveKey('identity-b');
      final repository = await activeRepository(
        scopeToken: 'opaque-scope-a',
        storageKey: keyA,
      );
      final oldLease = await repository.acquireContextLease();
      await repository.addInContext(oldLease, message('old-context'));

      final switchFuture = repository.setActiveContext(
        scopeToken: 'opaque-scope-b',
        storageKey: keyB,
      );
      // Invalidation is synchronous: the old lease is dead while the queued
      // switch is still pending.
      await expectLater(
        repository.getAllMessagesInContext(oldLease),
        throwsStateError,
      );
      await expectLater(
        repository.addInContext(oldLease, message('stale-write')),
        throwsStateError,
      );
      await switchFuture;

      final newLease = await repository.acquireContextLease();
      expect(await repository.getAllMessagesInContext(newLease), isEmpty);
      repository.dispose();
    });

    test('refreshing the same context invalidates existing leases', () async {
      final repository = await activeRepository(
        scopeToken: 'opaque-scope-alpha',
        storageKey: await deriveKey('primary'),
      );
      final lease = await repository.acquireContextLease();
      await repository.addInContext(lease, message('before-refresh'));

      await repository.setActiveContext(
        scopeToken: 'opaque-scope-alpha',
        storageKey: await deriveKey('primary'),
      );

      await expectLater(
        repository.addInContext(lease, message('aba-write')),
        throwsStateError,
      );

      final refreshed = await repository.acquireContextLease();
      expect(
        (await repository.getAllMessagesInContext(refreshed))
            .map((m) => m.id)
            .toList(),
        ['before-refresh'],
      );
      repository.dispose();
    });

    test('disposal revokes outstanding leases and future admission', () async {
      final repository = await activeRepository(
        scopeToken: 'opaque-scope-alpha',
        storageKey: await deriveKey('primary'),
      );
      final lease = await repository.acquireContextLease();

      repository.dispose();

      await expectLater(repository.acquireContextLease(), throwsStateError);
      await expectLater(
        repository.getAllMessagesInContext(lease),
        throwsStateError,
      );
      await expectLater(
        repository.addInContext(lease, message('late-write')),
        throwsStateError,
      );
    });

    test('stale lease writes cannot modify the replacement context', () async {
      final keyA = await deriveKey('identity-a');
      final keyB = await deriveKey('identity-b');
      final repository = await activeRepository(
        scopeToken: 'opaque-scope-a',
        storageKey: keyA,
      );
      final staleLease = await repository.acquireContextLease();
      await repository.addInContext(staleLease, message('scoped-a'));

      await repository.setActiveContext(
        scopeToken: 'opaque-scope-b',
        storageKey: keyB,
      );
      await expectLater(
        repository.addInContext(staleLease, message('scoped-b')),
        throwsStateError,
      );
      await expectLater(
        repository.deleteInContext(staleLease, 'scoped-a'),
        throwsStateError,
      );

      final scopeB = await repository.acquireContextLease();
      expect(await repository.getAllMessagesInContext(scopeB), isEmpty);

      await repository.setActiveContext(
        scopeToken: 'opaque-scope-a',
        storageKey: keyA,
      );
      final scopeA = await repository.acquireContextLease();
      expect(
        (await repository.getAllMessagesInContext(scopeA))
            .map((m) => m.id)
            .toList(),
        ['scoped-a'],
      );
      repository.dispose();
    });
  });
}
