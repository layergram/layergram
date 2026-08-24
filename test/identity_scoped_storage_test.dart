import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';

import 'package:layergram/core/crypto/message_record_cipher.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/sealed_map_cipher.dart';
import 'package:layergram/core/storage/identities_repository.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';

void main() {
  late Directory tmpDir;
  final keyMaterial = Uint8List.fromList(List<int>.generate(32, (i) => i));

  Future<void> initRepo(
    MessagesRepository repo,
    String scopeToken,
    String keyTag,
  ) async {
    final storageKey = await MessageRecordCipher.deriveKey(
      keyMaterial,
      keyTag: keyTag,
    );
    await repo.setActiveContext(
      scopeToken: scopeToken,
      storageKey: storageKey,
    );
  }

  Future<SecretKey> deriveContactsKey(String keyScope) {
    return SealedMapCipher.deriveKey(
      keyMaterial,
      scope: keyScope,
      info: 'contacts-test',
    );
  }

  Future<void> initIdentitiesRepo(
    IdentitiesRepository repo,
    String scopeToken,
    String keyScope,
  ) async {
    final key = await deriveContactsKey(keyScope);
    await repo.setActiveContext(
      scopeToken: scopeToken,
      encryptionKey: key,
      selfIdentity: null,
    );
  }

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();

    tmpDir = await Directory.systemTemp.createTemp('layergram_hive_test_');
    Hive.init(tmpDir.path);

    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    await Hive.openBox<Map>(LocalDatabase.identitiesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tmpDir.delete(recursive: true);
  });

  setUp(() async {
    await Hive.box<Map>(LocalDatabase.messagesBoxName).clear();
    await Hive.box<Map>(LocalDatabase.identitiesBoxName).clear();
  });

  test('messages are isolated per opaque scope token', () async {
    final repoA = MessagesRepository();
    await initRepo(repoA, 'scope-a', 'A');
    await repoA.add(
      const MessageRecord(
        id: '1',
        senderId: 'A',
        recipientId: 'X',
        direction: 'outgoing',
        timestamp: 1,
      ),
    );
    repoA.dispose();

    final repoB = MessagesRepository();
    await initRepo(repoB, 'scope-b', 'B');
    await repoB.add(
      const MessageRecord(
        id: '2',
        senderId: 'B',
        recipientId: 'Y',
        direction: 'outgoing',
        timestamp: 1,
      ),
    );
    repoB.dispose();

    final repoA2 = MessagesRepository();
    await initRepo(repoA2, 'scope-a', 'A');
    final aMessages = await repoA2.watchAll().first;
    expect(aMessages.map((m) => m.id).toList(), ['1']);
    repoA2.dispose();

    final repoB2 = MessagesRepository();
    await initRepo(repoB2, 'scope-b', 'B');
    final bMessages = await repoB2.watchAll().first;
    expect(bMessages.map((m) => m.id).toList(), ['2']);
    repoB2.dispose();
  });

  test('remote identities are isolated per opaque scope token', () async {
    final repoA = IdentitiesRepository(ownerIdentityId: 'A');
    await initIdentitiesRepo(repoA, 'scope-a', 'A');
    await repoA.upsertRemoteIdentity(
      const RemoteIdentity(
        identityId: 'X',
        publicKeyBase64: 'pk-x',
        fingerprint: 'fp-x',
        displayName: 'X',
      ),
    );
    repoA.dispose();

    final repoB = IdentitiesRepository(ownerIdentityId: 'B');
    await initIdentitiesRepo(repoB, 'scope-b', 'B');
    await repoB.upsertRemoteIdentity(
      const RemoteIdentity(
        identityId: 'Y',
        publicKeyBase64: 'pk-y',
        fingerprint: 'fp-y',
        displayName: 'Y',
      ),
    );
    repoB.dispose();

    final repoA2 = IdentitiesRepository(ownerIdentityId: 'A');
    await initIdentitiesRepo(repoA2, 'scope-a', 'A');
    final aContacts = await repoA2.watchRemote().first;
    expect(aContacts.map((c) => c.identityId).toSet(), {'X'});
    repoA2.dispose();

    final repoB2 = IdentitiesRepository(ownerIdentityId: 'B');
    await initIdentitiesRepo(repoB2, 'scope-b', 'B');
    final bContacts = await repoB2.watchRemote().first;
    expect(bContacts.map((c) => c.identityId).toSet(), {'Y'});
    repoB2.dispose();
  });

  test('contact writes stay bound to their queued identity context', () async {
    final keyA = await deriveContactsKey('A');
    final keyB = await deriveContactsKey('B');
    final repo = IdentitiesRepository(ownerIdentityId: 'owner');
    await repo.setActiveContext(
      scopeToken: 'scope-a',
      encryptionKey: keyA,
      selfIdentity: null,
    );

    final writeA = repo.upsertRemoteIdentity(
      const RemoteIdentity(
        identityId: 'contact-a',
        publicKeyBase64: 'pk-a',
        fingerprint: 'fp-a',
        displayName: 'A',
      ),
    );
    final switchToB = repo.setActiveContext(
      scopeToken: 'scope-b',
      encryptionKey: keyB,
      selfIdentity: null,
    );
    final writeB = repo.upsertRemoteIdentity(
      const RemoteIdentity(
        identityId: 'contact-b',
        publicKeyBase64: 'pk-b',
        fingerprint: 'fp-b',
        displayName: 'B',
      ),
    );

    await Future.wait([writeA, switchToB, writeB]);
    repo.dispose();

    final viewA = IdentitiesRepository(ownerIdentityId: 'owner');
    await initIdentitiesRepo(viewA, 'scope-a', 'A');
    expect(
      (await viewA.watchRemote().first).map((contact) => contact.identityId),
      ['contact-a'],
    );
    viewA.dispose();

    final viewB = IdentitiesRepository(ownerIdentityId: 'owner');
    await initIdentitiesRepo(viewB, 'scope-b', 'B');
    expect(
      (await viewB.watchRemote().first).map((contact) => contact.identityId),
      ['contact-b'],
    );
    viewB.dispose();
  });

  test('verification changes only an unchanged persisted contact', () async {
    final repo = IdentitiesRepository(ownerIdentityId: 'owner');
    await initIdentitiesRepo(repo, 'scope-a', 'A');
    const contact = RemoteIdentity(
      identityId: 'contact-a',
      publicKeyBase64: 'pk-a',
      fingerprint: 'fp-a',
      displayName: 'A',
      verified: true,
    );

    await repo.upsertRemoteIdentity(contact);
    expect((await repo.getRemoteById(contact.identityId))?.verified, isFalse);

    await repo.setRemoteVerification(
      expectedIdentity: contact,
      verified: true,
    );
    expect((await repo.getRemoteById(contact.identityId))?.verified, isTrue);

    await repo.upsertRemoteIdentity(contact.copyWith(displayName: 'Renamed'));
    final renamed = await repo.getRemoteById(contact.identityId);
    expect(renamed?.displayName, 'Renamed');
    expect(renamed?.verified, isTrue);

    await expectLater(
      repo.setRemoteVerification(
        expectedIdentity: const RemoteIdentity(
          identityId: 'contact-a',
          publicKeyBase64: 'different-key',
          fingerprint: 'different-fingerprint',
          displayName: 'A',
        ),
        verified: false,
      ),
      throwsStateError,
    );
    await expectLater(
      repo.setRemoteVerification(
        expectedIdentity: const RemoteIdentity(
          identityId: 'missing-contact',
          publicKeyBase64: 'pk',
          fingerprint: 'fp',
          displayName: 'Missing',
        ),
        verified: true,
      ),
      throwsStateError,
    );
    repo.dispose();
  });
}
