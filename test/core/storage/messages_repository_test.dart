import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/message_record_cipher.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/sealed_map_cipher.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';

void main() {
  late Directory tmpDir;
  final keyMaterial = Uint8List.fromList(List<int>.generate(32, (i) => i));

  Future<SecretKey> deriveStorageKey(String keyTag) async {
    return MessageRecordCipher.deriveKey(keyMaterial, keyTag: keyTag);
  }

  Future<void> initRepo(
    MessagesRepository repo, {
    required String scopeToken,
    required SecretKey storageKey,
  }) async {
    await repo.setActiveContext(
      scopeToken: scopeToken,
      storageKey: storageKey,
    );
  }

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_messages_repo_');
    Hive.init(tmpDir.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tmpDir.delete(recursive: true);
  });

  setUp(() async {
    await Hive.box<Map>(LocalDatabase.messagesBoxName).clear();
  });

  group('MessagesRepository', () {
    test(
        'stores messages in one sealed state record per domain without plaintext fields',
        () async {
      final storageKey = await deriveStorageKey('orig');
      final repo = MessagesRepository();
      await initRepo(
        repo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );

      const firstMessage = MessageRecord(
        id: 'msg-1',
        senderId: 'me',
        recipientId: 'contact',
        direction: 'outgoing',
        timestamp: 111,
        text: 'secret',
        ciphertextBase64: 'cipher',
        nonceBase64: 'nonce',
        rawSource: 'hello visible cover',
        expireAfter: 9999999999,
        keyTag: 'orig',
      );
      const secondMessage = MessageRecord(
        id: 'msg-2',
        senderId: 'contact',
        recipientId: 'me',
        direction: 'incoming',
        timestamp: 222,
        text: 'secret-2',
        ciphertextBase64: 'cipher-2',
        nonceBase64: 'nonce-2',
        rawSource: 'cover 2',
        keyTag: 'orig',
      );

      await repo.add(firstMessage);
      await repo.add(secondMessage);

      final box = Hive.box<Map>(LocalDatabase.messagesBoxName);
      expect(box.keys.length, 1);
      final storedKey = box.keys.single as String;
      expect(storedKey.contains('IDENTITY_ALPHA'), isFalse);
      final persisted = Map<dynamic, dynamic>.from(box.get(storedKey)!);
      expect(persisted.length, 1);
      expect(persisted.containsKey('encryptedRecord'), isTrue);
      expect(persisted.containsKey('rawSource'), isFalse);
      expect(persisted.containsKey('text'), isFalse);
      expect(persisted.containsKey('senderId'), isFalse);
      expect(persisted.containsKey('recipientId'), isFalse);

      final decrypted = await SealedMapCipher.decrypt(
        encryptedRecord: persisted['encryptedRecord'] as String,
        key: storageKey,
      );
      final rawMessages = (decrypted?['messages'] as List?) ?? const [];
      expect(rawMessages.length, 2);
      final ids = rawMessages.whereType<Map>().map((m) => m['id']).toSet();
      expect(ids, {'msg-1', 'msg-2'});

      repo.dispose();

      final reopened = MessagesRepository();
      await initRepo(
        reopened,
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );
      final messages = await reopened.getAllMessages();
      expect(messages.map((m) => m.id).toSet(), {'msg-1', 'msg-2'});
      reopened.dispose();
    });

    test(
        'persists sender-direction backupExcluded and exposes official backup filter contract',
        () async {
      final storageKey = await deriveStorageKey('orig');
      final repo = MessagesRepository();
      await initRepo(
        repo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );

      await repo.add(
        const MessageRecord(
          id: 'backup-ok',
          senderId: 'me',
          recipientId: 'contact',
          direction: 'outgoing',
          timestamp: 1,
          text: 'eligible',
          keyTag: 'orig',
        ),
      );
      await repo.add(
        const MessageRecord(
          id: 'backup-excluded',
          senderId: 'me',
          recipientId: 'contact',
          direction: 'outgoing',
          timestamp: 2,
          text: 'do not export',
          keyTag: 'orig',
          backupExcluded: true,
        ),
      );
      repo.dispose();

      final reopened = MessagesRepository();
      await initRepo(
        reopened,
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );

      final messages = await reopened.getAllMessages();
      expect(
        messages
            .firstWhere((message) => message.id == 'backup-excluded')
            .backupExcluded,
        isTrue,
      );
      expect(
        messages
            .firstWhere((message) => message.id == 'backup-ok')
            .backupExcluded,
        isFalse,
      );
      expect(
        MessageRecord.backupEligibleRecords(messages).map((m) => m.id).toSet(),
        {'backup-ok'},
      );
      expect(
        MessageRecord.fromMap({
          'id': 'legacy',
          'senderId': 'contact',
          'recipientId': 'me',
          'direction': 'incoming',
          'timestamp': 3,
        }).backupExcluded,
        isFalse,
      );
      reopened.dispose();
    });

    test('disabling backup exclusion only affects new messages', () async {
      final storageKey = await deriveStorageKey('orig');
      final repo = MessagesRepository();
      await initRepo(
        repo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );

      await repo.add(
        const MessageRecord(
          id: 'old-excluded',
          senderId: 'me',
          recipientId: 'contact',
          direction: 'outgoing',
          timestamp: 1,
          text: 'sent while preference was on',
          keyTag: 'orig',
          backupExcluded: true,
        ),
      );
      await repo.add(
        const MessageRecord(
          id: 'new-included',
          senderId: 'me',
          recipientId: 'contact',
          direction: 'outgoing',
          timestamp: 2,
          text: 'sent after preference was off',
          keyTag: 'orig',
          backupExcluded: false,
        ),
      );
      repo.dispose();

      final reopened = MessagesRepository();
      await initRepo(
        reopened,
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );

      final messages = await reopened.getAllMessages();
      expect(
        messages
            .firstWhere((message) => message.id == 'old-excluded')
            .backupExcluded,
        isTrue,
      );
      expect(
        messages
            .firstWhere((message) => message.id == 'new-included')
            .backupExcluded,
        isFalse,
      );
      reopened.dispose();
    });

    test(
        'preserves records from other key domains while showing only the active one',
        () async {
      final originalKey = await deriveStorageKey('orig');
      final passKey = await deriveStorageKey('pass');

      final originalRepo = MessagesRepository();
      await initRepo(
        originalRepo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: originalKey,
      );
      await originalRepo.add(
        const MessageRecord(
          id: 'orig-1',
          senderId: 'me',
          recipientId: 'contact',
          direction: 'outgoing',
          timestamp: 1,
          ciphertextBase64: 'cipher-1',
          nonceBase64: 'nonce-1',
          rawSource: 'cover original',
          keyTag: 'orig',
        ),
      );
      originalRepo.dispose();

      final passRepo = MessagesRepository();
      await initRepo(
        passRepo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: passKey,
      );
      await passRepo.add(
        const MessageRecord(
          id: 'pass-1',
          senderId: 'me',
          recipientId: 'contact',
          direction: 'outgoing',
          timestamp: 2,
          ciphertextBase64: 'cipher-2',
          nonceBase64: 'nonce-2',
          rawSource: 'cover passphrase',
          keyTag: 'pass',
        ),
      );
      passRepo.dispose();

      final box = Hive.box<Map>(LocalDatabase.messagesBoxName);
      expect(box.keys.length, 2);

      final originalView = MessagesRepository();
      await initRepo(
        originalView,
        scopeToken: 'opaque-scope-alpha',
        storageKey: originalKey,
      );
      final originalMessages = await originalView.getAllMessages();
      expect(originalMessages.map((m) => m.id).toList(), ['orig-1']);
      await originalView.deleteByKeyFilter(
        effectiveTag: 'orig',
      );
      originalView.dispose();

      expect(box.keys.length, 1);

      final passView = MessagesRepository();
      await initRepo(
        passView,
        scopeToken: 'opaque-scope-alpha',
        storageKey: passKey,
      );
      final passMessages = await passView.getAllMessages();
      expect(passMessages.map((m) => m.id).toList(), ['pass-1']);
      expect(passMessages.single.rawSource, 'cover passphrase');
      passView.dispose();
    });

    test(
        'clearAll removes all message records for the active opaque scope across key domains',
        () async {
      final originalKey = await deriveStorageKey('orig');
      final passKey = await deriveStorageKey('pass');
      final box = Hive.box<Map>(LocalDatabase.messagesBoxName);

      final originalRepo = MessagesRepository();
      await initRepo(
        originalRepo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: originalKey,
      );
      await originalRepo.add(
        const MessageRecord(
          id: 'orig-1',
          senderId: 'me',
          recipientId: 'contact',
          direction: 'outgoing',
          timestamp: 1,
          ciphertextBase64: 'cipher-1',
          nonceBase64: 'nonce-1',
          rawSource: 'cover original',
          keyTag: 'orig',
        ),
      );
      originalRepo.dispose();

      final passRepo = MessagesRepository();
      await initRepo(
        passRepo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: passKey,
      );
      await passRepo.add(
        const MessageRecord(
          id: 'pass-1',
          senderId: 'me',
          recipientId: 'contact',
          direction: 'outgoing',
          timestamp: 2,
          ciphertextBase64: 'cipher-2',
          nonceBase64: 'nonce-2',
          rawSource: 'cover passphrase',
          keyTag: 'pass',
        ),
      );
      passRepo.dispose();

      final otherIdentityRepo = MessagesRepository();
      await initRepo(
        otherIdentityRepo,
        scopeToken: 'opaque-scope-beta',
        storageKey: originalKey,
      );
      await otherIdentityRepo.add(
        const MessageRecord(
          id: 'other-1',
          senderId: 'me',
          recipientId: 'contact',
          direction: 'outgoing',
          timestamp: 3,
          ciphertextBase64: 'cipher-3',
          nonceBase64: 'nonce-3',
          rawSource: 'cover other identity',
          keyTag: 'orig',
        ),
      );
      otherIdentityRepo.dispose();

      final repo = MessagesRepository();
      await initRepo(
        repo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: originalKey,
      );
      await repo.clearAll();
      expect(await repo.getAllMessages(), isEmpty);

      final remainingKeys = box.keys.cast<String>().toList();
      expect(
        remainingKeys.where((k) => k.startsWith('m|opaque-scope-alpha|')),
        isEmpty,
      );
      expect(
        remainingKeys.where((k) => k.startsWith('m|opaque-scope-beta|')).length,
        1,
      );
      repo.dispose();
    });

    test(
        'purgeReadDeleteAfterReadFor does not rewrite storage when nothing matches',
        () async {
      final storageKey = await deriveStorageKey('orig');
      final repo = MessagesRepository();
      await initRepo(
        repo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );

      await repo.add(
        const MessageRecord(
          id: 'msg-1',
          senderId: 'me',
          recipientId: 'contact',
          direction: 'outgoing',
          timestamp: 111,
          ciphertextBase64: 'cipher',
          nonceBase64: 'nonce',
          rawSource: 'cover',
          deleteAfterRead: false,
          keyTag: 'orig',
        ),
      );

      final box = Hive.box<Map>(LocalDatabase.messagesBoxName);
      final recordKey = box.keys.single as String;
      final before = Map<dynamic, dynamic>.from(box.get(recordKey)!);

      await repo.purgeReadDeleteAfterReadFor('contact');

      final after = Map<dynamic, dynamic>.from(box.get(recordKey)!);
      expect(after['encryptedRecord'], before['encryptedRecord']);
      repo.dispose();
    });

    test('watchThread does not rewrite storage when there is nothing to prune',
        () async {
      final storageKey = await deriveStorageKey('orig');
      final repo = MessagesRepository();
      await initRepo(
        repo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );

      await repo.add(
        const MessageRecord(
          id: 'msg-1',
          senderId: 'me',
          recipientId: 'contact',
          direction: 'outgoing',
          timestamp: 111,
          ciphertextBase64: 'cipher',
          nonceBase64: 'nonce',
          rawSource: 'cover',
          keyTag: 'orig',
        ),
      );

      final box = Hive.box<Map>(LocalDatabase.messagesBoxName);
      final recordKey = box.keys.single as String;
      final before = Map<dynamic, dynamic>.from(box.get(recordKey)!);

      final thread = await repo.watchThread('contact').first;

      expect(thread.map((m) => m.id).toList(), ['msg-1']);
      final after = Map<dynamic, dynamic>.from(box.get(recordKey)!);
      expect(after['encryptedRecord'], before['encryptedRecord']);
      repo.dispose();
    });

    test(
        'deduplicates identical incoming shared messages by normalized raw source',
        () async {
      final storageKey = await deriveStorageKey('orig');
      final repo = MessagesRepository();
      await initRepo(
        repo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );

      await repo.add(
        const MessageRecord(
          id: 'incoming-1',
          senderId: 'contact',
          recipientId: 'me',
          direction: 'incoming',
          timestamp: 111,
          ciphertextBase64: 'cipher-a',
          nonceBase64: 'nonce-a',
          rawSource: '  shared-cover  ',
          keyTag: 'orig',
        ),
      );
      await repo.add(
        const MessageRecord(
          id: 'incoming-2',
          senderId: 'contact',
          recipientId: 'me',
          direction: 'incoming',
          timestamp: 112,
          ciphertextBase64: 'cipher-a',
          nonceBase64: 'nonce-a',
          rawSource: 'shared-cover',
          keyTag: 'orig',
        ),
      );

      final messages = await repo.getAllMessages();
      expect(messages.length, 1);
      expect(messages.single.id, 'incoming-1');
      repo.dispose();
    });

    test(
        'keeps distinct incoming re-shares when their visible cover text differs',
        () async {
      final storageKey = await deriveStorageKey('orig');
      final repo = MessagesRepository();
      await initRepo(
        repo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );

      await repo.add(
        const MessageRecord(
          id: 'incoming-1',
          senderId: 'contact',
          recipientId: 'me',
          direction: 'incoming',
          timestamp: 111,
          ciphertextBase64: 'cipher-a',
          nonceBase64: 'nonce-a',
          rawSource: 'cover one',
          keyTag: 'orig',
        ),
      );
      await repo.add(
        const MessageRecord(
          id: 'incoming-2',
          senderId: 'contact',
          recipientId: 'me',
          direction: 'incoming',
          timestamp: 112,
          ciphertextBase64: 'cipher-a',
          nonceBase64: 'nonce-a',
          rawSource: 'cover two',
          keyTag: 'orig',
        ),
      );

      final messages = await repo.getAllMessages();
      expect(messages.map((m) => m.id).toSet(), {'incoming-1', 'incoming-2'});
      repo.dispose();
    });

    test('serializes writes across active identity context changes', () async {
      final keyA = await deriveStorageKey('identity-a');
      final keyB = await deriveStorageKey('identity-b');
      final repo = MessagesRepository();
      await initRepo(
        repo,
        scopeToken: 'opaque-scope-a',
        storageKey: keyA,
      );

      final writeA = repo.add(
        const MessageRecord(
          id: 'identity-a-message',
          senderId: 'me',
          recipientId: 'contact-a',
          direction: 'outgoing',
          timestamp: 1,
          text: 'identity a',
          keyTag: 'identity-a',
        ),
      );
      final switchToB = repo.setActiveContext(
        scopeToken: 'opaque-scope-b',
        storageKey: keyB,
      );
      final writeB = repo.add(
        const MessageRecord(
          id: 'identity-b-message',
          senderId: 'me',
          recipientId: 'contact-b',
          direction: 'outgoing',
          timestamp: 2,
          text: 'identity b',
          keyTag: 'identity-b',
        ),
      );

      await Future.wait([writeA, switchToB, writeB]);
      repo.dispose();

      final viewA = MessagesRepository();
      await initRepo(
        viewA,
        scopeToken: 'opaque-scope-a',
        storageKey: keyA,
      );
      expect(
        (await viewA.getAllMessages()).map((message) => message.id),
        ['identity-a-message'],
      );
      viewA.dispose();

      final viewB = MessagesRepository();
      await initRepo(
        viewB,
        scopeToken: 'opaque-scope-b',
        storageKey: keyB,
      );
      expect(
        (await viewB.getAllMessages()).map((message) => message.id),
        ['identity-b-message'],
      );
      viewB.dispose();
    });

    test('rejects new operations once disposal begins', () async {
      final storageKey = await deriveStorageKey('orig');
      final repo = MessagesRepository();
      await initRepo(
        repo,
        scopeToken: 'opaque-scope-alpha',
        storageKey: storageKey,
      );

      repo.dispose();

      await expectLater(
        repo.add(
          const MessageRecord(
            id: 'late-message',
            senderId: 'me',
            recipientId: 'contact',
            direction: 'outgoing',
            timestamp: 1,
          ),
        ),
        throwsStateError,
      );
    });
  });
}
