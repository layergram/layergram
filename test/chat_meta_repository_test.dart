import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';

import 'package:layergram/core/capabilities/chat_folders_capability.dart';
import 'package:layergram/core/crypto/sealed_map_cipher.dart';
import 'package:layergram/core/storage/chat_meta_repository.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  late Directory tmpDir;
  final keyMaterial = Uint8List.fromList(List<int>.generate(32, (i) => i));

  Future<void> initRepo(
    ChatMetaRepository repo,
    String scopeToken,
    String keyScope,
  ) async {
    final key = await SealedMapCipher.deriveKey(
      keyMaterial,
      scope: keyScope,
      info: 'chat-meta-test',
    );
    await repo.setActiveContext(
      scopeToken: scopeToken,
      encryptionKey: key,
    );
  }

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();

    tmpDir = await Directory.systemTemp.createTemp('layergram_hive_test_');
    Hive.init(tmpDir.path);

    await Hive.openBox<Map>(LocalDatabase.chatMetaBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tmpDir.delete(recursive: true);
  });

  setUp(() async {
    await Hive.box<Map>(LocalDatabase.chatMetaBoxName).clear();
  });

  test('pinned chats are isolated per opaque scope token and stored sealed', () async {
    final repoA = ChatMetaRepository(identityId: 'A');
    await initRepo(repoA, 'scope-a', 'A');
    await repoA.setPinned(folderId: kAllChatsFolderId, chatId: 'X', pinned: true);
    await repoA.setPinned(folderId: 'work', chatId: 'Y', pinned: true);
    repoA.dispose();

    final repoB = ChatMetaRepository(identityId: 'B');
    await initRepo(repoB, 'scope-b', 'B');
    await repoB.setPinned(folderId: kAllChatsFolderId, chatId: 'Z', pinned: true);
    repoB.dispose();

    final box = Hive.box<Map>(LocalDatabase.chatMetaBoxName);
    expect(box.keys.length, 2);
    final persisted = Map<dynamic, dynamic>.from(box.get(box.keys.first)!);
    expect(persisted.containsKey('encryptedRecord'), isTrue);
    expect(persisted.containsKey('X'), isFalse);

    final repoA2 = ChatMetaRepository(identityId: 'A');
    await initRepo(repoA2, 'scope-a', 'A');
    final aAll = await repoA2.watchPinnedChats(folderId: kAllChatsFolderId).first;
    expect(aAll.keys, contains('X'));
    expect(aAll.keys, isNot(contains('Z')));

    final aWork = await repoA2.watchPinnedChats(folderId: 'work').first;
    expect(aWork.keys, contains('Y'));
    expect(aWork.keys, isNot(contains('X')));
    repoA2.dispose();

    final repoB2 = ChatMetaRepository(identityId: 'B');
    await initRepo(repoB2, 'scope-b', 'B');
    final bAll = await repoB2.watchPinnedChats(folderId: kAllChatsFolderId).first;
    expect(bAll.keys, contains('Z'));
    expect(bAll.keys, isNot(contains('X')));
    repoB2.dispose();
  });

  test('togglePinned and chat settings roundtrip through sealed storage', () async {
    final repo = ChatMetaRepository(identityId: 'A');
    await initRepo(repo, 'scope-a', 'A');

    await repo.togglePinned(folderId: kAllChatsFolderId, chatId: 'X');
    expect(
      (await repo.watchPinnedChats(folderId: kAllChatsFolderId).first).keys,
      contains('X'),
    );

    await repo.saveChatSettings(
      chatId: 'X',
      linkMode: true,
      expiryMinutes: 60,
      deleteAfterRead: true,
    );
    final settings = await repo.getChatSettings(chatId: 'X');
    expect(settings?['linkMode'], isTrue);
    expect(settings?['expiryMinutes'], 60);
    expect(settings?['deleteAfterRead'], isTrue);

    await repo.togglePinned(folderId: kAllChatsFolderId, chatId: 'X');
    expect(
      (await repo.watchPinnedChats(folderId: kAllChatsFolderId).first).keys,
      isNot(contains('X')),
    );

    repo.dispose();
  });
}
