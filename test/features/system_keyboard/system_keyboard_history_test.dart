import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/fs_message_classification.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_history.dart';

class _Store implements V3LmfRecordStore {
  final entries = <String, Map<String, dynamic>>{};
  var next = 0;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = 'entry-${next++}';
    entries[id] = Map.of(payload);
    return id;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async => [
        for (final entry in entries.entries)
          V3LmfStoredRecord(storageId: entry.key, payload: entry.value),
      ];

  @override
  Future<void> delete(String storageId) async => entries.remove(storageId);
}

String _id(int byte) =>
    base64Url.encode(List.filled(16, byte)).replaceAll('=', '');

void main() {
  late Directory directory;

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    directory = await Directory.systemTemp.createTemp('keyboard_history_');
    Hive.init(directory.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await directory.delete(recursive: true);
  });

  setUp(() async => Hive.box<Map>(LocalDatabase.messagesBoxName).clear());

  test('keyboard pre-FS sends and receives restore into the matching chat once',
      () async {
    final store = _Store();
    await SystemKeyboardHistory.recordPreFs(
      store: store,
      stableMessageId: _id(1),
      localIdentityId: 'alice',
      contactId: 'bob',
      direction: 'outgoing',
      text: 'first from keyboard',
      timestampUnixSeconds: 1800000000,
    );
    await SystemKeyboardHistory.recordPreFs(
      store: store,
      stableMessageId: _id(2),
      localIdentityId: 'alice',
      contactId: 'bob',
      direction: 'incoming',
      text: 'reply from keyboard',
      timestampUnixSeconds: 1800000001,
    );
    final messages = MessagesRepository();
    await messages.setActiveContext(
      scopeToken: 'keyboard-history',
      storageKey: SecretKey(List.filled(32, 7)),
    );
    await messages.waitForReadyContext();
    final lease = await messages.acquireContextLease();
    Future<int> restore() => SystemKeyboardHistory.restore(
          store: store,
          isDeleted: (_) async => false,
          messages: messages,
          lease: lease,
          localIdentityId: 'alice',
          keyTag: 'ordinary',
        );
    expect(await restore(), 2);
    expect(await restore(), 0);
    final thread = await messages.watchThread('bob').first;
    expect(thread, hasLength(2));
    expect(thread.map((m) => m.text),
        containsAll(['first from keyboard', 'reply from keyboard']));
    expect(
        thread.singleWhere((m) => m.direction == 'incoming').senderId, 'bob');
    expect(
        thread
            .every((m) => m.fsClassification == FsMessageClassification.preFs),
        isTrue);
    expect(thread.every((m) => m.keyTag == 'ordinary'), isTrue);
    messages.dispose();
  });

  test('suppressed and wrong-identity handoffs never enter chat', () async {
    final store = _Store();
    await SystemKeyboardHistory.recordPreFs(
      store: store,
      stableMessageId: _id(3),
      localIdentityId: 'alice',
      contactId: 'bob',
      direction: 'incoming',
      text: 'private preview',
      timestampUnixSeconds: 1800000000,
    );
    final messages = MessagesRepository();
    await messages.setActiveContext(
      scopeToken: 'keyboard-history',
      storageKey: SecretKey(List.filled(32, 7)),
    );
    final lease = await messages.acquireContextLease();
    await expectLater(
      SystemKeyboardHistory.restore(
        store: store,
        isDeleted: (_) async => false,
        messages: messages,
        lease: lease,
        localIdentityId: 'charlie',
        keyTag: 'ordinary',
      ),
      throwsFormatException,
    );
    expect(await messages.getAllMessagesInContext(lease), isEmpty);
    expect(store.entries, hasLength(1));
    expect(
      await SystemKeyboardHistory.restore(
        store: store,
        isDeleted: (_) async => true,
        messages: messages,
        lease: lease,
        localIdentityId: 'alice',
        keyTag: 'ordinary',
      ),
      0,
    );
    expect(await messages.getAllMessagesInContext(lease), isEmpty);
    expect(store.entries, isEmpty);
    messages.dispose();
  });
}
