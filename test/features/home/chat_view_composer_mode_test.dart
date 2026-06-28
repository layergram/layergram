import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/chat_meta_repository.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';
import 'package:layergram/features/home/chat_view.dart';

void main() {
  late Directory tmpDir;

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_chat_view_test_');
    Hive.init(tmpDir.path);
    await Hive.openBox<Map>(LocalDatabase.chatMetaBoxName);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tmpDir.delete(recursive: true);
  });

  setUp(() async {
    await Hive.box<Map>(LocalDatabase.chatMetaBoxName).clear();
    await Hive.box<Map>(LocalDatabase.messagesBoxName).clear();
  });

  testWidgets('new chats default to link mode', (tester) async {
    await _pumpChat(
      tester,
      chatMetaRepository: _TestChatMetaRepository(),
    );

    expect(_composerModeSelection(tester), equals([false, true]));
    expect(find.text('coverText'), findsNothing);
  });

  testWidgets('explicit cover mode is preserved from initial state',
      (tester) async {
    await _pumpChat(
      tester,
      initialLinkMode: false,
      chatMetaRepository: _TestChatMetaRepository(),
    );

    expect(_composerModeSelection(tester), equals([true, false]));
    expect(find.text('coverText'), findsOneWidget);
  });

  testWidgets('persisted cover mode overrides the new-chat default',
      (tester) async {
    await _pumpChat(
      tester,
      chatMetaRepository: _TestChatMetaRepository(
        settings: const {
          'linkMode': false,
          'expiryMinutes': null,
          'deleteAfterRead': false,
        },
      ),
    );

    expect(_composerModeSelection(tester), equals([true, false]));
    expect(find.text('coverText'), findsOneWidget);
  });
}

List<bool> _composerModeSelection(WidgetTester tester) {
  final toggle = tester.widget<ToggleButtons>(find.byType(ToggleButtons).first);
  return toggle.isSelected;
}

Future<void> _pumpChat(
  WidgetTester tester, {
  bool? initialLinkMode,
  required _TestChatMetaRepository chatMetaRepository,
}) async {
  await tester.binding.setSurfaceSize(const Size(390, 844));
  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        chatMetaRepositoryProvider.overrideWithValue(chatMetaRepository),
        messagesRepositoryProvider
            .overrideWithValue(_EmptyMessagesRepository()),
      ],
      child: MaterialApp(
        home: ChatView(
          contact: _contact,
          embedded: true,
          initialLinkMode: initialLinkMode,
        ),
      ),
    ),
  );
  await tester.pump();
}

const _contact = RemoteIdentity(
  identityId: 'contact-a',
  publicKeyBase64: 'public-key',
  fingerprint: 'AA-BB-CC',
  displayName: 'Contact A',
  verified: true,
);

class _TestChatMetaRepository extends ChatMetaRepository {
  _TestChatMetaRepository({Map<String, dynamic>? settings})
      : _settings = settings,
        super(identityId: 'me');

  final Map<String, dynamic>? _settings;

  @override
  Future<Map<String, dynamic>?> getChatSettings({
    required String chatId,
  }) async {
    final settings = _settings;
    if (settings == null) return null;
    return Map<String, dynamic>.from(settings);
  }

  @override
  Future<void> saveChatSettings({
    required String chatId,
    required bool linkMode,
    required int? expiryMinutes,
    required bool deleteAfterRead,
  }) async {}
}

class _EmptyMessagesRepository extends MessagesRepository {
  @override
  Stream<List<MessageRecord>> watchThread(
    String contactId, {
    int limit = 50,
  }) async* {
    yield const <MessageRecord>[];
  }

  @override
  Future<void> purgeReadDeleteAfterReadFor(String peerId) async {}

  @override
  void dispose() {}
}
