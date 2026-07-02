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
import 'package:layergram/features/home/message_output_mode.dart';

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

  testWidgets('new chats default to text mode', (tester) async {
    await _pumpChat(
      tester,
      chatMetaRepository: _TestChatMetaRepository(),
    );

    expect(_composerModeSelection(tester), equals([false, true, false]));
    expect(find.text('coverText'), findsNothing);
  });

  testWidgets('explicit cover mode is preserved from initial state',
      (tester) async {
    await _pumpChat(
      tester,
      initialOutputMode: MessageOutputMode.cover,
      chatMetaRepository: _TestChatMetaRepository(),
    );

    expect(_composerModeSelection(tester), equals([true, false, false]));
    expect(find.text('coverText'), findsOneWidget);
  });

  testWidgets('persisted cover mode overrides the new-chat default',
      (tester) async {
    await _pumpChat(
      tester,
      chatMetaRepository: _TestChatMetaRepository(
        settings: const {
          'outputMode': 'cover',
          'expiryMinutes': null,
          'deleteAfterRead': false,
          'excludeFromBackups': false,
        },
      ),
    );

    expect(_composerModeSelection(tester), equals([true, false, false]));
    expect(find.text('coverText'), findsOneWidget);
  });

  testWidgets('manual mode selection is saved per chat', (tester) async {
    final repo = _TestChatMetaRepository();
    await _pumpChat(
      tester,
      chatMetaRepository: repo,
    );

    expect(_composerModeSelection(tester), equals([false, true, false]));

    await tester.tap(find.byIcon(Icons.link).first);
    await tester.pump();
    expect(_composerModeSelection(tester), equals([false, false, true]));
    expect(repo.savedOutputMode, 'link');
    expect(find.text('coverText'), findsNothing);

    await tester.tap(find.byIcon(Icons.chat_bubble_outline).first);
    await tester.pump();
    expect(_composerModeSelection(tester), equals([true, false, false]));
    expect(repo.savedOutputMode, 'cover');
    expect(find.text('coverText'), findsOneWidget);

    await tester.tap(find.byIcon(Icons.text_snippet_outlined).first);
    await tester.pump();
    expect(_composerModeSelection(tester), equals([false, true, false]));
    expect(repo.savedOutputMode, 'text');
    expect(find.text('coverText'), findsNothing);
  });

  testWidgets('secret clear button appears only with text and clears the field',
      (tester) async {
    await _pumpChat(
      tester,
      chatMetaRepository: _TestChatMetaRepository(),
    );

    final secretField = find.byType(TextField);
    expect(find.byKey(_secretClearButtonKey), findsNothing);

    await tester.enterText(secretField, 'A secret draft');
    await tester.pump();

    expect(find.byKey(_secretClearButtonKey), findsOneWidget);
    await tester.tap(find.byKey(_secretClearButtonKey));
    await tester.pump();

    final field = tester.widget<TextField>(secretField);
    expect(field.controller?.text, isEmpty);
    expect(find.byKey(_secretClearButtonKey), findsNothing);
  });

  testWidgets(
      'clear buttons fit compact landscape cover mode and clear independently',
      (tester) async {
    await _pumpChat(
      tester,
      size: const Size(844, 390),
      initialOutputMode: MessageOutputMode.cover,
      chatMetaRepository: _TestChatMetaRepository(),
    );

    expect(tester.takeException(), isNull);
    expect(_composerModeSelection(tester), equals([true, false, false]));

    final fields = find.byType(TextField);
    expect(fields, findsNWidgets(2));
    expect(tester.widget<TextField>(fields.at(0)).maxLines, 1);

    await tester.enterText(fields.at(0), 'Cover draft');
    await tester.enterText(fields.at(1), 'Secret draft');
    await tester.pump();

    expect(find.byKey(_coverClearButtonKey), findsOneWidget);
    expect(find.byKey(_secretClearButtonKey), findsOneWidget);
    expect(tester.takeException(), isNull);

    await tester.tap(find.byKey(_coverClearButtonKey));
    await tester.pump();

    final coverField = tester.widget<TextField>(fields.at(0));
    final secretField = tester.widget<TextField>(fields.at(1));
    expect(coverField.controller?.text, isEmpty);
    expect(secretField.controller?.text, 'Secret draft');
    expect(find.byKey(_coverClearButtonKey), findsNothing);
    expect(find.byKey(_secretClearButtonKey), findsOneWidget);
  });

  testWidgets('clear buttons fit desktop cover mode', (tester) async {
    await _pumpChat(
      tester,
      size: const Size(1200, 800),
      initialOutputMode: MessageOutputMode.cover,
      chatMetaRepository: _TestChatMetaRepository(),
    );

    final fields = find.byType(TextField);
    expect(fields, findsNWidgets(2));

    await tester.enterText(fields.at(0), 'Cover draft');
    await tester.enterText(fields.at(1), 'Secret draft');
    await tester.pump();

    expect(find.byKey(_coverClearButtonKey), findsOneWidget);
    expect(find.byKey(_secretClearButtonKey), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}

const _coverClearButtonKey = ValueKey<String>('chat_composer_clear_cover');
const _secretClearButtonKey = ValueKey<String>('chat_composer_clear_secret');

List<bool> _composerModeSelection(WidgetTester tester) {
  final toggle = tester.widget<ToggleButtons>(find.byType(ToggleButtons).first);
  return toggle.isSelected;
}

Future<void> _pumpChat(
  WidgetTester tester, {
  Size size = const Size(390, 844),
  MessageOutputMode? initialOutputMode,
  RemoteIdentity contact = _contact,
  required _TestChatMetaRepository chatMetaRepository,
  MessagesRepository? messagesRepository,
  List<Override> extraOverrides = const [],
}) async {
  addTearDown(() {
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });
  tester.view.devicePixelRatio = 1.0;
  tester.view.physicalSize = size;
  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        chatMetaRepositoryProvider.overrideWithValue(chatMetaRepository),
        messagesRepositoryProvider.overrideWithValue(
            messagesRepository ?? _EmptyMessagesRepository()),
        ...extraOverrides,
      ],
      child: MaterialApp(
        home: ChatView(
          contact: contact,
          embedded: true,
          initialOutputMode: initialOutputMode,
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
  String? savedOutputMode;
  bool? savedExcludeFromBackups;

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
    required String outputMode,
    required int? expiryMinutes,
    required bool deleteAfterRead,
    required bool excludeFromBackups,
  }) async {
    savedOutputMode = outputMode;
    savedExcludeFromBackups = excludeFromBackups;
  }
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
