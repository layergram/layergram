import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:layergram/core/crypto/identity_link_codec.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/identities_repository.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/core/utils/clipboard_service.dart';
import 'package:layergram/features/identities/add_identity_view.dart';
import 'package:layergram/features/shell/app_shell.dart';
import 'package:layergram/l10n/app_strings.dart';

class _InMemorySecureStorageService extends SecureStorageService {
  final Map<String, String> _values = <String, String>{};

  @override
  Future<void> write(String key, String value) async {
    _values[key] = value;
  }

  @override
  Future<String?> read(String key) async {
    return _values[key];
  }

  @override
  Future<void> delete(String key) async {
    _values.remove(key);
  }

  @override
  Future<void> deleteAll() async {
    _values.clear();
  }
}

class _FakeClipboardService extends ClipboardService {
  _FakeClipboardService(this.text);

  final String text;

  @override
  Future<String> readText() async => text;
}

class _FakeIdentitiesRepository extends IdentitiesRepository {
  _FakeIdentitiesRepository([
    Iterable<RemoteIdentity> initialContacts = const [],
  ]) : super(ownerIdentityId: 'local-owner') {
    contacts.addAll(initialContacts);
  }

  final List<RemoteIdentity> contacts = <RemoteIdentity>[];
  final StreamController<List<RemoteIdentity>> _changes =
      StreamController<List<RemoteIdentity>>.broadcast();
  int upsertCount = 0;

  @override
  Stream<List<RemoteIdentity>> watchRemote() async* {
    yield List<RemoteIdentity>.unmodifiable(contacts);
    yield* _changes.stream;
  }

  @override
  Future<void> upsertRemoteIdentity(RemoteIdentity identity) async {
    upsertCount++;
    contacts.removeWhere((item) => item.identityId == identity.identityId);
    contacts.add(identity);
    _changes.add(List<RemoteIdentity>.unmodifiable(contacts));
  }

  @override
  Future<RemoteIdentity?> getRemoteById(String identityId) async {
    for (final identity in contacts) {
      if (identity.identityId == identityId) return identity;
    }
    return null;
  }

  @override
  void dispose() {
    _changes.close();
    super.dispose();
  }
}

class _FakeMessagesRepository extends MessagesRepository {
  _FakeMessagesRepository([this.messages = const []]);

  final List<MessageRecord> messages;

  @override
  Stream<List<MessageRecord>> watchAll() => Stream.value(messages);

  @override
  Future<List<MessageRecord>> getAllMessages() async => messages;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Directory tempDirectory;

  setUpAll(() async {
    final strings = jsonDecode(
      File('assets/translations/en.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    AppStrings.registerStrings({
      'en': strings.map((key, value) => MapEntry(key, value as String)),
    });

    tempDirectory = await Directory.systemTemp.createTemp(
      'layergram_identity_paste_navigation_',
    );
    Hive.init(tempDirectory.path);
    await Hive.openBox<Map>(LocalDatabase.identitiesBoxName);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    await Hive.openBox<Map>(LocalDatabase.chatMetaBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tempDirectory.delete(recursive: true);
  });

  setUp(() async {
    await Hive.box<Map>(LocalDatabase.identitiesBoxName).clear();
    await Hive.box<Map>(LocalDatabase.messagesBoxName).clear();
    await Hive.box<Map>(LocalDatabase.chatMetaBoxName).clear();
  });

  testWidgets(
    'pasted identity link opens confirmed import in Contacts before saving',
    (tester) async {
      const sourceIdentity = LocalIdentity(
        identityId: 'alice-identity',
        publicKeyBase64: 'alice-public-key',
        fingerprint: 'AA-BB-CC-DD',
        displayName: 'Alice',
        mnemonic: 'not-used-by-link-encoding',
      );
      final link = IdentityLinkCodec.encode(sourceIdentity);
      final repository = _FakeIdentitiesRepository();
      addTearDown(repository.dispose);

      await _pumpShell(
        tester,
        clipboardText: link,
        identitiesRepository: repository,
      );

      await tester.tap(find.text('Paste & Decode'));
      await tester.pumpAndSettle();

      expect(find.byType(AddIdentityView), findsOneWidget);
      expect(find.text('Add contact'), findsOneWidget);
      expect(find.text('Alice'), findsOneWidget);
      expect(repository.upsertCount, 0);

      await tester.tap(find.text('Save'));
      await tester.pumpAndSettle();

      expect(find.byType(AddIdentityView), findsNothing);
      expect(repository.upsertCount, 1);
      expect(repository.contacts.single.identityId, 'alice-identity');
      expect(find.text('Contacts'), findsWidgets);
      expect(find.text('Alice'), findsOneWidget);

      final navigationBar =
          tester.widget<NavigationBar>(find.byType(NavigationBar));
      expect(navigationBar.selectedIndex, 1);
    },
  );

  testWidgets(
    'pasted identity text block opens the same confirmed Contacts import',
    (tester) async {
      const identityBlock = '''
Some surrounding text
[Layergram Identity]
Protocol: layergram/1
Name: Bob
Identity ID: bob-identity
Fingerprint: 11-22-33-44
Public Key (Base64):
bob-public-key
[/Layergram Identity]
''';
      final repository = _FakeIdentitiesRepository();
      addTearDown(repository.dispose);

      await _pumpShell(
        tester,
        clipboardText: identityBlock,
        identitiesRepository: repository,
      );

      await tester.tap(find.text('Paste & Decode'));
      await tester.pumpAndSettle();

      expect(find.byType(AddIdentityView), findsOneWidget);
      expect(find.text('Add contact'), findsOneWidget);
      expect(find.text('Bob'), findsOneWidget);
      expect(find.text('ID: bob-identity'), findsOneWidget);
      expect(repository.upsertCount, 0);
    },
  );

  testWidgets(
    'pasting an identity from an open chat also redirects to Contacts import',
    (tester) async {
      const existingContact = RemoteIdentity(
        identityId: 'charlie-identity',
        publicKeyBase64: 'charlie-public-key',
        fingerprint: 'CC-DD-EE-FF',
        displayName: 'Charlie',
      );
      const sourceIdentity = LocalIdentity(
        identityId: 'alice-from-chat',
        publicKeyBase64: 'alice-chat-public-key',
        fingerprint: 'AA-11-BB-22',
        displayName: 'Alice from chat',
        mnemonic: 'not-used-by-link-encoding',
      );
      final repository = _FakeIdentitiesRepository([existingContact]);
      addTearDown(repository.dispose);

      await _pumpShell(
        tester,
        clipboardText: IdentityLinkCodec.encode(sourceIdentity),
        identitiesRepository: repository,
        size: const Size(1200, 900),
        messages: const [
          MessageRecord(
            id: 'charlie-message',
            senderId: 'charlie-identity',
            recipientId: 'local-owner',
            direction: 'incoming',
            timestamp: 1,
          ),
        ],
      );

      expect(find.byTooltip('Paste & Decode'), findsOneWidget);
      await tester.tap(find.byTooltip('Paste & Decode'));
      await tester.pumpAndSettle();

      expect(find.byType(AddIdentityView), findsOneWidget);
      expect(find.text('Alice from chat'), findsOneWidget);
      expect(repository.upsertCount, 0);

      await tester.tap(find.text('Save'));
      await tester.pumpAndSettle();

      expect(find.byType(AddIdentityView), findsNothing);
      expect(repository.upsertCount, 1);
      expect(find.text('Contacts'), findsWidgets);
      expect(find.text('Alice from chat'), findsOneWidget);
    },
  );
}

Future<void> _pumpShell(
  WidgetTester tester, {
  required String clipboardText,
  required _FakeIdentitiesRepository identitiesRepository,
  Size size = const Size(600, 900),
  List<MessageRecord> messages = const [],
}) async {
  final messagesRepository = _FakeMessagesRepository(messages);
  addTearDown(messagesRepository.dispose);

  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        clipboardServiceProvider.overrideWithValue(
          _FakeClipboardService(clipboardText),
        ),
        identitiesRepositoryProvider.overrideWithValue(identitiesRepository),
        messagesRepositoryProvider.overrideWithValue(messagesRepository),
        secureStorageProvider.overrideWithValue(
          _InMemorySecureStorageService(),
        ),
      ],
      child: MaterialApp(
        theme: ThemeData(useMaterial3: true),
        home: const AppShell(),
      ),
    ),
  );
  await tester.pumpAndSettle();
  expect(find.text('Paste & Decode'), findsOneWidget);
}
