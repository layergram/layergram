import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/v3/identity_v3_adapter.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/identities_repository.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/messages_repository.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/core/utils/clipboard_service.dart';
import 'package:layergram/features/identities/add_identity_view.dart';
import 'package:layergram/features/identities/identities_controller.dart';
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

class _IdentityPasteTestController extends IdentitiesController {
  _IdentityPasteTestController(super.ref);

  @override
  Future<void> saveIdentity(RemoteIdentity identity) {
    return ref
        .read(identitiesRepositoryProvider)
        .upsertRemoteIdentity(identity);
  }
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
      final sourceIdentity = _v3Identity(
        displayName: 'Alice',
        seed: 1,
      );
      final link = V3PublicIdentityCodec.encodeLink(sourceIdentity);
      final repository = _FakeIdentitiesRepository();
      addTearDown(repository.dispose);

      await _pumpShell(
        tester,
        clipboardText: link,
        identitiesRepository: repository,
      );

      await tester.tap(find.text('Paste & Decode'));
      await _pumpNavigation(tester);

      expect(find.byType(AddIdentityView), findsOneWidget);
      expect(find.text('Add contact'), findsOneWidget);
      expect(find.text('Alice'), findsOneWidget);
      expect(repository.upsertCount, 0);

      await tester.tap(find.text('Save'));
      await _pumpNavigation(tester);

      expect(find.byType(AddIdentityView), findsNothing);
      expect(repository.upsertCount, 1);
      expect(repository.contacts.single.identityId, sourceIdentity.identityId);
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
      final sourceIdentity = _v3Identity(
        displayName: 'Bob',
        seed: 2,
      );
      final identityBlock = '''
Some surrounding text
${V3IdentityAdapter.encodeShareBlock(sourceIdentity)}
''';
      final repository = _FakeIdentitiesRepository();
      addTearDown(repository.dispose);

      await _pumpShell(
        tester,
        clipboardText: identityBlock,
        identitiesRepository: repository,
      );

      await tester.tap(find.text('Paste & Decode'));
      await _pumpNavigation(tester);

      expect(find.byType(AddIdentityView), findsOneWidget);
      expect(find.text('Add contact'), findsOneWidget);
      expect(find.text('Bob'), findsOneWidget);
      expect(find.text('ID: ${sourceIdentity.identityId}'), findsOneWidget);
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
      final sourceIdentity = _v3Identity(
        displayName: 'Alice from chat',
        seed: 3,
      );
      final repository = _FakeIdentitiesRepository([existingContact]);
      addTearDown(repository.dispose);

      await _pumpShell(
        tester,
        clipboardText: V3PublicIdentityCodec.encodeLink(sourceIdentity),
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
      await _pumpNavigation(tester);

      expect(find.byType(AddIdentityView), findsOneWidget);
      expect(find.text('Alice from chat'), findsOneWidget);
      expect(repository.upsertCount, 0);

      await tester.tap(find.text('Save'));
      await _pumpNavigation(tester);

      expect(find.byType(AddIdentityView), findsNothing);
      expect(repository.upsertCount, 1);
      expect(find.text('Contacts'), findsWidgets);
      expect(find.text('Alice from chat'), findsOneWidget);
    },
  );
}

V3PublicIdentity _v3Identity({
  required String displayName,
  required int seed,
}) {
  final x25519PublicKey = Uint8List.fromList(
    List<int>.generate(32, (index) => (seed + index) & 0xff),
  );
  final mlKem768PublicKey = Uint8List.fromList(
    List<int>.generate(
      MlKem768.publicKeyBytes,
      (index) => ((seed * 17) + index) % 251 + 1,
    ),
  );
  return V3PublicIdentity(
    x25519PublicKey: x25519PublicKey,
    mlKem768PublicKey: mlKem768PublicKey,
    displayName: displayName,
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
        identitiesControllerProvider.overrideWith(
          (ref) => _IdentityPasteTestController(ref),
        ),
        // This widget test covers the active v3 identity-import path only.
        // Keep the independent messaging-session lifecycle out of scope.
        protocolV3MessagingEnabledProvider.overrideWithValue(false),
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
  await _pumpNavigation(tester);
  expect(find.text('Paste & Decode'), findsOneWidget);
}

Future<void> _pumpNavigation(WidgetTester tester) async {
  for (var frame = 0; frame < 12; frame++) {
    await tester.pump(const Duration(milliseconds: 100));
  }
}
