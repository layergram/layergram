import 'dart:async';
import 'dart:io';

import 'package:easy_localization/easy_localization.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:layergram/app.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/security/screen_protection_service.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/l10n/app_strings.dart';
import 'package:layergram/ui/privacy_shield_overlay.dart';

class _MemorySecureStorage extends SecureStorageService {
  _MemorySecureStorage([Map<String, String> values = const {}])
      : _values = Map<String, String>.from(values);

  final Map<String, String> _values;

  @override
  Future<void> write(String key, String value) async {
    _values[key] = value;
  }

  @override
  Future<String?> read(String key) async => _values[key];

  @override
  Future<void> delete(String key) async {
    _values.remove(key);
  }

  @override
  Future<void> deleteAll() async {
    _values.clear();
  }
}

class _DeferredScreenProtectionService extends ScreenProtectionService {
  _DeferredScreenProtectionService(this.enabled, SecureStorageService storage)
      : super(storage);

  final Future<bool> enabled;

  @override
  Future<bool> isEnabled() => enabled;

  @override
  Future<void> applyToPlatform(bool enabled) async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const appLinksMethods = MethodChannel('com.llfbandit.app_links/messages');
  const appLinksEvents = EventChannel('com.llfbandit.app_links/events');
  const sharedPreferences =
      MethodChannel('plugins.flutter.io/shared_preferences');
  late Directory tempDirectory;

  setUpAll(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(sharedPreferences, (call) async {
      if (call.method == 'getAll') return <String, Object>{};
      return null;
    });
    await EasyLocalization.ensureInitialized();
    tempDirectory = await Directory.systemTemp.createTemp('privacy_lifecycle_');
    Hive.init(tempDirectory.path);
    await Hive.openBox<Map>(LocalDatabase.identitiesBoxName);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    await Hive.openBox<Map>(LocalDatabase.chatMetaBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tempDirectory.delete(recursive: true);
  });

  setUp(() {
    TestWidgetsFlutterBinding.instance.handleAppLifecycleStateChanged(
      AppLifecycleState.resumed,
    );
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(appLinksMethods, (_) async => null);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockStreamHandler(
      appLinksEvents,
      MockStreamHandler.inline(onListen: (_, __) {}),
    );
  });

  testWidgets('lifecycle keeps the privacy shield aligned', (tester) async {
    final enabled = Completer<bool>();
    final semantics = tester.ensureSemantics();
    final storage = _MemorySecureStorage();
    ProviderContainer? container;

    try {
      container = await _pumpApp(
        tester,
        storage: storage,
        screenProtectionService: _DeferredScreenProtectionService(
          enabled.future,
          storage,
        ),
      );

      container.read(isSharingProvider.notifier).state = true;
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      await _settle(tester);

      expect(find.byType(PrivacyShieldOverlay), findsOneWidget);
      expect(find.semantics.byLabel('Create identity'), findsNothing);

      enabled.complete(true);
      await _settle(tester);

      expect(find.byType(PrivacyShieldOverlay), findsOneWidget);
      expect(find.semantics.byLabel('Create identity'), findsNothing);
      expect(container.read(privacyShieldVisibleProvider), isTrue);

      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await _settle(tester);
      expect(find.byType(PrivacyShieldOverlay), findsNothing);
      expect(container.read(privacyShieldVisibleProvider), isFalse);

      container.read(screenProtectionEnabledProvider.notifier).state = false;
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      await _settle(tester);
      expect(find.byType(PrivacyShieldOverlay), findsNothing);

      container.read(screenProtectionEnabledProvider.notifier).state = true;
      await _settle(tester);
      expect(container.read(privacyShieldVisibleProvider), isTrue);
      expect(find.byType(PrivacyShieldOverlay), findsOneWidget);

      container.read(screenProtectionEnabledProvider.notifier).state = false;
      await _settle(tester);
      expect(find.byType(PrivacyShieldOverlay), findsNothing);
      expect(container.read(privacyShieldVisibleProvider), isFalse);
    } finally {
      semantics.dispose();
      if (container != null) {
        await _disposeApp(tester, container);
      }
    }
  });
}

Future<ProviderContainer> _pumpApp(
  WidgetTester tester, {
  required SecureStorageService storage,
  ScreenProtectionService? screenProtectionService,
}) async {
  final container = ProviderContainer(
    overrides: [
      secureStorageProvider.overrideWithValue(storage),
      protocolV3MessagingEnabledProvider.overrideWithValue(false),
      if (screenProtectionService != null)
        screenProtectionServiceProvider.overrideWithValue(
          screenProtectionService,
        ),
    ],
  );
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: container,
      child: EasyLocalization(
        supportedLocales: AppStrings.supportedLocales,
        path: 'assets/translations',
        fallbackLocale: const Locale('en'),
        child: const LayergramApp(),
      ),
    ),
  );
  await tester
      .runAsync(() => Future<void>.delayed(const Duration(milliseconds: 20)));
  await _settle(tester);
  return container;
}

Future<void> _disposeApp(
  WidgetTester tester,
  ProviderContainer container,
) async {
  tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pump();
  container.dispose();
}

Future<void> _settle(WidgetTester tester) async {
  for (var frame = 0; frame < 8; frame++) {
    await tester.pump(const Duration(milliseconds: 20));
  }
}
