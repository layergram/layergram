import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/local_identity_vault.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/features/onboarding/create_or_restore_view.dart';
import 'package:layergram/l10n/app_strings.dart';

const _testMnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

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

class _FixedSeedService extends SeedService {
  _FixedSeedService(this.mnemonic);

  final String mnemonic;

  @override
  String generateMnemonic({int words = 24}) => mnemonic;
}

void main() {
  setUpAll(() {
    final strings = jsonDecode(
      File('assets/translations/en.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    AppStrings.registerStrings({
      'en': strings.map((key, value) => MapEntry(key, value as String)),
    });
  });

  Future<void> pumpOnboarding(
    WidgetTester tester,
    Size size, {
    List<Override> overrides = const [],
  }) async {
    tester.view.physicalSize = size;
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(
      ProviderScope(
        overrides: overrides,
        child: MaterialApp(
          theme: ThemeData(useMaterial3: true),
          home: CreateOrRestoreView(onCompleted: (_) {}),
        ),
      ),
    );
    await tester.pumpAndSettle();
  }

  Future<void> startCreateFlow(
    WidgetTester tester,
    _InMemorySecureStorageService storage,
  ) async {
    await pumpOnboarding(
      tester,
      const Size(390, 844),
      overrides: [
        secureStorageProvider.overrideWithValue(storage),
        seedServiceProvider.overrideWithValue(_FixedSeedService(_testMnemonic)),
      ],
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.text('Name visible to contacts'),
      160,
      scrollable: scrollable,
    );
    await tester.enterText(find.byType(TextField).first, 'Alice');
    await tester.scrollUntilVisible(
      find.byType(Checkbox),
      160,
      scrollable: scrollable,
    );
    await tester.tap(find.byType(Checkbox));
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(
      find.text('Create now'),
      160,
      scrollable: scrollable,
    );
    await tester.tap(find.text('Create now'));
    await tester.pumpAndSettle();

    expect(find.text('Protect your private key'), findsOneWidget);
  }

  testWidgets('makes create the clear first-time path on mobile',
      (tester) async {
    await pumpOnboarding(tester, const Size(390, 844));

    expect(
      find.text('First time here? Create a new identity.'),
      findsOneWidget,
    );
    expect(
      find.text('Restore only if you already have a recovery phrase.'),
      findsNothing,
    );
    expect(tester.takeException(), isNull);

    await tester.tap(find.text('Restore identity'));
    await tester.pumpAndSettle();

    expect(
      find.text('Restore only if you already have a recovery phrase.'),
      findsOneWidget,
    );
    await tester.scrollUntilVisible(
      find.text('Restore from recovery phrase'),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.text('Restore from recovery phrase'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('keeps the onboarding path readable on desktop', (tester) async {
    await pumpOnboarding(tester, const Size(1024, 768));

    expect(find.text('Start with your Layergram identity'), findsOneWidget);
    expect(find.text('Create identity'), findsWidgets);
    await tester.scrollUntilVisible(
      find.text('Write recovery phrase'),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.text('Write recovery phrase'), findsOneWidget);
    expect(find.text('Share public identity'), findsOneWidget);
    expect(find.text('Add first contact'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('restore recovery phrase input disables autocorrect',
      (tester) async {
    await pumpOnboarding(tester, const Size(390, 844));

    await tester.tap(find.text('Restore identity'));
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(
      find.text('Restore from recovery phrase'),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.drag(find.byType(Scrollable).first, const Offset(0, -240));
    await tester.pumpAndSettle();

    final mnemonicField = tester
        .widgetList<TextField>(find.byType(TextField))
        .firstWhere((field) => field.minLines == 2 && field.maxLines == 4);
    expectMnemonicInputSettings(mnemonicField);
  });

  testWidgets('new identity confirmation word input disables autocorrect',
      (tester) async {
    final storage = _InMemorySecureStorageService();

    await startCreateFlow(tester, storage);

    final confirmWordField = tester.widget<TextField>(
      find.byWidgetPredicate(
        (widget) =>
            widget is TextField &&
            widget.textInputAction == TextInputAction.done,
      ),
    );
    expectMnemonicInputSettings(confirmWordField);
    expect(await storage.read(LocalIdentityVault.storageKey), isNull);
  });

  testWidgets('does not persist a new identity before word confirmation',
      (tester) async {
    final storage = _InMemorySecureStorageService();

    await startCreateFlow(tester, storage);

    expect(await storage.read(LocalIdentityVault.storageKey), isNull);
    expect(tester.takeException(), isNull);
  });

  testWidgets('persists a new identity only after the selected word matches',
      (tester) async {
    final storage = _InMemorySecureStorageService();

    await startCreateFlow(tester, storage);
    expect(await storage.read(LocalIdentityVault.storageKey), isNull);

    final label =
        tester.widget<Text>(find.textContaining('Word #').first).data!;
    final index = int.parse(RegExp(r'\d+').firstMatch(label)!.group(0)!);
    final expectedWord = _testMnemonic.split(' ')[index - 1];

    await tester.enterText(find.byType(TextField).last, expectedWord);
    await tester.tap(find.text('I wrote it on paper'));
    await tester.pumpAndSettle();

    expect(await storage.read(LocalIdentityVault.storageKey), isNotNull);
    expect(find.text('Identity created'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}

void expectMnemonicInputSettings(TextField field) {
  expect(field.autocorrect, isFalse);
  expect(field.enableSuggestions, isFalse);
  expect(field.smartDashesType, SmartDashesType.disabled);
  expect(field.smartQuotesType, SmartQuotesType.disabled);
  expect(field.textCapitalization, TextCapitalization.none);
}
