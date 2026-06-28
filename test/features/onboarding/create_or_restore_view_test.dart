import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/features/onboarding/create_or_restore_view.dart';
import 'package:layergram/l10n/app_strings.dart';

void main() {
  setUpAll(() {
    final strings = jsonDecode(
      File('assets/translations/en.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    AppStrings.registerStrings({
      'en': strings.map((key, value) => MapEntry(key, value as String)),
    });
  });

  Future<void> pumpOnboarding(WidgetTester tester, Size size) async {
    tester.view.physicalSize = size;
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(
      ProviderScope(
        child: MaterialApp(
          theme: ThemeData(useMaterial3: true),
          home: CreateOrRestoreView(onCompleted: (_) {}),
        ),
      ),
    );
    await tester.pumpAndSettle();
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
      find.text('Save recovery phrase'),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.text('Save recovery phrase'), findsOneWidget);
    expect(find.text('Share public identity'), findsOneWidget);
    expect(find.text('Add first contact'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
