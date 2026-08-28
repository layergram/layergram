import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/features/identities/add_identity_view.dart';
import 'package:layergram/l10n/app_strings.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(() {
    final strings = jsonDecode(
      File('assets/translations/en.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    AppStrings.registerStrings({
      'en': strings.map((key, value) => MapEntry(key, value as String)),
    });
  });

  testWidgets('contact import remains usable above the tablet keyboard', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 800);
    tester.view.devicePixelRatio = 1;
    tester.view.viewInsets = const FakeViewPadding(bottom: 330);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetViewInsets);

    await tester.pumpWidget(
      ProviderScope(
        child: MaterialApp(
          theme: ThemeData(useMaterial3: true),
          home: const AddIdentityView(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    final pastePane = find.byType(SingleChildScrollView).first;
    final pastePaneScrollable = find.descendant(
      of: pastePane,
      matching: find.byType(Scrollable),
    );
    expect(pastePaneScrollable, findsWidgets);
    expect(tester.takeException(), isNull);

    await tester.scrollUntilVisible(
      find.text('Import'),
      120,
      scrollable: pastePaneScrollable.first,
    );

    expect(
        tester.getBottomRight(find.text('Import')).dy, lessThanOrEqualTo(470));
    expect(tester.takeException(), isNull);
  });
}
