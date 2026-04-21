import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/features/identity_migration_notice/identity_migration_notice_dialog.dart';
import 'package:layergram/l10n/app_strings.dart';

void main() {
  setUpAll(() {
    AppStrings.registerStrings({
      'en': {
        'legacyIdentityNoticeTitle': 'Update Required',
        'legacyIdentityNoticeBody': 'Your identity uses a legacy key format.',
        'legacyIdentityNoticeRemindLater': 'Remind me later',
        'legacyIdentityNoticeUnderstand': 'I understand',
      },
    });
  });

  group('showIdentityMigrationNoticeDialog', () {
    testWidgets('dialog is displayed with title, body and both actions', (tester) async {
      late Future<IdentityMigrationNoticeAction?> result;

      await tester.pumpWidget(MaterialApp(
        home: Builder(builder: (context) => ElevatedButton(
          onPressed: () { result = showIdentityMigrationNoticeDialog(context); },
          child: const Text('open'),
        )),
      ));
      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();

      expect(find.text('Update Required'), findsOneWidget);
      expect(find.text('Your identity uses a legacy key format.'), findsOneWidget);
      expect(find.text('Remind me later'), findsOneWidget);
      expect(find.text('I understand'), findsOneWidget);
      result.ignore();
    });

    testWidgets('tapping "I understand" returns understand action', (tester) async {
      late Future<IdentityMigrationNoticeAction?> result;

      await tester.pumpWidget(MaterialApp(
        home: Builder(builder: (context) => ElevatedButton(
          onPressed: () { result = showIdentityMigrationNoticeDialog(context); },
          child: const Text('open'),
        )),
      ));
      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('I understand'));
      await tester.pumpAndSettle();

      expect(await result, equals(IdentityMigrationNoticeAction.understand));
    });

    testWidgets('tapping "Remind me later" returns remindLater action', (tester) async {
      late Future<IdentityMigrationNoticeAction?> result;

      await tester.pumpWidget(MaterialApp(
        home: Builder(builder: (context) => ElevatedButton(
          onPressed: () { result = showIdentityMigrationNoticeDialog(context); },
          child: const Text('open'),
        )),
      ));
      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Remind me later'));
      await tester.pumpAndSettle();

      expect(await result, equals(IdentityMigrationNoticeAction.remindLater));
    });

    testWidgets('dialog is not dismissible by tapping the barrier', (tester) async {
      late Future<IdentityMigrationNoticeAction?> result;

      await tester.pumpWidget(MaterialApp(
        home: Builder(builder: (context) => ElevatedButton(
          onPressed: () { result = showIdentityMigrationNoticeDialog(context); },
          child: const Text('open'),
        )),
      ));
      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();

      // Attempt to dismiss by tapping outside (barrierDismissible: false).
      await tester.tapAt(const Offset(10, 10));
      await tester.pumpAndSettle();

      expect(find.text('Update Required'), findsOneWidget);
      result.ignore();
    });

    testWidgets('back button (PopScope canPop: false) does not dismiss the dialog', (tester) async {
      late Future<IdentityMigrationNoticeAction?> result;

      await tester.pumpWidget(MaterialApp(
        home: Builder(builder: (context) => ElevatedButton(
          onPressed: () { result = showIdentityMigrationNoticeDialog(context); },
          child: const Text('open'),
        )),
      ));
      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();

      final NavigatorState navigator = tester.state(find.byType(Navigator).first);
      navigator.maybePop();
      await tester.pumpAndSettle();

      expect(find.text('Update Required'), findsOneWidget);
      result.ignore();
    });
  });
}
