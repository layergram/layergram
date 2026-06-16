import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/l10n/app_strings.dart';
import 'package:layergram/l10n/fs_strings_bundle.dart';
import 'package:layergram/ui/fs_contact_security_card.dart';
import 'package:layergram/ui/fs_info_sheet.dart';
import 'package:layergram/ui/fs_maximum_fs_dialog.dart';
import 'package:layergram/ui/fs_security_mode_sheet.dart';
import 'package:layergram/ui/fs_status_icon.dart';

void main() {
  late Directory tmpDir;

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    AppStrings.registerStrings(FsStringsBundle.bundle);
    tmpDir = await Directory.systemTemp.createTemp('layergram_fs_ux_test_');
    Hive.init(tmpDir.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tmpDir.delete(recursive: true);
  });

  Widget app(Widget child, {ThemeData? theme}) {
    return MaterialApp(
      theme: theme,
      home: Scaffold(body: Center(child: child)),
    );
  }

  testWidgets('broken FS status icon is a red warning with clear tooltip',
      (tester) async {
    final theme = ThemeData(
      colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
    );

    await tester.pumpWidget(
      app(
        const FsStatusIcon(fsState: FsSessionState.fsBroken, size: 24),
        theme: theme,
      ),
    );

    final warningFinder = find.byIcon(Icons.warning_amber_rounded);
    expect(warningFinder, findsOneWidget);
    final warning = tester.widget<Icon>(warningFinder);
    expect(warning.color, theme.colorScheme.error);
    expect(
      warning.semanticLabel,
      FsStringsBundle.bundle['en']!['security.fs.status.broken'],
    );

    final tooltip = tester.widget<Tooltip>(find.byType(Tooltip));
    expect(
      tooltip.message,
      FsStringsBundle.bundle['en']!['security.fs.status.broken'],
    );
  });

  testWidgets('broken FS info sheet explains what happened and next step',
      (tester) async {
    final en = FsStringsBundle.bundle['en']!;

    await tester.pumpWidget(
      app(const FsInfoSheet(fsState: FsSessionState.fsBroken)),
    );

    expect(find.text(en['security.fs.status.broken']!), findsOneWidget);
    expect(
      find.text(en['security.fs.info.broken_description']!),
      findsOneWidget,
    );
    expect(
      find.text(en['security.fs.info.broken_keep_in_mind']!),
      findsOneWidget,
    );
    expect(find.text(en['security.fs.info.action_close']!), findsOneWidget);
  });

  testWidgets('broken FS contact card shows recovery actions', (tester) async {
    final en = FsStringsBundle.bundle['en']!;
    final registry = FsContactSecurityRegistry()
      ..upsert(
        const FsContactSecurityState(
          contactId: 'alice',
          identityContext: 'primary',
          sessionId: 'broken-session',
          fsState: FsSessionState.fsBroken,
        ),
      );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          fsContactSecurityRegistryProvider.overrideWithValue(registry),
        ],
        child: const MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: FsContactSecurityCard(contactId: 'alice'),
            ),
          ),
        ),
      ),
    );

    expect(find.text(en['security.fs.status.broken']!), findsOneWidget);
    expect(find.text(en['security.fs.action.retry']!), findsOneWidget);
    expect(find.text(en['security.fs.action.reset']!), findsOneWidget);
    expect(find.byIcon(Icons.warning_amber_rounded), findsWidgets);
  });

  testWidgets('Maximum FS consent cannot be confirmed without both warnings',
      (tester) async {
    final en = FsStringsBundle.bundle['en']!;
    bool? result;

    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) => TextButton(
            onPressed: () async {
              result = await showMaximumFsConsentDialog(context);
            },
            child: const Text('open maximum dialog'),
          ),
        ),
      ),
    );

    await tester.tap(find.text('open maximum dialog'));
    await tester.pumpAndSettle();

    expect(find.text(en['security.fs.maximum.confirm_title']!), findsOneWidget);
    expect(find.text(en['security.fs.warning.device_bound_title']!),
        findsOneWidget);
    expect(find.text(en['security.fs.warning.recoverability_title']!),
        findsOneWidget);

    final confirmFinder = find.widgetWithText(
      FilledButton,
      en['security.fs.maximum.confirm_button']!,
    );
    expect(tester.widget<FilledButton>(confirmFinder).onPressed, isNull);

    final firstCheckbox = find.byType(Checkbox).first;
    final lastCheckbox = find.byType(Checkbox).last;

    await tester.ensureVisible(firstCheckbox);
    await tester.tap(firstCheckbox);
    await tester.pumpAndSettle();
    expect(tester.widget<FilledButton>(confirmFinder).onPressed, isNull);

    await tester.ensureVisible(lastCheckbox);
    await tester.tap(lastCheckbox);
    await tester.pumpAndSettle();
    expect(tester.widget<FilledButton>(confirmFinder).onPressed, isNotNull);

    await tester.tap(confirmFinder);
    await tester.pumpAndSettle();
    expect(result, isTrue);
  });

  testWidgets('Strict mode sheet requires device-bound acknowledgement',
      (tester) async {
    final en = FsStringsBundle.bundle['en']!;
    FsSecurityMode? result;

    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) => TextButton(
            onPressed: () async {
              result = await showFsSecurityModeSheet(
                context,
                currentMode: FsSecurityMode.base,
              );
            },
            child: const Text('open mode sheet'),
          ),
        ),
      ),
    );

    await tester.tap(find.text('open mode sheet'));
    await tester.pumpAndSettle();

    await tester.tap(find.text(en['security.fs.mode.strict_title']!));
    await tester.pumpAndSettle();

    expect(find.text(en['security.fs.warning.device_bound_title']!),
        findsOneWidget);
    expect(find.text(en['security.fs.warning.device_bound_body']!),
        findsOneWidget);

    final confirmFinder = find.widgetWithText(
      FilledButton,
      en['security.fs.mode.confirm_button']!,
    );
    expect(tester.widget<FilledButton>(confirmFinder).onPressed, isNull);

    final acknowledgement = find.byType(Checkbox);
    await tester.ensureVisible(acknowledgement);
    await tester.tap(acknowledgement);
    await tester.pumpAndSettle();
    expect(tester.widget<FilledButton>(confirmFinder).onPressed, isNotNull);

    await tester.tap(confirmFinder);
    await tester.pumpAndSettle();
    expect(result, FsSecurityMode.strict);
  });
}
