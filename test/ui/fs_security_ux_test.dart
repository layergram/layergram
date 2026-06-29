import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_message_classification.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/crypto/fs_state_persistence_service.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/l10n/app_strings.dart';
import 'package:layergram/l10n/fs_strings_bundle.dart';
import 'package:layergram/ui/fs_contact_security_card.dart';
import 'package:layergram/ui/fs_info_sheet.dart';
import 'package:layergram/ui/fs_maximum_fs_dialog.dart';
import 'package:layergram/ui/fs_maximum_setup_dialog.dart';
import 'package:layergram/ui/fs_message_classification_icon.dart';
import 'package:layergram/ui/fs_security_mode_sheet.dart';
import 'package:layergram/ui/fs_status_icon.dart';

class _MemoryFsSecurityModeService extends FsSecurityModeService {
  _MemoryFsSecurityModeService() : super(auxRepository: AuxRecordRepository());

  final Map<String, FsSecurityMode> _modes = {};

  @override
  Future<FsSecurityMode> getMode({
    required String contactId,
    required String identityContext,
  }) async =>
      getModeSync(contactId: contactId, identityContext: identityContext);

  @override
  FsSecurityMode getModeSync({
    required String contactId,
    required String identityContext,
  }) =>
      _modes['$contactId:$identityContext'] ?? FsSecurityMode.advanced;

  @override
  Future<void> setMode({
    required String contactId,
    required String identityContext,
    required FsSecurityMode mode,
  }) async {
    _modes['$contactId:$identityContext'] = mode;
  }
}

class _NoopFsStatePersistenceService extends FsStatePersistenceService {
  _NoopFsStatePersistenceService(FsContactSecurityRegistry registry)
      : super(auxRepository: AuxRecordRepository(), registry: registry);

  @override
  Future<void> saveState(FsContactSecurityState state) async {}

  @override
  Future<void> removeState(String contactId, String? sessionId) async {}
}

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

  testWidgets('disable Maximum FS requires confirmation before downgrade',
      (tester) async {
    final en = FsStringsBundle.bundle['en']!;
    final registry = FsContactSecurityRegistry()
      ..upsert(
        const FsContactSecurityState(
          contactId: 'alice',
          identityContext: 'primary',
          sessionId: 'current-session',
          fsState: FsSessionState.fsActive,
        ),
      )
      ..upsert(
        const FsContactSecurityState(
          contactId: 'alice',
          identityContext: 'primary',
          sessionId: 'registry-only-strict-session',
          fsState: FsSessionState.strictFsActive,
        ),
      );
    final sessionManager = FsSessionManager()
      ..setStateForTesting(
        FsSessionState.fsActive,
        sessionId: 'current-session',
      );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          fsContactSecurityRegistryProvider.overrideWithValue(registry),
          fsSessionManagerProvider('alice').overrideWithValue(sessionManager),
          fsSecurityModeServiceProvider
              .overrideWithValue(_MemoryFsSecurityModeService()),
          fsStatePersistenceServiceProvider
              .overrideWithValue(_NoopFsStatePersistenceService(registry)),
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

    final disableFinder = find.text(en['security.fs.action.disable_strict']!);
    expect(disableFinder, findsOneWidget);

    await tester.ensureVisible(disableFinder);
    await tester.tap(disableFinder);
    await tester.pumpAndSettle();

    expect(
      find.text(en['security.fs.maximum.disable_confirm_title']!),
      findsOneWidget,
    );
    expect(
      find.text(en['security.fs.maximum.disable_confirm_body']!),
      findsOneWidget,
    );
    expect(
      registry
          .lookup(
            contactId: 'alice',
            identityContext: 'primary',
            sessionId: 'registry-only-strict-session',
          )
          ?.fsState,
      FsSessionState.strictFsActive,
    );

    await tester.tap(find.text(en['security.fs.maximum.cancel_button']!));
    await tester.pumpAndSettle();
    expect(
      registry
          .lookup(
            contactId: 'alice',
            identityContext: 'primary',
            sessionId: 'registry-only-strict-session',
          )
          ?.fsState,
      FsSessionState.strictFsActive,
    );

    await tester.ensureVisible(disableFinder);
    await tester.tap(disableFinder);
    await tester.pumpAndSettle();
    await tester.tap(
      find.text(en['security.fs.maximum.disable_confirm_button']!),
    );
    await tester.pumpAndSettle();

    expect(
      registry
          .lookup(
            contactId: 'alice',
            identityContext: 'primary',
            sessionId: 'registry-only-strict-session',
          )
          ?.fsState,
      FsSessionState.fsActive,
    );
    expect(find.text(en['security.fs.mode.changed_snackbar']!), findsOneWidget);
    expect(disableFinder, findsNothing);
    expect(
        find.text(en['security.fs.action.request_maximum']!), findsOneWidget);
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

  testWidgets('Strict message classification uses green lock with gold outline',
      (tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: Center(
            child: FsMessageClassificationIcon(
              classification: FsMessageClassification.strictFs,
              size: 24,
            ),
          ),
        ),
      ),
    );

    final lockIcons = tester
        .widgetList<Icon>(find.byIcon(Icons.lock))
        .map((icon) => icon.color)
        .toSet();
    expect(lockIcons, contains(const Color(0xFFD4A017)));
    expect(lockIcons, contains(Colors.green.shade700));
    expect(find.byIcon(Icons.enhanced_encryption), findsNothing);
  });

  testWidgets('Maximum FS setup dialog requires outgoing confirmation',
      (tester) async {
    final en = FsStringsBundle.bundle['en']!;
    bool? result;

    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) => TextButton(
            onPressed: () async {
              result = await showMaximumFsSetupDialog(
                context,
                incoming: false,
              );
            },
            child: const Text('open setup dialog'),
          ),
        ),
      ),
    );

    await tester.tap(find.text('open setup dialog'));
    await tester.pumpAndSettle();

    expect(find.text(en['security.fs.maximum.setup_title']!), findsOneWidget);
    expect(
      find.text(en['security.fs.maximum.setup_outgoing_body']!),
      findsOneWidget,
    );
    expect(result, isNull);

    await tester.tap(find.text(en['security.fs.maximum.setup_send_button']!));
    await tester.pumpAndSettle();

    expect(result, isTrue);
  });
}
