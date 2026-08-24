import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:local_auth/local_auth.dart';

import 'package:layergram/core/capabilities/backup_capability.dart';
import 'package:layergram/core/capabilities/cover_message_generator_capability.dart';
import 'package:layergram/core/capabilities/identity_capability.dart';
import 'package:layergram/core/capabilities/layergram_capabilities.dart';
import 'package:layergram/core/security/app_lock_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/features/premium/backup_view.dart';
import 'package:layergram/features/premium/cover_generator_view.dart';
import 'package:layergram/features/premium/multi_identity_view.dart';
import 'package:layergram/features/settings/settings_view.dart';
import 'package:layergram/l10n/app_strings.dart';

class _FakeAppLockService extends AppLockService {
  _FakeAppLockService() : super(SecureStorageService());

  @override
  Future<List<BiometricType>> availableBiometrics() async =>
      const <BiometricType>[];

  @override
  Future<bool> isBiometricSupported() async => false;
}

class _AvailableBackupCapability implements BackupCapability {
  const _AvailableBackupCapability();

  @override
  bool get isAvailable => true;

  @override
  Future<void> createBackup({
    required String identityId,
    BackupProgressCallback? onProgress,
  }) async {
    onProgress
        ?.call(const BackupProgress(stage: BackupStage.done, fraction: 1));
  }

  @override
  Future<void> restoreBackup({
    required String identityId,
    BackupProgressCallback? onProgress,
  }) async {
    onProgress
        ?.call(const BackupProgress(stage: BackupStage.done, fraction: 1));
  }
}

class _AvailableCoverMessageGeneratorCapability
    implements CoverMessageGeneratorCapability {
  const _AvailableCoverMessageGeneratorCapability();

  @override
  bool get isAvailable => true;

  @override
  Future<String> generate({
    required String languageCode,
    List<String> recentMessages = const <String>[],
    String? tone,
    String? recipientId,
  }) async {
    return 'Generated cover';
  }
}

class _AvailableIdentityCapability implements IdentityCapability {
  const _AvailableIdentityCapability();

  @override
  bool get isAvailable => true;

  @override
  Future<void> setActiveIdentityId(String identityId) async {}

  @override
  Stream<String?> watchActiveIdentityId() => Stream.value('identity-1');

  @override
  Stream<List<IdentityProfile>> watchLocalIdentities() {
    return Stream.value(
      const <IdentityProfile>[
        IdentityProfile(
          identityId: 'identity-1',
          displayName: 'Primary',
        ),
      ],
    );
  }
}

void main() {
  setUpAll(() {
    AppStrings.registerStrings({
      'en': {
        'premiumTag': 'Premium',
        'settingsSectionMessaging': 'Messaging',
        'settingsSectionInformation': 'Information',
        'settingsSectionDanger': 'Danger zone',
        'premiumNotAvailable': 'Not available',
        'premiumFeatures': 'Premium features',
        'premiumBackupTitle': 'Cloud backup',
        'premiumBackupSubtitle': 'Encrypted backup and restore',
        'premiumCoverTitle': 'AI cover messages',
        'premiumCoverSubtitle': 'Generate natural cover text',
        'premiumMultiIdentityTitle': 'Multiple identities',
        'premiumMultiIdentitySubtitle': 'Switch local identities',
      },
    });
  });

  testWidgets('SettingsView hides premium entrypoints in OSS without throwing',
      (WidgetTester tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appLockServiceProvider.overrideWithValue(_FakeAppLockService()),
        ],
        child: const MaterialApp(home: SettingsView()),
      ),
    );

    await tester.pumpAndSettle();

    expect(find.text('Premium features', skipOffstage: false), findsNothing);
    expect(find.text('Cloud backup', skipOffstage: false), findsNothing);
    expect(find.text('AI cover messages', skipOffstage: false), findsNothing);
    expect(find.text('Multiple identities', skipOffstage: false), findsNothing);
    expect(
      find.byKey(const ValueKey('settings-section-premium')),
      findsNothing,
    );
    expect(
      find.byKey(const ValueKey('settings-section-security')),
      findsOneWidget,
    );
  });

  testWidgets('SettingsView reveals available optional capabilities',
      (WidgetTester tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appLockServiceProvider.overrideWithValue(_FakeAppLockService()),
          layergramCapabilitiesProvider.overrideWithValue(
            const LayergramCapabilities(
              backup: _AvailableBackupCapability(),
              coverGenerator: _AvailableCoverMessageGeneratorCapability(),
              identity: _AvailableIdentityCapability(),
            ),
          ),
        ],
        child: const MaterialApp(home: SettingsView()),
      ),
    );

    await tester.pumpAndSettle();

    await tester.scrollUntilVisible(
      find.byKey(const ValueKey('settings-section-premium')),
      300,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.text('Premium features'), findsOneWidget);
    expect(
      find.byKey(const ValueKey('settings-section-premium')),
      findsOneWidget,
    );

    await tester.scrollUntilVisible(
      find.text('Cloud backup'),
      300,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.text('Cloud backup'), findsOneWidget);

    await tester.scrollUntilVisible(
      find.text('AI cover messages'),
      300,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.text('AI cover messages'), findsOneWidget);

    await tester.scrollUntilVisible(
      find.text('Multiple identities'),
      300,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.text('Multiple identities'), findsOneWidget);
  });

  testWidgets('Premium views show locked state in OSS without throwing',
      (WidgetTester tester) async {
    Future<void> pump(Widget child) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(home: child),
        ),
      );
      await tester.pumpAndSettle();
    }

    await pump(const BackupView());
    expect(find.text('Premium'), findsWidgets);

    await pump(const CoverGeneratorView());
    expect(find.text('Premium'), findsWidgets);

    await pump(const MultiIdentityView());
    expect(find.text('Premium'), findsWidgets);
  });
}
