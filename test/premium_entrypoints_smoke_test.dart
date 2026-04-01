import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:local_auth/local_auth.dart';

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

void main() {
  setUpAll(() {
    AppStrings.registerStrings({
      'en': {
        'premiumTag': 'Premium',
        'premiumNotAvailable': 'Not available',
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
