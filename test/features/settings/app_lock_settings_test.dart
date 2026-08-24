import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:layergram/core/providers.dart';
import 'package:layergram/core/security/app_lock_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/features/settings/widgets/app_lock_settings.dart';
import 'package:layergram/l10n/app_strings.dart';

class _BiometricAppLockService extends AppLockService {
  _BiometricAppLockService() : super(SecureStorageService());

  @override
  Future<bool> isBiometricSupported() async => true;
}

void main() {
  setUpAll(() {
    AppStrings.registerStrings({
      'en': {
        'appLock': 'App lock',
        'appLockSubtitle': 'Require authentication to open Layergram',
        'biometricUnlock': 'Biometric unlock',
        'biometricAvailable': 'Available on this device',
        'lockTimeout': 'Lock timeout',
        'timeoutNow': 'Immediately',
        'timeoutSeconds': '{s} seconds',
        'timeoutMinutes': '{m} minutes',
        'lockNow': 'Lock now',
        'changePin': 'Change PIN',
      },
    });
  });

  Future<void> pumpSettings(
    WidgetTester tester, {
    required bool lockEnabled,
  }) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appLockServiceProvider.overrideWithValue(
            _BiometricAppLockService(),
          ),
          appLockEnabledProvider.overrideWith((ref) => lockEnabled),
        ],
        child: const MaterialApp(home: Scaffold(body: AppLockSettings())),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('hides biometric preference until app lock is active',
      (tester) async {
    await pumpSettings(tester, lockEnabled: false);

    expect(find.text('App lock'), findsOneWidget);
    expect(find.text('Biometric unlock'), findsNothing);
  });

  testWidgets('shows biometric preference when app lock is active',
      (tester) async {
    await pumpSettings(tester, lockEnabled: true);

    expect(find.text('Biometric unlock'), findsOneWidget);
    final tile = tester.widget<SwitchListTile>(
      find.widgetWithText(SwitchListTile, 'Biometric unlock'),
    );
    expect(tile.onChanged, isNotNull);
  });
}
