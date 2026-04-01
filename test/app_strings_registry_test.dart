import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/l10n/app_strings.dart';

void main() {
  testWidgets('AppStrings.registerStrings merges and falls back to en',
      (tester) async {
    AppStrings.registerStrings({
      'en': {
        'premium.hello': 'Hello Premium',
      },
      'it': {
        'premium.hello': 'Ciao Premium',
      },
    });

    String? out;

    Future<void> pumpWithLocale(Locale locale) async {
      await tester.pumpWidget(
        MaterialApp(
          locale: locale,
          supportedLocales: const [
            Locale('en'),
            Locale('it'),
            Locale('fr'),
          ],
          localizationsDelegates: GlobalMaterialLocalizations.delegates,
          home: Builder(
            builder: (context) {
              out = AppStrings.t(context, 'premium.hello');
              return const SizedBox.shrink();
            },
          ),
        ),
      );
    }

    await pumpWithLocale(const Locale('it'));
    expect(out, 'Ciao Premium');

    // Locale not registered -> fallback to en.
    await pumpWithLocale(const Locale('fr'));
    expect(out, 'Hello Premium');

    // Later bundle overrides earlier ones (deterministic by call order).
    AppStrings.registerStrings({
      'en': {
        'premium.hello': 'Hello Premium v2',
      },
    });

    await pumpWithLocale(const Locale('fr'));
    expect(out, 'Hello Premium v2');
  });

  test('AppStrings.registerStrings requires an en fallback for new keys', () {
    expect(
      () => AppStrings.registerStrings({
        'it': {
          'premium.onlyIt': 'Solo IT',
        },
      }),
      throwsArgumentError,
    );
  });
}
