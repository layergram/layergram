import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_setup_guide.dart';

void main() {
  testWidgets(
      'iOS guide explains both permission steps and honest Settings link',
      (tester) async {
    await tester.pumpWidget(const ProviderScope(
      child: MaterialApp(
        locale: Locale('it'),
        supportedLocales: [Locale('it'), Locale('en')],
        localizationsDelegates: [
          GlobalMaterialLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
        ],
        home: SystemKeyboardSetupGuide(iosOverride: true),
      ),
    ));
    expect(find.textContaining('Aggiungi nuova tastiera'), findsOneWidget);
    expect(find.textContaining('Accesso completo'), findsOneWidget);
    await tester.scrollUntilVisible(
        find.byKey(const ValueKey('system-keyboard-guide-open-settings')), 100);
    expect(find.textContaining('non offre un collegamento pubblico diretto'),
        findsOneWidget);
    expect(find.text('Apri impostazioni dell’app'), findsOneWidget);
  });

  testWidgets(
      'Android guide gives keyboard enabling steps without iOS access copy',
      (tester) async {
    await tester.pumpWidget(const ProviderScope(
      child: MaterialApp(
        locale: Locale('it'),
        supportedLocales: [Locale('it'), Locale('en')],
        localizationsDelegates: [
          GlobalMaterialLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
        ],
        home: SystemKeyboardSetupGuide(iosOverride: false),
      ),
    ));
    expect(find.textContaining('tastiere Android'), findsOneWidget);
    expect(find.textContaining('Accesso completo'), findsNothing);
    await tester.scrollUntilVisible(
        find.byKey(const ValueKey('system-keyboard-guide-open-settings')), 100);
    expect(find.text('Apri impostazioni tastiera'), findsOneWidget);
  });
}
