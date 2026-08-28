import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/app.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/l10n/app_strings.dart';

class _RetryHarness extends StatefulWidget {
  const _RetryHarness({required this.initialFuture});

  final Future<LocalIdentity?> initialFuture;

  @override
  State<_RetryHarness> createState() => _RetryHarnessState();
}

class _RetryHarnessState extends State<_RetryHarness> {
  late Future<LocalIdentity?> _future = widget.initialFuture;

  static final identity = LocalIdentity(
    identityId: 'test-id',
    publicKeyBase64: 'dGVzdA==',
    fingerprint: 'AA-BB',
    displayName: 'Alice',
    mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  );

  @override
  Widget build(BuildContext context) {
    return IdentityStartupGate(
      identityFuture: _future,
      onRetry: () {
        setState(() {
          _future = Future<LocalIdentity?>.value(identity);
        });
      },
      missingIdentityBuilder: (_) =>
          const SizedBox(key: ValueKey('missing-identity')),
      readyBuilder: (_) => const SizedBox(key: ValueKey('identity-ready')),
    );
  }
}

void main() {
  setUpAll(() {
    AppStrings.registerStrings({
      'en': {
        'noActiveIdentity': 'No active identity',
        'retry': 'Retry',
      },
    });
  });

  testWidgets('startup loading cannot expose onboarding actions', (
    tester,
  ) async {
    final pending = Completer<LocalIdentity?>();

    await tester.pumpWidget(
      MaterialApp(home: _RetryHarness(initialFuture: pending.future)),
    );
    await tester.pump();

    expect(find.byType(CircularProgressIndicator), findsOneWidget);
    expect(find.byKey(const ValueKey('missing-identity')), findsNothing);
    expect(find.byKey(const ValueKey('identity-ready')), findsNothing);
  });

  testWidgets('startup storage error is recoverable and never opens onboarding',
      (
    tester,
  ) async {
    final pending = Completer<LocalIdentity?>();

    await tester.pumpWidget(
      MaterialApp(home: _RetryHarness(initialFuture: pending.future)),
    );
    pending.completeError(StateError('test storage failure'));
    await tester.pumpAndSettle();

    expect(find.text('No active identity'), findsOneWidget);
    expect(find.text('Retry'), findsOneWidget);
    expect(find.byKey(const ValueKey('missing-identity')), findsNothing);
    expect(find.byKey(const ValueKey('identity-ready')), findsNothing);

    await tester.tap(find.text('Retry'));
    await tester.pumpAndSettle();

    expect(find.byKey(const ValueKey('identity-ready')), findsOneWidget);
    expect(find.byKey(const ValueKey('missing-identity')), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('only a successful null load opens onboarding', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: _RetryHarness(
          initialFuture: Future<LocalIdentity?>.value(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byKey(const ValueKey('missing-identity')), findsOneWidget);
    expect(find.text('Retry'), findsNothing);
    expect(tester.takeException(), isNull);
  });
}
