import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/features/contact_verification/contact_verification_actions.dart';

void main() {
  testWidgets('a verified identity can show its code without revocation',
      (tester) async {
    var comparisons = 0;
    var revocations = 0;
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: ContactVerificationActions(
          verified: true,
          onCompare: () => comparisons++,
          onRevoke: () => revocations++,
        ),
      ),
    ));

    expect(find.byType(FilledButton), findsOneWidget);
    expect(find.byType(TextButton), findsOneWidget);
    await tester.tap(find.byType(FilledButton));
    expect(comparisons, 1);
    expect(revocations, 0);
    await tester.tap(find.byType(TextButton));
    expect(revocations, 1);
  });
}
