import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:layergram/main.dart' as app;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('app launches and renders first frame', (tester) async {
    app.main();

    for (var i = 0; i < 30; i += 1) {
      await tester.pump(const Duration(milliseconds: 100));
      if (find.byType(MaterialApp).evaluate().isNotEmpty) break;
    }

    expect(find.byType(MaterialApp), findsOneWidget);
    expect(find.byType(Scaffold), findsWidgets);
    expect(tester.takeException(), isNull);
  });
}
