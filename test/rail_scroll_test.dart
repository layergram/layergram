import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('NavigationRail overflow test', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: SizedBox(
          width: 100,
          height: 200,
          child: LayoutBuilder(
            builder: (context, constraints) {
              return SingleChildScrollView(
                child: ConstrainedBox(
                  constraints: BoxConstraints(
                    minHeight: constraints.maxHeight,
                  ),
                  child: IntrinsicHeight(
                    child: NavigationRail(
                      selectedIndex: 0,
                      destinations: List.generate(20, (i) => NavigationRailDestination(
                        icon: Icon(Icons.ac_unit),
                        label: Text('Item $i'),
                      )),
                    ),
                  ),
                ),
              );
            }
          ),
        ),
      ),
    ));
    expect(find.byType(NavigationRail), findsOneWidget);
  });
}
