import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/ui/privacy_shield_overlay.dart';

void main() {
  testWidgets('private semantics are hidden and restored with the shield', (
    tester,
  ) async {
    var visible = false;
    late StateSetter setHostState;
    final semantics = tester.ensureSemantics();

    try {
      await tester.pumpWidget(
        MaterialApp(
          home: StatefulBuilder(
            builder: (context, setState) {
              setHostState = setState;
              return PrivacyShieldGate(
                visible: visible,
                child: Semantics(
                  label: 'private content',
                  child: SizedBox.expand(),
                ),
              );
            },
          ),
        ),
      );

      expect(find.semantics.byLabel('private content'), findsOneWidget);

      setHostState(() => visible = true);
      await tester.pump();
      expect(find.semantics.byLabel('private content'), findsNothing);

      setHostState(() => visible = false);
      await tester.pump();
      expect(find.semantics.byLabel('private content'), findsOneWidget);
    } finally {
      semantics.dispose();
    }
  });

  testWidgets('covered content cannot receive taps, focus, or keyboard input', (
    tester,
  ) async {
    var visible = false;
    var taps = 0;
    late StateSetter setHostState;
    final fieldFocus = FocusNode();
    final controller = TextEditingController();
    addTearDown(fieldFocus.dispose);
    addTearDown(controller.dispose);

    await tester.pumpWidget(
      MaterialApp(
        home: StatefulBuilder(
          builder: (context, setState) {
            setHostState = setState;
            return PrivacyShieldGate(
              visible: visible,
              child: Scaffold(
                body: Column(
                  children: [
                    FilledButton(
                      onPressed: () => taps++,
                      child: const Text('private action'),
                    ),
                    TextField(
                      focusNode: fieldFocus,
                      controller: controller,
                    ),
                  ],
                ),
              ),
            );
          },
        ),
      ),
    );

    await tester.tap(find.text('private action'));
    expect(taps, 1);

    await tester.tap(find.byType(TextField));
    expect(fieldFocus.hasFocus, isTrue);

    setHostState(() => visible = true);
    await tester.pump();
    expect(fieldFocus.hasFocus, isFalse);

    await tester.tap(find.text('private action'), warnIfMissed: false);
    await tester.sendKeyEvent(LogicalKeyboardKey.keyA);
    await tester.pump();

    expect(taps, 1);
    expect(controller.text, isEmpty);
    expect(fieldFocus.hasFocus, isFalse);
  });

  testWidgets('child state survives shield toggles', (tester) async {
    var visible = false;
    late StateSetter setHostState;

    await tester.pumpWidget(
      MaterialApp(
        home: StatefulBuilder(
          builder: (context, setState) {
            setHostState = setState;
            return PrivacyShieldGate(
              visible: visible,
              child: const _StatefulRoute(),
            );
          },
        ),
      ),
    );

    await tester.tap(find.text('increment'));
    await tester.pump();
    expect(find.text('1'), findsOneWidget);

    setHostState(() => visible = true);
    await tester.pump();
    setHostState(() => visible = false);
    await tester.pump();

    expect(find.text('1'), findsOneWidget);
  });

  testWidgets('shield paints fully black over a white surface', (
    tester,
  ) async {
    await tester.pumpWidget(
      const Directionality(
        textDirection: TextDirection.ltr,
        child: Center(
          child: SizedBox(
            width: 100,
            height: 100,
            child: PrivacyShieldGate(
              visible: true,
              child: ColoredBox(color: Colors.white),
            ),
          ),
        ),
      ),
    );

    final gate = tester.renderObject<RenderBox>(find.byType(PrivacyShieldGate));
    expect(
      gate,
      paints
        ..rect(rect: Offset.zero & gate.size, color: Colors.white)
        ..rect(rect: Offset.zero & gate.size, color: Colors.black),
    );
  });
}

class _StatefulRoute extends StatefulWidget {
  const _StatefulRoute();

  @override
  State<_StatefulRoute> createState() => _StatefulRouteState();
}

class _StatefulRouteState extends State<_StatefulRoute> {
  var _count = 0;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('$_count'),
            FilledButton(
              onPressed: () => setState(() => _count++),
              child: const Text('increment'),
            ),
          ],
        ),
      ),
    );
  }
}
