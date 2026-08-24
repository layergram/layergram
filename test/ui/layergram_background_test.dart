import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/ui/layergram_background.dart';

void main() {
  testWidgets('background is static and schedules no repeating animation', (
    tester,
  ) async {
    await tester.pumpWidget(
      Theme(
        data: ThemeData.light(),
        child: const Directionality(
          textDirection: TextDirection.ltr,
          child: LayergramBackground(child: SizedBox.expand()),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(AnimatedBuilder), findsNothing);
    expect(tester.hasRunningAnimations, isFalse);

    await tester.pump(const Duration(seconds: 30));

    expect(find.byType(AnimatedBuilder), findsNothing);
    expect(tester.hasRunningAnimations, isFalse);
    expect(tester.takeException(), isNull);
  });

  test('obsolete animation load limiter and chat holds are absent', () {
    final app = File('lib/app.dart').readAsStringSync();
    final providers = File('lib/core/providers.dart').readAsStringSync();
    final chat = File('lib/features/home/chat_view.dart').readAsStringSync();
    final background = File(
      'lib/ui/layergram_background.dart',
    ).readAsStringSync();

    expect(app, isNot(contains('addTimingsCallback')));
    expect(app, isNot(contains('FrameTiming')));
    expect(providers, isNot(contains('reducedEffectsProvider')));
    expect(providers, isNot(contains('backgroundAnimationHoldCountProvider')));
    expect(chat, isNot(contains('_backgroundHoldActive')));
    expect(background, isNot(contains('AnimationController')));
    expect(background, isNot(contains('AnimatedBuilder')));
  });
}
