// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/features/security/app_lock_gate.dart';

void main() {
  testWidgets('opaque lock gate blocks a sensitive route and its input',
      (tester) async {
    var locked = false;
    var sensitiveTaps = 0;
    late StateSetter setHostState;

    await tester.pumpWidget(
      MaterialApp(
        home: StatefulBuilder(
          builder: (context, setState) {
            setHostState = setState;
            return AppLockGate(
              lockStateReady: true,
              needsUnlock: locked,
              unlockBuilder: (_) => const Scaffold(
                body: Center(child: Text('Unlock Layergram')),
              ),
              child: Scaffold(
                body: Center(
                  child: FilledButton(
                    onPressed: () => sensitiveTaps++,
                    child: const Text('Sensitive chat'),
                  ),
                ),
              ),
            );
          },
        ),
      ),
    );

    await tester.tap(find.text('Sensitive chat'));
    expect(sensitiveTaps, 1);

    setHostState(() => locked = true);
    await tester.pump();
    expect(find.text('Unlock Layergram'), findsOneWidget);
    await tester.tap(find.text('Sensitive chat'), warnIfMissed: false);
    expect(sensitiveTaps, 1);
  });

  testWidgets('unlock UI has its own navigator for a PIN dialog',
      (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: AppLockGate(
          lockStateReady: true,
          needsUnlock: true,
          unlockBuilder: (context) => Scaffold(
            body: FilledButton(
              onPressed: () => showDialog<void>(
                context: context,
                builder: (_) => const AlertDialog(title: Text('PIN')),
              ),
              child: const Text('Open PIN'),
            ),
          ),
          child: const Scaffold(body: Text('Private route')),
        ),
      ),
    );

    await tester.tap(find.text('Open PIN'));
    await tester.pumpAndSettle();
    expect(find.text('PIN'), findsOneWidget);
  });
}
