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

/// Opaque, non-bypassable shield above the complete application navigator.
///
/// A nested navigator lets the unlock UI present its PIN dialog without
/// exposing or replacing the underlying route stack.
final class AppLockGate extends StatelessWidget {
  const AppLockGate({
    super.key,
    required this.child,
    required this.lockStateReady,
    required this.needsUnlock,
    required this.unlockBuilder,
    this.lockNavigatorKey,
  });

  final Widget child;
  final bool lockStateReady;
  final bool needsUnlock;
  final WidgetBuilder unlockBuilder;
  final GlobalKey<NavigatorState>? lockNavigatorKey;

  @override
  Widget build(BuildContext context) {
    final blocked = !lockStateReady || needsUnlock;
    return Stack(
      fit: StackFit.expand,
      children: [
        ExcludeSemantics(
          excluding: blocked,
          child: IgnorePointer(
            ignoring: blocked,
            child: TickerMode(enabled: !blocked, child: child),
          ),
        ),
        if (blocked)
          Positioned.fill(
            child: ColoredBox(
              color: Theme.of(context).scaffoldBackgroundColor,
              child: lockStateReady
                  ? Navigator(
                      key: lockNavigatorKey,
                      onGenerateRoute: (_) => MaterialPageRoute<void>(
                        builder: unlockBuilder,
                      ),
                    )
                  : const Scaffold(
                      body: Center(child: CircularProgressIndicator()),
                    ),
            ),
          ),
      ],
    );
  }
}
