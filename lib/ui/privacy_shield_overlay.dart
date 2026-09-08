// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'package:flutter/material.dart';

import '../l10n/app_strings.dart';

/// Keeps [child] mounted while preventing it from being exposed or interactive
/// whenever the privacy shield is visible.
class PrivacyShieldGate extends StatelessWidget {
  const PrivacyShieldGate({
    super.key,
    required this.visible,
    required this.child,
  });

  final bool visible;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Stack(
      fit: StackFit.expand,
      children: [
        ExcludeSemantics(
          excluding: visible,
          child: IgnorePointer(
            ignoring: visible,
            child: ExcludeFocus(
              excluding: visible,
              child: TickerMode(enabled: !visible, child: child),
            ),
          ),
        ),
        if (visible) const Positioned.fill(child: PrivacyShieldOverlay()),
      ],
    );
  }
}

class PrivacyShieldOverlay extends StatelessWidget {
  const PrivacyShieldOverlay({super.key});

  @override
  Widget build(BuildContext context) {
    return AbsorbPointer(
      child: ColoredBox(
        color: Colors.black,
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.shield_outlined,
                  size: 44, color: Colors.white70),
              const SizedBox(height: 12),
              Text(
                AppStrings.t(context, 'privacyShieldOverlay'),
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: Colors.white70,
                  fontSize: 14,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
