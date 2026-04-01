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
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/providers.dart';
import '../../l10n/app_strings.dart';

class UnlockView extends ConsumerStatefulWidget {
  const UnlockView({super.key, required this.onUnlocked});

  final VoidCallback onUnlocked;

  @override
  ConsumerState<UnlockView> createState() => _UnlockViewState();
}

class _UnlockViewState extends ConsumerState<UnlockView> {
  String? _error;

  Future<void> _unlock() async {
    final service = ref.read(appLockServiceProvider);
    final t = AppStrings.t;
    final forcePin = ref.read(appLockForcePinProvider);
    final biometricSupported = await service.isBiometricSupported();
    final usePinOnly = forcePin || !biometricSupported;
    final stored = await service.getPin();
    final hasPin = stored != null && stored.isNotEmpty;

    if (!mounted) return;
    final prompt = AppStrings.t(context, 'unlockWithBiometricsPrompt');

    if (!usePinOnly) {
      final bioOk = await service.authenticateBiometric(
        reason: prompt,
      );

      if (bioOk) {
        widget.onUnlocked();
        return;
      }

      if (!mounted) return;
      setState(() => _error = AppStrings.t(context, 'biometricAuthFailed'));
      return;
    }

    if (!hasPin) {
      if (!mounted) return;
      setState(() => _error = AppStrings.t(context, 'noPinSet'));
      return;
    }

    if (!mounted) return;
    final pin = await _askPin(context);
    if (pin == null) return;

    final ok = stored == pin;
    if (!ok) {
      setState(() => _error = t(context, 'invalidPin'));
      return;
    }

    widget.onUnlocked();
  }

  Future<String?> _askPin(BuildContext context) async {
    final t = AppStrings.t;
    String pin = '';
    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        return AlertDialog(
          title: Text(t(context, 'enterPin')),
          content: TextField(
            autofocus: true,
            obscureText: true,
            keyboardType: TextInputType.number,
            onChanged: (v) => pin = v,
            onSubmitted: (v) {
              Navigator.of(context).pop(v);
            },
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: Text(t(context, 'cancel')),
            ),
            TextButton(
              onPressed: () => Navigator.of(context).pop(pin),
              child: Text(t(context, 'unlock')), 
            ),
          ],
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final forcePin = ref.watch(appLockForcePinProvider);
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Card(
              elevation: 0,
              margin: const EdgeInsets.all(16),
              child: Padding(
                padding: const EdgeInsets.all(20),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.lock_outline,
                        size: 56,
                        color: Theme.of(context).colorScheme.primary),
                    const SizedBox(height: 12),
                    Text(t(context, 'unlockApp'),
                        style: Theme.of(context).textTheme.titleLarge),
                    const SizedBox(height: 6),
                    Text(
                      t(context, 'privacyShield'),
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                    const SizedBox(height: 16),
                    Icon(forcePin ? Icons.pin : Icons.fingerprint, size: 40),
                    const SizedBox(height: 10),
                    Text(
                      forcePin
                          ? t(context, 'unlockWithPin')
                          : t(context, 'biometricUnlock'),
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    if (_error != null) ...[
                      const SizedBox(height: 8),
                      Text(_error!,
                          style: const TextStyle(color: Colors.red)),
                    ],
                    const SizedBox(height: 14),
                    SizedBox(
                      width: double.infinity,
                      child: FilledButton(
                        onPressed: _unlock,
                        child: Text(t(context, 'unlock')),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
