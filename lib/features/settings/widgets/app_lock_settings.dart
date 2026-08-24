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
import '../../../core/providers.dart';
import '../../../l10n/app_strings.dart';
import 'change_pin_dialog.dart';
import 'pin_prompt_dialog.dart';

class AppLockSettings extends ConsumerWidget {
  const AppLockSettings({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = AppStrings.t;
    final lockEnabled = ref.watch(appLockEnabledProvider);
    final lockService = ref.read(appLockServiceProvider);
    final timeoutSeconds = ref.watch(appLockTimeoutProvider);

    Future<String?> promptForPin() async {
      return showDialog<String>(
        context: context,
        barrierDismissible: false,
        builder: (context) => const PinPromptDialog(),
      );
    }

    Future<bool> ensurePinConfigured() async {
      final hasPin = await lockService.hasPin();
      if (hasPin) {
        return true;
      }
      final pin = await promptForPin();
      if (pin == null || pin.isEmpty) {
        return false;
      }
      await lockService.setPin(pin);
      return true;
    }

    String describeTimeout(BuildContext context, int seconds) {
      if (seconds == 0) return AppStrings.t(context, 'timeoutNow');
      if (seconds < 60) {
        return AppStrings.t(context, 'timeoutSeconds').replaceAll('{s}', seconds.toString());
      }
      final mins = (seconds / 60).round();
      return AppStrings.t(context, 'timeoutMinutes').replaceAll('{m}', mins.toString());
    }

    Widget timeoutOption(
      BuildContext context, {
      required String label,
      required int value,
      required int currentValue,
    }) {
      final isSelected = value == currentValue;
      return ListTile(
        leading: isSelected ? const Icon(Icons.check, color: Colors.green) : const SizedBox(width: 24),
        title: Text(label),
        onTap: () => Navigator.of(context).pop(value),
      );
    }

    return Column(
      children: [
        SwitchListTile.adaptive(
          value: lockEnabled,
          title: Text(t(context, 'appLock')),
          subtitle: Text(t(context, 'appLockSubtitle')),
          onChanged: (value) async {
            if (value) {
              final supported = await lockService.isBiometricSupported();
              final storedForcePin = await lockService.getForcePin();
              final usePinOnly = !supported || storedForcePin;

              if (usePinOnly && !await ensurePinConfigured()) {
                return;
              }

              ref.read(appLockForcePinProvider.notifier).state = usePinOnly;
              if (usePinOnly != storedForcePin) {
                await lockService.setForcePin(usePinOnly);
              }

              await ref.read(appLockServiceProvider).setEnabled(true);
              ref.read(appLockEnabledProvider.notifier).state = true;
              ref.read(appNeedsUnlockProvider.notifier).state = true;
            } else {
              await ref.read(appLockServiceProvider).setEnabled(false);
              ref.read(appLockEnabledProvider.notifier).state = false;
              ref.read(appNeedsUnlockProvider.notifier).state = false;
              await lockService.clearPin();
            }
          },
        ),
        if (lockEnabled)
          FutureBuilder<bool>(
          future: lockService.isBiometricSupported(),
          builder: (context, snapshot) {
            final supported = snapshot.data ?? false;
            final isPinOnly = ref.watch(appLockForcePinProvider) || !supported;

            return SwitchListTile.adaptive(
              value: !isPinOnly,
              title: Text(t(context, 'biometricUnlock')),
              subtitle: supported ? Text(t(context, 'biometricAvailable')) : null,
              onChanged: supported
                  ? (useBiometrics) async {
                      final usePin = !useBiometrics;
                      if (usePin && !await ensurePinConfigured()) {
                        return;
                      }
                      ref.read(appLockForcePinProvider.notifier).state = usePin;
                      await lockService.setForcePin(usePin);
                    }
                  : null,
            );
          },
          ),
        if (lockEnabled) ...[
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16.0),
            child: Row(
              children: [
                Expanded(
                  child: ListTile(
                    leading: const Icon(Icons.timer_outlined),
                    title: Text(t(context, 'lockTimeout')),
                    subtitle: Text(describeTimeout(context, timeoutSeconds)),
                    contentPadding: EdgeInsets.zero,
                    onTap: () async {
              final selected = await showModalBottomSheet<int>(
                context: context,
                builder: (context) => SafeArea(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 16.0, horizontal: 24.0),
                        child: Text(
                          t(context, 'chooseTimeout'),
                          style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold),
                          textAlign: TextAlign.center,
                        ),
                      ),
                      const Divider(height: 1),
                      Flexible(
                        child: SingleChildScrollView(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              timeoutOption(context, label: describeTimeout(context, 0), value: 0, currentValue: timeoutSeconds),
                              timeoutOption(context, label: describeTimeout(context, 15), value: 15, currentValue: timeoutSeconds),
                              timeoutOption(context, label: describeTimeout(context, 30), value: 30, currentValue: timeoutSeconds),
                              timeoutOption(context, label: describeTimeout(context, 60), value: 60, currentValue: timeoutSeconds),
                              timeoutOption(context, label: describeTimeout(context, 120), value: 120, currentValue: timeoutSeconds),
                              timeoutOption(context, label: describeTimeout(context, 300), value: 300, currentValue: timeoutSeconds),
                              timeoutOption(context, label: describeTimeout(context, 600), value: 600, currentValue: timeoutSeconds),
                              timeoutOption(context, label: describeTimeout(context, 900), value: 900, currentValue: timeoutSeconds),
                              const SizedBox(height: 8),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              );

              if (selected == null) return;
              await ref.read(appLockServiceProvider).setTimeoutSeconds(selected);
              ref.read(appLockTimeoutProvider.notifier).state = selected;
            },
                  ),
                ),
                const SizedBox(width: 8),
                IconButton(
                  onPressed: () {
                    ref.read(appNeedsUnlockProvider.notifier).state = true;
                  },
                  icon: const Icon(Icons.lock),
                  tooltip: t(context, 'lockNow'),
                ),
              ],
            ),
          ),
          ListTile(
            leading: const Icon(Icons.password_outlined),
            title: Text(t(context, 'changePin')),
            onTap: () async {
              final hasPin = await lockService.hasPin();
              if (!hasPin) return;
              
              if (!context.mounted) return;
              final newPin = await ChangePinDialog(
                validateCurrentPin: lockService.validatePin,
              ).show(context);
              if (newPin != null && newPin.isNotEmpty) {
                await lockService.setPin(newPin);
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(t(context, 'pinChanged'))),
                  );
                }
              }
            },
          ),
        ],
      ],
    );
  }
}
