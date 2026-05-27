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

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../core/providers.dart';
import '../l10n/app_strings.dart';

/// Standalone passphrase toggle button.
///
/// When tapped while inactive, shows a dialog to enter a passphrase and
/// derives ephemeral keys.  When tapped while active, asks for confirmation
/// and destroys the passphrase-derived keys.
///
/// The button is excluded from keyboard focus traversal so it does not
/// interfere with the existing Tab/Shift+Tab order in the composer.
class PassphraseButton extends ConsumerWidget {
  const PassphraseButton({super.key, this.iconSize = 20});

  final double iconSize;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isActive = ref.watch(isPassphraseActiveProvider);
    final t = AppStrings.t;
    final theme = Theme.of(context);

    return ExcludeFocus(
      child: Tooltip(
        message: t(context, 'passphrase'),
        child: Material(
          color: Colors.transparent,
          child: InkWell(
            borderRadius: BorderRadius.circular(20),
            onTap: () => isActive
                ? _confirmDeactivate(context, ref)
                : _showActivateDialog(context, ref),
            child: Padding(
              padding: const EdgeInsets.all(8),
              child: Icon(
                Icons.key,
                size: iconSize,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _showActivateDialog(BuildContext context, WidgetRef ref) async {
    final result = await showDialog<String>(
      context: context,
      builder: (ctx) => const _PassphraseDialog(),
    );

    if (result == null || result.isEmpty) return;
    if (!context.mounted) return;

    final mnemonic =
        await ref.read(identityManagerProvider).getRecoveryPhrase();
    if (mnemonic == null) return;

    await ref.read(passphraseProvider.notifier).activate(mnemonic, result);

    // Start the passphrase timeout controller (§11.3)
    final prefs = ref.read(passphrasePreferencesProvider);
    final tc = ref.read(fsPassphraseTimeoutControllerProvider);
    tc.configure(
      timeout: prefs.timeout,
      expelOnScreenLock: prefs.expelOnScreenLock,
    );
    tc.start();
  }

  Future<void> _confirmDeactivate(BuildContext context, WidgetRef ref) async {
    final t = AppStrings.t;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(t(ctx, 'passphraseDeactivateTitle')),
        content: Text(t(ctx, 'passphraseDeactivateBody')),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: Text(t(ctx, 'cancel')),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: Text(t(ctx, 'confirm')),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      ref.read(fsPassphraseTimeoutControllerProvider).stop();
      ref.read(passphraseProvider.notifier).deactivate();
    }
  }
}

class _PassphraseDialog extends StatefulWidget {
  const _PassphraseDialog();

  @override
  State<_PassphraseDialog> createState() => _PassphraseDialogState();
}

class _PassphraseDialogState extends State<_PassphraseDialog> {
  late final TextEditingController _controller;
  bool _obscureText = true;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final theme = Theme.of(context);
    return AlertDialog(
      title: Text(t(context, 'passphrase')),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            TextField(
              controller: _controller,
              obscureText: _obscureText,
              autofocus: true,
              decoration: InputDecoration(
                hintText: t(context, 'passphraseHint'),
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscureText ? Icons.visibility : Icons.visibility_off,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  onPressed: () {
                    setState(() {
                      _obscureText = !_obscureText;
                    });
                  },
                ),
              ),
              onSubmitted: (value) {
                if (value.trim().isNotEmpty) Navigator.of(context).pop(value.trim());
              },
            ),
            const SizedBox(height: 16),
            RichText(
              text: TextSpan(
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
                children: [
                  TextSpan(text: t(context, 'passphraseWarning')),
                  TextSpan(
                    text: t(context, 'passphraseLearnMore'),
                    style: TextStyle(
                      color: theme.colorScheme.primary,
                      decoration: TextDecoration.underline,
                    ),
                    recognizer: TapGestureRecognizer()
                      ..onTap = () {
                        launchUrl(
                          Uri.parse('https://layergram.app/deniability.html'),
                          mode: LaunchMode.externalApplication,
                        );
                      },
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(t(context, 'cancel')),
        ),
        TextButton(
          onPressed: () {
            final value = _controller.text.trim();
            if (value.isNotEmpty) Navigator.of(context).pop(value);
          },
          child: Text(t(context, 'passphraseActivate')),
        ),
      ],
    );
  }
}
