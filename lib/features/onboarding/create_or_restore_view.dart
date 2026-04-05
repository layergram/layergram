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

import '../../core/providers.dart';
import '../../l10n/app_strings.dart';

class CreateOrRestoreView extends ConsumerStatefulWidget {
  const CreateOrRestoreView({super.key, required this.onCompleted});

  final VoidCallback onCompleted;

  @override
  ConsumerState<CreateOrRestoreView> createState() =>
      _CreateOrRestoreViewState();
}

class _CreateOrRestoreViewState extends ConsumerState<CreateOrRestoreView> {
  final _mnemonicCtrl = TextEditingController();
  final _confirmWordCtrl = TextEditingController();
  final _displayNameCtrl = TextEditingController();
  late final TapGestureRecognizer _termsRecognizer;
  late final TapGestureRecognizer _privacyRecognizer;
  String? _error;
  bool _busy = false;
  bool _acceptedLegalConsent = false;

  @override
  void initState() {
    super.initState();
    _termsRecognizer = TapGestureRecognizer()
      ..onTap = () => _openExternalLink('https://layergram.app/terms');
    _privacyRecognizer = TapGestureRecognizer()
      ..onTap = () => _openExternalLink('https://layergram.app/privacy');
  }

  @override
  void dispose() {
    _termsRecognizer.dispose();
    _privacyRecognizer.dispose();
    _mnemonicCtrl.dispose();
    _confirmWordCtrl.dispose();
    _displayNameCtrl.dispose();
    super.dispose();
  }

  Future<void> _openExternalLink(String url) async {
    await launchUrl(
      Uri.parse(url),
      mode: LaunchMode.externalApplication,
    );
  }

  void _dismissKeyboard() {
    FocusManager.instance.primaryFocus?.unfocus();
  }

  List<InlineSpan> _buildLegalConsentSpans(BuildContext context) {
    final theme = Theme.of(context);
    final template = AppStrings.t(
      context,
      'onboardingLegalConsent',
      namedArgs: const {
        'terms': '{terms}',
        'privacy': '{privacy}',
      },
    );
    final termsLabel = AppStrings.t(context, 'termsOfService');
    final privacyLabel = AppStrings.t(context, 'privacyPolicy');
    final linkStyle = theme.textTheme.bodyMedium?.copyWith(
      color: theme.colorScheme.primary,
      decoration: TextDecoration.underline,
    );

    final spans = <InlineSpan>[];
    var cursor = 0;

    while (cursor < template.length) {
      final termsIndex = template.indexOf('{terms}', cursor);
      final privacyIndex = template.indexOf('{privacy}', cursor);

      var nextIndex = -1;
      String? token;
      if (termsIndex != -1 && (privacyIndex == -1 || termsIndex < privacyIndex)) {
        nextIndex = termsIndex;
        token = '{terms}';
      } else if (privacyIndex != -1) {
        nextIndex = privacyIndex;
        token = '{privacy}';
      }

      if (nextIndex == -1) {
        spans.add(TextSpan(text: template.substring(cursor)));
        break;
      }

      if (nextIndex > cursor) {
        spans.add(TextSpan(text: template.substring(cursor, nextIndex)));
      }

      if (token == '{terms}') {
        spans.add(
          TextSpan(
            text: termsLabel,
            style: linkStyle,
            recognizer: _termsRecognizer,
          ),
        );
        cursor = nextIndex + '{terms}'.length;
      } else {
        spans.add(
          TextSpan(
            text: privacyLabel,
            style: linkStyle,
            recognizer: _privacyRecognizer,
          ),
        );
        cursor = nextIndex + token!.length;
      }
    }

    return spans;
  }

  Future<void> _create() async {
    final name = _displayNameCtrl.text.trim();
    if (name.isEmpty) {
      setState(() => _error = AppStrings.t(context, 'enterNameError'));
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final created =
          await ref.read(identityManagerProvider).createNewIdentity(displayName: name);
      if (!mounted) return;

      final words = created.mnemonic.trim().split(RegExp(r'\s+'));
      final targetIndex = words.length >= 7 ? 7 : words.length;
      final expected = words[targetIndex - 1];

      while (true) {
        _confirmWordCtrl.clear();
        if (!mounted) return;
        final confirm = await showDialog<bool>(
          context: context,
          barrierDismissible: false,
          builder: (dialogContext) {
            final t = AppStrings.t;
            return LayoutBuilder(
              builder: (context, constraints) {
                return AlertDialog(
                  title: Text(t(dialogContext, 'confirmRecoveryPhrase')),
                  content: ConstrainedBox(
                    constraints: BoxConstraints(
                      maxHeight: constraints.maxHeight * 0.7,
                    ),
                    child: SingleChildScrollView(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(t(dialogContext, 'recoveryPhraseWarning')),
                          const SizedBox(height: 8),
                          Text(
                            t(dialogContext, 'recoveryPhraseSaveWarning'),
                            style: const TextStyle(fontWeight: FontWeight.w600),
                          ),
                          const SizedBox(height: 12),
                          SelectableText(created.mnemonic),
                          const SizedBox(height: 12),
                          Text(
                            t(dialogContext, 'confirmWordPrompt')
                                .replaceAll('{index}', '$targetIndex'),
                          ),
                          const SizedBox(height: 8),
                          TextField(
                            controller: _confirmWordCtrl,
                            autofocus: true,
                            decoration: InputDecoration(
                              border: const OutlineInputBorder(),
                              hintText: t(dialogContext, 'mnemonic'),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                  actions: [
                    FilledButton(
                      onPressed: () => Navigator.of(dialogContext).pop(true),
                      child: Text(t(dialogContext, 'continueLabel')),
                    ),
                  ],
                );
              },
            );
          },
        );
        if (confirm == true &&
            _confirmWordCtrl.text.trim().toLowerCase() == expected) {
          widget.onCompleted();
          return;
        } else {
          if (!mounted) return;
          final retry = await showDialog<bool>(
            context: context,
            builder: (dialogContext) {
              final t = AppStrings.t;
              return AlertDialog(
                title: Text(t(dialogContext, 'wordMismatch')),
                content: Text(t(dialogContext, 'wordMismatchRetry')),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.of(dialogContext).pop(false),
                    child: Text(t(dialogContext, 'cancel')),
                  ),
                  FilledButton(
                    onPressed: () => Navigator.of(dialogContext).pop(true),
                    child: Text(t(dialogContext, 'retry')),
                  ),
                ],
              );
            },
          );
          if (retry != true) {
            setState(() => _error = AppStrings.t(context, 'wordMismatch'));
            return;
          }
        }
      }
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _restore() async {
    final name = _displayNameCtrl.text.trim();
    if (name.isEmpty) {
      setState(() => _error = AppStrings.t(context, 'enterNameError'));
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(identityManagerProvider).restoreIdentityFromMnemonic(
            _mnemonicCtrl.text.trim(),
            displayName: name,
          );
      widget.onCompleted();
    } catch (_) {
      setState(() => _error = AppStrings.t(context, 'recoveryPhraseHint'));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final isRestoreMode = _mnemonicCtrl.text.trim().isNotEmpty;
    return Scaffold(
      appBar: AppBar(title: Text(t(context, 'onboardingTitle'))),
      body: GestureDetector(
        behavior: HitTestBehavior.translucent,
        onTap: _dismissKeyboard,
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 640),
            child: Card(
              margin: const EdgeInsets.all(16),
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  Text(
                    t(context, 'onboardingSubtitle'),
                    style: Theme.of(context).textTheme.bodyLarge,
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _displayNameCtrl,
                    enabled: !_busy,
                    decoration: InputDecoration(
                      labelText: t(context, 'visibleNameLabel'),
                      hintText: t(context, 'displayNameHint'),
                      border: const OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    t(context, 'restoreFromMnemonic'),
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _mnemonicCtrl,
                    minLines: 2,
                    maxLines: 4,
                    onChanged: (_) => setState(() {}),
                    decoration: InputDecoration(
                        hintText: t(context, 'recoveryPhraseHint')),
                  ),
                  const SizedBox(height: 16),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Checkbox(
                        value: _acceptedLegalConsent,
                        onChanged: _busy
                            ? null
                            : (value) {
                                setState(() => _acceptedLegalConsent = value ?? false);
                              },
                      ),
                      Expanded(
                        child: Padding(
                          padding: const EdgeInsets.only(top: 12),
                          child: RichText(
                            text: TextSpan(
                              style: Theme.of(context).textTheme.bodyMedium,
                              children: _buildLegalConsentSpans(context),
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  FilledButton(
                    onPressed: _busy || !_acceptedLegalConsent
                        ? null
                        : (isRestoreMode ? _restore : _create),
                    child: Text(t(context, isRestoreMode ? 'restoreNow' : 'createNow')),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 12),
                    Text(_error!, style: const TextStyle(color: Colors.red)),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
