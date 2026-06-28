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

import 'dart:math' as math;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../core/crypto/seed_service.dart';
import '../../core/providers.dart';
import '../../l10n/app_strings.dart';

const _gettingStartedGuideUrl = 'https://layergram.app/gettingstarted/';

class CreateOrRestoreView extends ConsumerStatefulWidget {
  const CreateOrRestoreView({super.key, required this.onCompleted});

  final Function(bool isRestore) onCompleted;

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
  bool _isRestoreMode = false;
  String? _savedMnemonic;

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

  Future<void> _openGettingStartedGuide() {
    return _openExternalLink(_gettingStartedGuideUrl);
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
      if (termsIndex != -1 &&
          (privacyIndex == -1 || termsIndex < privacyIndex)) {
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
      final created = await ref
          .read(identityManagerProvider)
          .createNewIdentity(displayName: name);
      if (!mounted) return;

      final words = created.mnemonic.trim().split(RegExp(r'\s+'));
      final targetIndex = math.Random.secure().nextInt(words.length) + 1;
      final expected = words[targetIndex - 1].toLowerCase();

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
                  title: Text(t(dialogContext, 'recoveryPhraseDialogTitle')),
                  content: ConstrainedBox(
                    constraints: BoxConstraints(
                      maxHeight: constraints.maxHeight * 0.7,
                    ),
                    child: SingleChildScrollView(
                      child: _RecoveryPhraseDialogContent(
                        mnemonic: created.mnemonic,
                        targetIndex: targetIndex,
                        confirmWordController: _confirmWordCtrl,
                      ),
                    ),
                  ),
                  actions: [
                    TextButton.icon(
                      onPressed: _openGettingStartedGuide,
                      icon: const Icon(Icons.open_in_new),
                      label: Text(t(dialogContext, 'onboardingGuideCta')),
                    ),
                    FilledButton(
                      onPressed: () => Navigator.of(dialogContext).pop(true),
                      child: Text(t(dialogContext, 'recoveryPhraseSavedCta')),
                    ),
                  ],
                );
              },
            );
          },
        );
        if (confirm == true &&
            _confirmWordCtrl.text.trim().toLowerCase() == expected) {
          await _showIdentityCreatedDialog();
          widget.onCompleted(false);
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

  Future<void> _showIdentityCreatedDialog() async {
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (dialogContext) {
        final t = AppStrings.t;
        return AlertDialog(
          title: Text(t(dialogContext, 'identityCreatedTitle')),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(t(dialogContext, 'identityCreatedBody')),
              const SizedBox(height: 12),
              _InlineInfoBanner(
                icon: Icons.public,
                child: Text(t(dialogContext, 'identityCreatedPublicKeyNote')),
              ),
            ],
          ),
          actions: [
            TextButton.icon(
              onPressed: _openGettingStartedGuide,
              icon: const Icon(Icons.open_in_new),
              label: Text(t(dialogContext, 'onboardingGuideCta')),
            ),
            FilledButton(
              onPressed: () => Navigator.of(dialogContext).pop(),
              child: Text(t(dialogContext, 'openMyIdentity')),
            ),
          ],
        );
      },
    );
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
            _mnemonicCtrl.text.trim().toLowerCase(),
            displayName: name,
            derivationVersion: SeedService.preferredIdentityDerivationVersion,
          );
      widget.onCompleted(true);
    } catch (_) {
      setState(() => _error = AppStrings.t(context, 'recoveryPhraseHint'));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final theme = Theme.of(context);
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
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Icon(
                        Icons.enhanced_encryption_outlined,
                        color: theme.colorScheme.primary,
                        size: 34,
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              t(context, 'onboardingHeading'),
                              style: theme.textTheme.titleLarge,
                            ),
                            const SizedBox(height: 6),
                            Text(
                              t(context, 'onboardingIntro'),
                              style: theme.textTheme.bodyMedium,
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),
                  _InlineInfoBanner(
                    icon: Icons.help_outline,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(t(context, 'onboardingGuideHint')),
                        const SizedBox(height: 8),
                        Align(
                          alignment: Alignment.centerLeft,
                          child: TextButton.icon(
                            onPressed: _openGettingStartedGuide,
                            icon: const Icon(Icons.open_in_new),
                            label: Text(t(context, 'onboardingGuideCta')),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 18),
                  Text(
                    t(context, 'onboardingSubtitle'),
                    style: Theme.of(context).textTheme.bodyLarge,
                  ),
                  const SizedBox(height: 16),
                  SegmentedButton<bool>(
                    segments: [
                      ButtonSegment<bool>(
                        value: false,
                        label: Text(t(context, 'onboardingModeCreate')),
                        icon: const Icon(Icons.person_add),
                      ),
                      ButtonSegment<bool>(
                        value: true,
                        label: Text(t(context, 'onboardingModeRestore')),
                        icon: const Icon(Icons.restore),
                      ),
                    ],
                    selected: {_isRestoreMode},
                    onSelectionChanged: _busy
                        ? null
                        : (Set<bool> newSelection) {
                            setState(() {
                              final newMode = newSelection.first;
                              if (_isRestoreMode && !newMode) {
                                _savedMnemonic = _mnemonicCtrl.text.trim();
                                _mnemonicCtrl.clear();
                              } else if (!_isRestoreMode &&
                                  newMode &&
                                  _savedMnemonic != null) {
                                _mnemonicCtrl.text = _savedMnemonic!;
                                _savedMnemonic = null;
                              }
                              _isRestoreMode = newMode;
                            });
                          },
                  ),
                  const SizedBox(height: 12),
                  _ModeExplanationCard(isRestoreMode: _isRestoreMode),
                  const SizedBox(height: 16),
                  Text(
                    t(
                      context,
                      _isRestoreMode
                          ? 'onboardingRestoreHelper'
                          : 'onboardingCreateHelper',
                    ),
                    style: theme.textTheme.bodySmall,
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _displayNameCtrl,
                    enabled: !_busy,
                    decoration: InputDecoration(
                      labelText: t(context, 'visibleNameLabel'),
                      hintText: t(context, 'displayNameHint'),
                      border: const OutlineInputBorder(),
                    ),
                  ),
                  if (_isRestoreMode) ...[
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
                      enabled: !_busy,
                      decoration: InputDecoration(
                        hintText: t(context, 'recoveryPhraseHint'),
                        border: const OutlineInputBorder(),
                      ),
                    ),
                  ],
                  const SizedBox(height: 16),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Checkbox(
                        value: _acceptedLegalConsent,
                        onChanged: _busy
                            ? null
                            : (value) {
                                setState(() =>
                                    _acceptedLegalConsent = value ?? false);
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
                        : (_isRestoreMode ? _restore : _create),
                    child: Text(t(
                        context, _isRestoreMode ? 'restoreNow' : 'createNow')),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 12),
                    Text(_error!, style: const TextStyle(color: Colors.red)),
                  ],
                  const SizedBox(height: 18),
                  _OnboardingStepList(
                    steps: [
                      _OnboardingStepData(
                        icon: Icons.person_add_alt_1_outlined,
                        title: t(context, 'onboardingStepCreateTitle'),
                        body: t(context, 'onboardingStepCreateBody'),
                      ),
                      _OnboardingStepData(
                        icon: Icons.vpn_key_outlined,
                        title: t(context, 'onboardingStepSaveTitle'),
                        body: t(context, 'onboardingStepSaveBody'),
                      ),
                      _OnboardingStepData(
                        icon: Icons.qr_code_2_outlined,
                        title: t(context, 'onboardingStepShareTitle'),
                        body: t(context, 'onboardingStepShareBody'),
                      ),
                      _OnboardingStepData(
                        icon: Icons.person_search_outlined,
                        title: t(context, 'onboardingStepContactTitle'),
                        body: t(context, 'onboardingStepContactBody'),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _ModeExplanationCard extends StatelessWidget {
  const _ModeExplanationCard({required this.isRestoreMode});

  final bool isRestoreMode;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final t = AppStrings.t;
    final title = t(
      context,
      isRestoreMode
          ? 'onboardingRestoreModeTitle'
          : 'onboardingCreateModeTitle',
    );
    final body = t(
      context,
      isRestoreMode ? 'onboardingRestoreModeBody' : 'onboardingCreateModeBody',
    );

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: isRestoreMode
            ? theme.colorScheme.tertiaryContainer.withValues(alpha: 0.36)
            : theme.colorScheme.primaryContainer.withValues(alpha: 0.42),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: isRestoreMode
              ? theme.colorScheme.tertiary.withValues(alpha: 0.22)
              : theme.colorScheme.primary.withValues(alpha: 0.18),
        ),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(
            isRestoreMode ? Icons.restore : Icons.looks_one_outlined,
            color: isRestoreMode
                ? theme.colorScheme.tertiary
                : theme.colorScheme.primary,
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: theme.textTheme.titleSmall),
                const SizedBox(height: 4),
                Text(body, style: theme.textTheme.bodySmall),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _RecoveryPhraseDialogContent extends StatelessWidget {
  const _RecoveryPhraseDialogContent({
    required this.mnemonic,
    required this.targetIndex,
    required this.confirmWordController,
  });

  final String mnemonic;
  final int targetIndex;
  final TextEditingController confirmWordController;

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final theme = Theme.of(context);
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          t(context, 'recoveryPhraseDialogBody'),
          style: theme.textTheme.bodyMedium,
        ),
        const SizedBox(height: 12),
        _InlineInfoBanner(
          icon: Icons.lock_outline,
          child: Text(t(context, 'recoveryPhraseDialogPrivacyNote')),
        ),
        const SizedBox(height: 16),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: theme.colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(
              color: theme.colorScheme.outlineVariant,
            ),
          ),
          child: SelectableText(
            mnemonic,
            style: theme.textTheme.bodyLarge?.copyWith(
              fontFamily: 'monospace',
              fontWeight: FontWeight.w500,
              letterSpacing: 0.5,
            ),
          ),
        ),
        const SizedBox(height: 12),
        Text(t(context, 'confirmWordBody')),
        const SizedBox(height: 8),
        TextField(
          controller: confirmWordController,
          textInputAction: TextInputAction.done,
          decoration: InputDecoration(
            border: const OutlineInputBorder(),
            hintText: t(
              context,
              'confirmWordFieldLabel',
              namedArgs: {'index': '$targetIndex'},
            ),
            labelText: t(
              context,
              'confirmWordFieldLabel',
              namedArgs: {'index': '$targetIndex'},
            ),
          ),
        ),
      ],
    );
  }
}

class _InlineInfoBanner extends StatelessWidget {
  const _InlineInfoBanner({
    required this.icon,
    required this.child,
  });

  final IconData icon;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.colorScheme.primaryContainer.withValues(alpha: 0.42),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: theme.colorScheme.primary.withValues(alpha: 0.18),
        ),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 20, color: theme.colorScheme.primary),
          const SizedBox(width: 10),
          Expanded(child: child),
        ],
      ),
    );
  }
}

class _OnboardingStepData {
  const _OnboardingStepData({
    required this.icon,
    required this.title,
    required this.body,
  });

  final IconData icon;
  final String title;
  final String body;
}

class _OnboardingStepList extends StatelessWidget {
  const _OnboardingStepList({required this.steps});

  final List<_OnboardingStepData> steps;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final wide = constraints.maxWidth >= 560;
        if (!wide) {
          return Column(
            children: [
              for (var i = 0; i < steps.length; i++) ...[
                _OnboardingStep(step: steps[i], index: i + 1),
                if (i != steps.length - 1) const SizedBox(height: 8),
              ],
            ],
          );
        }

        return Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            for (var i = 0; i < steps.length; i++)
              SizedBox(
                width: (constraints.maxWidth - 8) / 2,
                child: _OnboardingStep(step: steps[i], index: i + 1),
              ),
          ],
        );
      },
    );
  }
}

class _OnboardingStep extends StatelessWidget {
  const _OnboardingStep({
    required this.step,
    required this.index,
  });

  final _OnboardingStepData step;
  final int index;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface.withValues(alpha: 0.54),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Stack(
            alignment: Alignment.center,
            children: [
              Icon(step.icon, color: theme.colorScheme.primary, size: 30),
              Positioned(
                right: 0,
                bottom: 0,
                child: Container(
                  width: 16,
                  height: 16,
                  alignment: Alignment.center,
                  decoration: BoxDecoration(
                    color: theme.colorScheme.primary,
                    shape: BoxShape.circle,
                  ),
                  child: Text(
                    '$index',
                    style: theme.textTheme.labelSmall?.copyWith(
                      color: theme.colorScheme.onPrimary,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(step.title, style: theme.textTheme.titleSmall),
                const SizedBox(height: 3),
                Text(step.body, style: theme.textTheme.bodySmall),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
