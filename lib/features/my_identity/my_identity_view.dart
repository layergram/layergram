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

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:share_plus/share_plus.dart';

import '../../core/providers.dart';
import '../../l10n/app_strings.dart';
import '../../ui/passphrase_button.dart';
import '../../utils/sharing.dart';
import 'identity_qr_code.dart';
import 'my_identity_controller.dart';

class MyIdentityView extends ConsumerStatefulWidget {
  const MyIdentityView({super.key});

  @override
  ConsumerState<MyIdentityView> createState() => _MyIdentityViewState();
}

class _MyIdentityViewState extends ConsumerState<MyIdentityView> {
  final _nameCtrl = TextEditingController();
  final _nameFocus = FocusNode();
  String? _originalName;

  @override
  void dispose() {
    _nameCtrl.dispose();
    _nameFocus.dispose();
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
    _nameFocus.addListener(() {
      if (!_nameFocus.hasFocus) {
        _saveDisplayName();
      }
    });
  }

  Future<void> _saveDisplayName() async {
    final newName = _nameCtrl.text.trim();
    final current = _originalName ?? '';
    if (newName.isEmpty) {
      _nameCtrl.text = current;
      return;
    }
    if (newName == current) return;
    await ref.read(myIdentityControllerProvider).updateDisplayName(newName);
    if (mounted) {
      setState(() {
        _originalName = newName;
      });
    }
  }

  Future<void> _shareQrImage(Object data) async {
    final messenger = ScaffoldMessenger.of(context);
    final isEmpty = switch (data) {
      final String value => value.trim().isEmpty,
      final Uint8List value => value.isEmpty,
      _ => true,
    };
    if (isEmpty) {
      messenger.showSnackBar(
        SnackBar(
          content: Text(AppStrings.t(context, 'identityQrImageUnavailable')),
        ),
      );
      return;
    }

    final container = ProviderScope.containerOf(context);
    container.read(isSharingProvider.notifier).state = true;
    try {
      final bytes = await renderIdentityQrPng(data);
      if (bytes == null || bytes.isEmpty) {
        if (!mounted) return;
        messenger.showSnackBar(
          SnackBar(
            content: Text(AppStrings.t(context, 'identityQrImageShareFailed')),
          ),
        );
        return;
      }
      if (!mounted) return;
      await SharePlus.instance.share(
        ShareParams(
          files: [
            XFile.fromData(
              bytes,
              mimeType: 'image/png',
              name: 'layergram-identity-qr.png',
            ),
          ],
          text: AppStrings.t(context, 'identityQrImageShareText'),
          subject: AppStrings.t(context, 'identityQrImageShareSubject'),
          sharePositionOrigin: sharePositionOriginForContext(context),
        ),
      );
    } catch (_) {
      if (!mounted) return;
      messenger.showSnackBar(
        SnackBar(
          content: Text(AppStrings.t(context, 'identityQrImageShareFailed')),
        ),
      );
    } finally {
      container.read(isSharingProvider.notifier).state = false;
    }
  }

  Future<void> _showQrActions(Object data) async {
    await showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (sheetContext) {
        final t = AppStrings.t;
        return SafeArea(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  t(sheetContext, 'identityQrActionsTitle'),
                  style: Theme.of(sheetContext).textTheme.titleLarge,
                ),
                const SizedBox(height: 8),
                Text(t(sheetContext, 'identityQrActionsSubtitle')),
                if (data is Uint8List) ...[
                  const SizedBox(height: 16),
                  Center(
                    child: IdentityQrCode(
                      data: data,
                      size: (MediaQuery.sizeOf(sheetContext).width - 32)
                          .clamp(160.0, identityQrV3MaxPreviewSize)
                          .toDouble(),
                      color: Colors.black,
                      backgroundColor: Colors.white,
                    ),
                  ),
                ],
                const SizedBox(height: 12),
                ListTile(
                  leading: const Icon(Icons.file_download_outlined),
                  title: Text(t(sheetContext, 'shareOrSaveQrImage')),
                  onTap: () async {
                    Navigator.of(sheetContext).pop();
                    await _shareQrImage(data);
                  },
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    // Watch the passphrase state so the view rebuilds when the active key changes
    ref.watch(passphraseProvider);

    return Scaffold(
      backgroundColor: Colors.transparent,
      appBar: AppBar(
        title: Text(AppStrings.t(context, 'myIdentity')),
        actions: const [PassphraseButton(), SizedBox(width: 8)],
      ),
      body: FutureBuilder(
        future: ref.read(myIdentityControllerProvider).getActiveIdentity(),
        builder: (fbContext, snapshot) {
          final local = snapshot.data;
          if (local == null) {
            return Center(
              child: FilledButton(
                onPressed: () async {
                  final created = await ref
                      .read(identityManagerProvider)
                      .createNewIdentity();
                  ref.read(activeIdentityIdProvider.notifier).state =
                      created.identityId;
                  ref.read(identityReloadTokenProvider.notifier).state++;
                  if (!mounted) return;
                  setState(() {});
                },
                child: Text(AppStrings.t(context, 'createIdentity')),
              ),
            );
          }

          if (_nameCtrl.text != local.displayName) {
            _nameCtrl.text = local.displayName;
            _originalName = local.displayName;
          }

          return ListView(
            padding: const EdgeInsets.all(16),
            children: [
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Shortcuts(
                        shortcuts: {
                          const SingleActivator(LogicalKeyboardKey.escape):
                              const ActivateIntent(),
                        },
                        child: Actions(
                          actions: {
                            ActivateIntent: CallbackAction<ActivateIntent>(
                              onInvoke: (_) {
                                _nameCtrl.text =
                                    _originalName ?? _nameCtrl.text;
                                return null;
                              },
                            ),
                          },
                          child: TextField(
                            controller: _nameCtrl,
                            focusNode: _nameFocus,
                            onSubmitted: (_) => _saveDisplayName(),
                            decoration: InputDecoration(
                              labelText:
                                  AppStrings.t(context, 'displayNameLabel'),
                              hintText:
                                  AppStrings.t(context, 'displayNameHint'),
                              border: const OutlineInputBorder(),
                              suffixIcon: IconButton(
                                tooltip:
                                    AppStrings.t(context, 'saveDisplayName'),
                                icon: const Icon(Icons.check_circle_outline),
                                onPressed: () {
                                  _saveDisplayName();
                                  _nameFocus.unfocus();
                                },
                              ),
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 12),
                      SelectableText(
                          '${AppStrings.t(context, 'identityIdLabel')}: ${local.identityId}'),
                      const SizedBox(height: 8),
                      SelectableText(
                          '${AppStrings.t(context, 'fingerprintLabel')}: ${local.fingerprint}'),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 12),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: LayoutBuilder(
                    builder: (lbContext, constraints) {
                      final isWide = constraints.maxWidth > 600;
                      final qr = FutureBuilder<Object?>(
                        future: ref
                            .read(myIdentityControllerProvider)
                            .identityQrPayload(),
                        builder: (qrContext, payloadSnap) {
                          final payload = payloadSnap.data;
                          final Object data = payload == null
                              ? ''
                              : payload is Uint8List
                                  ? payload
                                  : jsonEncode(payload);
                          final hasData = switch (data) {
                            final String value => value.isNotEmpty,
                            final Uint8List value => value.isNotEmpty,
                            _ => false,
                          };
                          final qrColumnWidth = isWide
                              ? (constraints.maxWidth - 16) / 2
                              : constraints.maxWidth;
                          final qrSize = data is Uint8List
                              ? (qrColumnWidth - 16)
                                  .clamp(160.0, identityQrV3MaxPreviewSize)
                                  .toDouble()
                              : 220.0;
                          return Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Tooltip(
                                message: AppStrings.t(
                                    context, 'identityQrActionHint'),
                                child: Semantics(
                                  button: true,
                                  label: AppStrings.t(
                                      context, 'identityQrActionHint'),
                                  child: InkWell(
                                    borderRadius: BorderRadius.circular(18),
                                    onTap: !hasData
                                        ? null
                                        : () => _showQrActions(data),
                                    onLongPress: !hasData
                                        ? null
                                        : () => _showQrActions(data),
                                    child: Padding(
                                      padding: const EdgeInsets.all(8),
                                      child: IdentityQrCode(
                                        data: data,
                                        size: qrSize,
                                        color: data is Uint8List
                                            ? Colors.black
                                            : Theme.of(
                                                context,
                                              ).colorScheme.onSurface,
                                        backgroundColor: data is Uint8List
                                            ? Colors.white
                                            : Colors.transparent,
                                      ),
                                    ),
                                  ),
                                ),
                              ),
                              const SizedBox(height: 8),
                              TextButton.icon(
                                onPressed: !hasData
                                    ? null
                                    : () => _showQrActions(data),
                                icon: const Icon(Icons.file_download_outlined),
                                label: Text(AppStrings.t(
                                    context, 'shareOrSaveQrImage')),
                              ),
                            ],
                          );
                        },
                      );

                      final actions = Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Row(
                            children: [
                              Expanded(
                                child: FilledButton.tonal(
                                  style: FilledButton.styleFrom(
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 16,
                                      vertical: 16,
                                    ),
                                  ),
                                  onPressed: () async {
                                    final messenger =
                                        ScaffoldMessenger.of(context);
                                    final successMsg = AppStrings.t(
                                        context, 'identityLinkCopied');
                                    final link = await ref
                                        .read(myIdentityControllerProvider)
                                        .identityShareLink();
                                    await ref
                                        .read(clipboardServiceProvider)
                                        .writeText(link);
                                    if (!context.mounted) return;
                                    messenger.showSnackBar(
                                      SnackBar(
                                        content: Text(successMsg),
                                      ),
                                    );
                                  },
                                  child: Text(AppStrings.t(
                                      context, 'copyIdentityAsLink')),
                                ),
                              ),
                              const SizedBox(width: 8),
                              Tooltip(
                                message: AppStrings.t(
                                    context, 'shareContactTooltip'),
                                child: FilledButton.tonal(
                                  style: FilledButton.styleFrom(
                                    minimumSize: const Size.square(48),
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 12,
                                      vertical: 16,
                                    ),
                                  ),
                                  onPressed: () async {
                                    final link = await ref
                                        .read(myIdentityControllerProvider)
                                        .identityShareLink();
                                    if (link.isEmpty || !context.mounted) {
                                      return;
                                    }
                                    await shareTextExternally(context, link);
                                  },
                                  child: const Icon(Icons.ios_share_outlined),
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 8),
                          OutlinedButton.icon(
                            onPressed: () async {
                              final messenger = ScaffoldMessenger.of(context);
                              final block = await ref
                                  .read(myIdentityControllerProvider)
                                  .identityShareBlock();
                              await ref
                                  .read(clipboardServiceProvider)
                                  .writeText(block);
                              if (!context.mounted) return;
                              messenger.showSnackBar(
                                SnackBar(
                                  content: Text(AppStrings.t(
                                      context, 'identityTextCopied')),
                                ),
                              );
                            },
                            icon: const Icon(Icons.content_copy_outlined),
                            label: Text(
                                AppStrings.t(context, 'copyIdentityAsText')),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            AppStrings.t(context, 'recoveryPhraseWarning1'),
                            textAlign: TextAlign.center,
                          ),
                          const SizedBox(height: 6),
                          Text(
                            AppStrings.t(context, 'recoveryPhraseWarning2'),
                            textAlign: TextAlign.center,
                            style: const TextStyle(fontSize: 13),
                          ),
                          const SizedBox(height: 6),
                          OutlinedButton(
                            onPressed: () async {
                              final t = AppStrings.t;
                              final reason =
                                  t(context, 'unlockWithBiometricsPrompt');
                              final lockEnabled = await ref
                                  .read(appLockServiceProvider)
                                  .isEnabled();
                              if (lockEnabled) {
                                if (!context.mounted) return;
                                final ok = await ref
                                    .read(appLockServiceProvider)
                                    .authenticate(reason: reason);
                                if (!ok) return;
                              }

                              final phrase = await ref
                                      .read(identityManagerProvider)
                                      .getRecoveryPhrase() ??
                                  '';
                              if (!context.mounted) return;
                              await showDialog(
                                context: context,
                                builder: (ctx) => AlertDialog(
                                  title: Text(t(ctx, 'recoveryPhraseLabel')),
                                  content: SelectableText(phrase),
                                  actions: [
                                    FilledButton(
                                      onPressed: () => Navigator.of(ctx).pop(),
                                      child: Text(t(ctx, 'continueLabel')),
                                    ),
                                  ],
                                ),
                              );
                            },
                            child: Text(
                                AppStrings.t(context, 'showRecoveryPhrase')),
                          ),
                        ],
                      );

                      if (isWide) {
                        return Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Expanded(
                              flex: 1,
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.center,
                                children: [
                                  Text(AppStrings.t(context, 'shareQrHint')),
                                  const SizedBox(height: 8),
                                  Center(child: qr),
                                ],
                              ),
                            ),
                            const SizedBox(width: 16),
                            Expanded(
                              flex: 1,
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.center,
                                children: [
                                  Text(
                                    AppStrings.t(context, 'shareLinkHeading'),
                                    textAlign: TextAlign.center,
                                  ),
                                  const SizedBox(height: 8),
                                  actions,
                                ],
                              ),
                            ),
                          ],
                        );
                      }

                      return Column(
                        children: [
                          Text(AppStrings.t(context, 'shareQrHint')),
                          const SizedBox(height: 8),
                          qr,
                          const SizedBox(height: 16),
                          Text(
                            AppStrings.t(context, 'shareLinkHeading'),
                            textAlign: TextAlign.center,
                          ),
                          const SizedBox(height: 8),
                          actions,
                        ],
                      );
                    },
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}
