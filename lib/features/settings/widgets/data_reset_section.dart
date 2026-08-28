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
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/crypto/message_record_cipher.dart';
import '../../../core/providers.dart';
import '../../../l10n/app_strings.dart';

typedef _ResetResult = ({
  bool confirmed,
  bool deleteIdentities,
  bool deleteMessages,
  bool deleteContacts
});

class DataResetSection extends ConsumerWidget {
  const DataResetSection({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = AppStrings.t;

    return Column(
      children: [
        ListTile(
          leading: const Icon(Icons.delete_forever_outlined,
              color: Colors.redAccent),
          title: Text(t(context, 'resetIdentityTitle')),
          subtitle: Text(t(context, 'resetIdentitySubtitle')),
          onTap: () async {
            // ── First confirmation dialog ──
            final first = await _showResetDialog(
              context: context,
              t: t,
              titleKey: 'confirmResetTitle',
              iconColor: Colors.amber,
              bodyKeys: (
                'confirmResetBody1',
                'confirmResetBody2',
                'confirmResetBody3'
              ),
              confirmKey: 'confirmResetYes',
              reverseActions: true,
              initialDeleteIdentities: true,
              initialDeleteMessages: false,
              initialDeleteContacts: false,
            );
            if (first == null || !first.confirmed) return;
            if (!context.mounted) return;

            // ── Second (final) confirmation dialog ──
            final second = await _showResetDialog(
              context: context,
              t: t,
              titleKey: 'confirmResetFinalTitle',
              iconColor: Colors.red,
              bodyKeys: (
                'confirmResetFinalBody1',
                'confirmResetFinalBody2',
                'confirmResetFinalBody3'
              ),
              confirmKey: 'confirmResetFinalYes',
              reverseActions: false,
              initialDeleteIdentities: first.deleteIdentities,
              initialDeleteMessages: first.deleteMessages,
              initialDeleteContacts: first.deleteContacts,
            );
            if (second == null || !second.confirmed) return;

            // ── Conditional data deletion ──
            final messagesRepo = ref.read(messagesRepositoryProvider);
            if (second.deleteMessages) {
              await messagesRepo.clearAll();
              await ref.read(chatMetaRepositoryProvider).clearAll();
            }

            final identitiesRepo = ref.read(identitiesRepositoryProvider);
            if (second.deleteContacts) {
              await identitiesRepo.clearAll(deleteLocalIdentity: false);
            }

            if (second.deleteIdentities) {
              // Fail closed while the original identity and encrypted scope
              // are still available. If any deletion fails, the mnemonic is
              // retained so the user can retry instead of leaving decryptable
              // records orphaned behind a destroyed identity context.
              await ref.read(v3ApplicationRuntimeOwnerProvider).closeCurrent();

              // ── Reset FS state per spec §8.6.3 ─────────────────────────────
              // Mark all sessions as broken, wipe ratchet keys, clear persisted state
              final registry = ref.read(fsContactSecurityRegistryProvider);
              registry.markAllBroken('primary');

              await ref
                  .read(fsStatePersistenceServiceProvider)
                  .removeAllStates('primary');
              await ref
                  .read(fsRatchetPersistenceServiceProvider)
                  .removeAllRatchetStates();

              // Clear in-memory ratchet state cache
              ref.read(fsRatchetStateCacheProvider.notifier).state = {};

              // §12.3: Strip persisted plaintext while the original scoped
              // message repository is still decryptable. FS plaintext Aux
              // records must also be removed before invalidating their scoped
              // repository.
              if (!second.deleteMessages) {
                final identityManager = ref.read(identityManagerProvider);
                final activePassphrase = ref.read(passphraseProvider);
                final localIdentity = await identityManager.getLocalIdentity();
                final primaryPrivateKey =
                    await identityManager.getLocalPrivateKeyBase64();
                final primaryKeyTag =
                    await ref.read(originalKeyTagProvider.future);
                if (localIdentity == null ||
                    primaryPrivateKey == null ||
                    primaryKeyTag == null) {
                  throw StateError(
                    'Cannot sanitize retained messages without the primary key',
                  );
                }
                final knownKeyMaterial = <({String privateKey, String keyTag})>[
                  (privateKey: primaryPrivateKey, keyTag: primaryKeyTag),
                ];
                if (activePassphrase.isActive) {
                  final passphrasePrivateKey =
                      activePassphrase.privateKeyBase64;
                  final passphraseKeyTag = activePassphrase.keyTag;
                  if (passphrasePrivateKey == null ||
                      passphraseKeyTag == null) {
                    throw StateError(
                      'Cannot sanitize the active passphrase message context',
                    );
                  }
                  if (passphraseKeyTag != primaryKeyTag) {
                    knownKeyMaterial.add((
                      privateKey: passphrasePrivateKey,
                      keyTag: passphraseKeyTag,
                    ));
                  }
                }

                final storageContext = await ref
                    .read(localStorageSecurityProvider)
                    .contextForIdentity(localIdentity.identityId);
                if (storageContext == null) {
                  throw StateError(
                    'Cannot sanitize retained messages without their scope',
                  );
                }

                final knownStorageKeys = <SecretKey>[];
                try {
                  for (final material in knownKeyMaterial) {
                    final keyBytes = Uint8List.fromList(
                      base64Decode(material.privateKey),
                    );
                    try {
                      knownStorageKeys.add(
                        await MessageRecordCipher.deriveKey(
                          keyBytes,
                          keyTag: material.keyTag,
                        ),
                      );
                    } finally {
                      keyBytes.fillRange(0, keyBytes.length, 0);
                    }
                  }
                  await messagesRepo.stripEncryptedPlaintextAcrossKnownContexts(
                    scopeToken: storageContext.scopeToken,
                    additionalStorageKeys: knownStorageKeys,
                  );
                } finally {
                  storageContext.destroy();
                  for (final storageKey in knownStorageKeys) {
                    storageKey.destroy();
                  }
                }
              }
              await ref.read(fsPlaintextPersistenceServiceProvider).removeAll();

              // Only after every scope-bound erasure has succeeded may the
              // recovery identity and passphrase context be destroyed.
              await ref.read(passphraseProvider.notifier).deactivate();
              await ref.read(identityManagerProvider).clearLocalIdentity();

              // Invalidate ALL FS-related providers to ensure fresh state after reset
              // Note: Provider.family instances are invalidated when their parent is invalidated
              // or when they have no more listeners (which happens after logout)
              ref.invalidate(fsContactSecurityRegistryProvider);
              ref.invalidate(fsSessionManagerProvider);
              ref.invalidate(fsStrictModeControllerProvider);
              ref.invalidate(fsOpportunisticControllerProvider);
              ref.invalidate(fsStateForContactProvider);
              ref.invalidate(fsStatePersistenceServiceProvider);
              ref.invalidate(fsRatchetPersistenceServiceProvider);
              // CRITICAL: Also invalidate aux repository so clearByKind has proper scope
              ref.invalidate(auxRecordRepositoryProvider);

              // Increment registry version to trigger UI refresh
              ref.read(fsRegistryVersionProvider.notifier).state++;
            }

            // Force provider invalidation and log out if identity was deleted
            if (second.deleteIdentities) {
              ref.invalidate(identitiesRepositoryProvider);
              ref.invalidate(identityManagerProvider);

              ref.read(activeIdentityIdProvider.notifier).state = null;
              ref.read(appLockEnabledProvider.notifier).state = false;
              ref.read(appNeedsUnlockProvider.notifier).state = false;
              ref.read(identityReloadTokenProvider.notifier).state++;

              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text(t(context, 'dataClearedSnackbar'))),
                );
              }
            } else {
              // Just show success if we remain logged in
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text(t(context, 'dataClearedSnackbar'))),
                );
              }
            }
          },
        ),
        ListTile(
          leading: const Icon(Icons.cleaning_services_outlined,
              color: Colors.orange),
          title: Text(t(context, 'security.cleanup.title')),
          subtitle: Text(t(context, 'security.cleanup.subtitle')),
          onTap: () => _confirmCleanUndecryptable(context, ref),
        ),
      ],
    );
  }

  Future<void> _confirmCleanUndecryptable(
      BuildContext context, WidgetRef ref) async {
    final t = AppStrings.t;
    var confirmed = false;

    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) {
        return StatefulBuilder(
          builder: (ctx, setDialogState) {
            return AlertDialog(
              title: Row(
                children: [
                  const Icon(Icons.warning_amber_outlined,
                      color: Colors.orange),
                  const SizedBox(width: 8),
                  Expanded(
                      child: Text(t(ctx, 'security.cleanup.dialog_title'))),
                ],
              ),
              content: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(t(ctx, 'security.cleanup.dialog_body')),
                    const SizedBox(height: 16),
                    CheckboxListTile(
                      contentPadding: EdgeInsets.zero,
                      dense: true,
                      value: confirmed,
                      onChanged: (v) =>
                          setDialogState(() => confirmed = v ?? false),
                      title: Text(
                        t(ctx, 'security.cleanup.confirm_checkbox'),
                        style: const TextStyle(fontSize: 13),
                      ),
                    ),
                  ],
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(ctx).pop(false),
                  child: Text(t(ctx, 'cancel')),
                ),
                FilledButton(
                  style: FilledButton.styleFrom(
                    backgroundColor: confirmed ? Colors.orange : Colors.grey,
                  ),
                  onPressed:
                      confirmed ? () => Navigator.of(ctx).pop(true) : null,
                  child: Text(t(ctx, 'security.cleanup.confirm_button')),
                ),
              ],
            );
          },
        );
      },
    );

    if (result != true) return;

    // Perform the cleanup
    final auxRepo = ref.read(auxRecordRepositoryProvider);
    await auxRepo.cleanUndecryptableRecords();

    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(t(context, 'security.cleanup.done'))),
      );
    }
  }
}

Future<_ResetResult?> _showResetDialog({
  required BuildContext context,
  required String Function(BuildContext, String) t,
  required String titleKey,
  required Color iconColor,
  required (String, String, String) bodyKeys,
  required String confirmKey,
  required bool reverseActions,
  required bool initialDeleteIdentities,
  required bool initialDeleteMessages,
  required bool initialDeleteContacts,
}) {
  var deleteIdentities = initialDeleteIdentities;
  var deleteMessages = initialDeleteMessages;
  var deleteContacts = initialDeleteContacts;

  return showDialog<_ResetResult>(
    context: context,
    builder: (ctx) {
      return StatefulBuilder(
        builder: (ctx, setDialogState) {
          return AlertDialog(
            title: Row(
              children: [
                Icon(Icons.warning_amber_outlined, color: iconColor),
                const SizedBox(width: 8),
                Text(t(ctx, titleKey)),
              ],
            ),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text.rich(
                    TextSpan(
                      children: [
                        TextSpan(text: t(ctx, bodyKeys.$1)),
                        TextSpan(
                          text: t(ctx, bodyKeys.$2),
                          style: const TextStyle(
                            fontWeight: FontWeight.bold,
                            color: Colors.red,
                          ),
                        ),
                        TextSpan(text: t(ctx, bodyKeys.$3)),
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),
                  CheckboxListTile(
                    contentPadding: EdgeInsets.zero,
                    dense: true,
                    value: deleteIdentities,
                    onChanged: (v) =>
                        setDialogState(() => deleteIdentities = v ?? false),
                    title: Text(t(ctx, 'deleteIdentities')),
                  ),
                  CheckboxListTile(
                    contentPadding: EdgeInsets.zero,
                    dense: true,
                    value: deleteMessages,
                    onChanged: (v) =>
                        setDialogState(() => deleteMessages = v ?? false),
                    title: Text(t(ctx, 'deleteAssociatedMessages')),
                  ),
                  CheckboxListTile(
                    contentPadding: EdgeInsets.zero,
                    dense: true,
                    value: deleteContacts,
                    onChanged: (v) =>
                        setDialogState(() => deleteContacts = v ?? false),
                    title: Text(t(ctx, 'deleteAllContacts')),
                  ),
                ],
              ),
            ),
            actionsAlignment: MainAxisAlignment.spaceBetween,
            actions: reverseActions
                ? [
                    TextButton(
                      onPressed: () => Navigator.of(ctx).pop(null),
                      child: Text(t(ctx, 'cancel')),
                    ),
                    FilledButton(
                      style: FilledButton.styleFrom(
                          backgroundColor: Colors.redAccent),
                      onPressed: () => Navigator.of(ctx).pop((
                        confirmed: true,
                        deleteIdentities: deleteIdentities,
                        deleteMessages: deleteMessages,
                        deleteContacts: deleteContacts,
                      )),
                      child: Text(t(ctx, confirmKey)),
                    ),
                  ]
                : [
                    FilledButton(
                      style: FilledButton.styleFrom(
                          backgroundColor: Colors.redAccent),
                      onPressed: () => Navigator.of(ctx).pop((
                        confirmed: true,
                        deleteIdentities: deleteIdentities,
                        deleteMessages: deleteMessages,
                        deleteContacts: deleteContacts,
                      )),
                      child: Text(t(ctx, confirmKey)),
                    ),
                    TextButton(
                      onPressed: () => Navigator.of(ctx).pop(null),
                      child: Text(t(ctx, 'cancel')),
                    ),
                  ],
          );
        },
      );
    },
  );
}
