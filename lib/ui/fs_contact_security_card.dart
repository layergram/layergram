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

import '../core/crypto/fs_contact_security_state.dart';
import '../core/crypto/fs_security_mode.dart';
import '../core/crypto/fs_session_manager.dart';
import '../core/providers.dart';
import '../l10n/app_strings.dart';
import 'fs_info_sheet.dart';
import 'fs_maximum_fs_dialog.dart';
import 'fs_security_mode_sheet.dart';
import 'fs_status_icon.dart';

/// Full per-contact Forward Secrecy security section for the contact detail
/// screen.
///
/// Shows:
/// - Section title with ⓘ tap-to-explain icon (spec §14.4)
/// - Per-session state rows (spec §14.4 — per-device/session details)
/// - Explanatory footer text
/// - Action buttons: retry, reset, request Maximum FS / disable Maximum FS
///
/// Spec reference: §14.4 — Per-contact and per-device security state.
class FsContactSecurityCard extends ConsumerWidget {
  const FsContactSecurityCard({super.key, required this.contactId});

  final String contactId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = AppStrings.t;
    final theme = Theme.of(context);

    ref.watch(fsRegistryVersionProvider);
    final registry = ref.watch(fsContactSecurityRegistryProvider);
    final sessions = registry.forContactAllContexts(contactId);
    final topState = ref.watch(fsStateForContactProvider(contactId));

    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Section header with ⓘ ──────────────────────────────────────
            Row(
              children: [
                Expanded(
                  child: Text(
                    t(context, 'security.fs.card.title'),
                    style: theme.textTheme.titleSmall,
                  ),
                ),
                IconButton(
                  tooltip: t(context, 'security.fs.info.title'),
                  icon: Icon(
                    Icons.info_outline,
                    size: 20,
                    color: theme.colorScheme.primary,
                  ),
                  onPressed: () => showFsInfoSheet(context, topState),
                ),
              ],
            ),
            const SizedBox(height: 4),

            // ── Prominent current status ───────────────────────────────────
            _StatusBadge(fsState: topState, sessions: sessions),
            const SizedBox(height: 12),

            // ── Per-session rows (only when >1 sessions or state is active) ─
            if (sessions.length > 1) ...[
              const Divider(height: 20),
              ...sessions.asMap().entries.map(
                    (entry) => _SessionRow(
                      session: entry.value,
                      index: entry.key + 1,
                    ),
                  ),
            ],

            const Divider(height: 24),

            // ── Explanation footer ─────────────────────────────────────────
            Text(
              t(context, 'security.fs.card.explanation_prefix'),
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 16),

            // ── Current security mode (§14.3) ──────────────────────────────
            _SecurityModeBadge(contactId: contactId),
            const SizedBox(height: 12),
            _BackupExclusionPreference(contactId: contactId),
            const SizedBox(height: 16),

            // ── Actions ────────────────────────────────────────────────────
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                _ActionChip(
                  label: t(context, 'security.fs.action.change_mode'),
                  icon: Icons.tune,
                  onPressed: () async {
                    final modeService = ref.read(fsSecurityModeServiceProvider);
                    final ctrl = ref.read(
                      fsOpportunisticControllerProvider(contactId),
                    );
                    final currentMode = modeService.getModeSync(
                      contactId: contactId,
                      identityContext: ctrl.identityContext,
                    );
                    final selected = await showFsSecurityModeSheet(
                      context,
                      currentMode: currentMode,
                    );
                    if (selected != null && context.mounted) {
                      await modeService.setMode(
                        contactId: contactId,
                        identityContext: ctrl.identityContext,
                        mode: selected,
                      );
                      ctrl.securityMode = selected;
                      if (selected == FsSecurityMode.strict) {
                        await _resetForStrictRekey(ref, contactId);
                      } else {
                        await ctrl.disableStrictForKnownActiveSessions();
                      }
                      ref.read(fsRegistryVersionProvider.notifier).state++;
                      if (context.mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(
                            content: Text(
                              t(context, 'security.fs.mode.changed_snackbar'),
                            ),
                          ),
                        );
                      }
                    }
                  },
                ),
                if (topState == FsSessionState.fsBroken ||
                    topState == FsSessionState.fsSuspended)
                  _ActionChip(
                    label: t(context, 'security.fs.action.retry'),
                    icon: Icons.refresh,
                    onPressed: () async {
                      await _resetForAdvancedRekey(ref, contactId);
                      ref.read(fsRegistryVersionProvider.notifier).state++;
                    },
                  ),
                if (topState != FsSessionState.legacyOnly)
                  _ActionChip(
                    label: t(context, 'security.fs.action.reset'),
                    icon: Icons.lock_reset,
                    onPressed: () async {
                      await _resetForAdvancedRekey(ref, contactId);
                      ref.read(fsRegistryVersionProvider.notifier).state++;
                      if (!context.mounted) return;
                      // Snackbar confirmation
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text(
                            t(context, 'security.fs.session_reset_done'),
                          ),
                        ),
                      );
                    },
                  ),
                if (topState == FsSessionState.strictFsActive)
                  _ActionChip(
                    label: t(context, 'security.fs.action.disable_strict'),
                    icon: Icons.shield_outlined,
                    color: Theme.of(context).colorScheme.error,
                    onPressed: () async {
                      final confirmed =
                          await showDisableMaximumFsDialog(context);
                      if (confirmed != true || !context.mounted) {
                        return;
                      }
                      final fsCtrl = ref.read(
                        fsOpportunisticControllerProvider(contactId),
                      );
                      final modeService =
                          ref.read(fsSecurityModeServiceProvider);
                      await modeService.setMode(
                        contactId: contactId,
                        identityContext: fsCtrl.identityContext,
                        mode: FsSecurityMode.advanced,
                      );
                      fsCtrl.securityMode = FsSecurityMode.advanced;
                      await fsCtrl.disableStrictForKnownActiveSessions();
                      ref.read(fsRegistryVersionProvider.notifier).state++;
                      if (context.mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(
                            content: Text(
                              t(context, 'security.fs.mode.changed_snackbar'),
                            ),
                          ),
                        );
                      }
                    },
                  )
                else if (topState != FsSessionState.strictRequested)
                  _ActionChip(
                    label: t(context, 'security.fs.action.request_maximum'),
                    icon: Icons.diamond_outlined,
                    onPressed: () async {
                      final confirmed =
                          await showMaximumFsConsentDialog(context);
                      if (confirmed == true && context.mounted) {
                        final fsCtrl = ref.read(
                          fsOpportunisticControllerProvider(contactId),
                        );
                        final modeService =
                            ref.read(fsSecurityModeServiceProvider);
                        await modeService.setMode(
                          contactId: contactId,
                          identityContext: fsCtrl.identityContext,
                          mode: FsSecurityMode.strict,
                        );
                        fsCtrl.securityMode = FsSecurityMode.strict;
                        await _resetForStrictRekey(ref, contactId);
                        ref.read(fsRegistryVersionProvider.notifier).state++;
                      }
                    },
                  ),
                if (topState == FsSessionState.strictRequested)
                  Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: Row(
                      children: [
                        Icon(
                          Icons.timelapse,
                          size: 14,
                          color: Colors.orange.shade700,
                        ),
                        const SizedBox(width: 6),
                        Expanded(
                          child: Text(
                            t(context, 'security.fs.warning.pending_body'),
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: Colors.orange.shade800,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

Future<void> _resetForAdvancedRekey(WidgetRef ref, String contactId) async {
  final fsCtrl = ref.read(fsOpportunisticControllerProvider(contactId));
  final removedSessionIds = await fsCtrl.resetForAdvancedRekey();

  ref.read(fsRatchetStateCacheProvider.notifier).update((cache) {
    final next = {...cache};
    for (final sessionId in removedSessionIds) {
      next.remove(sessionId);
    }
    return next;
  });
}

Future<void> _resetForStrictRekey(WidgetRef ref, String contactId) async {
  final fsCtrl = ref.read(fsOpportunisticControllerProvider(contactId));
  final removedSessionIds = await fsCtrl.resetForStrictRekey();
  if (removedSessionIds.isEmpty) return;

  ref.read(fsRatchetStateCacheProvider.notifier).update((cache) {
    final next = {...cache};
    for (final sessionId in removedSessionIds) {
      next.remove(sessionId);
    }
    return next;
  });
}

// ── Security mode badge (§14.3) ───────────────────────────────────────────────

class _SecurityModeBadge extends ConsumerWidget {
  const _SecurityModeBadge({required this.contactId});

  final String contactId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = AppStrings.t;
    final theme = Theme.of(context);

    ref.watch(fsRegistryVersionProvider);
    final modeService = ref.read(fsSecurityModeServiceProvider);
    final ctrl = ref.read(fsOpportunisticControllerProvider(contactId));
    final mode = modeService.getModeSync(
      contactId: contactId,
      identityContext: ctrl.identityContext,
    );

    final modeLabel = _modeLabelKey(mode);

    return Row(
      children: [
        Icon(
          _modeIcon(mode),
          size: 16,
          color: _modeColor(mode),
        ),
        const SizedBox(width: 6),
        Text(
          t(context, 'security.fs.mode.current_label')
              .replaceAll('{mode}', t(context, modeLabel)),
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );
  }

  static String _modeLabelKey(FsSecurityMode mode) {
    switch (mode) {
      case FsSecurityMode.base:
        return 'security.fs.mode.base_title';
      case FsSecurityMode.advanced:
        return 'security.fs.mode.advanced_title';
      case FsSecurityMode.strict:
        return 'security.fs.mode.strict_title';
    }
  }

  static IconData _modeIcon(FsSecurityMode mode) {
    switch (mode) {
      case FsSecurityMode.base:
        return Icons.shield_outlined;
      case FsSecurityMode.advanced:
        return Icons.shield;
      case FsSecurityMode.strict:
        return Icons.shield;
    }
  }

  static Color _modeColor(FsSecurityMode mode) {
    switch (mode) {
      case FsSecurityMode.base:
        return Colors.grey;
      case FsSecurityMode.advanced:
        return Colors.green;
      case FsSecurityMode.strict:
        return Colors.green.shade800;
    }
  }
}

// ── Backup exclusion preference ─────────────────────────────────────────────

class _BackupExclusionPreference extends ConsumerStatefulWidget {
  const _BackupExclusionPreference({required this.contactId});

  final String contactId;

  @override
  ConsumerState<_BackupExclusionPreference> createState() =>
      _BackupExclusionPreferenceState();
}

class _BackupExclusionPreferenceState
    extends ConsumerState<_BackupExclusionPreference> {
  bool _loaded = false;
  bool _excludeFromBackups = false;
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final settings = await ref
        .read(chatMetaRepositoryProvider)
        .getChatSettings(chatId: widget.contactId);
    if (!mounted) return;
    setState(() {
      _excludeFromBackups = (settings?['excludeFromBackups'] as bool?) ?? false;
      _loaded = true;
    });
  }

  Future<void> _setExcludeFromBackups(bool value) async {
    if (_saving || _excludeFromBackups == value) {
      return;
    }
    setState(() {
      _excludeFromBackups = value;
      _saving = true;
    });
    await ref.read(chatMetaRepositoryProvider).setExcludeFromBackups(
          chatId: widget.contactId,
          excludeFromBackups: value,
        );
    if (!mounted) return;
    setState(() => _saving = false);
    final t = AppStrings.t;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          t(
            context,
            value
                ? 'touchComposerExcludeFromBackupsOn'
                : 'touchComposerExcludeFromBackupsOff',
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 2),
            child: Icon(
              _excludeFromBackups
                  ? Icons.cloud_off_outlined
                  : Icons.cloud_queue_outlined,
              size: 20,
              color: _excludeFromBackups
                  ? theme.colorScheme.primary
                  : theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  t(context, 'excludeFromBackups'),
                  style: theme.textTheme.labelLarge,
                ),
                const SizedBox(height: 2),
                Text(
                  t(context, 'excludeFromBackupsShort'),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  t(context, 'excludeFromBackupsCaveat'),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 8),
          Switch.adaptive(
            value: _excludeFromBackups,
            onChanged: _loaded && !_saving ? _setExcludeFromBackups : null,
          ),
        ],
      ),
    );
  }
}

// ── Prominent status badge ────────────────────────────────────────────────────

class _StatusBadge extends StatelessWidget {
  const _StatusBadge({
    required this.fsState,
    required this.sessions,
  });

  final FsSessionState fsState;
  final List<FsContactSecurityState> sessions;

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    final statusKey = FsInfoSheet.statusKeyFor(fsState);
    final descKey = FsInfoSheet.descriptionKeyFor(fsState);
    final badgeColor = _badgeColor(cs, fsState);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: badgeColor.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: badgeColor.withValues(alpha: 0.3)),
      ),
      child: Row(
        children: [
          FsStatusIcon(fsState: fsState, size: 20, showTooltip: false),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  t(context, statusKey),
                  style: theme.textTheme.labelLarge?.copyWith(
                    color: badgeColor,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  t(context, descKey),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                if (_remainingExchanges(fsState) > 0) ...[
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      Icon(
                        Icons.sync_alt,
                        size: 12,
                        color: Colors.orange.shade700,
                      ),
                      const SizedBox(width: 4),
                      Text(
                        _progressText(context, fsState),
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: Colors.orange.shade800,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ],
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  static Color _badgeColor(ColorScheme cs, FsSessionState state) {
    switch (state) {
      case FsSessionState.fsBroken:
        return cs.error;
      case FsSessionState.strictFsActive:
        return Colors.green.shade700;
      case FsSessionState.fsActive:
        return Colors.green.shade700;
      case FsSessionState.strictRequested:
      case FsSessionState.fsInitSent:
      case FsSessionState.fsInitSeen:
      case FsSessionState.fsReplySent:
      case FsSessionState.fsReplySeen:
      case FsSessionState.fsConfirmSent:
      case FsSessionState.fsConfirmed:
        return Colors.orange.shade700;
      case FsSessionState.fsSuspended:
        return Colors.grey;
      case FsSessionState.legacyOnly:
        return Colors.grey;
    }
  }

  /// Returns estimated remaining message exchanges before FS is active.
  static int _remainingExchanges(FsSessionState state) {
    switch (state) {
      case FsSessionState.legacyOnly:
        return 3; // Need: send/receive init, reply, confirm
      case FsSessionState.fsInitSent:
      case FsSessionState.fsInitSeen:
        return 2; // Need: reply + confirm
      case FsSessionState.fsReplySent:
      case FsSessionState.fsReplySeen:
        return 1; // Need: confirm
      case FsSessionState.fsConfirmSent:
      case FsSessionState.fsConfirmed:
        return 1; // Need: final activation
      case FsSessionState.fsActive:
      case FsSessionState.strictFsActive:
      case FsSessionState.strictRequested:
      case FsSessionState.fsBroken:
      case FsSessionState.fsSuspended:
        return 0;
    }
  }

  /// Returns localized progress text showing remaining exchanges.
  String _progressText(BuildContext context, FsSessionState state) {
    final t = AppStrings.t;
    final remaining = _remainingExchanges(state);
    if (remaining == 0) return '';
    if (remaining == 1) {
      return t(context, 'security.fs.progress.one_more_exchange');
    }
    return t(context, 'security.fs.progress.exchanges_remaining')
        .replaceAll('{n}', '$remaining');
  }
}

// ── Session row ──────────────────────────────────────────────────────────────

class _SessionRow extends StatelessWidget {
  const _SessionRow({required this.session, required this.index});

  final FsContactSecurityState session;
  final int index;

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final theme = Theme.of(context);

    final label = t(
      context,
      'security.fs.device.session_label',
    ).replaceAll('{n}', '$index');

    final fallbackLabel = t(context, 'security.fs.device.fallback_not_allowed');

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          FsStatusIcon(fsState: session.fsState, size: 16),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label, style: theme.textTheme.bodyMedium),
                Text(
                  fallbackLabel,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ── Action chip helper ────────────────────────────────────────────────────────

class _ActionChip extends StatelessWidget {
  const _ActionChip({
    required this.label,
    required this.icon,
    required this.onPressed,
    this.color,
  });

  final String label;
  final IconData icon;
  final VoidCallback onPressed;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final foreground = color ?? cs.primary;
    return ActionChip(
      avatar: Icon(icon, size: 16, color: foreground),
      label: Text(label, style: TextStyle(color: foreground)),
      onPressed: onPressed,
    );
  }
}
