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
import '../core/crypto/fs_session_manager.dart';
import '../core/providers.dart';
import '../l10n/app_strings.dart';
import 'fs_info_sheet.dart';
import 'fs_maximum_fs_dialog.dart';
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

            // ── Actions ────────────────────────────────────────────────────
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                if (topState == FsSessionState.fsBroken ||
                    topState == FsSessionState.fsSuspended)
                  _ActionChip(
                    label: t(context, 'security.fs.action.retry'),
                    icon: Icons.refresh,
                    onPressed: () {
                      final sm = ref.read(
                        fsSessionManagerProvider(contactId),
                      );
                      sm.reset();
                      // Update registry so UI reflects legacyOnly immediately
                      final registry =
                          ref.read(fsContactSecurityRegistryProvider);
                      final ctrl = ref.read(
                        fsOpportunisticControllerProvider(contactId),
                      );
                      registry.upsert(FsContactSecurityState(
                        contactId: contactId,
                        identityContext: ctrl.identityContext,
                        sessionId: null,
                        fsState: FsSessionState.legacyOnly,
                      ));
                      ref.read(fsRegistryVersionProvider.notifier).state++;
                    },
                  ),
                if (topState != FsSessionState.legacyOnly)
                  _ActionChip(
                    label: t(context, 'security.fs.action.reset'),
                    icon: Icons.lock_reset,
                    onPressed: () {
                      final sm = ref.read(
                        fsSessionManagerProvider(contactId),
                      );
                      final oldSessionId = sm.activeSessionId;
                      sm.reset();
                      // Remove orphaned ratchet state from cache
                      if (oldSessionId != null) {
                        ref
                            .read(fsRatchetStateCacheProvider.notifier)
                            .update((cache) {
                          final c = {...cache};
                          c.remove(oldSessionId);
                          return c;
                        });
                      }
                      // Update registry so UI reflects legacyOnly immediately
                      final registry =
                          ref.read(fsContactSecurityRegistryProvider);
                      final ctrl = ref.read(
                        fsOpportunisticControllerProvider(contactId),
                      );
                      registry.upsert(FsContactSecurityState(
                        contactId: contactId,
                        identityContext: ctrl.identityContext,
                        sessionId: null,
                        fsState: FsSessionState.legacyOnly,
                      ));
                      ref.read(fsRegistryVersionProvider.notifier).state++;
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
                    onPressed: () {
                      final ctrl = ref.read(
                        fsStrictModeControllerProvider(contactId),
                      );
                      final session = ref
                          .read(fsContactSecurityRegistryProvider)
                          .forContactAllContexts(contactId)
                          .firstOrNull;
                      ctrl.disableStrict(session?.sessionId ?? '');
                      ref.read(fsRegistryVersionProvider.notifier).state++;
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
                        final ctrl = ref.read(
                          fsStrictModeControllerProvider(contactId),
                        );
                        final session = ref
                            .read(fsContactSecurityRegistryProvider)
                            .forContactAllContexts(contactId)
                            .firstOrNull;
                        ctrl.requestMaximum(session?.sessionId ?? '');
                        ref
                            .read(fsRegistryVersionProvider.notifier)
                            .state++;
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

    final fallbackLabel = session.fsState == FsSessionState.strictFsActive
        ? t(context, 'security.fs.device.fallback_not_allowed')
        : t(context, 'security.fs.device.fallback_allowed');

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
