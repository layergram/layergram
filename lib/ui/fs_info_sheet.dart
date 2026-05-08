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

import '../core/crypto/fs_session_manager.dart';
import '../l10n/app_strings.dart';
import 'fs_status_icon.dart';

/// Opens the FS security info bottom sheet for [fsState].
///
/// Spec reference: §14.4 — Security status info modal.
void showFsInfoSheet(BuildContext context, FsSessionState fsState) {
  showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    showDragHandle: true,
    builder: (_) => FsInfoSheet(fsState: fsState),
  );
}

/// Bottom sheet that explains the current Forward Secrecy state for a contact.
///
/// Structure (spec §14.4):
///   Title        — "Security with this contact"
///   Current mode — icon + label
///   Description  — 1-2 sentences
///   Advantages   — bullet list
///   Keep in mind — bullet list
///
/// The sheet is purely informational; it does not change state.
/// Action buttons (Request Maximum FS, etc.) live in [FsContactSecurityCard].
class FsInfoSheet extends StatelessWidget {
  const FsInfoSheet({super.key, required this.fsState});

  final FsSessionState fsState;

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    final descKey = _descriptionKey(fsState);
    final advantagesKey = _advantagesKey(fsState);
    final keepInMindKey = _keepInMindKey(fsState);

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(20, 0, 20, 24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Title ────────────────────────────────────────────────────────
            Text(
              t(context, 'security.fs.info.title'),
              style: theme.textTheme.titleLarge,
            ),
            const SizedBox(height: 16),

            // ── Current mode chip ─────────────────────────────────────────────
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: cs.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  FsStatusIcon(fsState: fsState, size: 18, showTooltip: false),
                  const SizedBox(width: 8),
                  Text(
                    t(context, _statusKey(fsState)),
                    style: theme.textTheme.labelLarge,
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // ── Description ───────────────────────────────────────────────────
            Text(
              t(context, descKey),
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),

            // ── Advantages ────────────────────────────────────────────────────
            _SectionBlock(
              title: t(context, 'security.fs.info.section_advantages'),
              bullets: _split(t(context, advantagesKey)),
              color: Colors.green,
            ),
            const SizedBox(height: 12),

            // ── Keep in mind ──────────────────────────────────────────────────
            _SectionBlock(
              title: t(context, 'security.fs.info.section_keep_in_mind'),
              bullets: _split(t(context, keepInMindKey)),
              color: Colors.amber.shade700,
            ),
            const SizedBox(height: 24),

            // ── Close ─────────────────────────────────────────────────────────
            SizedBox(
              width: double.infinity,
              child: FilledButton.tonal(
                onPressed: () => Navigator.of(context).pop(),
                child: Text(t(context, 'security.fs.info.action_close')),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── Key helpers ─────────────────────────────────────────────────────────────

  static String _statusKey(FsSessionState state) {
    switch (state) {
      case FsSessionState.legacyOnly:
        return 'security.fs.status.legacy';
      case FsSessionState.fsInitSent:
      case FsSessionState.fsInitSeen:
      case FsSessionState.fsReplySent:
      case FsSessionState.fsReplySeen:
      case FsSessionState.fsConfirmSent:
      case FsSessionState.fsConfirmed:
        return 'security.fs.status.upgrading';
      case FsSessionState.fsActive:
        return 'security.fs.status.active';
      case FsSessionState.strictFsActive:
        return 'security.fs.status.strict';
      case FsSessionState.strictRequested:
        return 'security.fs.status.upgrading';
      case FsSessionState.fsSuspended:
        return 'security.fs.status.suspended';
      case FsSessionState.fsBroken:
        return 'security.fs.status.broken';
    }
  }

  static String _descriptionKey(FsSessionState state) {
    switch (state) {
      case FsSessionState.legacyOnly:
        return 'security.fs.info.legacy_description';
      case FsSessionState.fsInitSent:
      case FsSessionState.fsInitSeen:
      case FsSessionState.fsReplySent:
      case FsSessionState.fsReplySeen:
      case FsSessionState.fsConfirmSent:
      case FsSessionState.fsConfirmed:
        return 'security.fs.info.upgrading_description';
      case FsSessionState.fsActive:
        return 'security.fs.info.active_description';
      case FsSessionState.strictFsActive:
        return 'security.fs.info.strict_description';
      case FsSessionState.strictRequested:
        return 'security.fs.info.strict_requested_description';
      case FsSessionState.fsSuspended:
        return 'security.fs.info.suspended_description';
      case FsSessionState.fsBroken:
        return 'security.fs.info.broken_description';
    }
  }

  static String _advantagesKey(FsSessionState state) {
    switch (state) {
      case FsSessionState.legacyOnly:
        return 'security.fs.info.legacy_advantages';
      case FsSessionState.fsInitSent:
      case FsSessionState.fsInitSeen:
      case FsSessionState.fsReplySent:
      case FsSessionState.fsReplySeen:
      case FsSessionState.fsConfirmSent:
      case FsSessionState.fsConfirmed:
        return 'security.fs.info.upgrading_advantages';
      case FsSessionState.fsActive:
        return 'security.fs.info.active_advantage';
      case FsSessionState.strictFsActive:
        return 'security.fs.info.strict_advantages';
      case FsSessionState.strictRequested:
        return 'security.fs.info.strict_requested_advantages';
      case FsSessionState.fsSuspended:
      case FsSessionState.fsBroken:
        return 'security.fs.info.upgrading_advantages';
    }
  }

  static String _keepInMindKey(FsSessionState state) {
    switch (state) {
      case FsSessionState.legacyOnly:
        return 'security.fs.info.legacy_keep_in_mind';
      case FsSessionState.fsInitSent:
      case FsSessionState.fsInitSeen:
      case FsSessionState.fsReplySent:
      case FsSessionState.fsReplySeen:
      case FsSessionState.fsConfirmSent:
      case FsSessionState.fsConfirmed:
        return 'security.fs.info.upgrading_keep_in_mind';
      case FsSessionState.fsActive:
        return 'security.fs.info.active_keep_in_mind';
      case FsSessionState.strictFsActive:
        return 'security.fs.info.strict_keep_in_mind';
      case FsSessionState.strictRequested:
        return 'security.fs.info.strict_requested_keep_in_mind';
      case FsSessionState.fsSuspended:
        return 'security.fs.info.suspended_keep_in_mind';
      case FsSessionState.fsBroken:
        return 'security.fs.info.broken_keep_in_mind';
    }
  }

  /// Splits a multi-sentence string into bullet list items at '. ' boundaries.
  static List<String> _split(String text) {
    return text
        .split('. ')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .map((s) => s.endsWith('.') ? s : '$s.')
        .toList();
  }
}

// ── Internal widget ──────────────────────────────────────────────────────────

class _SectionBlock extends StatelessWidget {
  const _SectionBlock({
    required this.title,
    required this.bullets,
    required this.color,
  });

  final String title;
  final List<String> bullets;
  final Color color;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: theme.textTheme.labelMedium?.copyWith(
            color: color,
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 4),
        ...bullets.map(
          (b) => Padding(
            padding: const EdgeInsets.only(bottom: 4),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('• ', style: theme.textTheme.bodySmall?.copyWith(color: color)),
                Expanded(child: Text(b, style: theme.textTheme.bodySmall)),
              ],
            ),
          ),
        ),
      ],
    );
  }
}
