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

/// Compact Forward Secrecy status icon for in-chat display.
///
/// Shows a small glyph and color that communicates the current FS state
/// without cluttering the chat.  Wrap in a [Tooltip] by passing
/// [showTooltip] = true (default).
///
/// Spec reference: §9.1 — Compact chat icon.
///
/// Glyphs:
/// ```
/// ○  Base / legacy           — grey
/// ◐  Upgrading in progress   — amber
/// ●  Forward Secrecy active  — green
/// ◆  Strict / Maximum FS     — teal
/// ⚠  Warning / broken        — red
/// ```
class FsStatusIcon extends StatelessWidget {
  const FsStatusIcon({
    super.key,
    required this.fsState,
    this.size = 16.0,
    this.showTooltip = true,
  });

  final FsSessionState fsState;
  final double size;
  final bool showTooltip;

  @override
  Widget build(BuildContext context) {
    final icon = Icon(
      _iconData(fsState),
      size: size,
      color: _color(fsState, Theme.of(context)),
      semanticLabel: _semanticLabel(context, fsState),
    );

    if (!showTooltip) return icon;

    return Tooltip(
      message: _tooltipText(context, fsState),
      child: icon,
    );
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  static IconData _iconData(FsSessionState state) {
    switch (state) {
      case FsSessionState.legacyOnly:
        return Icons.radio_button_unchecked;
      case FsSessionState.fsInitSent:
      case FsSessionState.fsInitSeen:
      case FsSessionState.fsReplySent:
      case FsSessionState.fsReplySeen:
      case FsSessionState.fsConfirmSent:
      case FsSessionState.fsConfirmed:
        return Icons.timelapse;
      case FsSessionState.fsActive:
        return Icons.circle;
      case FsSessionState.strictFsActive:
        return Icons.diamond;
      case FsSessionState.fsSuspended:
        return Icons.pause_circle_outline;
      case FsSessionState.strictRequested:
        return Icons.timelapse;
      case FsSessionState.fsBroken:
        return Icons.warning_amber_rounded;
    }
  }

  static Color _color(FsSessionState state, ThemeData theme) {
    switch (state) {
      case FsSessionState.legacyOnly:
        return theme.disabledColor;
      case FsSessionState.fsInitSent:
      case FsSessionState.fsInitSeen:
      case FsSessionState.fsReplySent:
      case FsSessionState.fsReplySeen:
      case FsSessionState.fsConfirmSent:
      case FsSessionState.fsConfirmed:
      case FsSessionState.strictRequested:
        return Colors.amber;
      case FsSessionState.fsActive:
        return Colors.green;
      case FsSessionState.strictFsActive:
        return Colors.teal;
      case FsSessionState.fsSuspended:
        return Colors.grey;
      case FsSessionState.fsBroken:
        return theme.colorScheme.error;
    }
  }

  static String _tooltipText(BuildContext context, FsSessionState state) {
    final key = _statusKey(state);
    return AppStrings.t(context, key);
  }

  static String _semanticLabel(BuildContext context, FsSessionState state) {
    return _tooltipText(context, state);
  }

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
      case FsSessionState.strictRequested:
        return 'security.fs.status.upgrading';
      case FsSessionState.fsActive:
        return 'security.fs.status.active';
      case FsSessionState.strictFsActive:
        return 'security.fs.status.strict';
      case FsSessionState.fsSuspended:
        return 'security.fs.status.suspended';
      case FsSessionState.fsBroken:
        return 'security.fs.status.broken';
    }
  }
}
