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
/// Shows a shield glyph whose fill color communicates the current FS state.
/// Tap/click opens the contact security section (handled by the caller).
///
/// Spec reference: §9.1 — Compact chat icon.
///
/// Shields:
/// ```
/// 🛡 grey             — no FS (legacy only)
/// 🛡 orange           — handshake / negotiation in progress
/// 🛡 green            — Opportunistic FS active (multi-device)
/// 🛡 green + gold rim — Strict / Maximum FS active (single device)
/// 🛡 grey             — suspended
/// ⚠  red              — broken / warning
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
    final theme = Theme.of(context);

    // Broken state keeps the warning triangle icon
    if (fsState == FsSessionState.fsBroken) {
      final icon = Icon(
        Icons.warning_amber_rounded,
        size: size,
        color: theme.colorScheme.error,
        semanticLabel: _semanticLabel(context, fsState),
      );
      if (!showTooltip) return icon;
      return Tooltip(
        message: _tooltipText(context, fsState),
        child: icon,
      );
    }

    final fillColor = _fillColor(fsState, theme);
    final borderColor = _borderColor(fsState);
    final hasBorder = borderColor != null;

    final shield = SizedBox(
      width: size,
      height: size,
      child: CustomPaint(
        painter: _ShieldPainter(
          fillColor: fillColor,
          borderColor: borderColor,
          borderWidth: hasBorder ? size * 0.12 : 0,
        ),
        child: Center(
          child: Semantics(
            label: _semanticLabel(context, fsState),
            child: const SizedBox.shrink(),
          ),
        ),
      ),
    );

    if (!showTooltip) return shield;

    return Tooltip(
      message: _tooltipText(context, fsState),
      child: shield,
    );
  }

  // ── Color helpers ─────────────────────────────────────────────────────────

  /// Returns the fill color for the shield.
  static Color fillColor(FsSessionState state, ThemeData theme) =>
      _fillColor(state, theme);

  static Color _fillColor(FsSessionState state, ThemeData theme) {
    switch (state) {
      case FsSessionState.legacyOnly:
        return Colors.grey;
      case FsSessionState.fsInitSent:
      case FsSessionState.fsInitSeen:
      case FsSessionState.fsReplySent:
      case FsSessionState.fsReplySeen:
      case FsSessionState.fsConfirmSent:
      case FsSessionState.fsConfirmed:
      case FsSessionState.strictRequested:
        return Colors.orange;
      case FsSessionState.fsActive:
        return Colors.green;
      case FsSessionState.strictFsActive:
        return Colors.green;
      case FsSessionState.fsSuspended:
        return Colors.grey;
      case FsSessionState.fsBroken:
        return theme.colorScheme.error;
    }
  }

  /// Returns the border color for the shield, or null if no border.
  /// Only Strict FS gets a gold border.
  static Color? _borderColor(FsSessionState state) {
    if (state == FsSessionState.strictFsActive) {
      return const Color(0xFFD4A017); // gold
    }
    return null;
  }

  // ── Text helpers ──────────────────────────────────────────────────────────

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

/// Custom painter that draws a shield shape.
class _ShieldPainter extends CustomPainter {
  _ShieldPainter({
    required this.fillColor,
    this.borderColor,
    this.borderWidth = 0,
  });

  final Color fillColor;
  final Color? borderColor;
  final double borderWidth;

  @override
  void paint(Canvas canvas, Size size) {
    final w = size.width;
    final h = size.height;

    // Shield path: rounded top, pointed bottom
    final path = Path()
      ..moveTo(w * 0.5, 0)
      ..lineTo(w * 0.85, 0)
      ..quadraticBezierTo(w, 0, w, h * 0.15)
      ..lineTo(w, h * 0.45)
      ..quadraticBezierTo(w, h * 0.7, w * 0.5, h)
      ..quadraticBezierTo(0, h * 0.7, 0, h * 0.45)
      ..lineTo(0, h * 0.15)
      ..quadraticBezierTo(0, 0, w * 0.15, 0)
      ..close();

    // Fill
    canvas.drawPath(path, Paint()..color = fillColor);

    // Border (only for strict FS)
    if (borderColor != null && borderWidth > 0) {
      canvas.drawPath(
        path,
        Paint()
          ..color = borderColor!
          ..style = PaintingStyle.stroke
          ..strokeWidth = borderWidth,
      );
    }
  }

  @override
  bool shouldRepaint(_ShieldPainter oldDelegate) =>
      fillColor != oldDelegate.fillColor ||
      borderColor != oldDelegate.borderColor ||
      borderWidth != oldDelegate.borderWidth;
}
