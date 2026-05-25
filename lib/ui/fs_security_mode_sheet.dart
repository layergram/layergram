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

import '../core/crypto/fs_security_mode.dart';
import '../l10n/app_strings.dart';

/// Opens the security mode selector bottom sheet (spec §14.3).
///
/// Returns the selected [FsSecurityMode], or `null` if dismissed.
Future<FsSecurityMode?> showFsSecurityModeSheet(
  BuildContext context, {
  required FsSecurityMode currentMode,
}) {
  return showModalBottomSheet<FsSecurityMode>(
    context: context,
    isScrollControlled: true,
    showDragHandle: true,
    builder: (_) => _FsSecurityModeSheet(currentMode: currentMode),
  );
}

class _FsSecurityModeSheet extends StatefulWidget {
  const _FsSecurityModeSheet({required this.currentMode});

  final FsSecurityMode currentMode;

  @override
  State<_FsSecurityModeSheet> createState() => _FsSecurityModeSheetState();
}

class _FsSecurityModeSheetState extends State<_FsSecurityModeSheet> {
  late FsSecurityMode _selected;
  bool _strictWarningAccepted = false;

  @override
  void initState() {
    super.initState();
    _selected = widget.currentMode;
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(20, 0, 20, 24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              t(context, 'security.fs.mode.sheet_title'),
              style: theme.textTheme.titleLarge,
            ),
            const SizedBox(height: 4),
            Text(
              t(context, 'security.fs.mode.sheet_subtitle'),
              style: theme.textTheme.bodySmall?.copyWith(
                color: cs.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 16),

            // ── Mode cards ──────────────────────────────────────────────────
            _ModeCard(
              mode: FsSecurityMode.base,
              selected: _selected == FsSecurityMode.base,
              icon: Icons.shield_outlined,
              iconColor: Colors.grey,
              titleKey: 'security.fs.mode.base_title',
              descKey: 'security.fs.mode.base_desc',
              onTap: () => setState(() {
                _selected = FsSecurityMode.base;
                _strictWarningAccepted = false;
              }),
            ),
            const SizedBox(height: 8),
            _ModeCard(
              mode: FsSecurityMode.advanced,
              selected: _selected == FsSecurityMode.advanced,
              icon: Icons.shield,
              iconColor: Colors.green,
              titleKey: 'security.fs.mode.advanced_title',
              descKey: 'security.fs.mode.advanced_desc',
              onTap: () => setState(() {
                _selected = FsSecurityMode.advanced;
                _strictWarningAccepted = false;
              }),
            ),
            const SizedBox(height: 8),
            _ModeCard(
              mode: FsSecurityMode.strict,
              selected: _selected == FsSecurityMode.strict,
              icon: Icons.shield,
              iconColor: Colors.green.shade800,
              borderColor: Colors.amber.shade700,
              titleKey: 'security.fs.mode.strict_title',
              descKey: 'security.fs.mode.strict_desc',
              onTap: () => setState(() {
                _selected = FsSecurityMode.strict;
              }),
            ),

            // ── Strict FS warning (§14.6.2) ─────────────────────────────────
            if (_selected == FsSecurityMode.strict &&
                widget.currentMode != FsSecurityMode.strict) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: cs.errorContainer,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      t(context, 'security.fs.warning.device_bound_title'),
                      style: theme.textTheme.labelMedium?.copyWith(
                        color: cs.onErrorContainer,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      t(context, 'security.fs.warning.device_bound_body'),
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: cs.onErrorContainer,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 8),
              CheckboxListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                controlAffinity: ListTileControlAffinity.leading,
                value: _strictWarningAccepted,
                onChanged: (v) =>
                    setState(() => _strictWarningAccepted = v ?? false),
                title: Text(
                  t(context, 'security.fs.warning.device_bound_confirm'),
                  style: theme.textTheme.bodySmall,
                ),
              ),
            ],

            const SizedBox(height: 20),

            // ── Confirm button ──────────────────────────────────────────────
            SizedBox(
              width: double.infinity,
              child: FilledButton(
                onPressed: _canConfirm ? _onConfirm : null,
                child: Text(t(context, 'security.fs.mode.confirm_button')),
              ),
            ),
            const SizedBox(height: 8),
            SizedBox(
              width: double.infinity,
              child: TextButton(
                onPressed: () => Navigator.of(context).pop(),
                child: Text(t(context, 'security.fs.mode.cancel_button')),
              ),
            ),
          ],
        ),
      ),
    );
  }

  bool get _canConfirm {
    if (_selected == widget.currentMode) return false;
    if (_selected == FsSecurityMode.strict &&
        widget.currentMode != FsSecurityMode.strict) {
      return _strictWarningAccepted;
    }
    return true;
  }

  void _onConfirm() {
    Navigator.of(context).pop(_selected);
  }
}

// ── Mode card widget ──────────────────────────────────────────────────────────

class _ModeCard extends StatelessWidget {
  const _ModeCard({
    required this.mode,
    required this.selected,
    required this.icon,
    required this.iconColor,
    required this.titleKey,
    required this.descKey,
    required this.onTap,
    this.borderColor,
  });

  final FsSecurityMode mode;
  final bool selected;
  final IconData icon;
  final Color iconColor;
  final String titleKey;
  final String descKey;
  final VoidCallback onTap;
  final Color? borderColor;

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Material(
      color: selected
          ? cs.primaryContainer.withValues(alpha: 0.4)
          : cs.surfaceContainerHighest.withValues(alpha: 0.5),
      borderRadius: BorderRadius.circular(12),
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(12),
            border: Border.all(
              color: selected
                  ? cs.primary
                  : (borderColor ?? cs.outlineVariant).withValues(alpha: 0.5),
              width: selected ? 2 : 1,
            ),
          ),
          child: Row(
            children: [
              Container(
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: iconColor.withValues(alpha: 0.15),
                ),
                child: Icon(icon, color: iconColor, size: 20),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      t(context, titleKey),
                      style: theme.textTheme.labelLarge?.copyWith(
                        fontWeight: selected ? FontWeight.bold : FontWeight.w500,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      t(context, descKey),
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: cs.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
              if (selected)
                Icon(Icons.check_circle, color: cs.primary, size: 22),
            ],
          ),
        ),
      ),
    );
  }
}
