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

import '../l10n/app_strings.dart';

/// Shows the Maximum FS consent dialog (spec §14.6.1 + §14.6.2).
///
/// Returns `true` only when the user explicitly ticks both checkboxes and
/// confirms.  Returns `null` or `false` when dismissed or cancelled.
Future<bool?> showMaximumFsConsentDialog(BuildContext context) {
  return showDialog<bool>(
    context: context,
    barrierDismissible: false,
    builder: (_) => const _MaximumFsDialog(),
  );
}

class _MaximumFsDialog extends StatefulWidget {
  const _MaximumFsDialog();

  @override
  State<_MaximumFsDialog> createState() => _MaximumFsDialogState();
}

class _MaximumFsDialogState extends State<_MaximumFsDialog> {
  bool _recoverabilityChecked = false;
  bool _deviceBoundChecked = false;

  bool get _canConfirm => _recoverabilityChecked && _deviceBoundChecked;

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return AlertDialog(
      title: Text(t(context, 'security.fs.maximum.confirm_title')),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Device-bound warning ─────────────────────────────────────────
            _WarningBlock(
              title: t(context, 'security.fs.warning.device_bound_title'),
              body: t(context, 'security.fs.warning.device_bound_body'),
              color: cs.errorContainer,
              textColor: cs.onErrorContainer,
            ),
            const SizedBox(height: 16),

            // ── Recoverability warning ────────────────────────────────────────
            _WarningBlock(
              title: t(context, 'security.fs.warning.recoverability_title'),
              body: t(context, 'security.fs.warning.recoverability_body'),
              color: cs.tertiaryContainer,
              textColor: cs.onTertiaryContainer,
            ),
            const SizedBox(height: 20),

            // ── Checkbox 1: device-bound consent ─────────────────────────────
            _ConsentCheckbox(
              value: _deviceBoundChecked,
              label: t(context, 'security.fs.warning.device_bound_confirm'),
              onChanged: (v) => setState(() => _deviceBoundChecked = v ?? false),
            ),
            const SizedBox(height: 8),

            // ── Checkbox 2: recoverability consent ───────────────────────────
            _ConsentCheckbox(
              value: _recoverabilityChecked,
              label: t(context, 'security.fs.warning.recoverability_confirm'),
              onChanged: (v) => setState(() => _recoverabilityChecked = v ?? false),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: Text(t(context, 'security.fs.maximum.cancel_button')),
        ),
        FilledButton(
          onPressed: _canConfirm ? () => Navigator.of(context).pop(true) : null,
          child: Text(t(context, 'security.fs.maximum.confirm_button')),
        ),
      ],
    );
  }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

class _WarningBlock extends StatelessWidget {
  const _WarningBlock({
    required this.title,
    required this.body,
    required this.color,
    required this.textColor,
  });

  final String title;
  final String body;
  final Color color;
  final Color textColor;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: theme.textTheme.labelMedium?.copyWith(
              color: textColor,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 4),
          Text(body, style: theme.textTheme.bodySmall?.copyWith(color: textColor)),
        ],
      ),
    );
  }
}

class _ConsentCheckbox extends StatelessWidget {
  const _ConsentCheckbox({
    required this.value,
    required this.label,
    required this.onChanged,
  });

  final bool value;
  final String label;
  final ValueChanged<bool?> onChanged;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: () => onChanged(!value),
      borderRadius: BorderRadius.circular(4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Checkbox(value: value, onChanged: onChanged),
          const SizedBox(width: 4),
          Expanded(
            child: Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(label, style: Theme.of(context).textTheme.bodySmall),
            ),
          ),
        ],
      ),
    );
  }
}
