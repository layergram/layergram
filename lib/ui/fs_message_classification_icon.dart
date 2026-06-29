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

import '../core/crypto/fs_message_classification.dart';
import '../l10n/app_strings.dart';

/// Compact per-message security classification indicator (§14.4).
///
/// Shows a tiny icon next to the message timestamp. Tapping opens a
/// bottom sheet with a human-readable explanation of the classification.
class FsMessageClassificationIcon extends StatelessWidget {
  const FsMessageClassificationIcon({
    super.key,
    required this.classification,
    this.size = 12.0,
  });

  final FsMessageClassification classification;
  final double size;

  @override
  Widget build(BuildContext context) {
    final Widget icon = classification == FsMessageClassification.strictFs
        ? _StrictFsLockIcon(size: size)
        : Icon(
            _icon(classification),
            size: size,
            color: _color(classification, Theme.of(context)),
          );

    return GestureDetector(
      onTap: () => showFsClassificationDetail(context, classification),
      child: Tooltip(
        message: _shortLabel(context, classification),
        child: icon,
      ),
    );
  }

  static IconData _icon(FsMessageClassification cls) {
    switch (cls) {
      case FsMessageClassification.legacy:
        return Icons.lock_open;
      case FsMessageClassification.preFs:
        return Icons.lock_open;
      case FsMessageClassification.fsNegotiation:
        return Icons.sync;
      case FsMessageClassification.fsWithFallback:
        return Icons.lock_outline;
      case FsMessageClassification.fsOnly:
        return Icons.lock;
      case FsMessageClassification.strictFs:
        return Icons.lock;
      case FsMessageClassification.fsFailed:
        return Icons.lock_open;
      case FsMessageClassification.unknown:
        return Icons.help_outline;
    }
  }

  static Color _color(FsMessageClassification cls, ThemeData theme) {
    switch (cls) {
      case FsMessageClassification.legacy:
      case FsMessageClassification.preFs:
        return Colors.grey;
      case FsMessageClassification.fsNegotiation:
        return Colors.orange;
      case FsMessageClassification.fsWithFallback:
        return Colors.green;
      case FsMessageClassification.fsOnly:
        return Colors.green.shade700;
      case FsMessageClassification.strictFs:
        return Colors.green.shade700;
      case FsMessageClassification.fsFailed:
        return theme.colorScheme.error;
      case FsMessageClassification.unknown:
        return Colors.grey;
    }
  }

  static String _shortLabel(BuildContext context, FsMessageClassification cls) {
    return AppStrings.t(context, _labelKey(cls));
  }

  static String _labelKey(FsMessageClassification cls) {
    switch (cls) {
      case FsMessageClassification.legacy:
        return 'security.fs.cls.legacy';
      case FsMessageClassification.preFs:
        return 'security.fs.cls.pre_fs';
      case FsMessageClassification.fsNegotiation:
        return 'security.fs.cls.negotiation';
      case FsMessageClassification.fsWithFallback:
        return 'security.fs.cls.fs_fallback';
      case FsMessageClassification.fsOnly:
        return 'security.fs.cls.fs_only';
      case FsMessageClassification.strictFs:
        return 'security.fs.cls.strict';
      case FsMessageClassification.fsFailed:
        return 'security.fs.cls.failed';
      case FsMessageClassification.unknown:
        return 'security.fs.cls.unknown';
    }
  }

  static String _descriptionKey(FsMessageClassification cls) {
    switch (cls) {
      case FsMessageClassification.legacy:
        return 'security.fs.cls.legacy.desc';
      case FsMessageClassification.preFs:
        return 'security.fs.cls.pre_fs.desc';
      case FsMessageClassification.fsNegotiation:
        return 'security.fs.cls.negotiation.desc';
      case FsMessageClassification.fsWithFallback:
        return 'security.fs.cls.fs_fallback.desc';
      case FsMessageClassification.fsOnly:
        return 'security.fs.cls.fs_only.desc';
      case FsMessageClassification.strictFs:
        return 'security.fs.cls.strict.desc';
      case FsMessageClassification.fsFailed:
        return 'security.fs.cls.failed.desc';
      case FsMessageClassification.unknown:
        return 'security.fs.cls.unknown.desc';
    }
  }
}

class _StrictFsLockIcon extends StatelessWidget {
  const _StrictFsLockIcon({required this.size});

  final double size;

  @override
  Widget build(BuildContext context) {
    const gold = Color(0xFFD4A017);
    return SizedBox.square(
      dimension: size,
      child: Stack(
        alignment: Alignment.center,
        children: [
          Icon(Icons.lock, size: size, color: gold),
          Icon(Icons.lock, size: size * 0.78, color: Colors.green.shade700),
        ],
      ),
    );
  }
}

/// Shows a bottom sheet explaining the given message classification.
void showFsClassificationDetail(
    BuildContext context, FsMessageClassification cls) {
  showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
    ),
    builder: (context) => SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(20, 16, 20, 20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Center(
              child: Container(
                width: 32,
                height: 4,
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                FsMessageClassificationIcon(
                  classification: cls,
                  size: 20,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    AppStrings.t(
                        context, FsMessageClassificationIcon._labelKey(cls)),
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Text(
              AppStrings.t(
                  context, FsMessageClassificationIcon._descriptionKey(cls)),
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
          ],
        ),
      ),
    ),
  );
}
