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

import '../../core/capabilities/backup_capability.dart';
import '../../core/providers.dart';
import '../../l10n/app_strings.dart';

class BackupView extends ConsumerStatefulWidget {
  const BackupView({super.key});

  @override
  ConsumerState<BackupView> createState() => _BackupViewState();
}

class _BackupViewState extends ConsumerState<BackupView> {
  BackupProgress? _progress;
  bool _busy = false;
  String? _error;

  void _onProgress(BackupProgress progress) {
    if (!mounted) return;
    setState(() => _progress = progress);
  }

  Future<void> _run(Future<void> Function(BackupProgressCallback cb) action) async {
    if (_busy) return;

    setState(() {
      _busy = true;
      _error = null;
      _progress = null;
    });

    try {
      await action(_onProgress);
      if (!mounted) return;
      setState(() {
        _busy = false;
        _progress = const BackupProgress(stage: BackupStage.done, fraction: 1);
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final caps = ref.watch(layergramCapabilitiesProvider);
    final backup = caps.backup;
    final identityId = ref.watch(activeIdentityIdProvider) ?? '';

    final available = backup.isAvailable;

    return Scaffold(
      backgroundColor: Colors.transparent,
      appBar: AppBar(title: Text(t(context, 'premiumBackupTitle'))),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: available
            ? _buildAvailable(context, t, backup, identityId)
            : _buildLocked(context, t),
      ),
    );
  }

  Widget _buildLocked(
    BuildContext context,
    String Function(BuildContext, String) t,
  ) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.lock_outline, size: 44),
          const SizedBox(height: 12),
          Text(
            t(context, 'premiumTag'),
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Text(
            t(context, 'premiumNotAvailable'),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildAvailable(
    BuildContext context,
    String Function(BuildContext, String) t,
    BackupCapability backup,
    String identityId,
  ) {
    final canRun = !_busy && identityId.isNotEmpty;
    final progress = _progress;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Text(
              '${t(context, 'identityIdLabel')}: ',
              style: Theme.of(context).textTheme.labelLarge,
            ),
            Expanded(
              child: SelectableText(
                identityId.isEmpty ? t(context, 'noActiveIdentity') : identityId,
                maxLines: 1,
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: canRun
              ? () => _run((cb) => backup.createBackup(
                    identityId: identityId,
                    onProgress: cb,
                  ))
              : null,
          icon: const Icon(Icons.cloud_upload_outlined),
          label: Text(t(context, 'createBackup')),
        ),
        const SizedBox(height: 8),
        OutlinedButton.icon(
          onPressed: canRun
              ? () => _run((cb) => backup.restoreBackup(
                    identityId: identityId,
                    onProgress: cb,
                  ))
              : null,
          icon: const Icon(Icons.cloud_download_outlined),
          label: Text(t(context, 'restoreBackup')),
        ),
        const SizedBox(height: 16),
        if (_busy || progress != null) ...[
          LinearProgressIndicator(
            value: progress?.fraction.clamp(0.0, 1.0),
          ),
          const SizedBox(height: 8),
          Text(
            progress == null
                ? t(context, 'preparing')
                : '${progress.stage.name} (${(progress.fraction * 100).round()}%)',
          ),
        ],
        if (_error != null) ...[
          const SizedBox(height: 12),
          Text(
            _error!,
            style: TextStyle(color: Theme.of(context).colorScheme.error),
          ),
        ],
      ],
    );
  }
}
