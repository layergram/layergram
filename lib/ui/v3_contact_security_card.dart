// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/crypto/fs_security_mode.dart';
import '../core/crypto/fs_session_manager.dart';
import '../core/crypto/models.dart';
import '../core/crypto/v3/application_chat_bridge_v3.dart';
import '../core/crypto/v3/local_identity_v3.dart';
import '../features/home/home_controller.dart';
import '../l10n/app_strings.dart';
import 'fs_maximum_fs_dialog.dart';
import 'fs_status_icon.dart';

class V3ContactSecurityCard extends ConsumerWidget {
  const V3ContactSecurityCard({super.key, required this.contact});

  final RemoteIdentity contact;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final status = ref.watch(
      protocolV3ContactSecurityStatusProvider(contact),
    );
    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: status.when(
          loading: () => const Center(child: CircularProgressIndicator()),
          error: (_, __) => _SecurityBody(
            contact: contact,
            canChangePolicy: false,
            status: const V3ChatContactSecurityStatus(
              phase: V3ChatContactSecurityPhase.recoveryRequired,
              selectedMode: V3HandshakeMode.normal,
              activeSessionCount: 0,
              hasSessionsInAnotherMode: false,
            ),
          ),
          data: (value) => _SecurityBody(
              contact: contact,
              canChangePolicy: value != null,
              status: value ??
                  const V3ChatContactSecurityStatus(
                    phase: V3ChatContactSecurityPhase.recoveryRequired,
                    selectedMode: V3HandshakeMode.normal,
                    activeSessionCount: 0,
                    hasSessionsInAnotherMode: false,
                  )),
        ),
      ),
    );
  }
}

class V3ContactStatusButton extends ConsumerWidget {
  const V3ContactStatusButton({
    super.key,
    required this.contact,
    this.size = 14,
  });

  final RemoteIdentity contact;
  final double size;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final asyncStatus = ref.watch(
      protocolV3ContactSecurityStatusProvider(contact),
    );
    final status = asyncStatus.valueOrNull ??
        const V3ChatContactSecurityStatus(
          phase: V3ChatContactSecurityPhase.setupRequired,
          selectedMode: V3HandshakeMode.normal,
          activeSessionCount: 0,
          hasSessionsInAnotherMode: false,
        );
    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onTap: () => showModalBottomSheet<void>(
        context: context,
        isScrollControlled: true,
        showDragHandle: true,
        builder: (_) => SafeArea(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
            child: V3ContactSecurityCard(contact: contact),
          ),
        ),
      ),
      child: FsStatusIcon(
        fsState: _fsState(status.phase),
        size: size,
      ),
    );
  }
}

class V3LegacyContactMigrationCard extends StatelessWidget {
  const V3LegacyContactMigrationCard({super.key});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(
              Icons.warning_amber_rounded,
              color: theme.colorScheme.error,
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    AppStrings.t(
                      context,
                      'security.fs.v3.contact_migration_title',
                    ),
                    style: theme.textTheme.titleSmall,
                  ),
                  const SizedBox(height: 6),
                  Text(
                    AppStrings.t(
                      context,
                      'security.fs.v3.contact_migration_required',
                    ),
                    style: theme.textTheme.bodySmall,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class V3LegacyContactStatusButton extends StatelessWidget {
  const V3LegacyContactStatusButton({super.key, this.size = 14});

  final double size;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onTap: () => showModalBottomSheet<void>(
        context: context,
        showDragHandle: true,
        builder: (_) => const SafeArea(
          child: Padding(
            padding: EdgeInsets.fromLTRB(16, 0, 16, 24),
            child: V3LegacyContactMigrationCard(),
          ),
        ),
      ),
      child: FsStatusIcon(
        fsState: FsSessionState.fsBroken,
        size: size,
      ),
    );
  }
}

class _SecurityBody extends ConsumerWidget {
  const _SecurityBody({
    required this.contact,
    required this.status,
    this.canChangePolicy = true,
  });

  final RemoteIdentity contact;
  final V3ChatContactSecurityStatus status;
  final bool canChangePolicy;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = AppStrings.t;
    final theme = Theme.of(context);
    final currentMode = status.selectedMode == V3HandshakeMode.maximum
        ? FsSecurityMode.strict
        : FsSecurityMode.advanced;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: Text(
                t(context, 'security.fs.v3.card_title'),
                style: theme.textTheme.titleSmall,
              ),
            ),
            FsStatusIcon(
              fsState: _fsState(status.phase),
              size: 20,
              showTooltip: false,
            ),
          ],
        ),
        const SizedBox(height: 10),
        Text(
          t(context, _statusKey(status.phase)),
          style: theme.textTheme.titleMedium,
        ),
        const SizedBox(height: 6),
        Text(
          t(context, _descriptionKey(status.phase)),
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        if (status.activeSessionCount > 1) ...[
          const SizedBox(height: 8),
          Text(
            t(
              context,
              'security.fs.v3.active_sessions',
              namedArgs: {'count': '${status.activeSessionCount}'},
            ),
            style: theme.textTheme.bodySmall,
          ),
        ],
        if (canChangePolicy) ...[
          const Divider(height: 28),
          Row(
            children: [
              Icon(
                currentMode == FsSecurityMode.strict
                    ? Icons.diamond_outlined
                    : Icons.devices_outlined,
                size: 18,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  t(
                    context,
                    'security.fs.mode.current_label',
                    namedArgs: {
                      'mode': t(
                        context,
                        currentMode == FsSecurityMode.strict
                            ? 'security.fs.mode.strict_title'
                            : 'security.fs.v3.normal_title',
                      ),
                    },
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              ActionChip(
                avatar: const Icon(Icons.tune, size: 18),
                label: Text(t(context, 'security.fs.action.change_mode')),
                onPressed: () => _changeMode(context, ref, currentMode),
              ),
              ActionChip(
                avatar: const Icon(Icons.lock_reset, size: 18),
                label: Text(t(context, 'security.fs.action.reset')),
                onPressed: () => _reset(context, ref, currentMode),
              ),
            ],
          ),
        ],
      ],
    );
  }

  Future<void> _changeMode(
    BuildContext context,
    WidgetRef ref,
    FsSecurityMode currentMode,
  ) async {
    final selected = await _showModeSheet(context, currentMode);
    if (selected == null || selected == currentMode || !context.mounted) {
      return;
    }
    if (selected == FsSecurityMode.strict) {
      final confirmed = await showMaximumFsConsentDialog(context);
      if (confirmed != true || !context.mounted) return;
    } else if (currentMode == FsSecurityMode.strict) {
      final confirmed = await showDisableMaximumFsDialog(context);
      if (confirmed != true || !context.mounted) return;
    }
    await ref
        .read(homeControllerProvider)
        .setProtocolV3SecurityMode(contact, selected);
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          AppStrings.t(context, 'security.fs.v3.mode_changed'),
        ),
      ),
    );
  }

  Future<void> _reset(
    BuildContext context,
    WidgetRef ref,
    FsSecurityMode currentMode,
  ) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(
          AppStrings.t(dialogContext, 'security.fs.v3.reset_title'),
        ),
        content: Text(
          AppStrings.t(dialogContext, 'security.fs.v3.reset_body'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: Text(AppStrings.t(dialogContext, 'cancel')),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: Text(
              AppStrings.t(dialogContext, 'security.fs.action.reset'),
            ),
          ),
        ],
      ),
    );
    if (confirmed != true || !context.mounted) return;
    await ref
        .read(homeControllerProvider)
        .setProtocolV3SecurityMode(contact, currentMode);
  }
}

Future<FsSecurityMode?> _showModeSheet(
  BuildContext context,
  FsSecurityMode currentMode,
) {
  return showModalBottomSheet<FsSecurityMode>(
    context: context,
    showDragHandle: true,
    builder: (sheetContext) => SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              AppStrings.t(sheetContext, 'security.fs.mode.sheet_title'),
              style: Theme.of(sheetContext).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            ListTile(
              leading: Icon(
                currentMode == FsSecurityMode.advanced
                    ? Icons.radio_button_checked
                    : Icons.radio_button_unchecked,
              ),
              title: Text(
                AppStrings.t(sheetContext, 'security.fs.v3.normal_title'),
              ),
              subtitle: Text(
                AppStrings.t(sheetContext, 'security.fs.v3.normal_desc'),
              ),
              onTap: () => Navigator.of(sheetContext).pop(
                FsSecurityMode.advanced,
              ),
            ),
            ListTile(
              leading: Icon(
                currentMode == FsSecurityMode.strict
                    ? Icons.radio_button_checked
                    : Icons.radio_button_unchecked,
              ),
              title: Text(
                AppStrings.t(sheetContext, 'security.fs.mode.strict_title'),
              ),
              subtitle: Text(
                AppStrings.t(sheetContext, 'security.fs.v3.maximum_desc'),
              ),
              onTap: () => Navigator.of(sheetContext).pop(
                FsSecurityMode.strict,
              ),
            ),
          ],
        ),
      ),
    ),
  );
}

FsSessionState _fsState(V3ChatContactSecurityPhase phase) => switch (phase) {
      V3ChatContactSecurityPhase.setupRequired ||
      V3ChatContactSecurityPhase.setupPending =>
        FsSessionState.fsInitSent,
      V3ChatContactSecurityPhase.normalActive => FsSessionState.fsActive,
      V3ChatContactSecurityPhase.maximumActive => FsSessionState.strictFsActive,
      V3ChatContactSecurityPhase.recoveryRequired => FsSessionState.fsBroken,
    };

String _statusKey(V3ChatContactSecurityPhase phase) => switch (phase) {
      V3ChatContactSecurityPhase.setupRequired =>
        'security.fs.v3.status.setup_required',
      V3ChatContactSecurityPhase.setupPending =>
        'security.fs.v3.status.setup_pending',
      V3ChatContactSecurityPhase.normalActive =>
        'security.fs.v3.status.normal_active',
      V3ChatContactSecurityPhase.maximumActive =>
        'security.fs.v3.status.maximum_active',
      V3ChatContactSecurityPhase.recoveryRequired =>
        'security.fs.status.broken',
    };

String _descriptionKey(V3ChatContactSecurityPhase phase) => switch (phase) {
      V3ChatContactSecurityPhase.setupRequired =>
        'security.fs.v3.description.setup_required',
      V3ChatContactSecurityPhase.setupPending =>
        'security.fs.v3.description.setup_pending',
      V3ChatContactSecurityPhase.normalActive =>
        'security.fs.v3.description.normal_active',
      V3ChatContactSecurityPhase.maximumActive =>
        'security.fs.v3.description.maximum_active',
      V3ChatContactSecurityPhase.recoveryRequired =>
        'security.fs.info.broken_description',
    };
