import 'package:flutter/material.dart';

import '../../core/crypto/models.dart';
import '../../l10n/app_strings.dart';
import 'identity_migration_notice_service.dart';

typedef LoadIdentityForMigrationNotice = Future<LocalIdentity?> Function();
typedef LoadIdentityMigrationNoticeTarget
    = Future<IdentityMigrationNoticeTarget?> Function();
typedef PresentIdentityMigrationNotice = Future<bool> Function(
    BuildContext context);

class IdentityMigrationNoticeController {
  IdentityMigrationNoticeController({
    required IdentityMigrationNoticeService service,
    LoadIdentityForMigrationNotice? loadIdentity,
    LoadIdentityMigrationNoticeTarget? loadTarget,
    PresentIdentityMigrationNotice? presentNotice,
  })  : _service = service,
        _loadIdentity = loadIdentity,
        _loadTarget = loadTarget,
        _presentNotice = presentNotice,
        assert(loadIdentity != null || loadTarget != null);

  final IdentityMigrationNoticeService _service;
  final LoadIdentityForMigrationNotice? _loadIdentity;
  final LoadIdentityMigrationNoticeTarget? _loadTarget;
  final PresentIdentityMigrationNotice? _presentNotice;

  Future<void> checkAndShowIfNeeded(BuildContext context) async {
    final target = await _loadNoticeTarget();
    if (!context.mounted) return;
    await processTargetIfNeeded(
      target: target,
      presentNotice: () async {
        final presenter = _presentNotice;
        if (presenter != null) return presenter(context);
        return await showDialog<bool>(
              context: context,
              barrierDismissible: false,
              builder: (dialogContext) => AlertDialog(
                title: Text(
                  AppStrings.t(
                    dialogContext,
                    'security.fs.v3.migration_title',
                  ),
                ),
                content: Text(
                  AppStrings.t(
                    dialogContext,
                    'security.fs.v3.migration_body',
                  ),
                ),
                actions: [
                  FilledButton(
                    onPressed: () => Navigator.of(dialogContext).pop(true),
                    child: Text(
                      AppStrings.t(
                        dialogContext,
                        'security.fs.v3.migration_view_identity',
                      ),
                    ),
                  ),
                ],
              ),
            ) ??
            false;
      },
    );
  }

  Future<void> processIdentityIfNeeded({
    required LocalIdentity? identity,
    required Future<bool> Function() presentNotice,
  }) async {
    return processTargetIfNeeded(
      target: identity == null
          ? null
          : IdentityMigrationNoticeTarget.fromLocalIdentity(identity),
      presentNotice: presentNotice,
    );
  }

  Future<void> processTargetIfNeeded({
    required IdentityMigrationNoticeTarget? target,
    required Future<bool> Function() presentNotice,
  }) async {
    if (!await _service.shouldShowForTarget(target)) return;
    final acknowledged = await presentNotice();
    if (acknowledged && target != null) {
      await _service.markAcknowledgedForTarget(target);
    }
  }

  Future<IdentityMigrationNoticeTarget?> _loadNoticeTarget() async {
    final loadTarget = _loadTarget;
    if (loadTarget != null) return loadTarget();
    final identity = await _loadIdentity?.call();
    return identity == null
        ? null
        : IdentityMigrationNoticeTarget.fromLocalIdentity(identity);
  }
}
