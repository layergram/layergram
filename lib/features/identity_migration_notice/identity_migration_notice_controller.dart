import 'package:flutter/material.dart';

import '../../core/crypto/models.dart';
import 'identity_migration_notice_dialog.dart';
import 'identity_migration_notice_service.dart';

typedef LoadIdentityForMigrationNotice = Future<LocalIdentity?> Function();
typedef PresentIdentityMigrationNotice =
    Future<IdentityMigrationNoticeAction?> Function(BuildContext context);

class IdentityMigrationNoticeController {
  IdentityMigrationNoticeController({
    required IdentityMigrationNoticeService service,
    required LoadIdentityForMigrationNotice loadIdentity,
    PresentIdentityMigrationNotice? presentNotice,
  })  : _service = service,
        _loadIdentity = loadIdentity,
        _presentNotice = presentNotice ?? showIdentityMigrationNoticeDialog;

  final IdentityMigrationNoticeService _service;
  final LoadIdentityForMigrationNotice _loadIdentity;
  final PresentIdentityMigrationNotice _presentNotice;

  bool _handledThisSession = false;
  bool _showing = false;

  Future<void> checkAndShowIfNeeded(BuildContext context) async {
    final identity = await _loadIdentity();
    if (!context.mounted) {
      return;
    }
    await processIdentityIfNeeded(
      identity: identity,
      presentNotice: () => _presentNotice(context),
    );
  }

  Future<void> processIdentityIfNeeded({
    required LocalIdentity? identity,
    required Future<IdentityMigrationNoticeAction?> Function() presentNotice,
  }) async {
    if (_handledThisSession || _showing) {
      return;
    }

    final shouldShow = await _service.shouldShowForIdentity(identity);
    if (!shouldShow) {
      return;
    }

    _handledThisSession = true;
    _showing = true;
    try {
      final action = await presentNotice();
      if (action == IdentityMigrationNoticeAction.understand) {
        await _service.markAcknowledged();
      }
      if (action == IdentityMigrationNoticeAction.remindLater) {
        await _service.remindLater();
      }
    } finally {
      _showing = false;
    }
  }
}
