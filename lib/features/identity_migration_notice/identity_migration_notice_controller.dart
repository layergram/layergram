import 'package:flutter/material.dart';

import '../../core/crypto/models.dart';
import 'identity_migration_notice_service.dart';

typedef LoadIdentityForMigrationNotice = Future<LocalIdentity?> Function();
typedef PresentIdentityMigrationNotice = Future<void> Function(
    BuildContext context);

class IdentityMigrationNoticeController {
  IdentityMigrationNoticeController({
    required IdentityMigrationNoticeService service,
    required LoadIdentityForMigrationNotice loadIdentity,
    PresentIdentityMigrationNotice? presentNotice,
  });

  Future<void> checkAndShowIfNeeded(BuildContext context) async {
    return;
  }

  Future<void> processIdentityIfNeeded({
    required LocalIdentity? identity,
    required Future<void> Function() presentNotice,
  }) async {
    return;
  }
}
