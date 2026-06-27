import '../../core/crypto/models.dart';
import '../../core/storage/secure_storage.dart';

class IdentityMigrationNoticeService {
  IdentityMigrationNoticeService(
    SecureStorageService storage, {
    bool Function()? isFeatureEnabled,
  });

  // Kept only for compatibility with older callers/tests while the legacy
  // identity notice is retired. New code must not persist acknowledgement
  // state for this feature.
  Future<bool> isAcknowledged() async {
    return false;
  }

  Future<void> markAcknowledged() async {}

  Future<void> remindLater() async {}

  Future<void> synchronizeIdentityState(LocalIdentity? identity) async {}

  Future<bool> shouldShowForIdentity(LocalIdentity? identity) async {
    return false;
  }

  bool shouldShowLegacyIdentityNotice(
    LocalIdentity? identity,
    bool acknowledged, {
    required bool featureEnabled,
  }) {
    return false;
  }
}
