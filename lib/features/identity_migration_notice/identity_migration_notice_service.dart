import '../../core/config/app_flags.dart';
import '../../core/crypto/models.dart';
import '../../core/crypto/seed_service.dart';
import '../../core/storage/secure_storage.dart';

class IdentityMigrationNoticeService {
  IdentityMigrationNoticeService(
    this._storage, {
    bool Function()? isFeatureEnabled,
  }) : _isFeatureEnabled = isFeatureEnabled ?? (() => showLegacyIdentityMigrationNotice);

  static const acknowledgedKey = 'legacy_identity_notice_acknowledged';

  final SecureStorageService _storage;
  final bool Function() _isFeatureEnabled;

  Future<bool> isAcknowledged() async {
    return (await _storage.read(acknowledgedKey)) == '1';
  }

  Future<void> markAcknowledged() {
    return _storage.write(acknowledgedKey, '1');
  }

  Future<void> remindLater() {
    return _storage.delete(acknowledgedKey);
  }

  Future<void> synchronizeIdentityState(LocalIdentity? identity) async {
    if (identity == null || identity.derivationVersion == IdentityDerivationVersion.v2) {
      await markAcknowledged();
    }
  }

  Future<bool> shouldShowForIdentity(LocalIdentity? identity) async {
    if (!_isFeatureEnabled()) {
      return false;
    }
    await synchronizeIdentityState(identity);
    final acknowledged = await isAcknowledged();
    return shouldShowLegacyIdentityNotice(
      identity,
      acknowledged,
      featureEnabled: true,
    );
  }

  bool shouldShowLegacyIdentityNotice(
    LocalIdentity? identity,
    bool acknowledged, {
    required bool featureEnabled,
  }) {
    if (!featureEnabled) {
      return false;
    }
    if (identity == null) {
      return false;
    }
    if (identity.derivationVersion != IdentityDerivationVersion.v1) {
      return false;
    }
    return !acknowledged;
  }
}
