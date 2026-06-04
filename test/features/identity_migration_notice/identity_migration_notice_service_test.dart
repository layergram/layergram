import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/features/identity_migration_notice/identity_migration_notice_service.dart';

class _InMemorySecureStorageService extends SecureStorageService {
  final Map<String, String> _values = <String, String>{};

  @override
  Future<void> write(String key, String value) async {
    _values[key] = value;
  }

  @override
  Future<String?> read(String key) async {
    return _values[key];
  }

  @override
  Future<void> delete(String key) async {
    _values.remove(key);
  }

  @override
  Future<void> deleteAll() async {
    _values.clear();
  }
}

void main() {
  late _InMemorySecureStorageService storage;
  late IdentityMigrationNoticeService service;

  setUp(() {
    storage = _InMemorySecureStorageService();
    service = IdentityMigrationNoticeService(storage);
  });

  group('IdentityMigrationNoticeService', () {
    test('legacy v1 identity never shows and does not write acknowledgement',
        () async {
      final shouldShow = await service.shouldShowForIdentity(_identityV1());

      expect(shouldShow, isFalse);
      expect(await service.isAcknowledged(), isFalse);
    });

    test('markAcknowledged is retained as a no-op for compatibility', () async {
      await service.markAcknowledged();

      final shouldShow = await service.shouldShowForIdentity(_identityV1());

      expect(shouldShow, isFalse);
      expect(await service.isAcknowledged(), isFalse);
    });

    test('v2 identity does not show and is not auto acknowledged', () async {
      final shouldShow = await service.shouldShowForIdentity(_identityV2());

      expect(shouldShow, isFalse);
      expect(await service.isAcknowledged(), isFalse);
    });

    test('missing identity does not show and is not auto acknowledged',
        () async {
      final shouldShow = await service.shouldShowForIdentity(null);

      expect(shouldShow, isFalse);
      expect(await service.isAcknowledged(), isFalse);
    });

    test('feature disabled never shows', () async {
      service = IdentityMigrationNoticeService(
        storage,
        isFeatureEnabled: () => false,
      );

      final shouldShow = await service.shouldShowForIdentity(_identityV1());

      expect(shouldShow, isFalse);
      expect(await service.isAcknowledged(), isFalse);
    });

    test('remind later is retained as a no-op for compatibility', () async {
      await service.markAcknowledged();
      await service.remindLater();

      final shouldShow = await service.shouldShowForIdentity(_identityV1());

      expect(await service.isAcknowledged(), isFalse);
      expect(shouldShow, isFalse);
    });

    test(
        'explicit logic returns false for acknowledged legacy and v2 identities',
        () {
      expect(
        service.shouldShowLegacyIdentityNotice(
          _identityV1(),
          true,
          featureEnabled: true,
        ),
        isFalse,
      );
      expect(
        service.shouldShowLegacyIdentityNotice(
          _identityV2(),
          false,
          featureEnabled: true,
        ),
        isFalse,
      );
      expect(
        service.shouldShowLegacyIdentityNotice(
          _identityV1(),
          false,
          featureEnabled: false,
        ),
        isFalse,
      );
    });

    test('shouldShowLegacyIdentityNotice always returns false', () {
      expect(
        service.shouldShowLegacyIdentityNotice(
          _identityV1(),
          false,
          featureEnabled: true,
        ),
        isFalse,
      );
    });

    test('shouldShowLegacyIdentityNotice returns false for null identity', () {
      expect(
        service.shouldShowLegacyIdentityNotice(
          null,
          false,
          featureEnabled: true,
        ),
        isFalse,
      );
    });

    test(
        'shouldShowLegacyIdentityNotice returns false for v2 identity regardless of acknowledged',
        () {
      expect(
        service.shouldShowLegacyIdentityNotice(
          _identityV2(),
          true,
          featureEnabled: true,
        ),
        isFalse,
      );
    });

    test(
        'feature disabled short-circuits before synchronizeIdentityState (no auto-ack)',
        () async {
      // With feature disabled, shouldShowForIdentity returns false immediately
      // WITHOUT calling synchronizeIdentityState, so a v2 identity does NOT
      // auto-acknowledge and does NOT pollute storage.
      service = IdentityMigrationNoticeService(
        storage,
        isFeatureEnabled: () => false,
      );

      await service.shouldShowForIdentity(_identityV2());

      expect(await service.isAcknowledged(), isFalse,
          reason: 'feature-disabled path must not write to storage');
    });

    test('synchronizeIdentityState does not write for null identity', () async {
      await service.synchronizeIdentityState(null);
      expect(await service.isAcknowledged(), isFalse);
    });

    test('synchronizeIdentityState does not write for v2 identity', () async {
      await service.synchronizeIdentityState(_identityV2());
      expect(await service.isAcknowledged(), isFalse);
    });

    test('synchronizeIdentityState does NOT mark acknowledged for v1 identity',
        () async {
      await service.synchronizeIdentityState(_identityV1());
      expect(await service.isAcknowledged(), isFalse);
    });
  });
}

LocalIdentity _identityV1() {
  return const LocalIdentity(
    identityId: 'legacy-id',
    publicKeyBase64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    fingerprint: 'AA-BB-CC-DD',
    displayName: 'Legacy',
    mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    derivationVersion: IdentityDerivationVersion.v1,
    derivationAlgorithm: 'sha256-seed',
  );
}

LocalIdentity _identityV2() {
  return const LocalIdentity(
    identityId: 'modern-id',
    publicKeyBase64: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
    fingerprint: '11-22-33-44',
    displayName: 'Modern',
    mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    derivationVersion: IdentityDerivationVersion.v2,
    derivationAlgorithm: 'hkdf-sha256',
  );
}
