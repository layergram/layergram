import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/features/identity_migration_notice/identity_migration_notice_service.dart';

class _InMemorySecureStorageService extends SecureStorageService {
  final Map<String, String> values = <String, String>{};

  @override
  Future<void> write(String key, String value) async => values[key] = value;

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> delete(String key) async => values.remove(key);

  @override
  Future<void> deleteAll() async => values.clear();
}

void main() {
  late _InMemorySecureStorageService storage;
  late IdentityMigrationNoticeService service;

  setUp(() {
    storage = _InMemorySecureStorageService();
    service = IdentityMigrationNoticeService(
      storage,
      isFeatureEnabled: () => true,
    );
  });

  test('v1 and v2 identities are prompted only when v3 is enabled', () async {
    expect(await service.shouldShowForIdentity(_identityV1()), isTrue);
    expect(await service.shouldShowForIdentity(_identityV2()), isTrue);

    final disabled = IdentityMigrationNoticeService(
      storage,
      isFeatureEnabled: () => false,
    );
    expect(await disabled.shouldShowForIdentity(_identityV2()), isFalse);
    expect(await disabled.isAcknowledged(), isFalse);
  });

  test('acknowledgement is scoped to the restored local identity', () async {
    await service.markAcknowledgedForIdentity(_identityV1());

    expect(await service.shouldShowForIdentity(_identityV1()), isFalse);
    expect(await service.shouldShowForIdentity(_identityV2()), isTrue);
    expect(await service.isAcknowledged(), isTrue);
  });

  test('acknowledgements survive A to B to A Premium-style switching',
      () async {
    await service.markAcknowledgedForIdentity(_identityV1());
    await service.markAcknowledgedForIdentity(_identityV2());

    expect(await service.shouldShowForIdentity(_identityV1()), isFalse);
    expect(await service.shouldShowForIdentity(_identityV2()), isFalse);
  });

  test('non-persistent targets never write a hidden identity identifier',
      () async {
    const hidden = IdentityMigrationNoticeTarget(
      identityId: 'hidden-passphrase-id',
      protocolVersion: 2,
      persistAcknowledgement: false,
    );
    expect(await service.shouldShowForTarget(hidden), isTrue);
    await service.markAcknowledgedForTarget(hidden);

    expect(await service.shouldShowForTarget(hidden), isFalse);
    expect(storage.values, isEmpty);
  });

  test('remind later leaves the migration notice pending', () async {
    await service.markAcknowledgedForIdentity(_identityV2());
    await service.remindLater();

    expect(await service.isAcknowledged(), isFalse);
    expect(await service.shouldShowForIdentity(_identityV2()), isTrue);
  });

  test('missing or already-v3 local identities are never prompted', () async {
    expect(await service.shouldShowForIdentity(null), isFalse);
    expect(await service.shouldShowForIdentity(_identityV3()), isFalse);
  });

  test('explicit predicate requires an unacknowledged pre-v3 identity', () {
    expect(
      service.shouldShowLegacyIdentityNotice(
        _identityV2(),
        false,
        featureEnabled: true,
      ),
      isTrue,
    );
    expect(
      service.shouldShowLegacyIdentityNotice(
        _identityV2(),
        true,
        featureEnabled: true,
      ),
      isFalse,
    );
    expect(
      service.shouldShowLegacyIdentityNotice(
        _identityV3(),
        false,
        featureEnabled: true,
      ),
      isFalse,
    );
  });
}

LocalIdentity _identityV1() => const LocalIdentity(
      identityId: 'legacy-id',
      publicKeyBase64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      fingerprint: 'AA-BB-CC-DD',
      displayName: 'Legacy',
      mnemonic:
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      derivationVersion: IdentityDerivationVersion.v1,
      derivationAlgorithm: 'sha256-seed',
    );

LocalIdentity _identityV2() => const LocalIdentity(
      identityId: 'modern-id',
      publicKeyBase64: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
      fingerprint: '11-22-33-44',
      displayName: 'Modern',
      mnemonic:
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      derivationVersion: IdentityDerivationVersion.v2,
      derivationAlgorithm: 'hkdf-sha256',
    );

LocalIdentity _identityV3() => const LocalIdentity(
      identityId: 'v3-id',
      publicKeyBase64: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
      fingerprint: '55-66-77-88',
      displayName: 'V3',
      mnemonic:
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      derivationVersion: IdentityDerivationVersion.v2,
      derivationAlgorithm: 'hkdf-sha256',
      protocolVersion: 3,
      publicIdentityBase64: 'complete-v3-public-identity',
    );
