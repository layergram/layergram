import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';

import 'package:layergram/core/crypto/identity_manager.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/local_identity_vault.dart';
import 'package:layergram/core/storage/local_storage_security_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';

class InMemorySecureStorageService extends SecureStorageService {
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
  late Directory tmpDir;
  late InMemorySecureStorageService secureStorage;
  late LocalIdentityVault vault;
  late SeedService seedService;
  late IdentityManager manager;
  late LocalStorageSecurityService storageSecurity;

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_identity_mgr_');
    Hive.init(tmpDir.path);
    await Hive.openBox<Map>(LocalDatabase.identitiesBoxName);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    await Hive.openBox<Map>(LocalDatabase.chatMetaBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tmpDir.delete(recursive: true);
  });

  setUp(() async {
    await Hive.box<Map>(LocalDatabase.identitiesBoxName).clear();
    await Hive.box<Map>(LocalDatabase.messagesBoxName).clear();
    await Hive.box<Map>(LocalDatabase.chatMetaBoxName).clear();
    secureStorage = InMemorySecureStorageService();
    vault = LocalIdentityVault(secureStorage: secureStorage);
    seedService = SeedService();
    manager = IdentityManager(
      seedService: seedService,
      localIdentityVault: vault,
    );
    storageSecurity = LocalStorageSecurityService(
      secureStorage: secureStorage,
      localIdentityVault: vault,
    );
  });

  group('IdentityManager', () {
    test(
        'creates a new identity in the secure vault and derives the private key on demand',
        () async {
      final created = await manager.createNewIdentity(displayName: 'Alice');

      final storedRaw = await secureStorage.read(LocalIdentityVault.storageKey);
      expect(storedRaw, isNotNull);
      expect(Hive.box<Map>(LocalDatabase.identitiesBoxName).isEmpty, isTrue);

      final loaded = await manager.getLocalIdentity();
      expect(loaded?.identityId, created.identityId);
      expect(loaded?.displayName, 'Alice');
      expect(loaded?.mnemonic, created.mnemonic);
      expect(loaded?.derivationVersion, IdentityDerivationVersion.v2);
      expect(
          loaded?.derivationAlgorithm, IdentityDerivationVersion.v2.algorithm);

      final privateKeyBase64 = await manager.getLocalPrivateKeyBase64();
      final expectedPrivateKey = base64Encode(
        await seedService.deriveIdentityPrivateKey(
          seedService.mnemonicToSeed(created.mnemonic),
          version: IdentityDerivationVersion.v2,
        ),
      );
      expect(privateKeyBase64, expectedPrivateKey);
    });

    test('restores and clears the secure local identity vault', () async {
      const mnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

      final restored = await manager.restoreIdentityFromMnemonic(
        mnemonic,
        displayName: 'Recovered',
      );
      expect(restored.displayName, 'Recovered');
      expect(restored.derivationVersion, IdentityDerivationVersion.v2);
      expect(
          restored.derivationAlgorithm, IdentityDerivationVersion.v2.algorithm);

      await manager.clearLocalIdentity();

      expect(await manager.getLocalIdentity(), isNull);
      expect(await secureStorage.read(LocalIdentityVault.storageKey), isNull);
    });

    test('does not persist a partial identity when v3 runtime is gated',
        () async {
      const mnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

      await expectLater(
        manager.restoreIdentityFromMnemonic(
          mnemonic,
          derivationVersion: IdentityDerivationVersion.v3,
        ),
        throwsUnsupportedError,
      );
      expect(await manager.getLocalIdentity(), isNull);
      expect(await secureStorage.read(LocalIdentityVault.storageKey), isNull);
    });

    test(
        'restores the same mnemonic deterministically for the selected derivation version',
        () async {
      const mnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

      final restoredV1 = await manager.restoreIdentityFromMnemonic(
        mnemonic,
        displayName: 'Recovered',
        derivationVersion: IdentityDerivationVersion.v1,
      );
      final restoredV1Again = await manager.restoreIdentityFromMnemonic(
        mnemonic,
        displayName: 'Recovered Again',
        derivationVersion: IdentityDerivationVersion.v1,
      );
      final restoredV2 = await manager.restoreIdentityFromMnemonic(
        mnemonic,
        displayName: 'Recovered V2',
        derivationVersion: IdentityDerivationVersion.v2,
      );
      final restoredV2Again = await manager.restoreIdentityFromMnemonic(
        mnemonic,
        displayName: 'Recovered V2 Again',
        derivationVersion: IdentityDerivationVersion.v2,
      );

      expect(restoredV1.identityId, restoredV1Again.identityId);
      expect(restoredV1.fingerprint, restoredV1Again.fingerprint);
      expect(restoredV2.identityId, restoredV2Again.identityId);
      expect(restoredV2.fingerprint, restoredV2Again.fingerprint);
      expect(restoredV2.identityId, isNot(restoredV1.identityId));
      expect(restoredV2.fingerprint, isNot(restoredV1.fingerprint));
      expect(restoredV2.derivationVersion, IdentityDerivationVersion.v2);
    });

    test(
        'derives stored local private keys using the saved legacy v1 version without upgrading',
        () async {
      const mnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      final seed = seedService.mnemonicToSeed(mnemonic);
      final legacyPrivateKey = seedService.derivePrivateKeyV1(seed);
      final pair = await X25519().newKeyPairFromSeed(legacyPrivateKey);
      final publicKey = await pair.extractPublicKey();

      final legacyIdentity = LocalIdentity(
        identityId: 'LEGACY-V1',
        publicKeyBase64: base64Encode(publicKey.bytes),
        fingerprint: 'AA-BB-CC-DD',
        displayName: 'Legacy User',
        mnemonic: mnemonic,
        derivationVersion: IdentityDerivationVersion.v1,
        derivationAlgorithm: IdentityDerivationVersion.v1.algorithm,
      );
      await vault.save(legacyIdentity);

      final privateKeyBase64 = await manager.getLocalPrivateKeyBase64();
      final loaded = await manager.getLocalIdentity();

      expect(privateKeyBase64, base64Encode(legacyPrivateKey));
      expect(loaded?.derivationVersion, IdentityDerivationVersion.v1);
      expect(
          loaded?.derivationAlgorithm, IdentityDerivationVersion.v1.algorithm);
    });

    test(
        'bootstraps legacy layout by migrating local identity to secure storage and clearing Hive boxes',
        () async {
      final legacyIdentity = <String, dynamic>{
        'identityId': 'LEGACY',
        'publicKeyBase64': base64Encode(List<int>.filled(32, 7)),
        'fingerprint': 'AA-BB-CC-DD',
        'displayName': 'Legacy User',
        'mnemonic':
            'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      };

      await Hive.box<Map>(LocalDatabase.identitiesBoxName)
          .put('__local_identity__', legacyIdentity);
      await Hive.box<Map>(LocalDatabase.messagesBoxName)
          .put('legacy-message', {'plaintext': true});
      await Hive.box<Map>(LocalDatabase.chatMetaBoxName)
          .put('legacy-meta', {'plaintext': true});

      await storageSecurity.ensureCurrentLayout();

      final migrated = await vault.read();
      expect(migrated?.identityId, 'LEGACY');
      expect(migrated?.derivationVersion, IdentityDerivationVersion.v1);
      expect(migrated?.derivationAlgorithm,
          IdentityDerivationVersion.v1.algorithm);
      expect(
        Hive.box<Map>(LocalDatabase.identitiesBoxName).isEmpty,
        isTrue,
      );
      expect(
        Hive.box<Map>(LocalDatabase.messagesBoxName).isEmpty,
        isTrue,
      );
      expect(
        Hive.box<Map>(LocalDatabase.chatMetaBoxName).isEmpty,
        isTrue,
      );
    });
  });
}
