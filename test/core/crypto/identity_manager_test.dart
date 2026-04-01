import 'dart:convert';
import 'dart:io';

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
    test('creates a new identity in the secure vault and derives the private key on demand', () async {
      final created = await manager.createNewIdentity(displayName: 'Alice');

      final storedRaw = await secureStorage.read(LocalIdentityVault.storageKey);
      expect(storedRaw, isNotNull);
      expect(Hive.box<Map>(LocalDatabase.identitiesBoxName).isEmpty, isTrue);

      final loaded = await manager.getLocalIdentity();
      expect(loaded?.identityId, created.identityId);
      expect(loaded?.displayName, 'Alice');
      expect(loaded?.mnemonic, created.mnemonic);

      final privateKeyBase64 = await manager.getLocalPrivateKeyBase64();
      final expectedPrivateKey = base64Encode(
        seedService.derivePrivateKey(
          seedService.mnemonicToSeed(created.mnemonic),
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

      await manager.clearLocalIdentity();

      expect(await manager.getLocalIdentity(), isNull);
      expect(await secureStorage.read(LocalIdentityVault.storageKey), isNull);
    });

    test('bootstraps legacy layout by migrating local identity to secure storage and clearing Hive boxes', () async {
      final legacyIdentity = LocalIdentity(
        identityId: 'LEGACY',
        publicKeyBase64: base64Encode(List<int>.filled(32, 7)),
        fingerprint: 'AA-BB-CC-DD',
        displayName: 'Legacy User',
        mnemonic:
            'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      );

      await Hive.box<Map>(LocalDatabase.identitiesBoxName)
          .put('__local_identity__', legacyIdentity.toMap());
      await Hive.box<Map>(LocalDatabase.messagesBoxName)
          .put('legacy-message', {'plaintext': true});
      await Hive.box<Map>(LocalDatabase.chatMetaBoxName)
          .put('legacy-meta', {'plaintext': true});

      await storageSecurity.ensureCurrentLayout();

      final migrated = await vault.read();
      expect(migrated?.identityId, 'LEGACY');
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
