import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:hive_flutter/hive_flutter.dart';

import '../crypto/models.dart';
import '../crypto/sealed_map_cipher.dart';
import 'local_database.dart';
import 'local_identity_vault.dart';
import 'secure_storage.dart';

class LocalStorageContext {
  const LocalStorageContext({
    required this.scopeToken,
    required this.contactsKey,
    required this.chatMetaKey,
  });

  final String scopeToken;
  final SecretKey contactsKey;
  final SecretKey chatMetaKey;
}

class LocalStorageSecurityService {
  LocalStorageSecurityService({
    required SecureStorageService secureStorage,
    required LocalIdentityVault localIdentityVault,
  })  : _secureStorage = secureStorage,
        _localIdentityVault = localIdentityVault;

  static const _layoutVersionKey = 'layergram_storage_layout_version';
  static const _layoutVersion = '2';
  static const _dbMasterKeyKey = 'layergram_db_master_key_v2';

  final SecureStorageService _secureStorage;
  final LocalIdentityVault _localIdentityVault;

  Future<void> ensureCurrentLayout() async {
    final current = await _secureStorage.read(_layoutVersionKey);
    if (current == _layoutVersion) {
      await _ensureMasterKeyBytes();
      return;
    }

    final existingLocal = await _localIdentityVault.read();
    if (existingLocal == null) {
      final legacyRaw =
          Hive.box<Map>(LocalDatabase.identitiesBoxName).get('__local_identity__');
      if (legacyRaw != null) {
        try {
          await _localIdentityVault.save(LocalIdentity.fromMap(legacyRaw));
        } catch (_) {}
      }
    }

    await LocalDatabase.clearAll();
    await _secureStorage.write(_layoutVersionKey, _layoutVersion);
    await _ensureMasterKeyBytes();
  }

  Future<LocalStorageContext?> contextForIdentity(String identityId) async {
    if (identityId.isEmpty) return null;
    final masterKey = await _ensureMasterKeyBytes();
    return LocalStorageContext(
      scopeToken: _scopeToken(masterKey, identityId),
      contactsKey: await SealedMapCipher.deriveKey(
        masterKey,
        scope: identityId,
        info: 'layergram-contacts-v1',
      ),
      chatMetaKey: await SealedMapCipher.deriveKey(
        masterKey,
        scope: identityId,
        info: 'layergram-chat-meta-v1',
      ),
    );
  }

  Future<Uint8List> _ensureMasterKeyBytes() async {
    final stored = await _secureStorage.read(_dbMasterKeyKey);
    if (stored != null && stored.isNotEmpty) {
      return Uint8List.fromList(base64Url.decode(_padBase64(stored)));
    }

    final bytes = Uint8List.fromList(
      List<int>.generate(32, (_) => Random.secure().nextInt(256)),
    );
    await _secureStorage.write(
      _dbMasterKeyKey,
      base64Url.encode(bytes).replaceAll('=', ''),
    );
    return bytes;
  }

  String _scopeToken(Uint8List masterKey, String identityId) {
    final mac = crypto.Hmac(crypto.sha256, masterKey)
        .convert(utf8.encode('scope|$identityId'));
    return base64Url.encode(mac.bytes.sublist(0, 12)).replaceAll('=', '');
  }

  String _padBase64(String input) {
    final rem = input.length % 4;
    if (rem == 0) return input;
    return input.padRight(input.length + (4 - rem), '=');
  }
}
