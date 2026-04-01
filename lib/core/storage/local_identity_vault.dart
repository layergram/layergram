import 'dart:convert';

import '../crypto/models.dart';
import 'secure_storage.dart';

class LocalIdentityVault {
  LocalIdentityVault({required SecureStorageService secureStorage})
      : _secureStorage = secureStorage;

  static const storageKey = 'layergram_local_identity_v2';

  final SecureStorageService _secureStorage;

  Future<LocalIdentity?> read() async {
    final raw = await _secureStorage.read(storageKey);
    if (raw == null || raw.isEmpty) return null;
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return null;
      return LocalIdentity.fromMap(decoded);
    } catch (_) {
      return null;
    }
  }

  Future<void> save(LocalIdentity identity) {
    return _secureStorage.write(storageKey, jsonEncode(identity.toMap()));
  }

  Future<void> clear() {
    return _secureStorage.delete(storageKey);
  }
}
