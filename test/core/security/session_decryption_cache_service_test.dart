import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/security/session_decryption_cache_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';

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
  group('SessionDecryptionCacheService', () {
    late _InMemorySecureStorageService storage;
    late SessionDecryptionCacheService service;

    setUp(() {
      storage = _InMemorySecureStorageService();
      service = SessionDecryptionCacheService(storage);
    });

    test('defaults to disabled', () async {
      expect(await service.isEnabled(), isFalse);
    });

    test('persists enabled state', () async {
      await service.setEnabled(true);
      expect(await service.isEnabled(), isTrue);

      await service.setEnabled(false);
      expect(await service.isEnabled(), isFalse);
    });
  });
}
