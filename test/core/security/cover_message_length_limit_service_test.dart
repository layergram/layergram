import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/security/cover_message_length_limit_service.dart';
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
  group('CoverMessageLengthLimitService', () {
    late _InMemorySecureStorageService storage;
    late CoverMessageLengthLimitService service;

    setUp(() {
      storage = _InMemorySecureStorageService();
      service = CoverMessageLengthLimitService(storage);
    });

    test('defaults to 4000 characters', () async {
      expect(
        await service.getLimit(),
        equals(CoverMessageLengthLimitService.defaultLimit),
      );
    });

    test('persists explicit numeric limits', () async {
      await service.setLimit(2000);
      expect(await service.getLimit(), equals(2000));

      await service.setLimit(1000);
      expect(await service.getLimit(), equals(1000));
    });

    test('persists no limit selection', () async {
      await service.setLimit(null);
      expect(await service.getLimit(), isNull);
    });
  });
}
