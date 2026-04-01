import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/security/app_lock_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:local_auth/local_auth.dart';

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

class FakeLocalAuthentication extends LocalAuthentication {
  FakeLocalAuthentication({
    this.canCheck = true,
    this.deviceSupported = true,
    this.availableBiometricTypes = const <BiometricType>[
      BiometricType.fingerprint,
    ],
    this.authenticateResult = true,
    this.throwOnCapabilityCheck = false,
    this.throwOnBiometricList = false,
    this.throwOnAuthenticate = false,
  });

  final bool canCheck;
  final bool deviceSupported;
  final List<BiometricType> availableBiometricTypes;
  final bool authenticateResult;
  final bool throwOnCapabilityCheck;
  final bool throwOnBiometricList;
  final bool throwOnAuthenticate;

  String? lastLocalizedReason;

  @override
  Future<bool> get canCheckBiometrics async {
    if (throwOnCapabilityCheck) {
      throw Exception('biometric capability failure');
    }
    return canCheck;
  }

  @override
  Future<bool> isDeviceSupported() async {
    if (throwOnCapabilityCheck) {
      throw Exception('device support failure');
    }
    return deviceSupported;
  }

  @override
  Future<List<BiometricType>> getAvailableBiometrics() async {
    if (throwOnBiometricList) {
      throw Exception('biometric list failure');
    }
    return availableBiometricTypes;
  }

  @override
  Future<bool> authenticate({
    required String localizedReason,
    Iterable<dynamic> authMessages = const <Object>[],
    AuthenticationOptions options = const AuthenticationOptions(),
  }) async {
    lastLocalizedReason = localizedReason;
    if (throwOnAuthenticate) {
      throw Exception('authentication failure');
    }
    return authenticateResult;
  }
}

void main() {
  group('AppLockService', () {
    late InMemorySecureStorageService secureStorage;
    late FakeLocalAuthentication localAuth;
    late AppLockService service;

    setUp(() {
      secureStorage = InMemorySecureStorageService();
      localAuth = FakeLocalAuthentication();
      service = AppLockService(secureStorage, localAuth: localAuth);
    });

    test('persists enabled state, timeout, pin, and force-pin mode', () async {
      expect(await service.isEnabled(), isFalse);
      expect(await service.getTimeoutSeconds(), 60);
      expect(await service.getPin(), isNull);
      expect(await service.getForcePin(), isFalse);

      await service.setEnabled(true);
      await service.setTimeoutSeconds(120);
      await service.setPin('2468');
      await service.setForcePin(true);

      expect(await service.isEnabled(), isTrue);
      expect(await service.getTimeoutSeconds(), 120);
      expect(await service.getPin(), '2468');
      expect(await service.getForcePin(), isTrue);
    });

    test('validates and clears the configured PIN', () async {
      await service.setPin('1357');

      expect(await service.validatePin('1357'), isTrue);
      expect(await service.validatePin('9999'), isFalse);

      await service.clearPin();

      expect(await service.getPin(), isNull);
      expect(await service.validatePin('1357'), isFalse);
    });

    test('reports biometric support only when both capability checks succeed', () async {
      expect(await service.isBiometricSupported(), isTrue);
      expect(
        await service.availableBiometrics(),
        equals(<BiometricType>[BiometricType.fingerprint]),
      );

      service = AppLockService(
        secureStorage,
        localAuth: FakeLocalAuthentication(
          canCheck: false,
          deviceSupported: true,
        ),
      );
      expect(await service.isBiometricSupported(), isFalse);

      service = AppLockService(
        secureStorage,
        localAuth: FakeLocalAuthentication(
          throwOnCapabilityCheck: true,
          throwOnBiometricList: true,
        ),
      );
      expect(await service.isBiometricSupported(), isFalse);
      expect(await service.availableBiometrics(), isEmpty);
    });

    test('authenticates biometrics and keeps the compatibility alias aligned', () async {
      expect(
        await service.authenticateBiometric(reason: 'Unlock Layergram'),
        isTrue,
      );
      expect(localAuth.lastLocalizedReason, 'Unlock Layergram');
      expect(
        await service.authenticate(reason: 'Unlock via alias'),
        isTrue,
      );
      expect(localAuth.lastLocalizedReason, 'Unlock via alias');

      service = AppLockService(
        secureStorage,
        localAuth: FakeLocalAuthentication(
          canCheck: false,
          deviceSupported: false,
        ),
      );
      expect(
        await service.authenticateBiometric(reason: 'Unavailable biometrics'),
        isFalse,
      );

      service = AppLockService(
        secureStorage,
        localAuth: FakeLocalAuthentication(
          throwOnAuthenticate: true,
        ),
      );
      expect(
        await service.authenticateBiometric(reason: 'Throwing auth'),
        isFalse,
      );
    });
  });
}
