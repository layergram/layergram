import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/security/app_lock_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:local_auth/local_auth.dart';

const enabledKey = 'app_lock_enabled';
const timeoutSecondsKey = 'app_lock_timeout_sec';
const pinKey = 'app_lock_pin';
const pinKdfVersionKey = 'pin_kdf_version';
const pinKdfParamsKey = 'pin_kdf_params';
const pinSaltKey = 'pin_salt';
const pinHashKey = 'pin_hash';
const pinFailedAttemptsKey = 'pin_failed_attempts';
const pinLockedUntilMsKey = 'pin_locked_until_ms';
const forcePinKey = 'app_lock_force_pin';
const legacyPinKdfVersion = 'pbkdf2_hmac_sha256_210000_v1';
const preferredPinKdfVersion = 'pbkdf2_hmac_sha256_v2';

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
    late DateTime currentTime;

    setUp(() {
      secureStorage = InMemorySecureStorageService();
      localAuth = FakeLocalAuthentication();
      currentTime = DateTime(2026, 1, 1, 12);
      service = AppLockService(
        secureStorage,
        localAuth: localAuth,
        nowProvider: () => currentTime,
      );
    });

    test('persists enabled state, timeout, pin, and force-pin mode', () async {
      expect(await service.isEnabled(), isFalse);
      expect(await service.getTimeoutSeconds(), 60);
      expect(await service.getPin(), isNull);
      expect(await service.hasPin(), isFalse);
      expect(await service.getForcePin(), isFalse);

      await service.setEnabled(true);
      await service.setTimeoutSeconds(120);
      await service.setPin('2468');
      await service.setForcePin(true);

      expect(await service.isEnabled(), isTrue);
      expect(await service.getTimeoutSeconds(), 120);
      expect(await service.getPin(), isNull);
      expect(await service.hasPin(), isTrue);
      expect(await service.getForcePin(), isTrue);
      expect(secureStorage._values[enabledKey], '1');
      expect(secureStorage._values[timeoutSecondsKey], '120');
      expect(secureStorage._values[forcePinKey], '1');
      expect(secureStorage._values.containsKey(pinKey), isFalse);
      expect(secureStorage._values[pinKdfVersionKey], preferredPinKdfVersion);
      expect(secureStorage._values[pinKdfParamsKey], isNotEmpty);
      expect(secureStorage._values[pinSaltKey], isNotEmpty);
      expect(secureStorage._values[pinHashKey], isNotEmpty);
      expect(secureStorage._values[pinHashKey], isNot('2468'));
    });

    test('validates and clears the configured PIN', () async {
      await service.setPin('1357');

      expect(await service.validatePin('1357'), isTrue);
      expect(await service.validatePin('9999'), isFalse);

      await service.clearPin();

      expect(await service.getPin(), isNull);
      expect(await service.hasPin(), isFalse);
      expect(await service.validatePin('1357'), isFalse);
      expect(secureStorage._values.containsKey(pinKey), isFalse);
      expect(secureStorage._values.containsKey(pinKdfVersionKey), isFalse);
      expect(secureStorage._values.containsKey(pinKdfParamsKey), isFalse);
      expect(secureStorage._values.containsKey(pinSaltKey), isFalse);
      expect(secureStorage._values.containsKey(pinHashKey), isFalse);
      expect(secureStorage._values.containsKey(pinFailedAttemptsKey), isFalse);
      expect(secureStorage._values.containsKey(pinLockedUntilMsKey), isFalse);
    });

    test(
        'uses a random salt so the same PIN produces different stored material',
        () async {
      await service.setPin('2468');
      final firstSalt = secureStorage._values[pinSaltKey];
      final firstHash = secureStorage._values[pinHashKey];

      await service.setPin('2468');
      final secondSalt = secureStorage._values[pinSaltKey];
      final secondHash = secureStorage._values[pinHashKey];

      expect(firstSalt, isNotNull);
      expect(firstHash, isNotNull);
      expect(secondSalt, isNotNull);
      expect(secondHash, isNotNull);
      expect(secondSalt, isNot(firstSalt));
      expect(secondHash, isNot(firstHash));
    });

    test(
        'migrates a legacy plaintext PIN to derived storage after successful validation',
        () async {
      await secureStorage.write(pinKey, '8642');

      expect(await service.hasPin(), isTrue);
      expect(await service.validatePin('8642'), isTrue);

      expect(secureStorage._values.containsKey(pinKey), isFalse);
      expect(secureStorage._values[pinKdfVersionKey], preferredPinKdfVersion);
      expect(secureStorage._values[pinKdfParamsKey], isNotEmpty);
      expect(secureStorage._values[pinSaltKey], isNotEmpty);
      expect(secureStorage._values[pinHashKey], isNotEmpty);
      expect(await service.getPin(), isNull);
      expect(await service.validatePin('8642'), isTrue);
      expect(await service.validatePin('1111'), isFalse);
    });

    test('does not migrate a legacy plaintext PIN when validation fails',
        () async {
      await secureStorage.write(pinKey, '8642');

      expect(await service.validatePin('1111'), isFalse);
      expect(secureStorage._values[pinKey], '8642');
      expect(secureStorage._values.containsKey(pinKdfVersionKey), isFalse);
      expect(secureStorage._values.containsKey(pinKdfParamsKey), isFalse);
      expect(secureStorage._values.containsKey(pinSaltKey), isFalse);
      expect(secureStorage._values.containsKey(pinHashKey), isFalse);
    });

    test(
        'rehashes legacy derived PBKDF2 material transparently after successful validation',
        () async {
      await service.setPin('2468');
      final previousSalt = secureStorage._values[pinSaltKey];
      final previousHash = secureStorage._values[pinHashKey];

      await secureStorage.write(pinKdfVersionKey, legacyPinKdfVersion);
      await secureStorage.delete(pinKdfParamsKey);

      expect(await service.validatePin('2468'), isTrue);
      expect(secureStorage._values[pinKdfVersionKey], preferredPinKdfVersion);
      expect(secureStorage._values[pinKdfParamsKey], isNotEmpty);
      expect(secureStorage._values[pinSaltKey], isNot(previousSalt));
      expect(secureStorage._values[pinHashKey], isNot(previousHash));
    });

    test(
      'tracks consecutive failed attempts and applies temporary lockout backoff',
      () async {
        await service.setPin('2468');

        for (var i = 1; i <= 4; i++) {
          expect(await service.validatePin('0000'), isFalse);
          expect(await service.getConsecutiveFailedPinAttempts(), i);
          expect(await service.isPinLockedOut(), isFalse);
        }

        expect(await service.validatePin('0000'), isFalse);
        expect(await service.getConsecutiveFailedPinAttempts(), 5);
        expect(await service.isPinLockedOut(), isTrue);
        expect(
          await service.getPinLockoutRemaining(),
          greaterThan(Duration.zero),
        );

        expect(await service.validatePin('2468'), isFalse);
        expect(await service.getConsecutiveFailedPinAttempts(), 5);

        currentTime = currentTime.add(const Duration(seconds: 6));

        expect(await service.validatePin('2468'), isTrue);
        expect(await service.getConsecutiveFailedPinAttempts(), 0);
        expect(await service.isPinLockedOut(), isFalse);
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );

    test(
      'increases lockout duration when failed attempts continue after expiry',
      () async {
        await service.setPin('2468');

        for (var i = 0; i < 5; i++) {
          expect(await service.validatePin('0000'), isFalse);
        }
        final firstLockout = await service.getPinLockoutRemaining();
        expect(firstLockout, greaterThan(Duration.zero));

        currentTime = currentTime.add(const Duration(seconds: 6));
        expect(await service.validatePin('0000'), isFalse);
        final secondLockout = await service.getPinLockoutRemaining();
        expect(await service.getConsecutiveFailedPinAttempts(), 6);
        expect(secondLockout, greaterThan(firstLockout));
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );

    test('reports biometric support only when both capability checks succeed',
        () async {
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

    test('authenticates biometrics and keeps the compatibility alias aligned',
        () async {
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
