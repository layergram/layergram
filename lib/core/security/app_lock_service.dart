// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:local_auth/local_auth.dart';

import '../storage/secure_storage.dart';

class _PinKdfDescriptor {
  const _PinKdfDescriptor({
    required this.version,
    required this.algorithm,
    required this.params,
    this.needsRehash = false,
  });

  final String version;
  final String algorithm;
  final Map<String, Object> params;
  final bool needsRehash;
}

class _StoredDerivedPin {
  const _StoredDerivedPin({
    required this.descriptor,
    required this.salt,
    required this.hash,
  });

  final _PinKdfDescriptor descriptor;
  final Uint8List salt;
  final Uint8List hash;
}

/// Service for managing app lock functionality including PIN and biometric authentication.
/// 
/// This service provides secure storage and retrieval of app lock settings,
/// PIN management, timeout configuration, and biometric authentication.
/// It uses the device's local authentication framework for biometric support
/// and secure storage for PIN data.
class AppLockService {
  /// Creates an [AppLockService] instance.
  /// 
  /// [storage] - The secure storage service for persisting app lock data
  /// [localAuth] - Optional local authentication instance, defaults to LocalAuthentication()
  AppLockService(
    this._storage, {
    LocalAuthentication? localAuth,
    Random? random,
    DateTime Function()? nowProvider,
  })  : _localAuth = localAuth ?? LocalAuthentication(),
        _random = random ?? Random.secure(),
        _now = nowProvider ?? DateTime.now;

  static const _enabledKey = 'app_lock_enabled';
  static const _timeoutSecondsKey = 'app_lock_timeout_sec';
  static const _pinKey = 'app_lock_pin';
  static const _pinKdfVersionKey = 'pin_kdf_version';
  static const _pinKdfParamsKey = 'pin_kdf_params';
  static const _pinSaltKey = 'pin_salt';
  static const _pinHashKey = 'pin_hash';
  static const _pinFailedAttemptsKey = 'pin_failed_attempts';
  static const _pinLockedUntilMsKey = 'pin_locked_until_ms';
  static const _forcePinKey = 'app_lock_force_pin';
  static const _pbkdf2Sha256Algorithm = 'pbkdf2-hmac-sha256';
  static const _legacyPinKdfVersion = 'pbkdf2_hmac_sha256_210000_v1';
  static const _preferredPinKdfVersion = 'pbkdf2_hmac_sha256_v2';
  static const _pinHashBits = 256;
  static const _pinSaltLength = 16;
  static const _pinIterations = 210000;
  static const _pinBackoffThreshold = 5;
  static const _initialBackoffSeconds = 5;
  static const _maxBackoffSeconds = 300;

  static const _preferredPinKdfDescriptor = _PinKdfDescriptor(
    version: _preferredPinKdfVersion,
    algorithm: _pbkdf2Sha256Algorithm,
    params: {
      'iterations': _pinIterations,
      'hash_bits': _pinHashBits,
      'salt_length': _pinSaltLength,
    },
  );

  static const _legacyPinKdfDescriptor = _PinKdfDescriptor(
    version: _legacyPinKdfVersion,
    algorithm: _pbkdf2Sha256Algorithm,
    params: {
      'iterations': _pinIterations,
      'hash_bits': _pinHashBits,
      'salt_length': _pinSaltLength,
    },
    needsRehash: true,
  );

  final SecureStorageService _storage;
  final LocalAuthentication _localAuth;
  final Random _random;
  final DateTime Function() _now;

  /// Checks if app lock is currently enabled.
  /// 
  /// Returns `true` if app lock is enabled, `false` otherwise.
  Future<bool> isEnabled() async {
    return (await _storage.read(_enabledKey)) == '1';
  }

  /// Enables or disables app lock.
  /// 
  /// [enabled] - `true` to enable app lock, `false` to disable
  Future<void> setEnabled(bool enabled) {
    return _storage.write(_enabledKey, enabled ? '1' : '0');
  }

  /// Gets the current app lock timeout in seconds.
  /// 
  /// Returns the timeout duration in seconds, defaults to 60 seconds if not set.
  Future<int> getTimeoutSeconds() async {
    final raw = await _storage.read(_timeoutSecondsKey);
    return int.tryParse(raw ?? '') ?? 60; // default 60s
  }

  /// Sets the app lock timeout duration.
  /// 
  /// [seconds] - Timeout duration in seconds (0 for immediate lock)
  Future<void> setTimeoutSeconds(int seconds) {
    return _storage.write(_timeoutSecondsKey, seconds.toString());
  }

  /// Sets the PIN for app lock.
  /// 
  /// [pin] - The PIN to set (4-8 digits recommended)
  Future<void> setPin(String pin) async {
    await _storeDerivedPin(pin, _preferredPinKdfDescriptor);
    await _clearPinRateLimit();
  }

  /// Gets the currently stored PIN.
  /// 
  /// Returns the PIN string if set, `null` otherwise.
  Future<String?> getPin() async {
    return _storage.read(_pinKey);
  }

  Future<bool> hasPin() async {
    final version = await _storage.read(_pinKdfVersionKey);
    final salt = await _storage.read(_pinSaltKey);
    final hash = await _storage.read(_pinHashKey);
    if (version != null && salt != null && hash != null) {
      return true;
    }
    final legacyPin = await _storage.read(_pinKey);
    return legacyPin != null && legacyPin.isNotEmpty;
  }

  /// Clears the stored PIN.
  Future<void> clearPin() async {
    await _storage.delete(_pinKey);
    await _storage.delete(_pinKdfVersionKey);
    await _storage.delete(_pinKdfParamsKey);
    await _storage.delete(_pinSaltKey);
    await _storage.delete(_pinHashKey);
    await _clearPinRateLimit();
  }

  Future<int> getConsecutiveFailedPinAttempts() async {
    final raw = await _storage.read(_pinFailedAttemptsKey);
    return int.tryParse(raw ?? '') ?? 0;
  }

  Future<Duration> getPinLockoutRemaining() async {
    final raw = await _storage.read(_pinLockedUntilMsKey);
    final lockedUntilMs = int.tryParse(raw ?? '');
    if (lockedUntilMs == null) {
      return Duration.zero;
    }
    final remaining =
        DateTime.fromMillisecondsSinceEpoch(lockedUntilMs).difference(_now());
    if (remaining <= Duration.zero) {
      await _storage.delete(_pinLockedUntilMsKey);
      return Duration.zero;
    }
    return remaining;
  }

  Future<bool> isPinLockedOut() async {
    return (await getPinLockoutRemaining()) > Duration.zero;
  }

  /// Checks if the device supports biometric authentication.
  /// 
  /// Returns `true` if biometric authentication is available, `false` otherwise.
  /// Handles exceptions gracefully and returns `false` on errors.
  Future<bool> isBiometricSupported() async {
    try {
      final canCheck = await _localAuth.canCheckBiometrics;
      final isSupported = await _localAuth.isDeviceSupported();
      return canCheck && isSupported;
    } catch (_) {
      return false;
    }
  }

  /// Gets the list of available biometric types on the device.
  /// 
  /// Returns a list of supported biometric types (fingerprint, face, etc.).
  /// Returns an empty list if biometrics are not supported or an error occurs.
  Future<List<BiometricType>> availableBiometrics() {
    return _localAuth.getAvailableBiometrics().catchError((_) {
      return <BiometricType>[];
    });
  }

  /// Performs biometric authentication with a localized reason.
  /// 
  /// [reason] - The reason displayed to the user for authentication
  /// Returns `true` if authentication succeeds, `false` otherwise.
  /// Returns `false` immediately if biometrics are not supported.
  Future<bool> authenticateBiometric({required String reason}) async {
    if (!await isBiometricSupported()) return false;
    try {
      return await _localAuth.authenticate(
        localizedReason: reason,
      );
    } catch (_) {
      return false;
    }
  }

  /// Backwards-compatible alias for [authenticateBiometric].
  /// 
  /// [reason] - The reason displayed to the user for authentication
  /// @deprecated Use [authenticateBiometric] instead
  Future<bool> authenticate({required String reason}) {
    return authenticateBiometric(reason: reason);
  }

  /// Sets whether to force PIN authentication (disable biometrics).
  /// 
  /// [enabled] - `true` to force PIN only, `false` to allow biometrics
  Future<void> setForcePin(bool enabled) {
    return _storage.write(_forcePinKey, enabled ? '1' : '0');
  }

  /// Gets whether PIN authentication is forced (biometrics disabled).
  /// 
  /// Returns `true` if PIN-only mode is enabled, `false` otherwise.
  Future<bool> getForcePin() async {
    return (await _storage.read(_forcePinKey)) == '1';
  }

  /// Validates a PIN against the stored PIN.
  /// 
  /// [pin] - The PIN to validate
  /// Returns `true` if the PIN matches, `false` otherwise.
  /// Returns `false` if no PIN is set.
  Future<bool> validatePin(String pin) async {
    if (await isPinLockedOut()) {
      return false;
    }

    final storedDerivedPin = await _readStoredDerivedPin();
    if (storedDerivedPin != null) {
      final derivedHash = await _derivePinHash(
        pin,
        storedDerivedPin.salt,
        storedDerivedPin.descriptor,
      );
      if (derivedHash == null) {
        await _recordFailedPinAttempt();
        return false;
      }
      if (_constantTimeEquals(storedDerivedPin.hash, derivedHash)) {
        await _clearPinRateLimit();
        if (storedDerivedPin.descriptor.needsRehash) {
          await _storeDerivedPin(pin, _preferredPinKdfDescriptor);
        }
        return true;
      }
      await _recordFailedPinAttempt();
      return false;
    }

    final storedPin = await _storage.read(_pinKey);
    if (storedPin == null || storedPin.isEmpty) {
      return false;
    }
    if (storedPin != pin) {
      await _recordFailedPinAttempt();
      return false;
    }

    await _clearPinRateLimit();
    await _storeDerivedPin(pin, _preferredPinKdfDescriptor);
    return true;
  }

  Future<void> _storeDerivedPin(
    String pin,
    _PinKdfDescriptor descriptor,
  ) async {
    final salt = _randomBytes(_saltLengthFor(descriptor));
    final hash = await _derivePinHash(pin, salt, descriptor);
    if (hash == null) {
      throw UnsupportedError('Unsupported PIN KDF algorithm: ${descriptor.algorithm}');
    }
    await _storage.write(_pinKdfVersionKey, descriptor.version);
    await _storage.write(_pinKdfParamsKey, jsonEncode(_encodeKdfParams(descriptor)));
    await _storage.write(_pinSaltKey, base64Encode(salt));
    await _storage.write(_pinHashKey, base64Encode(hash));
    await _storage.delete(_pinKey);
  }

  Future<_StoredDerivedPin?> _readStoredDerivedPin() async {
    final version = await _storage.read(_pinKdfVersionKey);
    final saltValue = await _storage.read(_pinSaltKey);
    final hashValue = await _storage.read(_pinHashKey);
    if (version == null || saltValue == null || hashValue == null) {
      return null;
    }
    final descriptor = await _readStoredDescriptor(version);
    final salt = _decodeBase64(saltValue);
    final hash = _decodeBase64(hashValue);
    if (descriptor == null || salt == null || hash == null) {
      return null;
    }
    return _StoredDerivedPin(descriptor: descriptor, salt: salt, hash: hash);
  }

  Future<_PinKdfDescriptor?> _readStoredDescriptor(String version) async {
    final paramsValue = await _storage.read(_pinKdfParamsKey);
    return _descriptorFromStored(version, paramsValue);
  }

  _PinKdfDescriptor? _descriptorFromStored(String version, String? paramsValue) {
    final params = _decodeKdfParams(paramsValue);
    if (params != null) {
      final algorithm = params['algorithm'];
      if (algorithm is! String) {
        return null;
      }
      final normalizedParams = <String, Object>{};
      for (final entry in params.entries) {
        if (entry.key == 'algorithm') {
          continue;
        }
        final value = entry.value;
        if (value is String) {
          normalizedParams[entry.key] = value;
          continue;
        }
        if (value is bool) {
          normalizedParams[entry.key] = value;
          continue;
        }
        if (value is num) {
          normalizedParams[entry.key] = value.toInt();
        }
      }
      return _PinKdfDescriptor(
        version: version,
        algorithm: algorithm,
        params: normalizedParams,
        needsRehash: !_sameDescriptor(
          version,
          algorithm,
          normalizedParams,
          _preferredPinKdfDescriptor,
        ),
      );
    }
    switch (version) {
      case _legacyPinKdfVersion:
        return _legacyPinKdfDescriptor;
      case _preferredPinKdfVersion:
        return const _PinKdfDescriptor(
          version: _preferredPinKdfVersion,
          algorithm: _pbkdf2Sha256Algorithm,
          params: {
            'iterations': _pinIterations,
            'hash_bits': _pinHashBits,
            'salt_length': _pinSaltLength,
          },
          needsRehash: true,
        );
      default:
        return null;
    }
  }

  Map<String, Object> _encodeKdfParams(_PinKdfDescriptor descriptor) {
    return <String, Object>{
      'algorithm': descriptor.algorithm,
      ...descriptor.params,
    };
  }

  Map<String, Object?>? _decodeKdfParams(String? value) {
    if (value == null || value.isEmpty) {
      return null;
    }
    try {
      final decoded = jsonDecode(value);
      if (decoded is! Map) {
        return null;
      }
      return decoded.map(
        (key, value) => MapEntry(key.toString(), value),
      );
    } catch (_) {
      return null;
    }
  }

  bool _sameDescriptor(
    String version,
    String algorithm,
    Map<String, Object> params,
    _PinKdfDescriptor other,
  ) {
    if (version != other.version || algorithm != other.algorithm) {
      return false;
    }
    if (params.length != other.params.length) {
      return false;
    }
    for (final entry in params.entries) {
      if (other.params[entry.key] != entry.value) {
        return false;
      }
    }
    return true;
  }

  Future<void> _recordFailedPinAttempt() async {
    final attempts = await getConsecutiveFailedPinAttempts() + 1;
    await _storage.write(_pinFailedAttemptsKey, attempts.toString());
    final backoff = _lockoutDurationForAttempts(attempts);
    if (backoff > Duration.zero) {
      final lockedUntil = _now().add(backoff).millisecondsSinceEpoch;
      await _storage.write(_pinLockedUntilMsKey, lockedUntil.toString());
    }
  }

  Future<void> _clearPinRateLimit() async {
    await _storage.delete(_pinFailedAttemptsKey);
    await _storage.delete(_pinLockedUntilMsKey);
  }

  Duration _lockoutDurationForAttempts(int attempts) {
    if (attempts < _pinBackoffThreshold) {
      return Duration.zero;
    }
    final exponent = attempts - _pinBackoffThreshold;
    final seconds = min(
      _maxBackoffSeconds,
      _initialBackoffSeconds * (1 << exponent.clamp(0, 16)),
    );
    return Duration(seconds: seconds);
  }

  Uint8List _randomBytes(int length) {
    return Uint8List.fromList(
      List<int>.generate(length, (_) => _random.nextInt(256)),
    );
  }

  int _saltLengthFor(_PinKdfDescriptor descriptor) {
    final value = descriptor.params['salt_length'];
    return value is int ? value : _pinSaltLength;
  }

  Future<Uint8List?> _derivePinHash(
    String pin,
    List<int> salt,
    _PinKdfDescriptor descriptor,
  ) async {
    if (descriptor.algorithm != _pbkdf2Sha256Algorithm) {
      return null;
    }
    final iterationsValue = descriptor.params['iterations'];
    final hashBitsValue = descriptor.params['hash_bits'];
    if (iterationsValue is! int || hashBitsValue is! int) {
      return null;
    }
    final algorithm = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: iterationsValue,
      bits: hashBitsValue,
    );
    final secretKey = await algorithm.deriveKey(
      secretKey: SecretKey(utf8.encode(pin)),
      nonce: salt,
    );
    return Uint8List.fromList(await secretKey.extractBytes());
  }

  Uint8List? _decodeBase64(String value) {
    try {
      return Uint8List.fromList(base64Decode(value));
    } catch (_) {
      return null;
    }
  }

  bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) {
      return false;
    }
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
