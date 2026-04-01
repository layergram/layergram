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

import 'package:local_auth/local_auth.dart';

import '../storage/secure_storage.dart';

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
  AppLockService(this._storage, {LocalAuthentication? localAuth})
       : _localAuth = localAuth ?? LocalAuthentication();

  static const _enabledKey = 'app_lock_enabled';
  static const _timeoutSecondsKey = 'app_lock_timeout_sec';
  static const _pinKey = 'app_lock_pin';
  static const _forcePinKey = 'app_lock_force_pin';

  final SecureStorageService _storage;
  final LocalAuthentication _localAuth;

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
  Future<void> setPin(String pin) {
    return _storage.write(_pinKey, pin);
  }

  /// Gets the currently stored PIN.
  /// 
  /// Returns the PIN string if set, `null` otherwise.
  Future<String?> getPin() {
    return _storage.read(_pinKey);
  }

  /// Clears the stored PIN.
  Future<void> clearPin() {
    return _storage.delete(_pinKey);
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
    final storedPin = await getPin();
    return storedPin != null && storedPin == pin;
  }
}
