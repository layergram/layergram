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

import 'package:flutter/services.dart';

import '../storage/secure_storage.dart';

class ScreenProtectionService {
  ScreenProtectionService(this._storage, {MethodChannel? channel})
      : _channel = channel ?? const MethodChannel(_channelName);

  static const String _enabledKey = 'screen_protection_enabled';
  static const String _channelName = 'layergram/screen_protection';

  final SecureStorageService _storage;
  final MethodChannel _channel;

  Future<bool> isEnabled() async {
    try {
      final raw = await _storage.read(_enabledKey);
      if (raw == null) return true; // default ON
      if (raw == '1') return true;
      if (raw == '0') return false;
      return raw.toLowerCase() == 'true';
    } catch (_) {
      return true;
    }
  }

  Future<void> setEnabled(bool enabled) async {
    try {
      await _storage.write(_enabledKey, enabled ? '1' : '0');
    } catch (_) {
      // Ignore persistence errors (platform support differences).
    }
    await applyToPlatform(enabled);
  }

  Future<void> syncFromStorageToPlatform() async {
    final enabled = await isEnabled();
    await applyToPlatform(enabled);
  }

  Future<void> applyToPlatform(bool enabled) async {
    try {
      await _channel.invokeMethod('setEnabled', enabled);
    } on MissingPluginException {
      // Platform not wired (e.g. web) - ignore.
    } catch (_) {
      // Best-effort.
    }
  }

  Future<bool> isSupported() async {
    try {
      final supported = await _channel.invokeMethod<bool>('isSupported');
      return supported ?? false;
    } on MissingPluginException {
      return false;
    } catch (_) {
      return false;
    }
  }
}
