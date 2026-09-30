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

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureStorageService {
  SecureStorageService()
      : _storage = const FlutterSecureStorage(iOptions: _iosAppStorage);

  // The default application Keychain access group, with a non-null service.
  // Do not widen fresh-install cleanup to shared keyboard/App Group services.
  static const _iosAppStorage = IOSOptions(
    accountName: AppleOptions.defaultAccountName,
  );

  final FlutterSecureStorage _storage;

  Future<void> write(String key, String value) {
    return _storage.write(key: key, value: value);
  }

  Future<String?> read(String key) {
    return _storage.read(key: key);
  }

  Future<void> delete(String key) {
    return _storage.delete(key: key);
  }

  Future<void> deleteAll() {
    return _storage.deleteAll();
  }

  Future<void> resetForFreshIosInstallation() async {
    await _storage.deleteAll(iOptions: _iosAppStorage);
    if ((await _storage.readAll(iOptions: _iosAppStorage)).isNotEmpty) {
      throw StateError('Fresh iOS app storage reset was not completed');
    }
  }
}
