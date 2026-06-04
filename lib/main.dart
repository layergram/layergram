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

import 'package:easy_localization/easy_localization.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app.dart';
import 'core/storage/local_database.dart';
import 'core/storage/local_identity_vault.dart';
import 'core/storage/local_storage_security_service.dart';
import 'core/storage/secure_storage.dart';
import 'l10n/app_strings.dart';
import 'l10n/fs_strings_bundle.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await EasyLocalization.ensureInitialized();
  await LocalDatabase.init();
  final secureStorage = SecureStorageService();
  final localIdentityVault = LocalIdentityVault(secureStorage: secureStorage);
  final localStorageSecurity = LocalStorageSecurityService(
    secureStorage: secureStorage,
    localIdentityVault: localIdentityVault,
  );
  await localStorageSecurity.ensureCurrentLayout();
  AppStrings.registerStrings(FsStringsBundle.bundle);
  runApp(
    EasyLocalization(
      supportedLocales: AppStrings.supportedLocales,
      path: 'assets/translations',
      fallbackLocale: const Locale('en'),
      child: const ProviderScope(child: LayergramApp()),
    ),
  );
}
