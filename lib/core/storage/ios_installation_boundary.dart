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

import 'dart:io';

import 'package:path_provider/path_provider.dart';

import '../../utils/app_platform.dart';
import 'local_database.dart';
import 'secure_storage.dart';

/// Distinguishes a complete iOS reinstall from an in-place app update.
///
/// The witness lives in the app container, not the Keychain or an App Group.
/// Existing database files preserve installations upgrading from older builds.
/// This must run before Hive creates any files or the identity vault is read.
class IosInstallationBoundary {
  IosInstallationBoundary({
    required Directory documents,
    required Future<void> Function() resetAppSecureStorage,
  })  : _documents = documents,
        _resetAppSecureStorage = resetAppSecureStorage;

  static const markerFileName = '.layergram_installation_v1';
  static const _markerContents = '1\n';

  final Directory _documents;
  final Future<void> Function() _resetAppSecureStorage;

  static Future<void> prepareForCurrentPlatform(
    SecureStorageService secureStorage,
  ) async {
    if (!AppPlatform.isIOS) return;
    await IosInstallationBoundary(
      documents: await getApplicationDocumentsDirectory(),
      resetAppSecureStorage: secureStorage.resetForFreshIosInstallation,
    ).prepare();
  }

  Future<void> prepare() async {
    await _documents.create(recursive: true);
    // Listing propagates filesystem errors. An unreadable container must never
    // be mistaken for an empty, freshly installed one.
    final entries = await _documents.list(followLinks: false).toList();
    final names = <String, FileSystemEntity>{
      for (final entry in entries)
        entry.path.split(Platform.pathSeparator).last: entry,
    };
    final witness = names[markerFileName];
    if (witness != null) {
      if (witness is! File || await witness.readAsString() != _markerContents) {
        throw StateError('Invalid iOS installation witness');
      }
      return;
    }

    final hasLegacyDatabase = <String>[
      LocalDatabase.identitiesBoxName,
      LocalDatabase.messagesBoxName,
      LocalDatabase.chatMetaBoxName,
    ].any((box) => <String>['hive', 'hivec', 'lock']
        .any((extension) => names.containsKey('$box.$extension')));
    if (!hasLegacyDatabase) {
      await _resetAppSecureStorage();
    }

    // Commit only after reset succeeds. A failed/partial reset is retried on
    // the next launch, before any vault read or database initialization.
    final pending = File('${_documents.path}/$markerFileName.pending');
    await pending.writeAsString(_markerContents, flush: true);
    await pending.rename('${_documents.path}/$markerFileName');
  }
}
