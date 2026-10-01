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

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/test/test_flutter_secure_storage_platform.dart';
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/storage/ios_installation_boundary.dart';
import 'package:layergram/core/storage/secure_storage.dart';

class _ScopedStorage extends TestFlutterSecureStoragePlatform {
  _ScopedStorage(super.data);

  final calls = <Map<String, String>>[];
  bool retainOneItem = false;

  @override
  Future<void> deleteAll({required Map<String, String> options}) async {
    calls.add(Map.of(options));
    if (!retainOneItem) await super.deleteAll(options: options);
  }

  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async {
    calls.add(Map.of(options));
    return super.readAll(options: options);
  }
}

void main() {
  late Directory documents;
  late _ScopedStorage platform;
  late FlutterSecureStoragePlatform previousPlatform;
  late SecureStorageService storage;

  setUp(() async {
    documents = await Directory.systemTemp.createTemp('ios_installation_test_');
    previousPlatform = FlutterSecureStoragePlatform.instance;
    platform = _ScopedStorage({'identity': 'retained-disposable-identity'});
    FlutterSecureStoragePlatform.instance = platform;
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    storage = SecureStorageService();
  });

  tearDown(() async {
    debugDefaultTargetPlatformOverride = null;
    FlutterSecureStoragePlatform.instance = previousPlatform;
    await documents.delete(recursive: true);
  });

  IosInstallationBoundary boundary({Future<void> Function()? reset}) =>
      IosInstallationBoundary(
        documents: documents,
        resetAppSecureStorage: reset ?? storage.resetForFreshIosInstallation,
      );

  File witness() =>
      File('${documents.path}/${IosInstallationBoundary.markerFileName}');

  test('fresh container cannot automatically restore a retained identity',
      () async {
    await boundary().prepare();
    expect(await storage.read('identity'), isNull);
    expect(await witness().readAsString(), '1\n');
    expect(platform.calls, hasLength(2));
    for (final options in platform.calls) {
      expect(options['accountName'], 'flutter_secure_storage_service');
      expect(options.containsKey('groupId'), isFalse);
      expect(options['synchronizable'], 'false');
    }
  });

  test('ordinary relaunch preserves the identity and new local data', () async {
    await boundary().prepare();
    await storage.write('identity', 'new-explicit-identity');
    final data = File('${documents.path}/layergram_messages.hive');
    await data.writeAsString('existing-encrypted-record');
    platform.calls.clear();

    await boundary().prepare();

    expect(await storage.read('identity'), 'new-explicit-identity');
    expect(await data.readAsString(), 'existing-encrypted-record');
    expect(platform.calls, isEmpty);
  });

  for (final box in [
    'layergram_identities',
    'layergram_messages',
    'layergram_chat_meta',
  ]) {
    for (final suffix in ['hive', 'hivec', 'lock']) {
      test('upgrade with $box.$suffix preserves identity and local data',
          () async {
        final legacy = File('${documents.path}/$box.$suffix');
        await legacy.writeAsString('legacy-installation-data');

        await boundary().prepare();

        expect(await storage.read('identity'), 'retained-disposable-identity');
        expect(await legacy.readAsString(), 'legacy-installation-data');
        expect(platform.calls, isEmpty);
        expect(await witness().exists(), isTrue);
      });
    }
  }

  test('complete reinstall removes witness and does not read retained identity',
      () async {
    await boundary().prepare();
    await storage.write('identity', 'deliberately-created-identity');
    await documents.delete(recursive: true);

    await boundary().prepare();

    expect(await storage.read('identity'), isNull);
    expect(await witness().exists(), isTrue);
  });

  test('incomplete Keychain cleanup fails closed and retries next launch',
      () async {
    platform.retainOneItem = true;
    await expectLater(boundary().prepare(), throwsStateError);
    expect(await witness().exists(), isFalse);
    expect(await storage.read('identity'), 'retained-disposable-identity');

    platform.retainOneItem = false;
    await boundary().prepare();
    expect(await storage.read('identity'), isNull);
    expect(await witness().exists(), isTrue);
  });

  test('reset error cannot commit a witness or continue startup', () async {
    await expectLater(
      boundary(reset: () async => throw StateError('locked storage')).prepare(),
      throwsStateError,
    );
    expect(await witness().exists(), isFalse);
    expect(await storage.read('identity'), 'retained-disposable-identity');
  });

  test('invalid or unreadable witness never triggers destructive cleanup',
      () async {
    await witness().writeAsString('invalid');
    await expectLater(boundary().prepare(), throwsStateError);
    expect(platform.calls, isEmpty);

    await witness().delete();
    await Directory(witness().path).create();
    await expectLater(boundary().prepare(), throwsStateError);
    expect(platform.calls, isEmpty);
  });

  test('marker write failure preserves a legacy installation on retry',
      () async {
    final data = File('${documents.path}/layergram_messages.hive');
    await data.writeAsString('existing-record');
    final pending = Directory('${witness().path}.pending');
    await pending.create();
    await expectLater(
      boundary().prepare(),
      throwsA(isA<FileSystemException>()),
    );
    expect(await witness().exists(), isFalse);
    expect(await storage.read('identity'), 'retained-disposable-identity');
    await pending.delete();
    await boundary().prepare();
    expect(await data.readAsString(), 'existing-record');
    expect(platform.calls, isEmpty);
  });

  test('container I/O failure cannot be classified as a fresh install',
      () async {
    await documents.delete(recursive: true);
    await File(documents.path).writeAsString('not-a-directory');
    await expectLater(
      boundary().prepare(),
      throwsA(isA<FileSystemException>()),
    );
    expect(platform.calls, isEmpty);
    expect(await storage.read('identity'), 'retained-disposable-identity');
    await File(documents.path).delete();
    await documents.create();
  });

  test('a symbolic witness cannot bypass validation or expose another file',
      () async {
    final unrelated = File('${documents.path}/unrelated');
    await unrelated.writeAsString('1\n');
    await Link(witness().path).create(unrelated.path);
    await expectLater(boundary().prepare(), throwsStateError);
    expect(platform.calls, isEmpty);
    expect(await unrelated.readAsString(), '1\n');
  });
}
