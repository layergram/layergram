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
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/crypto/fs_startup_restore.dart';
import 'package:layergram/core/crypto/identity_manager.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/local_database.dart';
import 'package:layergram/core/storage/local_identity_vault.dart';
import 'package:layergram/core/storage/secure_storage.dart';

void main() {
  late Directory tmpDir;
  late Box<Map> box;

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_fs_startup_');
    Hive.init(tmpDir.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    box = Hive.box<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await tmpDir.delete(recursive: true);
  });

  setUp(() async {
    await box.clear();
  });

  test('startup restore rebuilds security mode index with FS state and ratchet',
      () async {
    const contactId = 'alice-device';
    const sessionId = 'strict-session-after-restart';
    const identityContext = 'primary';
    final identityManager = IdentityManager(
      seedService: SeedService(),
      localIdentityVault: LocalIdentityVault(
        secureStorage: _InMemorySecureStorageService(),
      ),
    );
    await identityManager.restoreIdentityFromMnemonic(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      displayName: 'Test identity',
    );

    final firstRun = ProviderContainer(
      overrides: [
        identityManagerProvider.overrideWithValue(identityManager),
      ],
    );
    addTearDown(firstRun.dispose);
    await restorePersistedFsRuntimeState(firstRun.read);

    await firstRun.read(fsSecurityModeServiceProvider).setMode(
          contactId: contactId,
          identityContext: identityContext,
          mode: FsSecurityMode.strict,
        );

    final fsState = const FsContactSecurityState(
      contactId: contactId,
      identityContext: identityContext,
      sessionId: sessionId,
      fsState: FsSessionState.strictFsActive,
    );
    firstRun.read(fsContactSecurityRegistryProvider).upsert(fsState);
    await firstRun.read(fsStatePersistenceServiceProvider).saveState(fsState);

    final ratchet = _ratchet(sessionId);
    await firstRun
        .read(fsRatchetPersistenceServiceProvider)
        .saveRatchetState(ratchet);

    final secondRun = ProviderContainer(
      overrides: [
        identityManagerProvider.overrideWithValue(identityManager),
      ],
    );
    addTearDown(secondRun.dispose);

    await restorePersistedFsRuntimeState(secondRun.read);

    expect(
      secondRun.read(fsSecurityModeServiceProvider).getModeSync(
            contactId: contactId,
            identityContext: identityContext,
          ),
      FsSecurityMode.strict,
    );
    expect(
      secondRun.read(fsStateForContactProvider(contactId)),
      FsSessionState.strictFsActive,
    );
    expect(
      secondRun.read(fsRatchetStateCacheProvider)[sessionId],
      isNotNull,
    );
  });
}

Uint8List _bytes(int seed) => Uint8List.fromList(
      List<int>.generate(32, (i) => (seed + i) % 256),
    );

RatchetState _ratchet(String sessionId) => RatchetState(
      sessionId: sessionId,
      rootKey: _bytes(1),
      sendingChainKey: _bytes(33),
      receivingChainKey: _bytes(65),
      localRatchetPriv: _bytes(97),
      localRatchetPub: _bytes(129),
      lastRemoteRatchetPub: _bytes(161),
      sendCounter: 0,
      recvCounter: 0,
      skippedKeys: const {},
    );

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
