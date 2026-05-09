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

// Riverpod integration test: FS state after identity reset using real providers.
//
// This test simulates the EXACT flow from data_reset_section.dart:
// 1. Setup active FS session with persisted state
// 2. Reset identity (mark broken, remove states, invalidate providers)
// 3. Restore identity with same key
// 4. Verify NO ratchet states are loaded (cannot decrypt FS messages)

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_ratchet_persistence_service.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/crypto/fs_state_persistence_service.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  late Directory tmpDir;
  late Box<Map> box;

  // Same identity key (derived from seed)
  final identityPrivateKeyBytes = Uint8List(32)..fillRange(0, 32, 0x77);

  Future<SecretKey> deriveAuxKey() =>
      AuxRecordCipher.deriveAuxStorageKey(identityPrivateKeyBytes);

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_fs_riverpod_');
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

  // ---------------------------------------------------------------------------
  // T_RIVERPOD_1: Full provider-based identity reset simulation
  // ---------------------------------------------------------------------------
  test('T_RIVERPOD_1: Identity reset clears all FS state using real providers', () async {
    const contactId = 'bob_device';
    const sessionId = 'test_session_123';
    const identityContext = 'primary';

    // Create a ProviderContainer for this test (simulates app state)
    final container = ProviderContainer();
    addTearDown(container.dispose);

    // ========================================================================
    // PHASE 1: Setup - Create active FS session with persisted state
    // ========================================================================

    // Set up aux repository context (simulates app startup with identity)
    final auxKey = await deriveAuxKey();
    final auxRepo = container.read(auxRecordRepositoryProvider);
    auxRepo.setActiveContext(
      scopeToken: identityContext,
      auxStorageKey: auxKey,
    );

    // Create and persist ratchet state
    final ratchetState = RatchetState(
      sessionId: sessionId,
      rootKey: Uint8List(32)..fillRange(0, 32, 0x01),
      sendingChainKey: Uint8List(32)..fillRange(0, 32, 0x02),
      receivingChainKey: Uint8List(32)..fillRange(0, 32, 0x03),
      localRatchetPriv: Uint8List(32)..fillRange(0, 32, 0x04),
      localRatchetPub: Uint8List(32)..fillRange(0, 32, 0x05),
      lastRemoteRatchetPub: Uint8List(32)..fillRange(0, 32, 0x06),
      sendCounter: 42,
      recvCounter: 7,
      skippedKeys: const {},
    );

    await container.read(fsRatchetPersistenceServiceProvider)
        .saveRatchetState(ratchetState);

    // Create and persist FS contact state
    final fsState = FsContactSecurityState(
      contactId: contactId,
      identityContext: identityContext,
      sessionId: sessionId,
      fsState: FsSessionState.fsActive,
    );
    container.read(fsContactSecurityRegistryProvider).upsert(fsState);
    await container.read(fsStatePersistenceServiceProvider).saveState(fsState);

    // Verify setup: 2 records exist
    final allIdsBefore = auxRepo.getAllAuxRecordIds();
    expect(allIdsBefore.length, equals(2),
        reason: 'Setup: should have 2 aux records (ratchet + state)');

    // Load ratchet states into cache (simulates _loadPersistedFsState)
    final ratchetStatesBefore = await container.read(fsRatchetPersistenceServiceProvider)
        .loadAllRatchetStates();
    container.read(fsRatchetStateCacheProvider.notifier).state = {
      for (final s in ratchetStatesBefore) s.sessionId: s,
    };

    expect(container.read(fsRatchetStateCacheProvider).containsKey(sessionId), isTrue,
        reason: 'Setup: ratchet state should be in cache');

    // ========================================================================
    // PHASE 2: Identity reset (EXACT flow from data_reset_section.dart)
    // ========================================================================

    // 1. Mark all sessions as broken
    container.read(fsContactSecurityRegistryProvider).markAllBroken(identityContext);

    // 2. Remove all persisted FS states
    await container.read(fsStatePersistenceServiceProvider).removeAllStates(identityContext);

    // 3. Remove all persisted ratchet states
    await container.read(fsRatchetPersistenceServiceProvider).removeAllRatchetStates();

    // 4. Clear in-memory ratchet state cache
    container.read(fsRatchetStateCacheProvider.notifier).state = {};

    // 5. Invalidate ALL FS-related providers (this is critical!)
    container.invalidate(fsContactSecurityRegistryProvider);
    container.invalidate(fsSessionManagerProvider);
    container.invalidate(fsStrictModeControllerProvider);
    container.invalidate(fsOpportunisticControllerProvider);
    container.invalidate(fsStateForContactProvider);
    container.invalidate(fsStatePersistenceServiceProvider);
    container.invalidate(fsRatchetPersistenceServiceProvider);
    container.invalidate(auxRecordRepositoryProvider);

    // ========================================================================
    // PHASE 3: Verify after reset (before restore)
    // ========================================================================

    // After invalidation, we need fresh instances
    final freshAuxRepo = container.read(auxRecordRepositoryProvider);
    // Note: auxRepo needs context again after invalidation
    freshAuxRepo.setActiveContext(
      scopeToken: identityContext,
      auxStorageKey: auxKey,
    );

    // Verify: No aux records
    final allIdsAfter = freshAuxRepo.getAllAuxRecordIds();
    expect(allIdsAfter, isEmpty,
        reason: 'After reset, all aux records should be deleted');

    // Verify: No ratchet states loaded
    final ratchetStatesAfter = await container.read(fsRatchetPersistenceServiceProvider)
        .loadAllRatchetStates();
    expect(ratchetStatesAfter, isEmpty,
        reason: 'After reset, no ratchet states should exist');

    // ========================================================================
    // PHASE 4: Identity restore with same key (simulates _loadPersistedFsState)
    // ========================================================================

    // Simulate app startup after identity restore
    // 1. Set up aux repository context (same key = same storage)
    final restoreAuxKey = await deriveAuxKey();
    final restoreAuxRepo = container.read(auxRecordRepositoryProvider);
    restoreAuxRepo.setActiveContext(
      scopeToken: identityContext,
      auxStorageKey: restoreAuxKey,
    );

    // 2. Load persisted FS states (simulates _loadPersistedFsState)
    await container.read(fsStatePersistenceServiceProvider).loadPersistedState();

    // 3. Load ratchet states into cache (simulates _loadPersistedFsState)
    final restoredRatchets = await container.read(fsRatchetPersistenceServiceProvider)
        .loadAllRatchetStates();

    // ========================================================================
    // PHASE 5: CRITICAL VERIFICATION
    // ========================================================================

    // After restore with SAME key, if clearByKind worked correctly,
    // there should be NO ratchet states loaded because they were deleted.
    expect(restoredRatchets, isEmpty,
        reason: 'CRITICAL: After reset+restore, NO ratchet states should exist. '
                 'If this fails, clearByKind is not working correctly!');

    // Verify cache is empty
    final cacheAfter = <String, RatchetState>{};
    for (final state in restoredRatchets) {
      cacheAfter[state.sessionId] = state;
    }

    expect(cacheAfter.containsKey(sessionId), isFalse,
        reason: 'CRITICAL: Old session ratchet should NOT be in cache after restore');

    // Verify registry state
    final registryState = container.read(fsContactSecurityRegistryProvider)
        .lookup(contactId: contactId, identityContext: identityContext, sessionId: sessionId);

    // After invalidate + load, registry should be empty (or have broken state from persistence)
    // But since we called markAllBroken BEFORE removeAllStates, the broken state was also deleted
    // So registry should be empty after load (no persisted state found)
    expect(registryState?.fsState ?? FsSessionState.legacyOnly,
        isNot(equals(FsSessionState.fsActive)),
        reason: 'After restore, session should NOT be fsActive');
  });
}
