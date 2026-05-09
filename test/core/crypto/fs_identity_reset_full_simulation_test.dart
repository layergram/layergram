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

// Full simulation test: FS persistence after identity reset.
//
// This test verifies that after identity reset:
// 1. All ratchet states are removed from persistence
// 2. All FS contact states are removed from persistence
// 3. The registry correctly shows sessions as broken
// 4. Upon identity restore with same key, no old FS state survives
//
// This is the core test for the scenario where Device A resets identity
// and should NOT be able to decrypt FS messages from Device B.

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_ratchet_persistence_service.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/crypto/fs_state_persistence_service.dart';
import 'package:layergram/core/storage/aux_record_repository.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  late Directory tmpDir;
  late Box<Map> box;

  // Alice's identity key (derived from seed)
  final alicePrivateKeyBytes = Uint8List(32)..fillRange(0, 32, 0xAA);

  Future<SecretKey> deriveAuxKey(Uint8List privateKey) =>
      AuxRecordCipher.deriveAuxStorageKey(privateKey);

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_fs_full_sim_');
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
  // T_FULL_SIM_1: Identity reset clears all persisted FS state
  // ---------------------------------------------------------------------------
  test('T_FULL_SIM_1: After identity reset, all FS persisted state is cleared', () async {
    const aliceContactId = 'alice_device';
    const bobContactId = 'bob_device';
    const sessionId = 'shared_fs_session';
    const identityContext = 'primary';

    // =========================================================================
    // PHASE 1: Setup active FS session with persisted state
    // =========================================================================

    final aliceAuxKey = await deriveAuxKey(alicePrivateKeyBytes);
    final aliceAuxRepo = AuxRecordRepository();
    aliceAuxRepo.setActiveContext(
      scopeToken: identityContext,
      auxStorageKey: aliceAuxKey,
    );

    final aliceRegistry = FsContactSecurityRegistry();
    final aliceStateService = FsStatePersistenceService(
      auxRepository: aliceAuxRepo,
      registry: aliceRegistry,
    );
    final aliceRatchetService = FsRatchetPersistenceService(
      auxRepository: aliceAuxRepo,
    );

    // Create and persist a ratchet state
    final aliceRatchetState = RatchetState(
      sessionId: sessionId,
      rootKey: Uint8List(32)..fillRange(0, 32, 0x01),
      sendingChainKey: Uint8List(32)..fillRange(0, 32, 0x02),
      receivingChainKey: Uint8List(32)..fillRange(0, 32, 0x03),
      localRatchetPriv: Uint8List(32)..fillRange(0, 32, 0x04),
      localRatchetPub: Uint8List(32)..fillRange(0, 32, 0x05),
      lastRemoteRatchetPub: Uint8List(32)..fillRange(0, 32, 0x06),
      sendCounter: 10,
      recvCounter: 5,
      skippedKeys: const {},
    );
    await aliceRatchetService.saveRatchetState(aliceRatchetState);

    // Create and persist FS contact state
    final aliceFsState = FsContactSecurityState(
      contactId: bobContactId,
      identityContext: identityContext,
      sessionId: sessionId,
      fsState: FsSessionState.fsActive,
    );
    aliceRegistry.upsert(aliceFsState);
    await aliceStateService.saveState(aliceFsState);

    // Verify setup: 2 aux records exist
    expect(aliceAuxRepo.getAllAuxRecordIds().length, equals(2),
        reason: 'Setup: should have 2 aux records (ratchet + state)');
    expect(await aliceRatchetService.loadAllRatchetStates(), isNotEmpty,
        reason: 'Setup: ratchet state should be persisted');

    // =========================================================================
    // PHASE 2: Identity reset (simulating data_reset_section.dart)
    // =========================================================================

    // 1. Mark all sessions as broken
    aliceRegistry.markAllBroken(identityContext);

    // 2. Remove all persisted FS states
    await aliceStateService.removeAllStates(identityContext);

    // 3. Remove all persisted ratchet states
    await aliceRatchetService.removeAllRatchetStates();

    // 4. Clear in-memory cache
    final clearedCache = <String, RatchetState>{};

    // Verify: No ratchet states in storage
    final afterResetRatchets = await aliceRatchetService.loadAllRatchetStates();
    expect(afterResetRatchets, isEmpty,
        reason: 'After reset, no ratchet states should exist in storage');

    // Verify: No aux records
    final afterResetAux = aliceAuxRepo.getAllAuxRecordIds();
    expect(afterResetAux, isEmpty,
        reason: 'After reset, no aux records should exist');

    // Verify: Registry shows broken
    final brokenState = aliceRegistry.lookup(
      contactId: bobContactId,
      identityContext: identityContext,
      sessionId: sessionId,
    );
    expect(brokenState?.fsState, equals(FsSessionState.fsBroken),
        reason: 'Registry entry should be fsBroken after reset');

    // =========================================================================
    // PHASE 3: Identity restore with same key (no restart)
    // =========================================================================

    // Same aux key derived from same identity
    final restoredAuxKey = await deriveAuxKey(alicePrivateKeyBytes);
    final restoredAuxRepo = AuxRecordRepository();
    restoredAuxRepo.setActiveContext(
      scopeToken: identityContext,
      auxStorageKey: restoredAuxKey,
    );

    final restoredRatchetService = FsRatchetPersistenceService(
      auxRepository: restoredAuxRepo,
    );
    final restoredStateService = FsStatePersistenceService(
      auxRepository: restoredAuxRepo,
      registry: aliceRegistry,
    );

    // Simulate loading persisted state (as in _loadPersistedFsState)
    await restoredStateService.loadPersistedState();
    final restoredRatchets = await restoredRatchetService.loadAllRatchetStates();

    // Populate cache from loaded state
    final restoredCache = <String, RatchetState>{};
    for (final state in restoredRatchets) {
      restoredCache[state.sessionId] = state;
    }

    // =========================================================================
    // PHASE 4: Verify no ratchet state available after restore
    // =========================================================================

    // CRITICAL: After reset and restore, there should be NO ratchet state
    // for the old session. This is what prevents decryption of old messages.
    expect(restoredCache.containsKey(sessionId), isFalse,
        reason: 'After reset+restore, cache should NOT contain old session ratchet');
    expect(restoredRatchets, isEmpty,
        reason: 'After reset+restore, no ratchet states should be loaded from persistence');

    // =========================================================================
    // PHASE 5: Verify handshake blocked in broken state
    // =========================================================================

    final sessionManager = FsSessionManager();
    sessionManager.setStateForTesting(FsSessionState.fsBroken);

    // Cannot initiate handshake from broken state
    final sendResult = sessionManager.recordFsInitSent(FsInitPayload(
      initId: 'attempt_after_reset',
      initiatorDevicePub: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHw==',
      initiatorEphemeralPub: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHw==',
      caps: const ['fs_v1'],
      createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
      ekAPrivBytes: Uint8List(32)..fillRange(0, 32, 0x88),
    ));

    expect(sendResult.accepted, isFalse,
        reason: 'Cannot send FS_INIT from fsBroken state');

    // =========================================================================
    // PHASE 6: Bug simulation - what if reset failed?
    // =========================================================================

    // Simulate the BUG: reset didn't clear records, but identity was "restored"
    final buggyAuxRepo = AuxRecordRepository();
    buggyAuxRepo.setActiveContext(
      scopeToken: identityContext,
      auxStorageKey: aliceAuxKey, // Same key
    );

    // Save state WITHOUT clearing (simulating failed reset)
    final buggyRatchetService = FsRatchetPersistenceService(
      auxRepository: buggyAuxRepo,
    );
    await buggyRatchetService.saveRatchetState(aliceRatchetState);

    // If reset failed, old state survives
    final buggyLoaded = await buggyRatchetService.loadAllRatchetStates();
    expect(buggyLoaded.length, equals(1),
        reason: 'BUG SIMULATION: If clearByKind fails, ratchet state survives');
    expect(buggyLoaded.first.sessionId, equals(sessionId),
        reason: 'BUG: Old session ID matches - this would allow decryption!');
  });
}
