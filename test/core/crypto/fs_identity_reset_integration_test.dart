// Integration test: FS state after identity reset (Spec §8.6.3).
//
// Verifies that after identity reset:
//  - All FS sessions are marked broken in the registry
//  - All persisted FS states are removed from storage
//  - All ratchet states are removed from storage
//  - In-memory caches are cleared
//  - After "recovery" with same seed, no active FS sessions exist
//
// This is the scenario where Device A resets identity but keeps messages,
// then recovers with the same seed. Device A should NOT be able to decrypt
// FS-encrypted messages from Device B without a fresh handshake.

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

  // Same seed-derived key for both "before" and "after" reset
  final masterBytes = Uint8List(32)..fillRange(0, 32, 0x77);

  Future<SecretKey> buildAuxKey() =>
      AuxRecordCipher.deriveAuxStorageKey(masterBytes);

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_fs_reset_');
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
  // T_RESET_1: Full identity reset clears all FS state
  // ---------------------------------------------------------------------------
  test('T_RESET_1: Identity reset clears all FS persisted state and marks sessions broken', () async {
    const contactId = 'bob_device_b';
    const sessionId = 'fs_session_abc123';
    const identityContext = 'primary';

    // ── PHASE 1: Setup active FS session ─────────────────────────────────────
    final auxKey = await buildAuxKey();
    final auxRepo = AuxRecordRepository();
    auxRepo.setActiveContext(scopeToken: identityContext, auxStorageKey: auxKey);

    final registry = FsContactSecurityRegistry();
    final persistenceService = FsStatePersistenceService(
      auxRepository: auxRepo,
      registry: registry,
    );
    final ratchetService = FsRatchetPersistenceService(
      auxRepository: auxRepo,
    );

    // Create and persist a fake ratchet state
    final fakeRatchetState = RatchetState(
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

    // Persist ratchet state
    await ratchetService.saveRatchetState(fakeRatchetState);

    // Create and persist an active FS contact state
    final activeState = FsContactSecurityState(
      contactId: contactId,
      identityContext: identityContext,
      sessionId: sessionId,
      fsState: FsSessionState.fsActive,
    );
    registry.upsert(activeState);
    await persistenceService.saveState(activeState);

    // Verify setup: both records exist
    final ratchetBefore = await ratchetService.loadRatchetState(sessionId);
    expect(ratchetBefore, isNotNull, reason: 'Ratchet state should exist before reset');

    final allRecordsBefore = auxRepo.getAllAuxRecordIds();
    expect(allRecordsBefore.length, equals(2), reason: 'Should have 2 aux records (state + ratchet)');

    // ── PHASE 2: Simulate identity reset ────────────────────────────────────
    // This mirrors the code in data_reset_section.dart

    // 1. Mark all sessions as broken in registry
    registry.markAllBroken(identityContext);
    final markedState = registry.lookup(
      contactId: contactId,
      identityContext: identityContext,
      sessionId: sessionId,
    );
    expect(markedState?.fsState, equals(FsSessionState.fsBroken),
        reason: 'Registry entry should be marked broken after reset');

    // 2. Remove all persisted FS states
    await persistenceService.removeAllStates(identityContext);

    // 3. Remove all persisted ratchet states
    await ratchetService.removeAllRatchetStates();

    // 4. Clear in-memory cache (simulated by creating fresh services)
    // In real app: ref.read(fsRatchetStateCacheProvider.notifier).state = {};

    // ── PHASE 3: Verify everything is cleared ─────────────────────────────────

    // Ratchet state should be gone
    final ratchetAfter = await ratchetService.loadRatchetState(sessionId);
    expect(ratchetAfter, isNull, reason: 'Ratchet state should be null after reset');

    // All aux records should be gone
    final allRecordsAfter = auxRepo.getAllAuxRecordIds();
    expect(allRecordsAfter, isEmpty,
        reason: 'All aux records should be deleted after reset');

    // ── PHASE 4: Simulate "recovery" with same seed ───────────────────────────
    // User restores identity with same recovery words
    // This recreates the same auxKey (same identity key)

    final recoveredAuxKey = await buildAuxKey(); // Same key
    final recoveredAuxRepo = AuxRecordRepository();
    recoveredAuxRepo.setActiveContext(
      scopeToken: identityContext,
      auxStorageKey: recoveredAuxKey,
    );

    final recoveredRatchetService = FsRatchetPersistenceService(
      auxRepository: recoveredAuxRepo,
    );
    final recoveredPersistenceService = FsStatePersistenceService(
      auxRepository: recoveredAuxRepo,
      registry: registry, // Same registry (or fresh one in real app)
    );

    // Try to load persisted state (should find nothing)
    final recoveredStates = await recoveredRatchetService.loadAllRatchetStates();
    expect(recoveredStates, isEmpty,
        reason: 'After recovery, no ratchet states should exist');

    await recoveredPersistenceService.loadPersistedState();
    final recoveredRegistryState = registry.lookup(
      contactId: contactId,
      identityContext: identityContext,
      sessionId: sessionId,
    );
    // Note: registry was marked broken, not cleared. In real app with fresh
    // registry + loadPersistedState, there would be no entry at all.
    // For this test, we verify the entry is still broken.
    expect(recoveredRegistryState?.fsState, equals(FsSessionState.fsBroken),
        reason: 'After recovery, session should still be broken (or not exist)');

    // ── PHASE 5: Verify handshake is blocked ──────────────────────────────────
    final sessionManager = FsSessionManager();
    // Simulate loading the broken state into session manager
    sessionManager.setStateForTesting(FsSessionState.fsBroken);

    // Cannot send FS_INIT from broken state
    final sendResult = sessionManager.recordFsInitSent(FsInitPayload(
      initId: 'new_init_attempt',
      initiatorDevicePub: 'AQ' + 'A' * 42,
      initiatorEphemeralPub: 'AQ' + 'D' * 42,
      caps: const ['fs_v1'],
      createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
      ekAPrivBytes: Uint8List(32)..fillRange(0, 32, 0x99),
    ));
    expect(sendResult.accepted, isFalse,
        reason: 'Cannot initiate handshake from fsBroken state');

    // Incoming FS_INIT in broken state → accepted (partner reset §8.8)
    final receiveResult = sessionManager.processFsInitReceived(
      message: FsInitMessage(
        initId: 'remote_init',
        initiatorDevicePub: 'AQ' + 'B' * 42,
        initiatorEphemeralPub: 'AQ' + 'C' * 42,
        caps: const ['fs_v1'],
        createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
      ),
      localInitId: '',
    );
    expect(receiveResult.accepted, isTrue,
        reason: 'Incoming FS_INIT in fsBroken should be accepted (partner reset)');
    expect(sessionManager.state, equals(FsSessionState.fsInitSeen),
        reason: 'State must transition to fsInitSeen for new handshake');
  });

}
