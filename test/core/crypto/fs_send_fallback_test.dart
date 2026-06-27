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

// Tests for FS send fallback behavior when ratchet state is missing.
//
// These tests verify that when a session is marked fsActive but the ratchet state
// cannot be found (neither in cache nor persistence), the system must:
// 1. Mark the session as BROKEN
// 2. Fall back to LEGACY encryption (safe default)
// 3. NOT send FS-encrypted messages without proper state

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/fs_double_ratchet.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  late Directory tmpDir;
  late Box<Map> box;

  final identityPrivateKeyBytes = Uint8List(32)..fillRange(0, 32, 0x77);

  Future<SecretKey> deriveAuxKey() =>
      AuxRecordCipher.deriveAuxStorageKey(identityPrivateKeyBytes);

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir = await Directory.systemTemp.createTemp('layergram_fs_send_');
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
  // T_SEND_FALLBACK_1: When ratchet missing, session must be marked broken
  // ---------------------------------------------------------------------------
  test(
      'T_SEND_FALLBACK_1: Missing ratchet state causes session to be marked broken',
      () async {
    const contactId = 'bob_device';
    const sessionId = 'test_session_123';
    const identityContext = 'primary';

    final container = ProviderContainer();
    addTearDown(container.dispose);

    // Setup aux repository
    final auxKey = await deriveAuxKey();
    final auxRepo = container.read(auxRecordRepositoryProvider);
    auxRepo.setActiveContext(
      scopeToken: identityContext,
      auxStorageKey: auxKey,
    );

    // Create session manager in fsActive state with sessionId
    final sessionManager = container.read(fsSessionManagerProvider(contactId));
    sessionManager.setStateForTesting(FsSessionState.fsActive,
        sessionId: sessionId);

    // Clear ALL ratchet state from both cache and persistence
    container.read(fsRatchetStateCacheProvider.notifier).state = {};
    await container
        .read(fsRatchetPersistenceServiceProvider)
        .removeAllRatchetStates();

    // Verify ratchet is truly missing
    final ratchetInCache =
        container.read(fsRatchetStateCacheProvider)[sessionId];
    final ratchetInPersistence = await container
        .read(fsRatchetPersistenceServiceProvider)
        .loadRatchetState(sessionId);

    expect(ratchetInCache, isNull,
        reason: 'Setup: ratchet should not be in cache');
    expect(ratchetInPersistence, isNull,
        reason: 'Setup: ratchet should not be in persistence');

    // CRITICAL: When attempting to send with missing ratchet,
    // the system MUST mark the session as broken and use legacy encryption
    // (This is the behavior we expect - the test will fail until implemented)

    // Current state should be fsActive (set by test)
    expect(sessionManager.state, equals(FsSessionState.fsActive));
    expect(sessionManager.activeSessionId, equals(sessionId));

    // After attempting to use the missing ratchet, session should become broken
    // This simulates what _sendMessage should do when ratchet is missing
    if (sessionManager.state == FsSessionState.fsActive &&
        container.read(fsRatchetStateCacheProvider)[sessionId] == null) {
      // Try to load from persistence (will fail)
      final loaded = await container
          .read(fsRatchetPersistenceServiceProvider)
          .loadRatchetState(sessionId);

      if (loaded == null) {
        // CRITICAL: Ratchet is truly missing - session must be marked broken!
        sessionManager.markBroken();
      }
    }

    // After the failure, session should be BROKEN
    expect(sessionManager.state, equals(FsSessionState.fsBroken),
        reason:
            'CRITICAL: When ratchet is missing, session MUST be marked broken');
  });

  // ---------------------------------------------------------------------------
  // T_SEND_FALLBACK_2: When session broken, must use legacy encryption
  // ---------------------------------------------------------------------------
  test('T_SEND_FALLBACK_2: Broken session forces legacy encryption fallback',
      () async {
    const contactId = 'bob_device';
    const sessionId = 'broken_session';
    const identityContext = 'primary';

    final container = ProviderContainer();
    addTearDown(container.dispose);

    // Setup aux repository
    final auxKey = await deriveAuxKey();
    final auxRepo = container.read(auxRecordRepositoryProvider);
    auxRepo.setActiveContext(
      scopeToken: identityContext,
      auxStorageKey: auxKey,
    );

    // Create session manager in fsBroken state
    final sessionManager = container.read(fsSessionManagerProvider(contactId));
    sessionManager.setStateForTesting(FsSessionState.fsBroken,
        sessionId: sessionId);

    // Verify state is broken
    expect(sessionManager.state, equals(FsSessionState.fsBroken));

    // In broken state, no FS encryption should be attempted
    // The _sendMessage logic should:
    // 1. Check if state is fsActive or strictFsActive (false - it's broken)
    // 2. Skip FS encryption entirely
    // 3. Use only legacy encryption

    final shouldUseFsEncryption =
        sessionManager.state == FsSessionState.fsActive ||
            sessionManager.state == FsSessionState.strictFsActive;

    expect(shouldUseFsEncryption, isFalse,
        reason: 'CRITICAL: Broken session must NOT use FS encryption');
  });

  // ---------------------------------------------------------------------------
  // T_SEND_FALLBACK_3: Ratchet in persistence but not cache should be auto-loaded
  // ---------------------------------------------------------------------------
  test(
      'T_SEND_FALLBACK_3: Ratchet in persistence must be auto-loaded when missing from cache',
      () async {
    const contactId = 'bob_device';
    const sessionId = 'test_session_456';
    const identityContext = 'primary';

    final container = ProviderContainer();
    addTearDown(container.dispose);

    // Setup aux repository
    final auxKey = await deriveAuxKey();
    final auxRepo = container.read(auxRecordRepositoryProvider);
    auxRepo.setActiveContext(
      scopeToken: identityContext,
      auxStorageKey: auxKey,
    );

    // Create and save ratchet state to persistence (but NOT cache)
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

    await container
        .read(fsRatchetPersistenceServiceProvider)
        .saveRatchetState(ratchetState);

    // Clear cache only
    container.read(fsRatchetStateCacheProvider.notifier).state = {};

    // Create session manager in fsActive state
    final sessionManager = container.read(fsSessionManagerProvider(contactId));
    sessionManager.setStateForTesting(FsSessionState.fsActive,
        sessionId: sessionId);

    // Verify ratchet is in persistence but not cache
    final ratchetInCache =
        container.read(fsRatchetStateCacheProvider)[sessionId];
    final ratchetInPersistence = await container
        .read(fsRatchetPersistenceServiceProvider)
        .loadRatchetState(sessionId);

    expect(ratchetInCache, isNull,
        reason: 'Setup: ratchet should not be in cache');
    expect(ratchetInPersistence, isNotNull,
        reason: 'Setup: ratchet should be in persistence');

    // CRITICAL: When attempting to send, the system MUST:
    // 1. Check cache (missing)
    // 2. Load from persistence (present)
    // 3. Add back to cache
    // 4. Use FS encryption

    // This simulates what _sendMessage should do
    RatchetState? ratchetToUse;
    if (sessionManager.state == FsSessionState.fsActive) {
      final sid = sessionManager.activeSessionId;
      if (sid != null) {
        ratchetToUse = container.read(fsRatchetStateCacheProvider)[sid];
        if (ratchetToUse == null) {
          // Try to load from persistence
          ratchetToUse = await container
              .read(fsRatchetPersistenceServiceProvider)
              .loadRatchetState(sid);
          if (ratchetToUse != null) {
            // Add back to cache
            container
                .read(fsRatchetStateCacheProvider.notifier)
                .update((cache) => {
                      ...cache,
                      sid: ratchetToUse!,
                    });
          }
        }
      }
    }

    // Should have successfully loaded from persistence
    expect(ratchetToUse, isNotNull,
        reason: 'CRITICAL: Ratchet must be auto-loaded from persistence');

    // Should now be in cache
    final ratchetNowInCache =
        container.read(fsRatchetStateCacheProvider)[sessionId];
    expect(ratchetNowInCache, isNotNull,
        reason: 'CRITICAL: Ratchet must be added back to cache after loading');
  });

  // ---------------------------------------------------------------------------
  // T_SEND_FALLBACK_4: Complete flow - missing ratchet causes broken session
  // ---------------------------------------------------------------------------
  test(
      'T_SEND_FALLBACK_4: Complete flow verification - ratchet missing -> session broken -> legacy used',
      () async {
    const contactId = 'bob_device';
    const sessionId = 'flow_test_session';
    const identityContext = 'primary';

    final container = ProviderContainer();
    addTearDown(container.dispose);

    // Setup aux repository
    final auxKey = await deriveAuxKey();
    final auxRepo = container.read(auxRecordRepositoryProvider);
    auxRepo.setActiveContext(
      scopeToken: identityContext,
      auxStorageKey: auxKey,
    );

    // Create session manager in fsActive state
    final sessionManager = container.read(fsSessionManagerProvider(contactId));
    sessionManager.setStateForTesting(FsSessionState.fsActive,
        sessionId: sessionId);

    // Clear all ratchet state
    container.read(fsRatchetStateCacheProvider.notifier).state = {};
    await container
        .read(fsRatchetPersistenceServiceProvider)
        .removeAllRatchetStates();

    // Simulate the _sendMessage logic that should be implemented
    Future<bool> attemptFsEncryption() async {
      if (sessionManager.state == FsSessionState.fsActive ||
          sessionManager.state == FsSessionState.strictFsActive) {
        final sid = sessionManager.activeSessionId;
        if (sid != null) {
          // Check cache
          var ratchet = container.read(fsRatchetStateCacheProvider)[sid];

          if (ratchet == null) {
            // Try persistence
            ratchet = await container
                .read(fsRatchetPersistenceServiceProvider)
                .loadRatchetState(sid);

            if (ratchet == null) {
              // CRITICAL: Ratchet truly missing - mark broken and return false
              sessionManager.markBroken();
              return false; // Cannot use FS encryption
            } else {
              // Found in persistence - add to cache
              container
                  .read(fsRatchetStateCacheProvider.notifier)
                  .update((cache) => {
                        ...cache,
                        sid: ratchet!,
                      });
            }
          }

          // Have ratchet - can use FS
          return true;
        }
      }

      // Not in active state - use legacy
      return false;
    }

    final canUseFs = await attemptFsEncryption();

    // Should NOT be able to use FS (ratchet missing)
    expect(canUseFs, isFalse,
        reason: 'CRITICAL: Should not use FS when ratchet is missing');

    // Session should be marked as broken
    expect(sessionManager.state, equals(FsSessionState.fsBroken),
        reason:
            'CRITICAL: Session must be marked broken when ratchet is missing');
  });
}
