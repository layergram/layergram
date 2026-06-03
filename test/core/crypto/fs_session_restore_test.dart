/// Tests for FS session restore / recovery.
///
/// Verifies:
/// 1. FS session state persists through simulated app restart
/// 2. Ratchet state persists and is loadable after restart
/// 3. Partner reset (new fs_init from broken/active state) triggers recovery
/// 4. Multi-device session rotation preserves archived sessions through restart
/// 5. After identity reset + restore, partner can initiate fresh handshake
/// 6. Plausible deniability: persisted FS state contains no device labels
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/aux_record_cipher.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_device_session_router.dart';
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

  final masterBytes = Uint8List(32)..fillRange(0, 32, 0x42);

  Future<SecretKey> buildAuxKey() =>
      AuxRecordCipher.deriveAuxStorageKey(masterBytes);

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    tmpDir =
        await Directory.systemTemp.createTemp('layergram_session_restore_');
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

  // ── 1. FS session state survives app restart ──────────────────────────────

  group('Session state persistence through restart', () {
    test('active FS session state is restored from aux records after restart',
        () async {
      const contactId = 'contact-alice';
      const sessionId = 'session-xyz';
      const identityContext = 'primary';
      final auxKey = await buildAuxKey();

      // --- Session 1: save state ---
      final auxRepo1 = AuxRecordRepository();
      auxRepo1.setActiveContext(
          scopeToken: identityContext, auxStorageKey: auxKey);
      final registry1 = FsContactSecurityRegistry();
      final persistence1 = FsStatePersistenceService(
        auxRepository: auxRepo1,
        registry: registry1,
      );

      final activeState = FsContactSecurityState(
        contactId: contactId,
        identityContext: identityContext,
        sessionId: sessionId,
        fsState: FsSessionState.fsActive,
      );
      registry1.upsert(activeState);
      await persistence1.saveState(activeState);

      // Verify saved
      expect(
          registry1
              .lookup(
                contactId: contactId,
                identityContext: identityContext,
                sessionId: sessionId,
              )
              ?.fsState,
          FsSessionState.fsActive);

      // --- "Restart": new registry + persistence, same aux box ---
      final auxRepo2 = AuxRecordRepository();
      auxRepo2.setActiveContext(
          scopeToken: identityContext, auxStorageKey: auxKey);
      final registry2 = FsContactSecurityRegistry();
      final persistence2 = FsStatePersistenceService(
        auxRepository: auxRepo2,
        registry: registry2,
      );

      // Before load, registry is empty
      expect(registry2.isEmpty, isTrue);

      // Load persisted state
      await persistence2.loadPersistedState();

      // After load, state is restored
      final restored = registry2.lookup(
        contactId: contactId,
        identityContext: identityContext,
        sessionId: sessionId,
      );
      expect(restored, isNotNull, reason: 'State must survive restart');
      expect(restored!.fsState, FsSessionState.fsActive);
      expect(restored.contactId, contactId);
      expect(restored.sessionId, sessionId);
    });

    test('broken FS session state also survives restart', () async {
      const contactId = 'contact-bob';
      const sessionId = 'session-broken';
      const identityContext = 'primary';
      final auxKey = await buildAuxKey();

      final auxRepo = AuxRecordRepository();
      auxRepo.setActiveContext(
          scopeToken: identityContext, auxStorageKey: auxKey);
      final registry = FsContactSecurityRegistry();
      final persistence = FsStatePersistenceService(
        auxRepository: auxRepo,
        registry: registry,
      );

      final brokenState = FsContactSecurityState(
        contactId: contactId,
        identityContext: identityContext,
        sessionId: sessionId,
        fsState: FsSessionState.fsBroken,
      );
      registry.upsert(brokenState);
      await persistence.saveState(brokenState);

      // Restart
      final registry2 = FsContactSecurityRegistry();
      final persistence2 = FsStatePersistenceService(
        auxRepository: auxRepo,
        registry: registry2,
      );
      await persistence2.loadPersistedState();

      final restored = registry2.lookup(
        contactId: contactId,
        identityContext: identityContext,
        sessionId: sessionId,
      );
      expect(restored?.fsState, FsSessionState.fsBroken);
    });
  });

  // ── 2. Ratchet state persistence ──────────────────────────────────────────

  group('Ratchet state persistence through restart', () {
    test('ratchet state is loadable after simulated restart', () async {
      const sessionId = 'ratchet-session-1';
      const identityContext = 'primary';
      final auxKey = await buildAuxKey();

      final auxRepo = AuxRecordRepository();
      auxRepo.setActiveContext(
          scopeToken: identityContext, auxStorageKey: auxKey);
      final ratchetService =
          FsRatchetPersistenceService(auxRepository: auxRepo);

      final ratchet = RatchetState(
        sessionId: sessionId,
        rootKey: Uint8List(32)..fillRange(0, 32, 0xAA),
        sendingChainKey: Uint8List(32)..fillRange(0, 32, 0xBB),
        receivingChainKey: Uint8List(32)..fillRange(0, 32, 0xCC),
        localRatchetPriv: Uint8List(32)..fillRange(0, 32, 0xDD),
        localRatchetPub: Uint8List(32)..fillRange(0, 32, 0xEE),
        lastRemoteRatchetPub: Uint8List(32)..fillRange(0, 32, 0xFF),
        sendCounter: 5,
        recvCounter: 3,
        skippedKeys: const {},
      );

      await ratchetService.saveRatchetState(ratchet);

      // "Restart": new service, same storage
      final ratchetService2 =
          FsRatchetPersistenceService(auxRepository: auxRepo);
      final restored = await ratchetService2.loadRatchetState(sessionId);

      expect(restored, isNotNull, reason: 'Ratchet state must survive restart');
      expect(restored!.sessionId, sessionId);
      expect(restored.sendCounter, 5);
      expect(restored.recvCounter, 3);
    });

    test('all ratchet states are loadable (multi-device)', () async {
      const identityContext = 'primary';
      final auxKey = await buildAuxKey();

      final auxRepo = AuxRecordRepository();
      auxRepo.setActiveContext(
          scopeToken: identityContext, auxStorageKey: auxKey);
      final ratchetService =
          FsRatchetPersistenceService(auxRepository: auxRepo);

      // Save ratchets for two different devices/sessions
      for (final sid in ['device-a-session', 'device-b-session']) {
        await ratchetService.saveRatchetState(RatchetState(
          sessionId: sid,
          rootKey: Uint8List(32)..fillRange(0, 32, 0x11),
          sendingChainKey: Uint8List(32)..fillRange(0, 32, 0x22),
          receivingChainKey: Uint8List(32)..fillRange(0, 32, 0x33),
          localRatchetPriv: Uint8List(32)..fillRange(0, 32, 0x44),
          localRatchetPub: Uint8List(32)..fillRange(0, 32, 0x55),
          lastRemoteRatchetPub: Uint8List(32)..fillRange(0, 32, 0x66),
          sendCounter: 0,
          recvCounter: 0,
          skippedKeys: const {},
        ));
      }

      // Restart: load all
      final ratchetService2 =
          FsRatchetPersistenceService(auxRepository: auxRepo);
      final all = await ratchetService2.loadAllRatchetStates();

      expect(all.length, 2);
      final sessionIds = all.map((r) => r.sessionId).toSet();
      expect(sessionIds, {'device-a-session', 'device-b-session'});
    });
  });

  // ── 3. Partner reset recovery ─────────────────────────────────────────────

  group('Partner reset recovery (new fs_init from terminal state)', () {
    test('fs_init received in fsActive triggers partner reset recovery', () {
      final session = FsSessionManager();
      session.setStateForTesting(FsSessionState.fsActive,
          sessionId: 'old-session');

      final newInit = FsInitPayload(
        initId: 'partner-new-init',
        initiatorDevicePub: 'AQ${'A' * 42}',
        initiatorEphemeralPub: 'AQ${'B' * 42}',
        caps: const ['fs_v1'],
        createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
        ekAPrivBytes: Uint8List(32),
      );

      final result = session.processFsInitReceived(
        message: newInit.toMessage(),
        localInitId: '',
      );

      expect(result.accepted, isTrue,
          reason: 'Must accept fs_init from partner who reset');
      expect(session.state, FsSessionState.fsInitSeen);
    });

    test('fs_init received in fsBroken triggers recovery', () {
      final session = FsSessionManager();
      session.setStateForTesting(FsSessionState.fsBroken);

      final newInit = FsInitPayload(
        initId: 'recovery-init',
        initiatorDevicePub: 'AQ${'C' * 42}',
        initiatorEphemeralPub: 'AQ${'D' * 42}',
        caps: const ['fs_v1'],
        createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
        ekAPrivBytes: Uint8List(32),
      );

      final result = session.processFsInitReceived(
        message: newInit.toMessage(),
        localInitId: '',
      );

      expect(result.accepted, isTrue,
          reason: 'Must accept fs_init after identity reset (fsBroken)');
      expect(session.state, FsSessionState.fsInitSeen);
    });
  });

  // ── 4. Multi-device session rotation ──────────────────────────────────────

  group('Multi-device session rotation', () {
    test('router archives current session and creates new one on device change',
        () {
      final router = FsDeviceSessionRouter();

      // Simulate active session with device A
      router.currentSession.setStateForTesting(
        FsSessionState.fsActive,
        sessionId: 'device-a-session',
      );
      expect(router.currentSession.activeSessionId, 'device-a-session');
      expect(router.previousSessionCount, 0);

      // Device B arrives → rotate
      final newSession = router.rotateForNewDevice();
      expect(newSession.state, FsSessionState.legacyOnly);
      expect(router.previousSessionCount, 1);

      // Archived session still accessible by ID
      final archived = router.sessionForId('device-a-session');
      expect(archived, isNotNull);
      expect(archived!.state, FsSessionState.fsActive);
    });

    test('multiple rotations preserve all archived sessions', () {
      final router = FsDeviceSessionRouter();

      // Device A active
      router.currentSession.setStateForTesting(
        FsSessionState.fsActive,
        sessionId: 'session-a',
      );

      // Device B arrives
      router.rotateForNewDevice();
      router.currentSession.setStateForTesting(
        FsSessionState.fsActive,
        sessionId: 'session-b',
      );

      // Device C arrives
      router.rotateForNewDevice();
      router.currentSession.setStateForTesting(
        FsSessionState.fsActive,
        sessionId: 'session-c',
      );

      expect(router.sessionCount, 3);
      expect(router.previousSessionCount, 2);
      expect(router.sessionForId('session-a'), isNotNull);
      expect(router.sessionForId('session-b'), isNotNull);
      expect(router.currentSession.activeSessionId, 'session-c');
    });

    test('resetAll clears all sessions', () {
      final router = FsDeviceSessionRouter();

      router.currentSession.setStateForTesting(
        FsSessionState.fsActive,
        sessionId: 'session-a',
      );
      router.rotateForNewDevice();
      router.currentSession.setStateForTesting(
        FsSessionState.fsActive,
        sessionId: 'session-b',
      );

      router.resetAll();

      expect(router.currentSession.state, FsSessionState.legacyOnly);
      expect(router.previousSessionCount, 0);
      expect(router.sessionForId('session-a'), isNull);
      expect(router.sessionForId('session-b'), isNull);
    });
  });

  // ── 5. Identity reset → restore → fresh handshake ────────────────────────

  group('Identity reset → restore → fresh handshake', () {
    test(
        'after identity reset and restore, all FS state is gone, fresh handshake succeeds',
        () async {
      const contactId = 'contact-carol';
      const sessionId = 'session-old';
      const identityContext = 'primary';
      final auxKey = await buildAuxKey();

      // --- Phase 1: active FS session ---
      final auxRepo = AuxRecordRepository();
      auxRepo.setActiveContext(
          scopeToken: identityContext, auxStorageKey: auxKey);
      final registry = FsContactSecurityRegistry();
      final persistence = FsStatePersistenceService(
        auxRepository: auxRepo,
        registry: registry,
      );
      final ratchetService =
          FsRatchetPersistenceService(auxRepository: auxRepo);

      // Save active state + ratchet
      final state = FsContactSecurityState(
        contactId: contactId,
        identityContext: identityContext,
        sessionId: sessionId,
        fsState: FsSessionState.fsActive,
      );
      registry.upsert(state);
      await persistence.saveState(state);
      await ratchetService.saveRatchetState(RatchetState(
        sessionId: sessionId,
        rootKey: Uint8List(32)..fillRange(0, 32, 0x01),
        sendingChainKey: Uint8List(32)..fillRange(0, 32, 0x02),
        receivingChainKey: Uint8List(32)..fillRange(0, 32, 0x03),
        localRatchetPriv: Uint8List(32)..fillRange(0, 32, 0x04),
        localRatchetPub: Uint8List(32)..fillRange(0, 32, 0x05),
        lastRemoteRatchetPub: Uint8List(32)..fillRange(0, 32, 0x06),
        sendCounter: 10,
        recvCounter: 8,
        skippedKeys: const {},
      ));

      // --- Phase 2: identity reset ---
      registry.markAllBroken(identityContext);
      await persistence.removeAllStates(identityContext);
      await ratchetService.removeAllRatchetStates();

      // --- Phase 3: restore (same seed → same aux key) ---
      final restoredRegistry = FsContactSecurityRegistry();
      final restoredPersistence = FsStatePersistenceService(
        auxRepository: auxRepo,
        registry: restoredRegistry,
      );
      final restoredRatchet =
          FsRatchetPersistenceService(auxRepository: auxRepo);

      await restoredPersistence.loadPersistedState();
      final allRatchets = await restoredRatchet.loadAllRatchetStates();

      expect(restoredRegistry.isEmpty, isTrue,
          reason: 'No FS states should survive identity reset');
      expect(allRatchets, isEmpty,
          reason: 'No ratchets should survive identity reset');

      // --- Phase 4: partner sends fresh fs_init → accepted ---
      final freshSession = FsSessionManager();
      expect(freshSession.state, FsSessionState.legacyOnly);

      final partnerInit = FsInitPayload(
        initId: 'fresh-init-after-restore',
        initiatorDevicePub: 'AQ${'E' * 42}',
        initiatorEphemeralPub: 'AQ${'F' * 42}',
        caps: const ['fs_v1'],
        createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
        ekAPrivBytes: Uint8List(32),
      );

      final result = freshSession.processFsInitReceived(
        message: partnerInit.toMessage(),
        localInitId: '',
      );
      expect(result.accepted, isTrue,
          reason: 'Fresh handshake must succeed after identity restore');
      expect(freshSession.state, FsSessionState.fsInitSeen);
    });
  });

  // ── 6. Plausible deniability in persisted FS state ────────────────────────

  group('Plausible deniability in persisted state', () {
    test(
        'persisted aux records contain no device labels or platform identifiers',
        () async {
      const identityContext = 'primary';
      final auxKey = await buildAuxKey();

      final auxRepo = AuxRecordRepository();
      auxRepo.setActiveContext(
          scopeToken: identityContext, auxStorageKey: auxKey);
      final registry = FsContactSecurityRegistry();
      final persistence = FsStatePersistenceService(
        auxRepository: auxRepo,
        registry: registry,
      );

      // Save a state with remoteDeviceId (internal tracking only)
      final state = FsContactSecurityState(
        contactId: 'contact-dave',
        identityContext: identityContext,
        sessionId: 'session-123',
        fsState: FsSessionState.fsActive,
        remoteDeviceId: 'some-device-pub-key',
      );
      registry.upsert(state);
      await persistence.saveState(state);

      // Read raw aux records to verify what's actually stored
      final allRecords = auxRepo.getAllAuxRecordIds();
      expect(allRecords, isNotEmpty);

      for (final entry in allRecords.entries) {
        final payload = await auxRepo.read(
          storageId: entry.key,
          recordId: entry.value,
        );
        if (payload == null) continue;
        if (payload['kind'] != 'fs_state_v1') continue;

        // The payload is encrypted at rest, but verify the decrypted structure
        // doesn't contain forbidden fields
        final keys = payload.keys.toSet();
        for (final forbidden in [
          'deviceName',
          'device_name',
          'deviceLabel',
          'device_label',
          'platform',
          'os',
          'model',
          'manufacturer',
          'android',
          'ios',
          'phone',
          'tablet',
        ]) {
          expect(keys, isNot(contains(forbidden)),
              reason: 'Aux payload must not contain "$forbidden"');
        }

        // Verify the payload uses opaque identifiers
        expect(payload['kind'], 'fs_state_v1');
        expect(payload.containsKey('contactId'), isTrue);
        expect(payload.containsKey('fsState'), isTrue);
      }
    });

    test('passphrase context states are NOT persisted (RAM-only)', () async {
      const identityContext = 'primary';
      const passphraseContext = 'passphrase-ctx-abc';
      final auxKey = await buildAuxKey();

      final auxRepo = AuxRecordRepository();
      auxRepo.setActiveContext(
          scopeToken: identityContext, auxStorageKey: auxKey);
      final registry = FsContactSecurityRegistry();
      final persistence = FsStatePersistenceService(
        auxRepository: auxRepo,
        registry: registry,
      );

      // Save primary context state (should persist)
      final primaryState = FsContactSecurityState(
        contactId: 'contact-eve',
        identityContext: identityContext,
        sessionId: 'primary-session',
        fsState: FsSessionState.fsActive,
      );
      registry.upsert(primaryState);
      await persistence.saveState(primaryState);

      // Save passphrase context state (should NOT persist)
      final passphraseState = FsContactSecurityState(
        contactId: 'contact-eve',
        identityContext: passphraseContext,
        sessionId: 'passphrase-session',
        fsState: FsSessionState.fsActive,
      );
      registry.upsert(passphraseState);
      await persistence.saveState(passphraseState);

      // Restart: only primary context should be restored
      final registry2 = FsContactSecurityRegistry();
      final persistence2 = FsStatePersistenceService(
        auxRepository: auxRepo,
        registry: registry2,
      );
      await persistence2.loadPersistedState();

      expect(
          registry2.lookup(
            contactId: 'contact-eve',
            identityContext: identityContext,
            sessionId: 'primary-session',
          ),
          isNotNull,
          reason: 'Primary context must survive restart');

      expect(
          registry2.lookup(
            contactId: 'contact-eve',
            identityContext: passphraseContext,
            sessionId: 'passphrase-session',
          ),
          isNull,
          reason: 'Passphrase context must NOT survive restart');
    });
  });
}
