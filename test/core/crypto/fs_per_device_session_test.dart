/// Tests for per-device FS session management (§7.3, §7.9).
///
/// These tests verify that:
/// 1. FsDeviceSessionRouter correctly archives previous sessions
/// 2. FsOpportunisticController rotates sessions on new device detection
/// 3. Ratchets from both old and new devices can be used simultaneously
/// 4. Registry tracks per-device entries
/// 5. Plausible deniability is maintained (no device labels leak)
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_device_session_router.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_opportunistic_controller.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';

class _TestClock implements FsClock {
  int _now = 1700000000;

  @override
  int nowSeconds() => _now;

  void advance(int seconds) => _now += seconds;
}

void main() {
  group('FsDeviceSessionRouter', () {
    late _TestClock clock;
    late FsDeviceSessionRouter router;

    setUp(() {
      clock = _TestClock();
      router = FsDeviceSessionRouter(clock: clock);
    });

    test('initial state: one session, no previous', () {
      expect(router.sessionCount, 1);
      expect(router.previousSessionCount, 0);
      expect(router.currentSession, isNotNull);
      expect(router.currentSession.state, FsSessionState.legacyOnly);
    });

    test('rotateForNewDevice archives current session and creates fresh one',
        () {
      // Simulate current session reaching fsActive
      final original = router.currentSession;
      original.setStateForTesting(FsSessionState.fsActive,
          sessionId: 'session-A');

      // Rotate for new device
      final newSession = router.rotateForNewDevice();

      // New session is fresh
      expect(newSession, isNot(same(original)));
      expect(newSession.state, FsSessionState.legacyOnly);
      expect(router.currentSession, same(newSession));

      // Old session is archived
      expect(router.previousSessionCount, 1);
      expect(router.sessionForId('session-A'), same(original));
      expect(router.sessionForId('session-A')!.state, FsSessionState.fsActive);
    });

    test('multiple device rotations preserve all previous sessions', () {
      // Device A reaches active
      router.currentSession
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-A');
      router.rotateForNewDevice();

      // Device B reaches active
      router.currentSession
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-B');
      router.rotateForNewDevice();

      // Device C is current (handshaking)
      expect(router.previousSessionCount, 2);
      expect(router.sessionCount, 3);
      expect(router.sessionForId('session-A')!.state, FsSessionState.fsActive);
      expect(router.sessionForId('session-B')!.state, FsSessionState.fsActive);
      expect(router.currentSession.state, FsSessionState.legacyOnly);
    });

    test('sessionForId finds current session by its ID', () {
      router.currentSession.setStateForTesting(FsSessionState.fsActive,
          sessionId: 'current-session');

      final found = router.sessionForId('current-session');
      expect(found, same(router.currentSession));
    });

    test('sessionForId returns null for unknown ID', () {
      expect(router.sessionForId('unknown'), isNull);
    });

    test('bestState returns fsActive when current is active', () {
      router.currentSession
          .setStateForTesting(FsSessionState.fsActive, sessionId: 's1');
      expect(router.bestState, FsSessionState.fsActive);
    });

    test('bestState returns fsActive from previous when current is handshaking',
        () {
      // Previous device still active
      router.currentSession.setStateForTesting(FsSessionState.fsActive,
          sessionId: 'old-session');
      router.rotateForNewDevice();
      // Current is in handshake (legacyOnly)
      expect(router.currentSession.state, FsSessionState.legacyOnly);
      expect(router.bestState, FsSessionState.fsActive);
    });

    test('allActiveSessionIds returns IDs from current and previous', () {
      router.currentSession
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-A');
      router.rotateForNewDevice();
      router.currentSession
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-B');

      final ids = router.allActiveSessionIds;
      expect(ids, containsAll(['session-A', 'session-B']));
      expect(ids.length, 2);
    });

    test('resetAll clears current and previous sessions', () {
      router.currentSession
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-A');
      router.rotateForNewDevice();
      router.currentSession
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-B');

      router.resetAll();

      expect(router.previousSessionCount, 0);
      expect(router.currentSession.state, FsSessionState.legacyOnly);
    });

    test('markAllBroken marks current and all previous as broken', () {
      router.currentSession
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-A');
      router.rotateForNewDevice();
      router.currentSession
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-B');

      router.markAllBroken();

      expect(router.currentSession.state, FsSessionState.fsBroken);
      expect(router.sessionForId('session-A')!.state, FsSessionState.fsBroken);
    });

    test('cleanupStaleSessions removes broken/legacy previous sessions', () {
      // Device A → active
      router.currentSession
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-A');
      router.rotateForNewDevice();
      // Device B → broken
      router.currentSession
          .setStateForTesting(FsSessionState.fsBroken, sessionId: 'session-B');
      router.rotateForNewDevice();
      // Device C → active
      router.currentSession
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-C');

      // session-A is active (kept), session-B is broken (cleaned up)
      router.cleanupStaleSessions();

      expect(router.previousSessionCount, 1); // only session-A remains
      expect(router.sessionForId('session-A'), isNotNull);
      expect(router.sessionForId('session-B'), isNull);
    });
  });

  group('FsOpportunisticController per-device routing', () {
    late _TestClock clock;
    late FsContactSecurityRegistry registry;

    setUp(() {
      clock = _TestClock();
      registry = FsContactSecurityRegistry();
    });

    test('new fs_init in fsActive state creates new device session', () async {
      final controller = FsOpportunisticController(
        sessionManager: FsSessionManager(clock: clock),
        registry: registry,
        localContactId: 'contact-1',
        identityContext: 'primary',
        clock: clock,
      );

      // Simulate reaching fsActive
      controller.sessionManager.setStateForTesting(FsSessionState.fsActive,
          sessionId: 'session-deviceA');

      // New fs_init arrives (from Device B)
      final result = await controller.processIncomingEnvelope(
        {
          'x': {
            'fs': FsInitMessage(
              initId: 'init-deviceB',
              initiatorDevicePub: 'device-B-pub',
              initiatorEphemeralPub: 'ek-B',
              caps: const ['lgfs1'],
              createdAt: clock.nowSeconds(),
            ).toJson(),
          },
        },
        remoteContactId: 'contact-1',
      );

      // Should accept the new handshake
      expect(result.accepted, isTrue);
      expect(result.newDeviceDetected, isTrue);
      expect(result.type, FsIncomingType.fsInitAccepted);

      // The router should have archived the old session
      expect(controller.deviceRouter.previousSessionCount, 1);
      expect(
          controller.deviceRouter.sessionForId('session-deviceA'), isNotNull);
      expect(
        controller.deviceRouter.sessionForId('session-deviceA')!.state,
        FsSessionState.fsActive,
      );

      // Current session is now handshaking with Device B
      expect(controller.sessionManager.state, FsSessionState.fsInitSeen);
    });

    test('new fs_init in fsBroken state also rotates', () async {
      final controller = FsOpportunisticController(
        sessionManager: FsSessionManager(clock: clock),
        registry: registry,
        localContactId: 'contact-1',
        identityContext: 'primary',
        clock: clock,
      );

      controller.sessionManager.setStateForTesting(FsSessionState.fsBroken,
          sessionId: 'broken-session');

      final result = await controller.processIncomingEnvelope(
        {
          'x': {
            'fs': FsInitMessage(
              initId: 'init-recover',
              initiatorDevicePub: 'recover-pub',
              initiatorEphemeralPub: 'ek-recover',
              caps: const ['lgfs1'],
              createdAt: clock.nowSeconds(),
            ).toJson(),
          },
        },
        remoteContactId: 'contact-1',
      );

      expect(result.accepted, isTrue);
      expect(result.newDeviceDetected, isTrue);
    });

    test('fs_init in legacyOnly does NOT trigger device rotation', () async {
      final controller = FsOpportunisticController(
        sessionManager: FsSessionManager(clock: clock),
        registry: registry,
        localContactId: 'contact-1',
        identityContext: 'primary',
        clock: clock,
      );

      // State is legacyOnly (fresh, no previous session)
      expect(controller.state, FsSessionState.legacyOnly);

      final result = await controller.processIncomingEnvelope(
        {
          'x': {
            'fs': FsInitMessage(
              initId: 'first-init',
              initiatorDevicePub: 'first-pub',
              initiatorEphemeralPub: 'ek-first',
              caps: const ['lgfs1'],
              createdAt: clock.nowSeconds(),
            ).toJson(),
          },
        },
        remoteContactId: 'contact-1',
      );

      expect(result.accepted, isTrue);
      expect(result.newDeviceDetected, isFalse,
          reason: 'No device rotation when no previous terminal session');
      expect(controller.deviceRouter.previousSessionCount, 0);
    });

    test('registry tracks separate entries for each device session', () async {
      final controller = FsOpportunisticController(
        sessionManager: FsSessionManager(clock: clock),
        registry: registry,
        localContactId: 'contact-1',
        identityContext: 'primary',
        clock: clock,
      );

      // Device A reaches active
      controller.sessionManager
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-A');
      // Manually update registry for Device A
      registry.upsert(FsContactSecurityState(
        contactId: 'contact-1',
        identityContext: 'primary',
        sessionId: 'session-A',
        fsState: FsSessionState.fsActive,
      ));

      // Device B sends fs_init → rotates
      await controller.processIncomingEnvelope(
        {
          'x': {
            'fs': FsInitMessage(
              initId: 'init-B',
              initiatorDevicePub: 'B-pub',
              initiatorEphemeralPub: 'ek-B',
              caps: const ['lgfs1'],
              createdAt: clock.nowSeconds(),
            ).toJson(),
          },
        },
        remoteContactId: 'contact-1',
      );

      // Registry should have entries for both sessions
      final entries = registry.forContact(
        contactId: 'contact-1',
        identityContext: 'primary',
      );
      // At least 2: session-A (from manual upsert) + init-B (from controller)
      expect(entries.length, greaterThanOrEqualTo(2));

      // Verify that session-A entry is still there with fsActive
      final sessionAEntry = entries.firstWhere(
        (e) => e.sessionId == 'session-A',
        orElse: () => throw StateError('session-A not found in registry'),
      );
      expect(sessionAEntry.fsState, FsSessionState.fsActive);
    });

    test('allActiveSessionIds returns IDs from all device sessions', () async {
      final controller = FsOpportunisticController(
        sessionManager: FsSessionManager(clock: clock),
        registry: registry,
        localContactId: 'contact-1',
        identityContext: 'primary',
        clock: clock,
      );

      controller.sessionManager
          .setStateForTesting(FsSessionState.fsActive, sessionId: 'session-A');

      // Before rotation: only session-A
      expect(controller.allActiveSessionIds, ['session-A']);

      // After rotation: session-A preserved, current has no active session yet
      await controller.processIncomingEnvelope(
        {
          'x': {
            'fs': FsInitMessage(
              initId: 'init-B',
              initiatorDevicePub: 'B-pub',
              initiatorEphemeralPub: 'ek-B',
              caps: const ['lgfs1'],
              createdAt: clock.nowSeconds(),
            ).toJson(),
          },
        },
        remoteContactId: 'contact-1',
      );
      expect(controller.allActiveSessionIds, ['session-A']);
    });
  });

  group('Plausible deniability: per-device state', () {
    test('FsContactSecurityState does not expose device labels externally', () {
      // remoteDeviceId is opaque, not a human-readable label
      final state = FsContactSecurityState(
        contactId: 'contact-1',
        identityContext: 'primary',
        sessionId: 'session-123',
        fsState: FsSessionState.fsActive,
        remoteDeviceId: 'xoaRQVZhCE8ux1exf4uY5w==', // opaque pub key bytes
      );

      // toString should not reveal device identity in a meaningful way
      final str = state.toString();
      expect(str, isNot(contains('Device')),
          reason: 'No device label in toString()');
      expect(str, contains('session=session-123'));
    });

    test('per-device sessions are keyed by sessionId, not device name', () {
      final registry = FsContactSecurityRegistry();

      // Two sessions for same contact, different devices — keyed by sessionId
      registry.upsert(const FsContactSecurityState(
        contactId: 'alice',
        identityContext: 'primary',
        sessionId: 'sess-A',
        fsState: FsSessionState.fsActive,
        remoteDeviceId: 'opaque-bytes-A',
      ));
      registry.upsert(const FsContactSecurityState(
        contactId: 'alice',
        identityContext: 'primary',
        sessionId: 'sess-B',
        fsState: FsSessionState.fsInitSeen,
        remoteDeviceId: 'opaque-bytes-B',
      ));

      final entries = registry.forContact(
        contactId: 'alice',
        identityContext: 'primary',
      );
      expect(entries.length, 2);

      // No device labels are used as keys — only sessionId + identityContext
      final sessA = registry.lookup(
        contactId: 'alice',
        identityContext: 'primary',
        sessionId: 'sess-A',
      );
      expect(sessA?.fsState, FsSessionState.fsActive);
    });
  });
}
