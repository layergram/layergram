// Tests for FsStrictModeController — Phase 11.
//
// Mandatory tests (roadmap §14 Phase 11):
//
//  T11.1  Request Maximum FS for Bob only (not global).
//  T11.2  requestMaximum in legacyOnly → notYetActive (cannot activate yet).
//  T11.3  requestMaximum in fsActive → strictRequested.
//  T11.4  Alice/Bob handshake completes; activateStrict → strictFsActive.
//  T11.5  New Bob device appears; canSendMessage returns false (pause).
//  T11.6  Disable Maximum FS; state reverts to fsActive, fallback allowed.
//  T11.7  Passphrase context isolation: strict state per (contactId, context).
//  T11.8  activateStrict without prior requestMaximum → notRequested.
//  T11.9  canSendMessage in strictFsActive without device change → true.
//  T11.10 sendBlockReason explains the block reason correctly.

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_contact_security_state.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/core/crypto/fs_strict_mode_controller.dart';

class _FakeClock implements FsClock {
  _FakeClock();
  @override
  int nowSeconds() => 1700000000;
}

(FsStrictModeController, FsSessionManager, FsContactSecurityRegistry) _build({
  String contactId = 'bob',
  String identityContext = 'primary',
}) {
  final registry = FsContactSecurityRegistry();
  final mgr = FsSessionManager(clock: _FakeClock());
  final ctrl = FsStrictModeController(
    contactId: contactId,
    identityContext: identityContext,
    sessionManager: mgr,
    registry: registry,
  );
  return (ctrl, mgr, registry);
}

void main() {
  // T11.1 — Request Maximum FS for Bob only; Alice's state unchanged.
  test('T11.1: requestMaximum is per-contact — Alice registry unaffected', () {
    final (bobCtrl, bobMgr, bobRegistry) = _build(contactId: 'bob');
    final (aliceCtrl, aliceMgr, aliceRegistry) = _build(contactId: 'alice');

    // Drive Bob's session to fsActive.
    bobMgr.setStateForTesting(FsSessionState.fsActive,
        sessionId: 'session-bob');

    bobCtrl.requestMaximum('session-bob');
    expect(bobMgr.state, equals(FsSessionState.strictRequested));
    expect(bobRegistry.forContact(contactId: 'bob', identityContext: 'primary'),
        isNotEmpty);

    // Alice's registry is completely separate.
    expect(
      aliceRegistry.forContact(contactId: 'alice', identityContext: 'primary'),
      isEmpty,
    );
    expect(aliceMgr.state, equals(FsSessionState.legacyOnly));
  });

  // T11.2 — requestMaximum in legacyOnly → notYetActive.
  test('T11.2: requestMaximum in legacyOnly returns notYetActive', () {
    final (ctrl, mgr, _) = _build();
    expect(mgr.state, equals(FsSessionState.legacyOnly));

    final result = ctrl.requestMaximum('no-session-yet');
    expect(result.success, isFalse);
    expect(result.code, equals(FsStrictModeResultCode.notYetActive));
    expect(mgr.state, equals(FsSessionState.legacyOnly),
        reason: 'State must not change on failed request');
  });

  // T11.3 — requestMaximum in fsActive → strictRequested.
  test('T11.3: requestMaximum in fsActive transitions to strictRequested', () {
    final (ctrl, mgr, registry) = _build();
    mgr.setStateForTesting(FsSessionState.fsActive, sessionId: 'session-1');
    expect(mgr.state, equals(FsSessionState.fsActive));

    final result = ctrl.requestMaximum('session-1');
    expect(result.success, isTrue);
    expect(result.code, equals(FsStrictModeResultCode.ok));
    expect(mgr.state, equals(FsSessionState.strictRequested));

    // Registry updated.
    final state = registry.lookup(
      contactId: 'bob',
      identityContext: 'primary',
      sessionId: 'session-1',
    );
    expect(state?.fsState, equals(FsSessionState.strictRequested));
  });

  // T11.4 — activateStrict after requestMaximum → strictFsActive.
  test('T11.4: activateStrict after requestMaximum → strictFsActive', () {
    final (ctrl, mgr, registry) = _build();
    mgr.setStateForTesting(FsSessionState.fsActive, sessionId: 'session-1');
    ctrl.requestMaximum('session-1');
    expect(mgr.state, equals(FsSessionState.strictRequested));

    final result = ctrl.activateStrict('session-1');
    expect(result.success, isTrue);
    expect(mgr.state, equals(FsSessionState.strictFsActive));

    // Registry updated.
    final state = registry.lookup(
      contactId: 'bob',
      identityContext: 'primary',
      sessionId: 'session-1',
    );
    expect(state?.fsState, equals(FsSessionState.strictFsActive));
  });

  // T11.5 — strictFsActive + deviceChanged → canSendMessage = false (pause).
  test('T11.5: new remote device in strictFsActive pauses sending', () {
    final (ctrl, mgr, _) = _build();
    mgr.setStateForTesting(FsSessionState.fsActive, sessionId: 'session-1');
    ctrl.requestMaximum('session-1');
    ctrl.activateStrict('session-1');
    expect(mgr.state, equals(FsSessionState.strictFsActive));

    expect(ctrl.canSendMessage(deviceChanged: true), isFalse,
        reason: 'Unexpected device must block sending in strictFsActive');
    expect(ctrl.canSendMessage(deviceChanged: false), isTrue,
        reason: 'Known device must allow sending');
  });

  test('T11.5b: existing strict consent blocks sending after session rotation',
      () {
    final (ctrl, mgr, registry) = _build();
    mgr.setStateForTesting(FsSessionState.fsActive, sessionId: 'session-old');
    ctrl.requestMaximum('session-old');
    ctrl.activateStrict('session-old');

    expect(mgr.state, equals(FsSessionState.strictFsActive));
    expect(
      registry
          .lookup(
            contactId: 'bob',
            identityContext: 'primary',
            sessionId: 'session-old',
          )
          ?.fsState,
      equals(FsSessionState.strictFsActive),
    );

    mgr.setStateForTesting(FsSessionState.fsInitSeen, sessionId: 'session-new');

    expect(
      ctrl.canSendMessage(),
      isFalse,
      reason: 'A new pending session must not silently bypass Maximum FS',
    );
    expect(ctrl.sendBlockReason(), contains('Maximum Forward Secrecy'));
  });

  // T11.6 — Disable Maximum FS → fsActive, fallback allowed.
  test('T11.6: disableStrict reverts to fsActive; legacy fallback allowed', () {
    final (ctrl, mgr, registry) = _build();
    mgr.setStateForTesting(FsSessionState.fsActive, sessionId: 'session-1');
    ctrl.requestMaximum('session-1');
    ctrl.activateStrict('session-1');
    expect(mgr.state, equals(FsSessionState.strictFsActive));

    final result = ctrl.disableStrict('session-1');
    expect(result.success, isTrue);
    expect(mgr.state, equals(FsSessionState.fsActive));
    expect(ctrl.isStrictRequested, isFalse);

    // Registry updated.
    final state = registry.lookup(
      contactId: 'bob',
      identityContext: 'primary',
      sessionId: 'session-1',
    );
    expect(state?.fsState, equals(FsSessionState.fsActive));

    // Legacy fallback now allowed (no block on deviceChanged).
    expect(ctrl.canSendMessage(deviceChanged: true), isTrue,
        reason: 'After disable, device change must not block sending');
  });

  // T11.7 — Passphrase context isolation.
  test('T11.7: strict state is per (contactId, identityContext) pair', () {
    final sharedRegistry = FsContactSecurityRegistry();

    // Primary context controller for Bob.
    final primaryMgr = FsSessionManager(clock: _FakeClock());
    final primaryCtrl = FsStrictModeController(
      contactId: 'bob',
      identityContext: 'primary',
      sessionManager: primaryMgr,
      registry: sharedRegistry,
    );

    // Passphrase context controller for Bob.
    final ppMgr = FsSessionManager(clock: _FakeClock());
    final ppCtrl = FsStrictModeController(
      contactId: 'bob',
      identityContext: 'pp-ctx-deadbeef',
      sessionManager: ppMgr,
      registry: sharedRegistry,
    );

    primaryMgr.setStateForTesting(FsSessionState.fsActive,
        sessionId: 'primary-session');
    primaryCtrl.requestMaximum('primary-session');
    primaryCtrl.activateStrict('primary-session');
    expect(primaryMgr.state, equals(FsSessionState.strictFsActive));

    // Passphrase context remains independent.
    expect(ppMgr.state, equals(FsSessionState.legacyOnly));
    expect(ppCtrl.isStrictRequested, isFalse);

    final ppState = sharedRegistry.lookup(
      contactId: 'bob',
      identityContext: 'pp-ctx-deadbeef',
      sessionId: 'primary-session',
    );
    expect(ppState, isNull,
        reason: 'Primary strict state must not bleed into passphrase context');
  });

  // T11.8 — activateStrict without prior requestMaximum → notRequested.
  test('T11.8: activateStrict without requestMaximum → notRequested', () {
    final (ctrl, mgr, _) = _build();
    mgr.setStateForTesting(FsSessionState.fsActive, sessionId: 'session-1');
    mgr.requestStrict(); // Manually set state but without ctrl knowing.
    // Ctrl's _strictRequested is still false.
    final result = ctrl.activateStrict('session-1');
    expect(result.success, isFalse);
    expect(result.code, equals(FsStrictModeResultCode.notRequested));
  });

  // T11.9 — canSendMessage in strictFsActive without device change → true.
  test('T11.9: canSendMessage is true in strictFsActive with no device change',
      () {
    final (ctrl, mgr, _) = _build();
    mgr.setStateForTesting(FsSessionState.fsActive, sessionId: 'session-1');
    ctrl.requestMaximum('session-1');
    ctrl.activateStrict('session-1');
    expect(ctrl.canSendMessage(), isTrue);
  });

  // T11.10 — sendBlockReason provides meaningful message.
  test('T11.10: sendBlockReason explains why sending is blocked', () {
    final (ctrl, mgr, _) = _build();
    mgr.setStateForTesting(FsSessionState.fsActive, sessionId: 'session-1');
    ctrl.requestMaximum('session-1');
    ctrl.activateStrict('session-1');

    // Device changed → block with reason.
    final reason = ctrl.sendBlockReason(deviceChanged: true);
    expect(reason, isNotNull);
    expect(reason, contains('Unexpected device'));

    // No device change → no reason.
    expect(ctrl.sendBlockReason(deviceChanged: false), isNull);

    // Broken state → also blocked.
    mgr.markBroken();
    expect(ctrl.sendBlockReason(), isNotNull);
  });

  // T11.11 — Maximum FS cannot be enabled globally: no global flag.
  test('T11.11: FsStrictModeController has no static/global enabled flag', () {
    // Each instance is per-contact. Two controllers must not share state.
    final (ctrl1, mgr1, _) = _build(contactId: 'bob');
    final (ctrl2, mgr2, _) = _build(contactId: 'carol');

    mgr1.setStateForTesting(FsSessionState.fsActive, sessionId: 's1');
    ctrl1.requestMaximum('s1');
    ctrl1.activateStrict('s1');

    expect(mgr1.state, equals(FsSessionState.strictFsActive));
    expect(mgr2.state, equals(FsSessionState.legacyOnly),
        reason: 'Carol must not be affected by Bob\'s strict activation');
    expect(ctrl2.isStrictRequested, isFalse);
  });
}
