// Tests for FsSessionManager state machine (FS Spec Phase 4).
//
// Acceptance criteria (from roadmap §7 / Phase 4 Mandatory Tests):
//
//  T4.1  Alice sends fs_init; Bob replies later; session succeeds.
//  T4.2  Bob sends fs_init before seeing Alice's; tie-break selects one.
//  T4.3  fs_reply arrives before local fs_init processing; state remains safe.
//  T4.4  fs_confirm duplicated; no duplicate active session.
//  T4.5  Old fs_init replayed after fs_active; no downgrade.
//  T4.6  createdAt too far in future; no silent activation.
//  T4.7  createdAt too old; message rejected.
//  T4.8  Handshake TTL expired; local reset to legacyOnly.
//  T4.9  fs_confirm MAC failure; session transitions to fsBroken.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';

// ---------------------------------------------------------------------------
// Test clock that can be advanced manually.
// ---------------------------------------------------------------------------

class _FakeClock implements FsClock {
  int _now;

  _FakeClock(this._now);

  @override
  int nowSeconds() => _now;

  void advance(int seconds) => _now += seconds;
}

// ---------------------------------------------------------------------------
// Minimal stub messages for the state machine tests (no crypto needed here).
// ---------------------------------------------------------------------------

FsInitMessage _stubInit({
  String initId = 'initAAA',
  int? createdAt,
}) =>
    FsInitMessage(
      initId: initId,
      initiatorDevicePub: 'AQ${'A' * 42}',
      initiatorEphemeralPub: 'AQ${'A' * 42}',
      caps: const ['lgfs1'],
      createdAt: createdAt ?? _kNow,
    );

FsReplyMessage _stubReply({
  String initId = 'initAAA',
  String replyId = 'replyBBB',
  int? createdAt,
}) =>
    FsReplyMessage(
      initId: initId,
      replyId: replyId,
      responderDevicePub: 'AQ${'A' * 42}',
      responderEphemeralPub: 'AQ${'A' * 42}',
      responderInitialRatchetPub: 'AQ${'A' * 42}',
      caps: const ['lgfs1'],
      createdAt: createdAt ?? _kNow,
    );

FsConfirmMessage _stubConfirm({
  String initId = 'initAAA',
  String replyId = 'replyBBB',
}) =>
    FsConfirmMessage(
      initId: initId,
      replyId: replyId,
      transcriptHash: 'A' * 43,
      confirmTag: 'A' * 43,
      initiatorInitialRatchetPub: 'AQ${'A' * 42}',
    );

FsInitPayload _stubInitPayload({String initId = 'initAAA', int? createdAt}) =>
    FsInitPayload(
      initId: initId,
      initiatorDevicePub: 'AQ${'A' * 42}',
      initiatorEphemeralPub: 'AQ${'A' * 42}',
      caps: const ['lgfs1'],
      createdAt: createdAt ?? _kNow,
      ekAPrivBytes: Uint8List(32),
    );

FsReplyPayload _stubReplyPayload({
  String initId = 'initAAA',
  String replyId = 'replyBBB',
  int? createdAt,
}) =>
    FsReplyPayload(
      initId: initId,
      replyId: replyId,
      responderDevicePub: 'AQ${'A' * 42}',
      responderEphemeralPub: 'AQ${'A' * 42}',
      responderInitialRatchetPub: 'AQ${'A' * 42}',
      responderInitialRatchetPriv: Uint8List(32),
      caps: const ['lgfs1'],
      createdAt: createdAt ?? _kNow,
      partialState: FsHandshakePartialState(
        transcriptHash: Uint8List(32),
        rootKey0: Uint8List(32),
        sendingChainKey0: Uint8List(32),
        receivingChainKey0: Uint8List(32),
        isInitiator: false,
      ),
    );

FsConfirmPayload _stubConfirmPayload({
  String initId = 'initAAA',
  String replyId = 'replyBBB',
}) =>
    FsConfirmPayload(
      initId: initId,
      replyId: replyId,
      transcriptHash: 'A' * 43,
      confirmTag: 'A' * 43,
      initiatorInitialRatchetPub: 'AQ${'A' * 42}',
      initiatorInitialRatchetPriv: Uint8List(32),
      partialState: FsHandshakePartialState(
        transcriptHash: Uint8List(32),
        rootKey0: Uint8List(32),
        sendingChainKey0: Uint8List(32),
        receivingChainKey0: Uint8List(32),
        isInitiator: true,
      ),
    );

const int _kNow = 1700000000;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  // T4.1 — Full happy path.
  test(
      'T4.1: Alice → fs_init_sent; Bob → fs_init_seen → fs_reply_sent → fs_reply_seen; Alice → fs_confirm_sent; Bob → fs_confirmed; both → fs_active',
      () {
    final aliceMgr = FsSessionManager(clock: _FakeClock(_kNow));
    final bobMgr = FsSessionManager(clock: _FakeClock(_kNow));

    // Alice sends FS_INIT.
    final r1 = aliceMgr.recordFsInitSent(_stubInitPayload());
    expect(r1.accepted, isTrue);
    expect(aliceMgr.state, equals(FsSessionState.fsInitSent));

    // Bob receives FS_INIT.
    final r2 = bobMgr.processFsInitReceived(
      message: _stubInit(),
      localInitId: '',
    );
    expect(r2.accepted, isTrue);
    expect(bobMgr.state, equals(FsSessionState.fsInitSeen));

    // Bob sends FS_REPLY.
    final r3 = bobMgr.recordFsReplySent(_stubReplyPayload());
    expect(r3.accepted, isTrue);
    expect(bobMgr.state, equals(FsSessionState.fsReplySent));

    // Alice receives FS_REPLY.
    final r4 = aliceMgr.processFsReplyReceived(_stubReply());
    expect(r4.accepted, isTrue);
    expect(aliceMgr.state, equals(FsSessionState.fsReplySeen));

    // Alice sends FS_CONFIRM.
    final r5 = aliceMgr.recordFsConfirmSent(_stubConfirmPayload());
    expect(r5.accepted, isTrue);
    expect(aliceMgr.state, equals(FsSessionState.fsConfirmSent));

    // Alice activates (she knows it's confirmed after sending CONFIRM).
    final r6 = aliceMgr.activateSession('session-1');
    expect(r6.accepted, isTrue);
    expect(aliceMgr.state, equals(FsSessionState.fsActive));

    // Bob receives FS_CONFIRM (verified = true).
    final r7 = bobMgr.processFsConfirmReceived(
      message: _stubConfirm(),
      verified: true,
    );
    expect(r7.accepted, isTrue);
    expect(bobMgr.state, equals(FsSessionState.fsConfirmed));

    // Bob activates.
    final r8 = bobMgr.activateSession('session-1');
    expect(r8.accepted, isTrue);
    expect(bobMgr.state, equals(FsSessionState.fsActive));
  });

  // T4.2 — Simultaneous FS_INIT: tie-break.
  test('T4.2: simultaneous FS_INIT tie-break selects deterministic winner', () {
    final aliceMgr = FsSessionManager(clock: _FakeClock(_kNow));
    final bobMgr = FsSessionManager(clock: _FakeClock(_kNow));

    const aliceInitId = 'aaaaaaa'; // lexicographically smaller → Alice wins
    const bobInitId = 'zzzzzzz';

    // Both send their FS_INIT.
    aliceMgr.recordFsInitSent(_stubInitPayload(initId: aliceInitId));
    bobMgr.recordFsInitSent(_stubInitPayload(initId: bobInitId));

    // Alice receives Bob's FS_INIT while in fsInitSent.
    final rAlice = aliceMgr.processFsInitReceived(
      message: _stubInit(initId: bobInitId),
      localInitId: aliceInitId,
    );
    // Alice wins tie-break (smaller id) → she remains initiator, ignores Bob's init.
    expect(rAlice.accepted, isFalse,
        reason: 'Alice wins tie-break so she rejects the incoming FS_INIT');
    expect(aliceMgr.state, equals(FsSessionState.fsInitSent));

    // Bob receives Alice's FS_INIT while in fsInitSent.
    final rBob = bobMgr.processFsInitReceived(
      message: _stubInit(initId: aliceInitId),
      localInitId: bobInitId,
    );
    // Bob loses tie-break → he becomes responder.
    expect(rBob.accepted, isTrue,
        reason: 'Bob loses tie-break so he accepts the incoming FS_INIT');
    expect(bobMgr.state, equals(FsSessionState.fsInitSeen));
    expect(bobMgr.pendingInitId, equals(aliceInitId));
  });

  // T4.3 — FS_REPLY received before FS_INIT local processing: state remains safe.
  test('T4.3: FS_REPLY received while still in legacyOnly is rejected', () {
    final mgr = FsSessionManager(clock: _FakeClock(_kNow));

    // Never sent FS_INIT; receive FS_REPLY directly.
    final r = mgr.processFsReplyReceived(_stubReply());
    expect(r.accepted, isFalse);
    expect(mgr.state, equals(FsSessionState.legacyOnly),
        reason: 'State must not change on unexpected FS_REPLY');
  });

  // T4.4 — Duplicate FS_CONFIRM: no second active session.
  test('T4.4: duplicate FS_CONFIRM has no effect after fsConfirmed', () {
    final bobMgr = FsSessionManager(clock: _FakeClock(_kNow));
    bobMgr.processFsInitReceived(message: _stubInit(), localInitId: '');
    bobMgr.recordFsReplySent(_stubReplyPayload());

    // First CONFIRM.
    bobMgr.processFsConfirmReceived(message: _stubConfirm(), verified: true);
    expect(bobMgr.state, equals(FsSessionState.fsConfirmed));
    bobMgr.activateSession('session-1');
    expect(bobMgr.state, equals(FsSessionState.fsActive));

    // Duplicate CONFIRM.
    final r = bobMgr.processFsConfirmReceived(
        message: _stubConfirm(), verified: true);
    expect(r.accepted, isFalse,
        reason: 'Duplicate FS_CONFIRM must be rejected in fsActive state');
    expect(bobMgr.state, equals(FsSessionState.fsActive),
        reason: 'State must not change on duplicate FS_CONFIRM');
  });

  // T4.5 — New FS_INIT received after fsActive: accepted (partner reset §8.8).
  // Anti-replay for old initIds is handled by the controller's replay cache,
  // not by the session manager.
  test('T4.5: new FS_INIT after fsActive is accepted (partner reset)', () {
    final bobMgr = FsSessionManager(clock: _FakeClock(_kNow));
    // Fast-forward to fsActive.
    bobMgr.processFsInitReceived(message: _stubInit(), localInitId: '');
    bobMgr.recordFsReplySent(_stubReplyPayload());
    bobMgr.processFsConfirmReceived(message: _stubConfirm(), verified: true);
    bobMgr.activateSession('session-1');
    expect(bobMgr.state, equals(FsSessionState.fsActive));

    // New FS_INIT from partner who reset their identity.
    final r = bobMgr.processFsInitReceived(
      message: _stubInit(initId: 'new-init-after-reset'),
      localInitId: '',
    );
    expect(r.accepted, isTrue,
        reason: 'New FS_INIT in fsActive must be accepted (partner reset)');
    expect(bobMgr.state, equals(FsSessionState.fsInitSeen),
        reason: 'State must transition to fsInitSeen for new handshake');
    expect(bobMgr.activeSessionId, isNull,
        reason: 'Old session must be cleared');
  });

  // T4.6 — createdAt too far in the future: rejected.
  test('T4.6: FS_INIT with future createdAt is rejected', () {
    final clock = _FakeClock(_kNow);
    final mgr = FsSessionManager(clock: clock, maxCreatedAtSkewSeconds: 300);

    final farFuture = _kNow + 600; // 10 min in future > 5 min skew
    final r = mgr.processFsInitReceived(
      message: _stubInit(createdAt: farFuture),
      localInitId: '',
    );
    expect(r.accepted, isFalse, reason: 'Future createdAt must be rejected');
    expect(mgr.state, equals(FsSessionState.legacyOnly));
  });

  // T4.7 — createdAt too old: rejected.
  test('T4.7: FS_INIT with createdAt older than maxAge is rejected', () {
    final clock = _FakeClock(_kNow);
    final mgr = FsSessionManager(
      clock: clock,
      maxCreatedAtAgeSeconds: 60 * 60, // 1 hour
    );

    final tooOld = _kNow - 2 * 60 * 60; // 2 hours ago
    final r = mgr.processFsInitReceived(
      message: _stubInit(createdAt: tooOld),
      localInitId: '',
    );
    expect(r.accepted, isFalse, reason: 'Old createdAt must be rejected');
    expect(mgr.state, equals(FsSessionState.legacyOnly));
  });

  // T4.8 — Handshake TTL expired: local reset.
  test(
      'T4.8: FS_REPLY rejected and state reset when local handshake TTL expires',
      () {
    final clock = _FakeClock(_kNow);
    final mgr = FsSessionManager(
      clock: clock,
      maxHandshakeTtlSeconds: 60,
    );

    // Send FS_INIT.
    mgr.recordFsInitSent(_stubInitPayload());
    expect(mgr.state, equals(FsSessionState.fsInitSent));

    // Advance clock past TTL.
    clock.advance(120);

    // FS_REPLY arrives: should be rejected and state reset.
    final r = mgr.processFsReplyReceived(_stubReply(createdAt: _kNow + 120));
    expect(r.accepted, isFalse, reason: 'FS_REPLY must be rejected after TTL');
    expect(mgr.state, equals(FsSessionState.legacyOnly),
        reason: 'State must reset to legacyOnly after TTL expiry');
  });

  // T4.9 — FS_CONFIRM MAC failure: session becomes fsBroken.
  test('T4.9: FS_CONFIRM MAC failure transitions to fsBroken', () {
    final bobMgr = FsSessionManager(clock: _FakeClock(_kNow));
    bobMgr.processFsInitReceived(message: _stubInit(), localInitId: '');
    bobMgr.recordFsReplySent(_stubReplyPayload());

    final r = bobMgr.processFsConfirmReceived(
      message: _stubConfirm(),
      verified: false,
    );
    expect(r.accepted, isFalse);
    expect(bobMgr.state, equals(FsSessionState.fsBroken),
        reason: 'Failed CONFIRM MAC must result in fsBroken');
  });

  // T4.10 — fsBroken blocks outgoing FS_INIT but accepts incoming (partner reset).
  test(
      'T4.10: fsBroken blocks FS_INIT sending but accepts incoming FS_INIT (partner reset)',
      () {
    final mgr = FsSessionManager(clock: _FakeClock(_kNow));

    // Force state to fsBroken using setStateForTesting
    mgr.setStateForTesting(FsSessionState.fsBroken);

    // Verify cannot send FS_INIT from fsBroken (via recordFsInitSent)
    final sendResult = mgr.recordFsInitSent(_stubInitPayload());
    expect(sendResult.accepted, isFalse,
        reason: 'Cannot initiate handshake from fsBroken state');
    expect(mgr.state, equals(FsSessionState.fsBroken),
        reason: 'State must remain fsBroken after failed send attempt');

    // Incoming FS_INIT triggers partner-reset detection → accepted (§8.8)
    final receiveResult = mgr.processFsInitReceived(
      message: _stubInit(),
      localInitId: '',
    );
    expect(receiveResult.accepted, isTrue,
        reason:
            'Incoming FS_INIT in fsBroken must be accepted (partner reset)');
    expect(mgr.state, equals(FsSessionState.fsInitSeen),
        reason: 'State must transition to fsInitSeen after partner reset');
  });

  // T4.11 — fsActive accepts incoming FS_INIT (partner identity reset).
  test('T4.11: fsActive accepts incoming FS_INIT after partner identity reset',
      () {
    final mgr = FsSessionManager(clock: _FakeClock(_kNow));

    mgr.setStateForTesting(FsSessionState.fsActive);
    mgr.activeSessionId = 'old-session';

    final receiveResult = mgr.processFsInitReceived(
      message: _stubInit(),
      localInitId: '',
    );
    expect(receiveResult.accepted, isTrue,
        reason:
            'Incoming FS_INIT in fsActive must be accepted (partner reset)');
    expect(mgr.state, equals(FsSessionState.fsInitSeen));
    expect(mgr.activeSessionId, isNull,
        reason: 'Old session must be cleared on partner reset');
  });
}
