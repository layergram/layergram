// Tests for canonical tie-breaking (FS Spec §8.3.4).
//
// Spec requirement:
//   canonicalLocal = EncodeKey(localIdentityPublicKey)
//                  || EncodeKey(localDevicePublicKey)
//                  || localInitId
//   The lexicographically smaller canonical value becomes the winning initiator.
//
// Acceptance criteria:
//
//  T_TB_1  buildCanonical produces deterministic output.
//  T_TB_2  Canonical with smaller IK wins over canonical with larger IK
//          (even if initId alone would indicate the opposite).
//  T_TB_3  When IK and DK are equal, initId breaks the tie.
//  T_TB_4  processFsInitReceived uses canonical form when provided.
//  T_TB_5  Backward compat: when canonical is null, falls back to initId.
//  T_TB_6  buildCanonical includes all three components in correct order.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_handshake.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';

class _FakeClock implements FsClock {
  final int _now;
  const _FakeClock(this._now);

  @override
  int nowSeconds() => _now;
}

const _kNow = 1700000000;

FsInitMessage _stubInit({
  String initId = 'test-init-id',
  String devicePub = 'AQBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
  int? createdAt,
}) =>
    FsInitMessage(
      initId: initId,
      initiatorDevicePub: devicePub,
      initiatorEphemeralPub: 'AQCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
      caps: const ['fs_v1'],
      createdAt: createdAt ?? _kNow,
    );

FsInitPayload _stubInitPayload({String initId = 'test-init-id'}) =>
    FsInitPayload(
      initId: initId,
      initiatorDevicePub: 'AQBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      initiatorEphemeralPub: 'AQCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
      caps: const ['fs_v1'],
      createdAt: _kNow,
      ekAPrivBytes: Uint8List(32),
    );

void main() {
  // T_TB_1
  test('T_TB_1: buildCanonical produces deterministic output', () {
    final c1 = FsSessionManager.buildCanonical(
      identityPublicKey: 'IK_alice',
      devicePublicKey: 'DK_alice',
      initId: 'init-123',
    );
    final c2 = FsSessionManager.buildCanonical(
      identityPublicKey: 'IK_alice',
      devicePublicKey: 'DK_alice',
      initId: 'init-123',
    );
    expect(c1, equals(c2));
    expect(c1, equals('IK_aliceDK_aliceinit-123'));
  });

  // T_TB_2
  test('T_TB_2: canonical with smaller IK wins even if initId is larger', () {
    final mgr1 = FsSessionManager(clock: const _FakeClock(_kNow));
    final mgr2 = FsSessionManager(clock: const _FakeClock(_kNow));

    // Alice has smaller IK but larger initId.
    const aliceIK = 'AAAA_ik';
    const aliceDK = 'AAAA_dk';
    const aliceInitId = 'zzzz'; // larger initId

    // Bob has larger IK but smaller initId.
    const bobIK = 'ZZZZ_ik';
    const bobDK = 'ZZZZ_dk';
    const bobInitId = 'aaaa'; // smaller initId

    final aliceCanonical = FsSessionManager.buildCanonical(
      identityPublicKey: aliceIK,
      devicePublicKey: aliceDK,
      initId: aliceInitId,
    );
    final bobCanonical = FsSessionManager.buildCanonical(
      identityPublicKey: bobIK,
      devicePublicKey: bobDK,
      initId: bobInitId,
    );

    // Alice's canonical should be smaller (AAAA < ZZZZ).
    expect(aliceCanonical.compareTo(bobCanonical), lessThan(0));

    // Without canonical: Bob would win (aaaa < zzzz by initId).
    // With canonical: Alice should win.

    mgr1.recordFsInitSent(_stubInitPayload(initId: aliceInitId));
    mgr2.recordFsInitSent(_stubInitPayload(initId: bobInitId));

    // Alice receives Bob's init with canonical forms.
    final rAlice = mgr1.processFsInitReceived(
      message: _stubInit(initId: bobInitId),
      localInitId: aliceInitId,
      localCanonical: aliceCanonical,
      remoteCanonical: bobCanonical,
    );
    // Alice wins (smaller canonical) → she rejects Bob's init.
    expect(rAlice.accepted, isFalse,
        reason: 'Alice canonical is smaller, she should win');

    // Bob receives Alice's init with canonical forms.
    final rBob = mgr2.processFsInitReceived(
      message: _stubInit(initId: aliceInitId),
      localInitId: bobInitId,
      localCanonical: bobCanonical,
      remoteCanonical: aliceCanonical,
    );
    // Bob loses (larger canonical) → he accepts Alice's init.
    expect(rBob.accepted, isTrue,
        reason: 'Bob canonical is larger, he should lose');
  });

  // T_TB_3
  test('T_TB_3: when IK and DK are equal, initId breaks the tie', () {
    const sharedIK = 'shared_ik';
    const sharedDK = 'shared_dk';

    final c1 = FsSessionManager.buildCanonical(
      identityPublicKey: sharedIK,
      devicePublicKey: sharedDK,
      initId: 'aaaa',
    );
    final c2 = FsSessionManager.buildCanonical(
      identityPublicKey: sharedIK,
      devicePublicKey: sharedDK,
      initId: 'zzzz',
    );

    expect(c1.compareTo(c2), lessThan(0),
        reason: 'When keys are equal, initId determines order');
  });

  // T_TB_4
  test('T_TB_4: processFsInitReceived uses canonical form when provided', () {
    final mgr = FsSessionManager(clock: const _FakeClock(_kNow));
    mgr.recordFsInitSent(_stubInitPayload(initId: 'local-init'));

    // Without canonical, local-init < remote-init → local wins.
    // With canonical, we reverse: local canonical is LARGER.
    final result = mgr.processFsInitReceived(
      message: _stubInit(initId: 'remote-init'),
      localInitId: 'local-init',
      localCanonical: 'ZZZZ_big_canonical',
      remoteCanonical: 'AAAA_small_canonical',
    );

    // Remote canonical is smaller → remote wins → local accepts.
    expect(result.accepted, isTrue,
        reason: 'Remote canonical is smaller, local should accept');
  });

  // T_TB_5
  test('T_TB_5: backward compat — falls back to initId when canonical is null', () {
    final mgr = FsSessionManager(clock: const _FakeClock(_kNow));
    mgr.recordFsInitSent(_stubInitPayload(initId: 'aaaa'));

    final result = mgr.processFsInitReceived(
      message: _stubInit(initId: 'zzzz'),
      localInitId: 'aaaa',
      // No canonical parameters — should fall back to initId comparison.
    );

    // aaaa < zzzz → local wins → rejects remote.
    expect(result.accepted, isFalse,
        reason: 'Without canonical, falls back to initId comparison');
  });

  // T_TB_6
  test('T_TB_6: buildCanonical includes all three components in order', () {
    final canonical = FsSessionManager.buildCanonical(
      identityPublicKey: 'IK',
      devicePublicKey: 'DK',
      initId: 'INIT',
    );
    expect(canonical, equals('IKDKINIT'));
    expect(canonical.startsWith('IK'), isTrue);
    expect(canonical.endsWith('INIT'), isTrue);
    expect(canonical.contains('DK'), isTrue);
  });

  // T_TB_7: Identity key vs device key must be distinct in canonical form
  test('T_TB_7: canonical uses distinct IK and DK (not same key twice)', () {
    final withDistinct = FsSessionManager.buildCanonical(
      identityPublicKey: 'IDENTITY_KEY_ABC',
      devicePublicKey: 'DEVICE_KEY_XYZ',
      initId: 'init-1',
    );
    final withSame = FsSessionManager.buildCanonical(
      identityPublicKey: 'DEVICE_KEY_XYZ',
      devicePublicKey: 'DEVICE_KEY_XYZ',
      initId: 'init-1',
    );
    expect(withDistinct, isNot(equals(withSame)),
        reason: 'Using IK=DK produces a different canonical than IK!=DK');
  });

  // T_TB_8: Realistic base64url-encoded keys produce correct canonical form
  test('T_TB_8: realistic base64url keys produce deterministic canonical', () {
    // Simulating real 32-byte X25519 keys as base64url
    const aliceIK = 'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0';
    const aliceDK = 'AQBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBk';
    const bobIK = 'AQCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCs';
    const bobDK = 'AQDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDw';

    final aliceCanonical = FsSessionManager.buildCanonical(
      identityPublicKey: aliceIK,
      devicePublicKey: aliceDK,
      initId: 'alice-init-001',
    );
    final bobCanonical = FsSessionManager.buildCanonical(
      identityPublicKey: bobIK,
      devicePublicKey: bobDK,
      initId: 'bob-init-001',
    );

    // Alice's IK starts with AQA, Bob's with AQC → Alice canonical < Bob canonical
    expect(aliceCanonical.compareTo(bobCanonical), lessThan(0));

    // Verify the canonical contains all three components concatenated
    expect(aliceCanonical, equals('$aliceIK$aliceDK' 'alice-init-001'));
    expect(bobCanonical, equals('$bobIK$bobDK' 'bob-init-001'));
  });

  // T_TB_9: Tie-break symmetry — both parties must reach the same conclusion
  test('T_TB_9: tie-break is symmetric (both sides agree on winner)', () {
    const aliceIK = 'IK_ALICE';
    const aliceDK = 'DK_ALICE';
    const bobIK = 'IK_BOB';
    const bobDK = 'DK_BOB';
    const aliceInitId = 'init-A';
    const bobInitId = 'init-B';

    final aliceCanonical = FsSessionManager.buildCanonical(
      identityPublicKey: aliceIK,
      devicePublicKey: aliceDK,
      initId: aliceInitId,
    );
    final bobCanonical = FsSessionManager.buildCanonical(
      identityPublicKey: bobIK,
      devicePublicKey: bobDK,
      initId: bobInitId,
    );

    final mgr1 = FsSessionManager(clock: const _FakeClock(_kNow));
    final mgr2 = FsSessionManager(clock: const _FakeClock(_kNow));

    mgr1.recordFsInitSent(_stubInitPayload(initId: aliceInitId));
    mgr2.recordFsInitSent(_stubInitPayload(initId: bobInitId));

    // Alice receives Bob's init
    final rAlice = mgr1.processFsInitReceived(
      message: _stubInit(initId: bobInitId),
      localInitId: aliceInitId,
      localCanonical: aliceCanonical,
      remoteCanonical: bobCanonical,
    );

    // Bob receives Alice's init
    final rBob = mgr2.processFsInitReceived(
      message: _stubInit(initId: aliceInitId),
      localInitId: bobInitId,
      localCanonical: bobCanonical,
      remoteCanonical: aliceCanonical,
    );

    // Exactly one must accept and one must reject
    expect(rAlice.accepted != rBob.accepted, isTrue,
        reason: 'Tie-break must produce opposite outcomes');
  });
}
