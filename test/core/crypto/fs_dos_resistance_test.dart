// Tests for FsDoSGuard (FS Spec §20.3).
//
// Acceptance criteria:
//
//  T_DOS_1  First handshake initiation for a contact is allowed.
//  T_DOS_2  Handshakes up to maxPendingHandshakesPerContact are allowed.
//  T_DOS_3  Exceeding maxPendingHandshakesPerContact is rejected.
//  T_DOS_4  Completing a handshake frees a slot.
//  T_DOS_5  Rate limit allows maxHandshakeInitiationsPerWindow in window.
//  T_DOS_6  Exceeding rate limit is rejected.
//  T_DOS_7  Rate limit resets after window expires.
//  T_DOS_8  isOrphanAuxRecordLimitExceeded correctly checks limit.
//  T_DOS_9  orphanRecordsToPrune returns correct count.
//  T_DOS_10 clearContact removes tracking for a specific contact.
//  T_DOS_11 clearAll removes all tracking.
//  T_DOS_12 Different contacts have independent limits.

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_dos_resistance.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';

class _FakeClock implements FsClock {
  int _now;
  _FakeClock(this._now);

  @override
  int nowSeconds() => _now;

  void advance(int seconds) => _now += seconds;
}

void main() {
  // T_DOS_1
  test('T_DOS_1: first handshake initiation for a contact is allowed', () {
    final guard = FsDoSGuard();
    final result = guard.canInitiateHandshake('alice');
    expect(result.allowed, isTrue);
    expect(result.reason, isNull);
  });

  // T_DOS_2
  test('T_DOS_2: handshakes up to max are allowed', () {
    final clock = _FakeClock(1000000);
    final guard = FsDoSGuard(
      clock: clock,
      maxPendingHandshakesPerContact: 4,
      maxHandshakeInitiationsPerWindow: 100, // high to not hit rate limit
    );

    for (var i = 0; i < 4; i++) {
      final result = guard.canInitiateHandshake('alice');
      expect(result.allowed, isTrue, reason: 'handshake $i should be allowed');
      guard.recordHandshakeInitiation(
        contactId: 'alice',
        initId: 'init-$i',
      );
    }
    expect(guard.pendingHandshakeCount('alice'), equals(4));
  });

  // T_DOS_3
  test('T_DOS_3: exceeding maxPendingHandshakesPerContact is rejected', () {
    final clock = _FakeClock(1000000);
    final guard = FsDoSGuard(
      clock: clock,
      maxPendingHandshakesPerContact: 2,
      maxHandshakeInitiationsPerWindow: 100,
    );

    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-0');
    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-1');

    final result = guard.canInitiateHandshake('alice');
    expect(result.allowed, isFalse);
    expect(result.reason,
        equals(FsDoSRejectionReason.tooManyPendingHandshakes));
    expect(result.detail, contains('alice'));
  });

  // T_DOS_4
  test('T_DOS_4: completing a handshake frees a slot', () {
    final clock = _FakeClock(1000000);
    final guard = FsDoSGuard(
      clock: clock,
      maxPendingHandshakesPerContact: 2,
      maxHandshakeInitiationsPerWindow: 100,
    );

    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-0');
    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-1');
    expect(guard.canInitiateHandshake('alice').allowed, isFalse);

    guard.completeHandshake(contactId: 'alice', initId: 'init-0');
    expect(guard.pendingHandshakeCount('alice'), equals(1));
    expect(guard.canInitiateHandshake('alice').allowed, isTrue);
  });

  // T_DOS_5
  test('T_DOS_5: rate limit allows max initiations in window', () {
    final clock = _FakeClock(1000000);
    final guard = FsDoSGuard(
      clock: clock,
      maxPendingHandshakesPerContact: 100, // high to not hit pending limit
      maxHandshakeInitiationsPerWindow: 3,
      handshakeRateWindowSecs: 60,
    );

    for (var i = 0; i < 3; i++) {
      expect(guard.canInitiateHandshake('alice').allowed, isTrue);
      guard.recordHandshakeInitiation(
          contactId: 'alice', initId: 'init-$i');
    }
  });

  // T_DOS_6
  test('T_DOS_6: exceeding rate limit is rejected', () {
    final clock = _FakeClock(1000000);
    final guard = FsDoSGuard(
      clock: clock,
      maxPendingHandshakesPerContact: 100,
      maxHandshakeInitiationsPerWindow: 2,
      handshakeRateWindowSecs: 60,
    );

    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-0');
    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-1');

    final result = guard.canInitiateHandshake('alice');
    expect(result.allowed, isFalse);
    expect(result.reason, equals(FsDoSRejectionReason.rateLimitExceeded));
  });

  // T_DOS_7
  test('T_DOS_7: rate limit resets after window expires', () {
    final clock = _FakeClock(1000000);
    final guard = FsDoSGuard(
      clock: clock,
      maxPendingHandshakesPerContact: 100,
      maxHandshakeInitiationsPerWindow: 2,
      handshakeRateWindowSecs: 60,
    );

    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-0');
    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-1');
    // Complete them so pending count doesn't block us.
    guard.completeHandshake(contactId: 'alice', initId: 'init-0');
    guard.completeHandshake(contactId: 'alice', initId: 'init-1');

    expect(guard.canInitiateHandshake('alice').allowed, isFalse);

    // Advance past the rate window.
    clock.advance(61);
    expect(guard.canInitiateHandshake('alice').allowed, isTrue);
  });

  // T_DOS_8
  test('T_DOS_8: isOrphanAuxRecordLimitExceeded checks limit correctly', () {
    final guard = FsDoSGuard(maxOrphanAuxRecords: 16);

    expect(guard.isOrphanAuxRecordLimitExceeded(0), isFalse);
    expect(guard.isOrphanAuxRecordLimitExceeded(15), isFalse);
    expect(guard.isOrphanAuxRecordLimitExceeded(16), isTrue);
    expect(guard.isOrphanAuxRecordLimitExceeded(100), isTrue);
  });

  // T_DOS_9
  test('T_DOS_9: orphanRecordsToPrune returns correct count', () {
    final guard = FsDoSGuard(maxOrphanAuxRecords: 16);

    expect(guard.orphanRecordsToPrune(0), equals(0));
    expect(guard.orphanRecordsToPrune(16), equals(0));
    expect(guard.orphanRecordsToPrune(17), equals(1));
    expect(guard.orphanRecordsToPrune(32), equals(16));
  });

  // T_DOS_10
  test('T_DOS_10: clearContact removes tracking for specific contact', () {
    final clock = _FakeClock(1000000);
    final guard = FsDoSGuard(
      clock: clock,
      maxHandshakeInitiationsPerWindow: 100,
    );

    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-0');
    guard.recordHandshakeInitiation(contactId: 'bob', initId: 'init-1');

    guard.clearContact('alice');

    expect(guard.pendingHandshakeCount('alice'), equals(0));
    expect(guard.pendingHandshakeCount('bob'), equals(1));
  });

  // T_DOS_11
  test('T_DOS_11: clearAll removes all tracking', () {
    final clock = _FakeClock(1000000);
    final guard = FsDoSGuard(
      clock: clock,
      maxHandshakeInitiationsPerWindow: 100,
    );

    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-0');
    guard.recordHandshakeInitiation(contactId: 'bob', initId: 'init-1');

    guard.clearAll();

    expect(guard.pendingHandshakeCount('alice'), equals(0));
    expect(guard.pendingHandshakeCount('bob'), equals(0));
  });

  // T_DOS_12
  test('T_DOS_12: different contacts have independent limits', () {
    final clock = _FakeClock(1000000);
    final guard = FsDoSGuard(
      clock: clock,
      maxPendingHandshakesPerContact: 2,
      maxHandshakeInitiationsPerWindow: 100,
    );

    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-0');
    guard.recordHandshakeInitiation(contactId: 'alice', initId: 'init-1');

    // Alice is at limit; Bob should still be allowed.
    expect(guard.canInitiateHandshake('alice').allowed, isFalse);
    expect(guard.canInitiateHandshake('bob').allowed, isTrue);
  });
}
