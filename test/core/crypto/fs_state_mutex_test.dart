// Tests for FsStateMutex (FS Spec §20.1).
//
// Acceptance criteria:
//
//  T_MX_1  Single operation acquires lock and completes.
//  T_MX_2  Two sequential operations for same contact run in order.
//  T_MX_3  Concurrent operations for same contact are serialized.
//  T_MX_4  Concurrent operations for different contacts run in parallel.
//  T_MX_5  Lock is released even if the action throws.
//  T_MX_6  isLocked returns true while lock is held, false after release.
//  T_MX_7  queueLength reflects the number of waiting operations.
//  T_MX_8  Three concurrent operations for same contact run in FIFO order.
//  T_MX_9  After exception, subsequent operations still proceed.
//  T_MX_10 Interleaved concurrent operations for two contacts.

import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_state_mutex.dart';

void main() {
  // T_MX_1
  test('T_MX_1: single operation acquires lock and completes', () async {
    final mutex = FsStateMutex();
    final result = await mutex.withLock('alice|primary', () async => 42);
    expect(result, equals(42));
    expect(mutex.isLocked('alice|primary'), isFalse);
  });

  // T_MX_2
  test('T_MX_2: two sequential operations run in order', () async {
    final mutex = FsStateMutex();
    final log = <int>[];

    await mutex.withLock('alice|primary', () async {
      log.add(1);
    });
    await mutex.withLock('alice|primary', () async {
      log.add(2);
    });

    expect(log, equals([1, 2]));
  });

  // T_MX_3
  test('T_MX_3: concurrent operations for same contact are serialized', () async {
    final mutex = FsStateMutex();
    final log = <String>[];
    final gate1 = Completer<void>();

    final op1 = mutex.withLock('alice|primary', () async {
      log.add('op1-start');
      await gate1.future;
      log.add('op1-end');
    });

    // Start op2 while op1 is running (before gate1 completes).
    final op2 = mutex.withLock('alice|primary', () async {
      log.add('op2-start');
      log.add('op2-end');
    });

    // Allow a microtask cycle so op2 gets queued.
    await Future<void>.delayed(Duration.zero);

    // op1 is still running; op2 should not have started.
    expect(log, equals(['op1-start']));
    expect(mutex.isLocked('alice|primary'), isTrue);

    // Complete op1.
    gate1.complete();
    await op1;
    await op2;

    expect(log, equals(['op1-start', 'op1-end', 'op2-start', 'op2-end']));
    expect(mutex.isLocked('alice|primary'), isFalse);
  });

  // T_MX_4
  test('T_MX_4: concurrent operations for different contacts run in parallel', () async {
    final mutex = FsStateMutex();
    final log = <String>[];
    final gate = Completer<void>();

    final op1 = mutex.withLock('alice|primary', () async {
      log.add('alice-start');
      await gate.future;
      log.add('alice-end');
    });

    final op2 = mutex.withLock('bob|primary', () async {
      log.add('bob-start');
      log.add('bob-end');
    });

    // Allow microtasks.
    await Future<void>.delayed(Duration.zero);

    // Both should have started.
    expect(log, contains('alice-start'));
    expect(log, contains('bob-start'));

    gate.complete();
    await op1;
    await op2;

    expect(log, containsAll(['alice-start', 'alice-end', 'bob-start', 'bob-end']));
  });

  // T_MX_5
  test('T_MX_5: lock is released even if action throws', () async {
    final mutex = FsStateMutex();

    try {
      await mutex.withLock('alice|primary', () async {
        throw StateError('boom');
      });
    } catch (_) {
      // expected
    }

    expect(mutex.isLocked('alice|primary'), isFalse);

    // Can acquire again.
    final result = await mutex.withLock('alice|primary', () async => 'ok');
    expect(result, equals('ok'));
  });

  // T_MX_6
  test('T_MX_6: isLocked returns true while lock is held', () async {
    final mutex = FsStateMutex();
    final gate = Completer<void>();

    expect(mutex.isLocked('alice|primary'), isFalse);

    final op = mutex.withLock('alice|primary', () async {
      await gate.future;
    });

    await Future<void>.delayed(Duration.zero);
    expect(mutex.isLocked('alice|primary'), isTrue);

    gate.complete();
    await op;
    expect(mutex.isLocked('alice|primary'), isFalse);
  });

  // T_MX_7
  test('T_MX_7: queueLength reflects number of waiting operations', () async {
    final mutex = FsStateMutex();
    final gate = Completer<void>();

    expect(mutex.queueLength('alice|primary'), equals(0));

    final op1 = mutex.withLock('alice|primary', () async {
      await gate.future;
    });

    await Future<void>.delayed(Duration.zero);
    expect(mutex.queueLength('alice|primary'), equals(0)); // op1 holds lock, not queued

    final op2 = mutex.withLock('alice|primary', () async {});
    await Future<void>.delayed(Duration.zero);
    expect(mutex.queueLength('alice|primary'), equals(1));

    final op3 = mutex.withLock('alice|primary', () async {});
    await Future<void>.delayed(Duration.zero);
    expect(mutex.queueLength('alice|primary'), equals(2));

    gate.complete();
    await op1;
    await op2;
    await op3;
    expect(mutex.queueLength('alice|primary'), equals(0));
  });

  // T_MX_8
  test('T_MX_8: three concurrent operations run in FIFO order', () async {
    final mutex = FsStateMutex();
    final log = <int>[];
    final gate = Completer<void>();

    final op1 = mutex.withLock('alice|primary', () async {
      log.add(1);
      await gate.future;
    });

    final op2 = mutex.withLock('alice|primary', () async {
      log.add(2);
    });

    final op3 = mutex.withLock('alice|primary', () async {
      log.add(3);
    });

    await Future<void>.delayed(Duration.zero);

    gate.complete();
    await op1;
    await op2;
    await op3;

    expect(log, equals([1, 2, 3]));
  });

  // T_MX_9
  test('T_MX_9: after exception, subsequent operations still proceed', () async {
    final mutex = FsStateMutex();
    final gate = Completer<void>();

    final op1 = mutex.withLock('alice|primary', () async {
      await gate.future;
      throw StateError('op1 fails');
    });

    final op2Future = mutex.withLock('alice|primary', () async => 'op2-ok');

    await Future<void>.delayed(Duration.zero);
    gate.complete();

    try {
      await op1;
    } catch (_) {}

    final result = await op2Future;
    expect(result, equals('op2-ok'));
  });

  // T_MX_10
  test('T_MX_10: interleaved concurrent operations for two contacts', () async {
    final mutex = FsStateMutex();
    final log = <String>[];
    final aliceGate = Completer<void>();
    final bobGate = Completer<void>();

    final aliceOp1 = mutex.withLock('alice', () async {
      log.add('a1-start');
      await aliceGate.future;
      log.add('a1-end');
    });
    final aliceOp2 = mutex.withLock('alice', () async {
      log.add('a2');
    });

    final bobOp1 = mutex.withLock('bob', () async {
      log.add('b1-start');
      await bobGate.future;
      log.add('b1-end');
    });
    final bobOp2 = mutex.withLock('bob', () async {
      log.add('b2');
    });

    await Future<void>.delayed(Duration.zero);

    // Both first ops started.
    expect(log, containsAll(['a1-start', 'b1-start']));

    // Release alice first.
    aliceGate.complete();
    await aliceOp1;
    await aliceOp2;

    // Bob's second op should still be waiting.
    expect(log, contains('a1-end'));
    expect(log, contains('a2'));
    expect(log, isNot(contains('b2')));

    // Release bob.
    bobGate.complete();
    await bobOp1;
    await bobOp2;

    expect(log, containsAll(['b1-end', 'b2']));
  });
}
