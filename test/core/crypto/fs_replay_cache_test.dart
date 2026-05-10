// Tests for FsReplayCache (FS Spec §7.7, §8.7).
//
// Acceptance criteria:
//
//  T_RC_1  Recording a message and querying it returns isReplay = true.
//  T_RC_2  Querying an unrecorded counter returns isReplay = false.
//  T_RC_3  highestReceivedCounter tracks the maximum counter seen.
//  T_RC_4  Expired message entries are pruned automatically.
//  T_RC_5  Excess message entries (>256) are pruned by removing oldest.
//  T_RC_6  Recording a handshake ID and querying it returns isReplay = true.
//  T_RC_7  Querying an unrecorded handshake ID returns isReplay = false.
//  T_RC_8  Expired handshake ID entries are pruned automatically.
//  T_RC_9  Excess handshake ID entries (>32) are pruned by removing oldest.
//  T_RC_10 Serialization round-trip preserves all state.
//  T_RC_11 clear() removes all state.
//  T_RC_12 fromJson prunes expired entries on construction.
//  T_RC_13 Different sessions have independent replay tracking.

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_replay_cache.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';

class _FakeClock implements FsClock {
  int _now;
  _FakeClock(this._now);

  @override
  int nowSeconds() => _now;

  void advance(int seconds) => _now += seconds;
}

void main() {
  // T_RC_1
  test('T_RC_1: recorded message counter is detected as replay', () {
    final cache = FsReplayCache();
    cache.recordMessage(sessionId: 'sess-1', counter: 0);
    expect(cache.isMessageReplay(sessionId: 'sess-1', counter: 0), isTrue);
  });

  // T_RC_2
  test('T_RC_2: unrecorded counter is not a replay', () {
    final cache = FsReplayCache();
    expect(cache.isMessageReplay(sessionId: 'sess-1', counter: 0), isFalse);
    cache.recordMessage(sessionId: 'sess-1', counter: 0);
    expect(cache.isMessageReplay(sessionId: 'sess-1', counter: 1), isFalse);
  });

  // T_RC_3
  test('T_RC_3: highestReceivedCounter tracks max counter per session', () {
    final cache = FsReplayCache();
    expect(cache.highestReceivedCounter('sess-1'), equals(-1));

    cache.recordMessage(sessionId: 'sess-1', counter: 5);
    expect(cache.highestReceivedCounter('sess-1'), equals(5));

    cache.recordMessage(sessionId: 'sess-1', counter: 3);
    expect(cache.highestReceivedCounter('sess-1'), equals(5));

    cache.recordMessage(sessionId: 'sess-1', counter: 10);
    expect(cache.highestReceivedCounter('sess-1'), equals(10));

    // Different session is independent.
    expect(cache.highestReceivedCounter('sess-2'), equals(-1));
  });

  // T_RC_4
  test('T_RC_4: expired message entries are pruned automatically', () {
    final clock = _FakeClock(1000000);
    final cache = FsReplayCache(
      clock: clock,
      maxReplayEntryAgeSecs: 100,
    );

    cache.recordMessage(sessionId: 'sess-1', counter: 0);
    expect(cache.isMessageReplay(sessionId: 'sess-1', counter: 0), isTrue);

    // Advance past expiry.
    clock.advance(200);

    // Recording a new message triggers pruning.
    cache.recordMessage(sessionId: 'sess-1', counter: 99);
    expect(cache.isMessageReplay(sessionId: 'sess-1', counter: 0), isFalse);
    expect(cache.isMessageReplay(sessionId: 'sess-1', counter: 99), isTrue);
  });

  // T_RC_5
  test('T_RC_5: excess message entries are pruned by removing oldest', () {
    final clock = _FakeClock(1000000);
    final cache = FsReplayCache(
      clock: clock,
      maxReplayEntries: 10,
    );

    // Add 10 entries.
    for (var i = 0; i < 10; i++) {
      cache.recordMessage(sessionId: 'sess-1', counter: i);
      clock.advance(1);
    }
    expect(cache.messageEntryCount, equals(10));

    // Adding one more triggers eviction of the oldest.
    cache.recordMessage(sessionId: 'sess-1', counter: 10);
    expect(cache.messageEntryCount, equals(10));

    // Counter 0 (oldest) should have been evicted.
    expect(cache.isMessageReplay(sessionId: 'sess-1', counter: 0), isFalse);
    // Counter 10 (newest) should still be present.
    expect(cache.isMessageReplay(sessionId: 'sess-1', counter: 10), isTrue);
  });

  // T_RC_6
  test('T_RC_6: recorded handshake ID is detected as replay', () {
    final cache = FsReplayCache();
    cache.recordHandshakeId('init-AAA');
    expect(cache.isHandshakeIdReplay('init-AAA'), isTrue);
  });

  // T_RC_7
  test('T_RC_7: unrecorded handshake ID is not a replay', () {
    final cache = FsReplayCache();
    expect(cache.isHandshakeIdReplay('init-AAA'), isFalse);
  });

  // T_RC_8
  test('T_RC_8: expired handshake ID entries are pruned automatically', () {
    final clock = _FakeClock(1000000);
    final cache = FsReplayCache(
      clock: clock,
      maxHandshakeIdAgeSecs: 100,
    );

    cache.recordHandshakeId('init-AAA');
    expect(cache.isHandshakeIdReplay('init-AAA'), isTrue);

    clock.advance(200);
    cache.recordHandshakeId('init-BBB');
    expect(cache.isHandshakeIdReplay('init-AAA'), isFalse);
    expect(cache.isHandshakeIdReplay('init-BBB'), isTrue);
  });

  // T_RC_9
  test('T_RC_9: excess handshake ID entries are pruned by removing oldest', () {
    final clock = _FakeClock(1000000);
    final cache = FsReplayCache(
      clock: clock,
      maxHandshakeIds: 5,
    );

    for (var i = 0; i < 5; i++) {
      cache.recordHandshakeId('id-$i');
      clock.advance(1);
    }
    expect(cache.handshakeIdCount, equals(5));

    cache.recordHandshakeId('id-5');
    expect(cache.handshakeIdCount, equals(5));
    expect(cache.isHandshakeIdReplay('id-0'), isFalse);
    expect(cache.isHandshakeIdReplay('id-5'), isTrue);
  });

  // T_RC_10
  test('T_RC_10: serialization round-trip preserves all state', () {
    final cache = FsReplayCache();
    cache.recordMessage(sessionId: 'sess-1', counter: 0);
    cache.recordMessage(sessionId: 'sess-1', counter: 5);
    cache.recordMessage(sessionId: 'sess-2', counter: 3);
    cache.recordHandshakeId('init-X');
    cache.recordHandshakeId('reply-Y');

    final json = cache.toJson();
    final restored = FsReplayCache.fromJson(json);

    expect(restored.isMessageReplay(sessionId: 'sess-1', counter: 0), isTrue);
    expect(restored.isMessageReplay(sessionId: 'sess-1', counter: 5), isTrue);
    expect(restored.isMessageReplay(sessionId: 'sess-2', counter: 3), isTrue);
    expect(restored.isMessageReplay(sessionId: 'sess-1', counter: 1), isFalse);
    expect(restored.highestReceivedCounter('sess-1'), equals(5));
    expect(restored.highestReceivedCounter('sess-2'), equals(3));
    expect(restored.isHandshakeIdReplay('init-X'), isTrue);
    expect(restored.isHandshakeIdReplay('reply-Y'), isTrue);
    expect(restored.isHandshakeIdReplay('unknown'), isFalse);
  });

  // T_RC_11
  test('T_RC_11: clear() removes all state', () {
    final cache = FsReplayCache();
    cache.recordMessage(sessionId: 'sess-1', counter: 0);
    cache.recordHandshakeId('init-X');

    cache.clear();

    expect(cache.isMessageReplay(sessionId: 'sess-1', counter: 0), isFalse);
    expect(cache.isHandshakeIdReplay('init-X'), isFalse);
    expect(cache.highestReceivedCounter('sess-1'), equals(-1));
    expect(cache.messageEntryCount, equals(0));
    expect(cache.handshakeIdCount, equals(0));
  });

  // T_RC_12
  test('T_RC_12: fromJson prunes expired entries on construction', () {
    final clock = _FakeClock(1000000);
    final cache = FsReplayCache(clock: clock, maxReplayEntryAgeSecs: 100);
    cache.recordMessage(sessionId: 'sess-1', counter: 0);
    cache.recordHandshakeId('init-old');
    final json = cache.toJson();

    // Advance time past expiry before deserializing.
    final clock2 = _FakeClock(1000200);
    final restored = FsReplayCache.fromJson(
      json,
      clock: clock2,
    );

    expect(restored.isMessageReplay(sessionId: 'sess-1', counter: 0), isFalse);
    expect(restored.isHandshakeIdReplay('init-old'), isFalse);
  });

  // T_RC_13
  test('T_RC_13: different sessions have independent replay tracking', () {
    final cache = FsReplayCache();
    cache.recordMessage(sessionId: 'sess-A', counter: 0);
    cache.recordMessage(sessionId: 'sess-B', counter: 0);

    expect(cache.isMessageReplay(sessionId: 'sess-A', counter: 0), isTrue);
    expect(cache.isMessageReplay(sessionId: 'sess-B', counter: 0), isTrue);
    expect(cache.isMessageReplay(sessionId: 'sess-A', counter: 1), isFalse);
    expect(cache.isMessageReplay(sessionId: 'sess-B', counter: 1), isFalse);

    expect(cache.highestReceivedCounter('sess-A'), equals(0));
    expect(cache.highestReceivedCounter('sess-B'), equals(0));
  });
}
