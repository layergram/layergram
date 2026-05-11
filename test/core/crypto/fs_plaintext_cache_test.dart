// Tests for FsPlaintextCache (FS Spec §12.3).
//
// Spec requirement:
//   Never store decrypted FS plaintext in a persistent database.
//   Use a memory-only cache with lifecycle wiping.
//
// Acceptance criteria:
//
//  T_PC_1  put + get returns the cached plaintext.
//  T_PC_2  get returns null for uncached keys.
//  T_PC_3  Expired entries are evicted on access.
//  T_PC_4  LRU eviction: oldest-accessed entry is removed at capacity.
//  T_PC_5  wipe() clears all entries.
//  T_PC_6  removeByContact removes entries for that contact only.
//  T_PC_7  removeBySession removes entries for that session only.
//  T_PC_8  buildKey produces deterministic and correctly formatted keys.
//  T_PC_9  prune() removes only expired entries.
//  T_PC_10 Accessing an entry updates its LRU position (not evicted next).
//  T_PC_11 remove() removes a specific entry.
//  T_PC_12 contains() returns correct status.

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_plaintext_cache.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';

class _FakeClock implements FsClock {
  int _now;
  _FakeClock(this._now);

  @override
  int nowSeconds() => _now;

  void advance(int seconds) => _now += seconds;
}

void main() {
  // T_PC_1
  test('T_PC_1: put + get returns cached plaintext', () {
    final cache = FsPlaintextCache();
    cache.put('alice|sess-1|0', 'Hello, World!');
    expect(cache.get('alice|sess-1|0'), equals('Hello, World!'));
  });

  // T_PC_2
  test('T_PC_2: get returns null for uncached keys', () {
    final cache = FsPlaintextCache();
    expect(cache.get('unknown-key'), isNull);
  });

  // T_PC_3
  test('T_PC_3: expired entries are evicted on access', () {
    final clock = _FakeClock(1000000);
    final cache = FsPlaintextCache(clock: clock, maxEntryAgeSecs: 100);

    cache.put('alice|sess-1|0', 'secret');
    expect(cache.get('alice|sess-1|0'), equals('secret'));

    clock.advance(200);
    expect(cache.get('alice|sess-1|0'), isNull);
  });

  // T_PC_4
  test('T_PC_4: LRU eviction removes oldest-accessed entry at capacity', () {
    final clock = _FakeClock(1000000);
    final cache = FsPlaintextCache(clock: clock, maxEntries: 3);

    cache.put('key-1', 'val-1'); clock.advance(1);
    cache.put('key-2', 'val-2'); clock.advance(1);
    cache.put('key-3', 'val-3'); clock.advance(1);
    expect(cache.length, equals(3));

    // Access key-1 to update its LRU position.
    cache.get('key-1'); clock.advance(1);

    // Add key-4 → should evict key-2 (oldest access, not key-1).
    cache.put('key-4', 'val-4');
    expect(cache.length, equals(3));
    expect(cache.get('key-1'), equals('val-1'), reason: 'key-1 was recently accessed');
    expect(cache.get('key-2'), isNull, reason: 'key-2 was LRU evicted');
    expect(cache.get('key-3'), isNotNull);
    expect(cache.get('key-4'), isNotNull);
  });

  // T_PC_5
  test('T_PC_5: wipe() clears all entries', () {
    final cache = FsPlaintextCache();
    cache.put('k1', 'v1');
    cache.put('k2', 'v2');

    cache.wipe();

    expect(cache.length, equals(0));
    expect(cache.get('k1'), isNull);
    expect(cache.get('k2'), isNull);
  });

  // T_PC_6
  test('T_PC_6: removeByContact removes entries for that contact only', () {
    final cache = FsPlaintextCache();
    cache.put('alice|sess-1|0', 'msg-1');
    cache.put('alice|sess-1|1', 'msg-2');
    cache.put('bob|sess-2|0', 'msg-3');

    cache.removeByContact('alice');

    expect(cache.get('alice|sess-1|0'), isNull);
    expect(cache.get('alice|sess-1|1'), isNull);
    expect(cache.get('bob|sess-2|0'), equals('msg-3'));
  });

  // T_PC_7
  test('T_PC_7: removeBySession removes entries for that session only', () {
    final cache = FsPlaintextCache();
    cache.put('alice|sess-1|0', 'msg-1');
    cache.put('alice|sess-2|0', 'msg-2');
    cache.put('bob|sess-1|0', 'msg-3');

    cache.removeBySession('sess-1');

    expect(cache.get('alice|sess-1|0'), isNull);
    expect(cache.get('bob|sess-1|0'), isNull);
    expect(cache.get('alice|sess-2|0'), equals('msg-2'));
  });

  // T_PC_8
  test('T_PC_8: buildKey produces deterministic and correctly formatted keys', () {
    final key = FsPlaintextCache.buildKey(
      contactId: 'alice',
      sessionId: 'sess-1',
      counter: 42,
    );
    expect(key, equals('alice|sess-1|42'));

    final key2 = FsPlaintextCache.buildKey(
      contactId: 'alice',
      sessionId: 'sess-1',
      counter: 42,
    );
    expect(key, equals(key2));
  });

  // T_PC_9
  test('T_PC_9: prune() removes only expired entries', () {
    final clock = _FakeClock(1000000);
    final cache = FsPlaintextCache(clock: clock, maxEntryAgeSecs: 100);

    cache.put('old', 'old-value');
    clock.advance(50);
    cache.put('new', 'new-value');
    clock.advance(60);

    // 'old' is now 110s old (expired), 'new' is 60s old (not expired).
    cache.prune();

    expect(cache.get('old'), isNull);
    expect(cache.get('new'), equals('new-value'));
  });

  // T_PC_10
  test('T_PC_10: accessing an entry updates its LRU position', () {
    final clock = _FakeClock(1000000);
    final cache = FsPlaintextCache(clock: clock, maxEntries: 2);

    cache.put('k1', 'v1'); clock.advance(1);
    cache.put('k2', 'v2'); clock.advance(1);

    // Access k1 → it's now more recently used than k2.
    cache.get('k1'); clock.advance(1);

    // Adding k3 should evict k2 (LRU), not k1.
    cache.put('k3', 'v3');
    expect(cache.get('k1'), equals('v1'));
    expect(cache.get('k2'), isNull);
    expect(cache.get('k3'), equals('v3'));
  });

  // T_PC_11
  test('T_PC_11: remove() removes a specific entry', () {
    final cache = FsPlaintextCache();
    cache.put('k1', 'v1');
    cache.put('k2', 'v2');

    cache.remove('k1');

    expect(cache.get('k1'), isNull);
    expect(cache.get('k2'), equals('v2'));
  });

  // T_PC_12
  test('T_PC_12: contains() returns correct status', () {
    final cache = FsPlaintextCache();
    expect(cache.contains('k1'), isFalse);

    cache.put('k1', 'v1');
    expect(cache.contains('k1'), isTrue);

    cache.remove('k1');
    expect(cache.contains('k1'), isFalse);
  });
}
