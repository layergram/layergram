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

import 'fs_session_manager.dart';

/// In-memory cache for FS-decrypted plaintext.
///
/// **Spec requirement (§12.3):**
/// > Never store decrypted FS plaintext in a persistent database.
/// > Use a memory-only cache with lifecycle wiping:
/// >   - Wiped on app background (if policy requires)
/// >   - Wiped on identity reset
/// >   - Wiped on session termination
/// >   - Size-bounded (LRU eviction)
///
/// The cache stores decrypted text keyed by message identifier (typically
/// `"$contactId|$sessionId|$counter"` or a message UUID).
///
/// **This cache does NOT persist across app restarts.** Messages that
/// have been decrypted once and then evicted from the cache cannot be
/// re-decrypted (the Double Ratchet has already advanced).
///
/// Spec reference: §12.3 — Plaintext storage.
class FsPlaintextCache {
  FsPlaintextCache({
    FsClock? clock,
    this.maxEntries = 1024,
    this.maxEntryAgeSecs = 24 * 60 * 60,
  }) : _clock = clock ?? const _DefaultPlaintextClock();

  final FsClock _clock;

  /// Maximum number of cached entries (LRU eviction).
  final int maxEntries;

  /// Maximum age of a cached entry in seconds.
  final int maxEntryAgeSecs;

  /// Cache entries: key → (plaintext, timestamp, lastAccessTimestamp).
  final Map<String, _CacheEntry> _entries = {};

  /// Stores decrypted plaintext in the cache.
  ///
  /// If the cache is at capacity, evicts the least-recently-used entry.
  void put(String messageKey, String plaintext) {
    final now = _clock.nowSeconds();
    _entries[messageKey] = _CacheEntry(plaintext, now, now);
    _evict();
  }

  /// Retrieves cached plaintext for the given message key.
  ///
  /// Returns `null` if the entry is not cached or has expired.
  /// Updates the last-access timestamp on hit (for LRU ordering).
  String? get(String messageKey) {
    final entry = _entries[messageKey];
    if (entry == null) return null;

    final now = _clock.nowSeconds();
    if (now - entry.createdAt > maxEntryAgeSecs) {
      _entries.remove(messageKey);
      return null;
    }

    // Update last-access time for LRU.
    _entries[messageKey] = _CacheEntry(
      entry.plaintext,
      entry.createdAt,
      now,
    );
    return entry.plaintext;
  }

  /// Whether the cache contains an entry for the given message key.
  bool contains(String messageKey) => get(messageKey) != null;

  /// Number of currently cached entries.
  int get length => _entries.length;

  /// Removes a specific entry from the cache.
  void remove(String messageKey) {
    _entries.remove(messageKey);
  }

  /// Removes all entries for a specific contact.
  void removeByContact(String contactId) {
    _entries.removeWhere((key, _) => key.startsWith('$contactId|'));
  }

  /// Removes all entries for a specific session.
  void removeBySession(String sessionId) {
    _entries.removeWhere((key, _) => key.contains('|$sessionId|'));
  }

  /// Wipes the entire cache (identity reset, app background, etc.).
  void wipe() {
    _entries.clear();
  }

  /// Prunes expired entries.
  void prune() {
    final now = _clock.nowSeconds();
    final cutoff = now - maxEntryAgeSecs;
    _entries.removeWhere((_, entry) => entry.createdAt < cutoff);
  }

  // ---------------------------------------------------------------------------
  // Key builder
  // ---------------------------------------------------------------------------

  /// Builds a cache key from message identifiers.
  static String buildKey({
    required String contactId,
    required String sessionId,
    required int counter,
  }) =>
      '$contactId|$sessionId|$counter';

  // ---------------------------------------------------------------------------
  // LRU eviction
  // ---------------------------------------------------------------------------

  void _evict() {
    // First prune expired.
    prune();

    // Then evict LRU if still over capacity.
    while (_entries.length > maxEntries) {
      String? lruKey;
      int lruAccess = 0x7FFFFFFFFFFFFFFF;
      for (final entry in _entries.entries) {
        if (entry.value.lastAccessAt < lruAccess) {
          lruAccess = entry.value.lastAccessAt;
          lruKey = entry.key;
        }
      }
      if (lruKey != null) {
        _entries.remove(lruKey);
      } else {
        break;
      }
    }
  }
}

class _CacheEntry {
  const _CacheEntry(this.plaintext, this.createdAt, this.lastAccessAt);

  final String plaintext;
  final int createdAt;
  final int lastAccessAt;
}

class _DefaultPlaintextClock implements FsClock {
  const _DefaultPlaintextClock();

  @override
  int nowSeconds() => DateTime.now().millisecondsSinceEpoch ~/ 1000;
}
