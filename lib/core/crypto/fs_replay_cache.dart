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

/// Per-session replay cache for Forward Secrecy messages.
///
/// Prevents re-processing of already-seen FS message counters and already-seen
/// handshake initId/replyId values.
///
/// Recommended limits (spec §8.7):
/// ```text
/// max replay entries per session: 256
/// max replay entry age: 7 days
/// max stored handshake IDs per contact/device: 32
/// max handshake ID age: 7 days
/// ```
///
/// The replay cache is pruned:
/// - on session load
/// - on session save
/// - after successful message processing
/// - during periodic maintenance
///
/// Spec reference: §7.7, §8.7.
class FsReplayCache {
  FsReplayCache({
    FsClock? clock,
    this.maxReplayEntries = 256,
    this.maxReplayEntryAgeSecs = 7 * 24 * 60 * 60,
    this.maxHandshakeIds = 32,
    this.maxHandshakeIdAgeSecs = 7 * 24 * 60 * 60,
  }) : _clock = clock ?? const _DefaultClock();

  final FsClock _clock;

  /// Maximum number of message-counter replay entries per session.
  final int maxReplayEntries;

  /// Maximum age (in seconds) of a message-counter replay entry.
  final int maxReplayEntryAgeSecs;

  /// Maximum number of stored handshake IDs (initId/replyId) per contact.
  final int maxHandshakeIds;

  /// Maximum age (in seconds) of a handshake ID entry.
  final int maxHandshakeIdAgeSecs;

  // ---------------------------------------------------------------------------
  // Message replay tracking
  // ---------------------------------------------------------------------------

  /// Map of (sessionId, counter) → timestamp when it was first seen.
  final Map<_MessageId, int> _seenMessages = {};

  /// Highest received counter per sessionId.
  final Map<String, int> _highestCounter = {};

  /// Checks whether a message with the given [sessionId] and [counter] has
  /// already been processed.
  ///
  /// Returns `true` if this is a **replay** (already seen), `false` if new.
  bool isMessageReplay({
    required String sessionId,
    required int counter,
  }) {
    final id = _MessageId(sessionId, counter);
    return _seenMessages.containsKey(id);
  }

  /// Records that a message with the given [sessionId] and [counter] was
  /// successfully processed.
  ///
  /// Also updates [highestReceivedCounter] for the session.
  /// Prunes old entries if the cache is at capacity.
  void recordMessage({
    required String sessionId,
    required int counter,
  }) {
    final now = _clock.nowSeconds();
    final id = _MessageId(sessionId, counter);
    _seenMessages[id] = now;

    final prev = _highestCounter[sessionId];
    if (prev == null || counter > prev) {
      _highestCounter[sessionId] = counter;
    }

    _pruneMessages();
  }

  /// Returns the highest received counter for the given [sessionId],
  /// or -1 if no messages have been recorded.
  int highestReceivedCounter(String sessionId) {
    return _highestCounter[sessionId] ?? -1;
  }

  /// Number of currently tracked message replay entries.
  int get messageEntryCount => _seenMessages.length;

  // ---------------------------------------------------------------------------
  // Handshake ID replay tracking
  // ---------------------------------------------------------------------------

  /// Map of handshakeId → timestamp when it was first seen.
  final Map<String, int> _seenHandshakeIds = {};

  /// Checks whether a handshake ID (initId or replyId) has already been
  /// processed.
  ///
  /// Returns `true` if this is a **replay** (already seen), `false` if new.
  bool isHandshakeIdReplay(String handshakeId) {
    return _seenHandshakeIds.containsKey(handshakeId);
  }

  /// Records that a handshake ID was successfully processed.
  /// Prunes old entries if the cache is at capacity.
  void recordHandshakeId(String handshakeId) {
    final now = _clock.nowSeconds();
    _seenHandshakeIds[handshakeId] = now;
    _pruneHandshakeIds();
  }

  /// Number of currently tracked handshake ID entries.
  int get handshakeIdCount => _seenHandshakeIds.length;

  // ---------------------------------------------------------------------------
  // Pruning
  // ---------------------------------------------------------------------------

  /// Prunes all expired entries from both caches.
  ///
  /// Called automatically after recording, but may also be called explicitly
  /// during session load/save or periodic maintenance.
  void prune() {
    _pruneMessages();
    _pruneHandshakeIds();
  }

  void _pruneMessages() {
    final now = _clock.nowSeconds();
    final cutoff = now - maxReplayEntryAgeSecs;

    // Remove expired entries first.
    _seenMessages.removeWhere((_, ts) => ts < cutoff);

    // If still over capacity, remove oldest entries.
    if (_seenMessages.length > maxReplayEntries) {
      final sorted = _seenMessages.entries.toList()
        ..sort((a, b) => a.value.compareTo(b.value));
      final toRemove = sorted.length - maxReplayEntries;
      for (var i = 0; i < toRemove; i++) {
        _seenMessages.remove(sorted[i].key);
      }
    }
  }

  void _pruneHandshakeIds() {
    final now = _clock.nowSeconds();
    final cutoff = now - maxHandshakeIdAgeSecs;

    // Remove expired entries first.
    _seenHandshakeIds.removeWhere((_, ts) => ts < cutoff);

    // If still over capacity, remove oldest entries.
    if (_seenHandshakeIds.length > maxHandshakeIds) {
      final sorted = _seenHandshakeIds.entries.toList()
        ..sort((a, b) => a.value.compareTo(b.value));
      final toRemove = sorted.length - maxHandshakeIds;
      for (var i = 0; i < toRemove; i++) {
        _seenHandshakeIds.remove(sorted[i].key);
      }
    }
  }

  /// Clears all replay cache state.
  void clear() {
    _seenMessages.clear();
    _highestCounter.clear();
    _seenHandshakeIds.clear();
  }

  // ---------------------------------------------------------------------------
  // Serialization (for aux record persistence)
  // ---------------------------------------------------------------------------

  Map<String, dynamic> toJson() => {
    'messages': _seenMessages.map(
      (k, v) => MapEntry('${k.sessionId}|${k.counter}', v),
    ),
    'highest': _highestCounter,
    'handshakeIds': _seenHandshakeIds,
  };

  factory FsReplayCache.fromJson(
    Map<String, dynamic> json, {
    FsClock? clock,
    int maxReplayEntries = 256,
    int maxReplayEntryAgeSecs = 7 * 24 * 60 * 60,
    int maxHandshakeIds = 32,
    int maxHandshakeIdAgeSecs = 7 * 24 * 60 * 60,
  }) {
    final cache = FsReplayCache(
      clock: clock,
      maxReplayEntries: maxReplayEntries,
      maxReplayEntryAgeSecs: maxReplayEntryAgeSecs,
      maxHandshakeIds: maxHandshakeIds,
      maxHandshakeIdAgeSecs: maxHandshakeIdAgeSecs,
    );

    final messages = json['messages'] as Map<String, dynamic>?;
    if (messages != null) {
      for (final entry in messages.entries) {
        final parts = entry.key.split('|');
        if (parts.length == 2) {
          final counter = int.tryParse(parts[1]);
          if (counter != null) {
            cache._seenMessages[_MessageId(parts[0], counter)] =
                entry.value as int;
          }
        }
      }
    }

    final highest = json['highest'] as Map<String, dynamic>?;
    if (highest != null) {
      for (final entry in highest.entries) {
        cache._highestCounter[entry.key] = entry.value as int;
      }
    }

    final handshakeIds = json['handshakeIds'] as Map<String, dynamic>?;
    if (handshakeIds != null) {
      for (final entry in handshakeIds.entries) {
        cache._seenHandshakeIds[entry.key] = entry.value as int;
      }
    }

    cache.prune();
    return cache;
  }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

class _MessageId {
  const _MessageId(this.sessionId, this.counter);

  final String sessionId;
  final int counter;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is _MessageId &&
          sessionId == other.sessionId &&
          counter == other.counter;

  @override
  int get hashCode => Object.hash(sessionId, counter);
}

class _DefaultClock implements FsClock {
  const _DefaultClock();

  @override
  int nowSeconds() => DateTime.now().millisecondsSinceEpoch ~/ 1000;
}
