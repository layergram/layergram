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

import 'dart:async';
import 'dart:collection';

/// Per-contact mutex for serializing FS state transitions.
///
/// **Spec requirement (§20.1):**
/// > Processing two imported Layergram messages concurrently must never
/// > corrupt the auxiliary security state, create two active sessions for
/// > the same contact/device context, or resurrect an older session.
///
/// Dart is single-threaded (runs on one isolate), but async operations
/// (awaiting persistence writes, crypto computations) can interleave
/// if two messages arrive close together.
///
/// This mutex ensures that state transitions for the same contact/device
/// are serialized (run one at a time), while transitions for different
/// contacts can proceed concurrently.
///
/// Usage:
/// ```dart
/// final mutex = FsStateMutex();
/// final result = await mutex.withLock('alice|primary', () async {
///   // state transition for alice...
///   return outcome;
/// });
/// ```
///
/// Spec reference: §20.1 — Atomic state transitions.
class FsStateMutex {
  /// Pending operation queues per contact key.
  final Map<String, Queue<Completer<void>>> _queues = {};

  /// Currently held locks.
  final Set<String> _locks = {};

  /// Runs [action] while holding the lock for [contactKey].
  ///
  /// If another async operation is already running for the same [contactKey],
  /// this call waits until the previous operation completes.
  ///
  /// Operations for different [contactKey] values run concurrently.
  ///
  /// The [contactKey] should be `"$contactId|$identityContext"` to ensure
  /// per-contact/device serialization.
  Future<T> withLock<T>(String contactKey, Future<T> Function() action) async {
    // Wait until we can acquire the lock.
    await _acquire(contactKey);

    try {
      return await action();
    } finally {
      _release(contactKey);
    }
  }

  /// Whether the lock for [contactKey] is currently held.
  bool isLocked(String contactKey) => _locks.contains(contactKey);

  /// Number of queued (waiting) operations for [contactKey].
  int queueLength(String contactKey) =>
      _queues[contactKey]?.length ?? 0;

  Future<void> _acquire(String contactKey) async {
    if (!_locks.contains(contactKey)) {
      // No one holds the lock; acquire immediately.
      _locks.add(contactKey);
      return;
    }

    // Someone holds the lock; queue up.
    final completer = Completer<void>();
    _queues.putIfAbsent(contactKey, () => Queue()).add(completer);
    await completer.future;
  }

  void _release(String contactKey) {
    final queue = _queues[contactKey];
    if (queue != null && queue.isNotEmpty) {
      // Hand the lock to the next waiter.
      final next = queue.removeFirst();
      if (queue.isEmpty) {
        _queues.remove(contactKey);
      }
      next.complete();
    } else {
      // No waiters; release the lock.
      _locks.remove(contactKey);
      _queues.remove(contactKey);
    }
  }
}
