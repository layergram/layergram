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

/// Local DoS resistance for the Forward Secrecy subsystem.
///
/// Prevents state explosion attacks by bounding:
/// - pending handshakes per contact
/// - orphan/stale aux records
/// - handshake rate per contact
///
/// Recommended limits (spec §20.3):
/// ```text
/// max pending handshakes per contact:   4
/// max orphan aux records per contact:  16
/// max handshake initiations per minute: 2
/// handshake rate window:               60 seconds
/// ```
///
/// Spec reference: §20.3 — Local DoS resistance.
class FsDoSGuard {
  FsDoSGuard({
    FsClock? clock,
    this.maxPendingHandshakesPerContact = 4,
    this.maxOrphanAuxRecords = 16,
    this.maxHandshakeInitiationsPerWindow = 2,
    this.handshakeRateWindowSecs = 60,
  }) : _clock = clock ?? const _DefaultDoSClock();

  final FsClock _clock;

  /// Maximum pending handshakes per contact before new FS_INIT is rejected.
  final int maxPendingHandshakesPerContact;

  /// Maximum orphan/stale aux records per contact.
  final int maxOrphanAuxRecords;

  /// Maximum handshake initiations per rate window.
  final int maxHandshakeInitiationsPerWindow;

  /// Rate window duration in seconds.
  final int handshakeRateWindowSecs;

  // ---------------------------------------------------------------------------
  // Pending handshake tracking
  // ---------------------------------------------------------------------------

  /// Active pending handshake IDs per contact.
  /// Key: contactId, Value: set of initIds.
  final Map<String, Set<String>> _pendingHandshakes = {};

  /// Timestamps of handshake initiations per contact.
  /// Key: contactId, Value: list of timestamps (seconds).
  final Map<String, List<int>> _handshakeTimestamps = {};

  /// Checks whether a new handshake initiation is allowed for the contact.
  ///
  /// Returns [FsDoSCheckResult] with the reason for rejection, if any.
  FsDoSCheckResult canInitiateHandshake(String contactId) {
    // Check pending handshake count.
    final pending = _pendingHandshakes[contactId];
    if (pending != null && pending.length >= maxPendingHandshakesPerContact) {
      return FsDoSCheckResult._(
        allowed: false,
        reason: FsDoSRejectionReason.tooManyPendingHandshakes,
        detail: 'contact "$contactId" has ${pending.length} pending '
            '(max $maxPendingHandshakesPerContact)',
      );
    }

    // Check rate limit.
    _pruneRateTimestamps(contactId);
    final timestamps = _handshakeTimestamps[contactId];
    if (timestamps != null &&
        timestamps.length >= maxHandshakeInitiationsPerWindow) {
      return FsDoSCheckResult._(
        allowed: false,
        reason: FsDoSRejectionReason.rateLimitExceeded,
        detail: 'contact "$contactId" exceeded '
            '$maxHandshakeInitiationsPerWindow initiations '
            'in ${handshakeRateWindowSecs}s window',
      );
    }

    return FsDoSCheckResult._(allowed: true);
  }

  /// Records that a new handshake was initiated for the contact.
  void recordHandshakeInitiation({
    required String contactId,
    required String initId,
  }) {
    _pendingHandshakes.putIfAbsent(contactId, () => {}).add(initId);
    _handshakeTimestamps
        .putIfAbsent(contactId, () => [])
        .add(_clock.nowSeconds());
  }

  /// Records that a pending handshake completed or failed (remove from pending).
  void completeHandshake({
    required String contactId,
    required String initId,
  }) {
    _pendingHandshakes[contactId]?.remove(initId);
    if (_pendingHandshakes[contactId]?.isEmpty ?? false) {
      _pendingHandshakes.remove(contactId);
    }
  }

  /// Returns the number of pending handshakes for the contact.
  int pendingHandshakeCount(String contactId) {
    return _pendingHandshakes[contactId]?.length ?? 0;
  }

  // ---------------------------------------------------------------------------
  // Orphan aux record tracking
  // ---------------------------------------------------------------------------

  /// Checks whether the count of aux records for a contact exceeds the limit.
  ///
  /// Returns `true` if the number of orphan records is excessive.
  bool isOrphanAuxRecordLimitExceeded(int currentCount) {
    return currentCount >= maxOrphanAuxRecords;
  }

  /// Returns the number of aux records that should be pruned to bring the
  /// count within limits, or 0 if no pruning is needed.
  int orphanRecordsToPrune(int currentCount) {
    if (currentCount <= maxOrphanAuxRecords) return 0;
    return currentCount - maxOrphanAuxRecords;
  }

  // ---------------------------------------------------------------------------
  // Rate limiting internals
  // ---------------------------------------------------------------------------

  void _pruneRateTimestamps(String contactId) {
    final timestamps = _handshakeTimestamps[contactId];
    if (timestamps == null) return;
    final cutoff = _clock.nowSeconds() - handshakeRateWindowSecs;
    timestamps.removeWhere((ts) => ts < cutoff);
    if (timestamps.isEmpty) {
      _handshakeTimestamps.remove(contactId);
    }
  }

  /// Clears all tracking state for a specific contact.
  void clearContact(String contactId) {
    _pendingHandshakes.remove(contactId);
    _handshakeTimestamps.remove(contactId);
  }

  /// Clears all tracking state.
  void clearAll() {
    _pendingHandshakes.clear();
    _handshakeTimestamps.clear();
  }
}

/// Result of a DoS guard check.
class FsDoSCheckResult {
  const FsDoSCheckResult._({
    required this.allowed,
    this.reason,
    this.detail,
  });

  /// Whether the operation is allowed.
  final bool allowed;

  /// If rejected, the reason.
  final FsDoSRejectionReason? reason;

  /// Human-readable detail string (for logging).
  final String? detail;
}

/// Reasons for DoS guard rejection.
enum FsDoSRejectionReason {
  /// Too many pending handshakes for this contact.
  tooManyPendingHandshakes,

  /// Rate limit exceeded for handshake initiations.
  rateLimitExceeded,
}

class _DefaultDoSClock implements FsClock {
  const _DefaultDoSClock();

  @override
  int nowSeconds() => DateTime.now().millisecondsSinceEpoch ~/ 1000;
}
