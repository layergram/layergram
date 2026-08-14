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

import 'dart:typed_data';

import 'triple_ratchet_state_v3.dart';

/// Local retention profile for the inactive protocol-v3 ratchets.
///
/// Normal mode favors long, manually transported conversations. Maximum mode
/// retains out-of-order message keys for less time, reducing the lifetime of
/// old key material. Neither profile silently deletes an incomplete incoming
/// message or an unacknowledged outgoing message.
enum V3RetentionProfile { normal, maximum }

enum V3RetentionBlocker {
  localClockMovedBackward,
  minimumAgeNotReached,
  sessionMismatch,
  snapshotNotActive,
  targetEpochAhead,
  pqSkippedKeyStillUsable,
  pqReceiveChainCanStillDerive,
  acknowledgementIncomplete,
  outboxEntryStillPresent,
}

/// Explainable result from a non-destructive retention eligibility check.
final class V3RetentionDecision {
  V3RetentionDecision._(Iterable<V3RetentionBlocker> blockers)
      : blockers = List<V3RetentionBlocker>.unmodifiable(blockers);

  final List<V3RetentionBlocker> blockers;

  bool get eligible => blockers.isEmpty;
}

/// Conservative, local-clock-only policy for future v3 state retirement.
///
/// This class does not delete anything. It freezes the preconditions that a
/// future crash-consistent retirement journal must prove before it may remove
/// replay/completion proofs and cumulative checkpoint receipts.
final class V3RetentionPolicy {
  factory V3RetentionPolicy.forProfile(V3RetentionProfile profile) {
    return switch (profile) {
      V3RetentionProfile.normal => V3RetentionPolicy._(
          profile: profile,
          skippedKeyLifetimeSeconds: normalSkippedKeyLifetimeSeconds,
          minimumProofLifetimeSeconds: normalMinimumProofLifetimeSeconds,
        ),
      V3RetentionProfile.maximum => V3RetentionPolicy._(
          profile: profile,
          skippedKeyLifetimeSeconds: maximumSkippedKeyLifetimeSeconds,
          minimumProofLifetimeSeconds: maximumMinimumProofLifetimeSeconds,
        ),
    };
  }

  factory V3RetentionPolicy.custom({
    required int skippedKeyLifetimeSeconds,
    required int minimumProofLifetimeSeconds,
  }) {
    _validateLifetime(
      skippedKeyLifetimeSeconds,
      'skippedKeyLifetimeSeconds',
    );
    _validateLifetime(
      minimumProofLifetimeSeconds,
      'minimumProofLifetimeSeconds',
    );
    if (minimumProofLifetimeSeconds < skippedKeyLifetimeSeconds) {
      throw ArgumentError.value(
        minimumProofLifetimeSeconds,
        'minimumProofLifetimeSeconds',
        'must not be shorter than skipped-key retention',
      );
    }
    return V3RetentionPolicy._(
      profile: null,
      skippedKeyLifetimeSeconds: skippedKeyLifetimeSeconds,
      minimumProofLifetimeSeconds: minimumProofLifetimeSeconds,
    );
  }

  const V3RetentionPolicy._({
    required this.profile,
    required this.skippedKeyLifetimeSeconds,
    required this.minimumProofLifetimeSeconds,
  });

  static const int secondsPerDay = 24 * 60 * 60;

  /// Normal mode tolerates six months of delayed, out-of-order delivery.
  static const int normalSkippedKeyLifetimeSeconds = 180 * secondsPerDay;

  /// Maximum mode limits old message-key retention to thirty days.
  static const int maximumSkippedKeyLifetimeSeconds = 30 * secondsPerDay;

  /// A normal-mode compact proof remains durable for at least one year.
  static const int normalMinimumProofLifetimeSeconds = 365 * secondsPerDay;

  /// A maximum-mode compact proof remains durable for at least ninety days.
  static const int maximumMinimumProofLifetimeSeconds = 90 * secondsPerDay;

  final V3RetentionProfile? profile;
  final int skippedKeyLifetimeSeconds;
  final int minimumProofLifetimeSeconds;

  /// Pending sealed frames are bounded but never silently time-purged.
  bool get automaticallyPurgesPendingInboxFrames => false;

  /// Lost ACKs keep exact sealed bytes available until explicit user action.
  bool get automaticallyPurgesUnacknowledgedOutboxEntries => false;

  /// Checks whether an incoming replay proof is old enough and its exact
  /// Sparse-PQ key is independently unavailable in [snapshot].
  ///
  /// [committedAt] and [now] are local timestamps. Sender-declared expiry is
  /// intentionally absent from this API and can never authorize retirement.
  V3RetentionDecision evaluateIncomingReplay({
    required V3TripleRatchetState snapshot,
    required Uint8List targetSessionId,
    required int targetEpoch,
    required int targetMessageCounter,
    required DateTime committedAt,
    required DateTime now,
  }) {
    _validateCounter(targetEpoch, 'targetEpoch');
    _validateCounter(targetMessageCounter, 'targetMessageCounter');
    if (targetSessionId.length != 16) {
      throw ArgumentError.value(
        targetSessionId.length,
        'targetSessionId.length',
      );
    }
    if (_isAllZero(targetSessionId)) {
      throw ArgumentError('targetSessionId must not be all-zero');
    }

    final blockers = <V3RetentionBlocker>[];
    _appendAgeBlockers(
      blockers,
      recordedAt: committedAt,
      now: now,
    );
    if (snapshot.lifecycle != V3RatchetLifecycle.active) {
      blockers.add(V3RetentionBlocker.snapshotNotActive);
    }

    final snapshotSessionId = snapshot.sessionId;
    final skipped = snapshot.pqSkippedMessageKeys;
    final epochs = snapshot.pqEpochStates;
    try {
      if (!_bytesEqual(snapshotSessionId, targetSessionId)) {
        blockers.add(V3RetentionBlocker.sessionMismatch);
      }
      if (targetEpoch > snapshot.pqReceivingEpoch ||
          targetEpoch > snapshot.pqCurrentEpoch) {
        blockers.add(V3RetentionBlocker.targetEpochAhead);
      }

      final nowSeconds = now.toUtc().millisecondsSinceEpoch ~/ 1000;
      var matchingUsableSkippedKey = false;
      for (final candidate in skipped) {
        if (candidate.epoch == targetEpoch &&
            candidate.messageCounter == targetMessageCounter &&
            candidate.expiresAtUnixSeconds > nowSeconds) {
          matchingUsableSkippedKey = true;
          break;
        }
      }
      if (matchingUsableSkippedKey) {
        blockers.add(V3RetentionBlocker.pqSkippedKeyStillUsable);
      }

      V3PqEpochState? retainedEpoch;
      for (final candidate in epochs) {
        if (candidate.epoch == targetEpoch) {
          retainedEpoch = candidate;
          break;
        }
      }
      if (!matchingUsableSkippedKey &&
          retainedEpoch != null &&
          retainedEpoch.hasReceivingChain &&
          targetMessageCounter >= retainedEpoch.receiveCounter) {
        blockers.add(V3RetentionBlocker.pqReceiveChainCanStillDerive);
      }
    } finally {
      snapshotSessionId.fillRange(0, snapshotSessionId.length, 0);
      for (final candidate in skipped) {
        candidate.wipeSecret();
      }
      for (final epoch in epochs) {
        epoch.wipeSecrets();
      }
    }
    return V3RetentionDecision._(blockers);
  }

  /// Checks the non-secret preconditions for retiring an outgoing completion.
  V3RetentionDecision evaluateOutgoingCompletion({
    required bool fullyAcknowledged,
    required bool outboxEntryAbsent,
    required DateTime completedAt,
    required DateTime now,
  }) {
    final blockers = <V3RetentionBlocker>[];
    _appendAgeBlockers(
      blockers,
      recordedAt: completedAt,
      now: now,
    );
    if (!fullyAcknowledged) {
      blockers.add(V3RetentionBlocker.acknowledgementIncomplete);
    }
    if (!outboxEntryAbsent) {
      blockers.add(V3RetentionBlocker.outboxEntryStillPresent);
    }
    return V3RetentionDecision._(blockers);
  }

  void _appendAgeBlockers(
    List<V3RetentionBlocker> blockers, {
    required DateTime recordedAt,
    required DateTime now,
  }) {
    final recordedUtc = recordedAt.toUtc();
    final nowUtc = now.toUtc();
    if (nowUtc.isBefore(recordedUtc)) {
      blockers.add(V3RetentionBlocker.localClockMovedBackward);
      return;
    }
    final ageSeconds = nowUtc.difference(recordedUtc).inSeconds;
    if (ageSeconds < minimumProofLifetimeSeconds) {
      blockers.add(V3RetentionBlocker.minimumAgeNotReached);
    }
  }
}

const int _maxCounter = 0x7fffffffffffffff;

void _validateLifetime(int value, String name) {
  if (value <= 0 || value > _maxCounter) {
    throw ArgumentError.value(value, name);
  }
}

void _validateCounter(int value, String name) {
  if (value < 0 || value > _maxCounter) {
    throw ArgumentError.value(value, name);
  }
}

bool _isAllZero(Uint8List value) {
  var aggregate = 0;
  for (final byte in value) {
    aggregate |= byte;
  }
  return aggregate == 0;
}

bool _bytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
