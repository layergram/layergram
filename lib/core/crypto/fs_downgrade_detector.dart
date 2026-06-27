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

import 'fs_message_classification.dart';
import 'fs_session_manager.dart';

/// Tracks the highest confirmed security level per (contactId, identityContext)
/// and detects unexpected downgrades.
///
/// **Spec requirement (§7.6):**
/// > Once a contact/device has reached an FS state, Layergram must remember
/// > the highest confirmed security level in encrypted auxiliary state.
/// > If future messages from the same contact/device fall back to legacy
/// > unexpectedly:
/// >   Opportunistic mode: allow but show an internal or visible warning.
/// >   Strict mode: reject or mark as not accepted.
///
/// Spec reference: §7.6 — Downgrade resistance.
class FsDowngradeDetector {
  FsDowngradeDetector();

  /// Per-contact highest confirmed security level.
  /// Key: `contactId|identityContext`.
  final Map<String, FsMessageSecurity> _highestLevel = {};

  /// Returns the highest confirmed security level for the given contact.
  FsMessageSecurity highestLevel({
    required String contactId,
    required String identityContext,
  }) {
    return _highestLevel[_key(contactId, identityContext)] ??
        FsMessageSecurity.legacy;
  }

  /// Records that a message with the given security level was successfully
  /// processed for the given contact.
  ///
  /// Only advances the highest level, never regresses.
  void recordSecurityLevel({
    required String contactId,
    required String identityContext,
    required FsMessageSecurity level,
  }) {
    final key = _key(contactId, identityContext);
    final current = _highestLevel[key];
    if (current == null || level.index > current.index) {
      _highestLevel[key] = level;
    }
  }

  /// Evaluates whether an incoming message represents a downgrade from the
  /// highest confirmed security level.
  ///
  /// Returns [FsDowngradeResult] with:
  /// - [isDowngrade]: `true` if the incoming level is lower than the highest.
  /// - [previousLevel]: the highest level previously confirmed.
  /// - [currentLevel]: the level of the incoming message.
  /// - [action]: the recommended action based on the session mode.
  FsDowngradeResult evaluate({
    required String contactId,
    required String identityContext,
    required FsMessageSecurity incomingLevel,
    required FsSessionState sessionState,
  }) {
    final highest = highestLevel(
      contactId: contactId,
      identityContext: identityContext,
    );

    if (incomingLevel.index >= highest.index) {
      return FsDowngradeResult._(
        isDowngrade: false,
        previousLevel: highest,
        currentLevel: incomingLevel,
        action: FsDowngradeAction.accept,
      );
    }

    // Determine action based on session mode.
    final isStrict = sessionState == FsSessionState.strictFsActive ||
        sessionState == FsSessionState.strictRequested;

    return FsDowngradeResult._(
      isDowngrade: true,
      previousLevel: highest,
      currentLevel: incomingLevel,
      action: isStrict
          ? FsDowngradeAction.reject
          : FsDowngradeAction.acceptWithWarning,
    );
  }

  /// Clears all tracked security levels for a specific contact.
  void clearContact({
    required String contactId,
    required String identityContext,
  }) {
    _highestLevel.remove(_key(contactId, identityContext));
  }

  /// Clears all tracked security levels.
  void clearAll() {
    _highestLevel.clear();
  }

  // ---------------------------------------------------------------------------
  // Serialization (for aux record persistence)
  // ---------------------------------------------------------------------------

  Map<String, dynamic> toJson() => {
    'highestLevels': _highestLevel.map(
      (k, v) => MapEntry(k, v.index),
    ),
  };

  factory FsDowngradeDetector.fromJson(Map<String, dynamic> json) {
    final detector = FsDowngradeDetector();
    final levels = json['highestLevels'] as Map<String, dynamic>?;
    if (levels != null) {
      for (final entry in levels.entries) {
        final idx = entry.value as int;
        if (idx >= 0 && idx < FsMessageSecurity.values.length) {
          detector._highestLevel[entry.key] =
              FsMessageSecurity.values[idx];
        }
      }
    }
    return detector;
  }

  static String _key(String contactId, String identityContext) =>
      '$contactId|$identityContext';
}

/// Result of a downgrade evaluation.
class FsDowngradeResult {
  const FsDowngradeResult._({
    required this.isDowngrade,
    required this.previousLevel,
    required this.currentLevel,
    required this.action,
  });

  /// Whether the incoming message represents a downgrade.
  final bool isDowngrade;

  /// The highest security level previously confirmed for this contact.
  final FsMessageSecurity previousLevel;

  /// The security level of the incoming message.
  final FsMessageSecurity currentLevel;

  /// The recommended action.
  final FsDowngradeAction action;
}

/// Recommended action when a downgrade is detected.
enum FsDowngradeAction {
  /// Accept the message normally (no downgrade detected).
  accept,

  /// Accept the message but show a warning (Opportunistic mode downgrade).
  acceptWithWarning,

  /// Reject the message (Strict mode — no legacy fallback allowed).
  reject,
}
