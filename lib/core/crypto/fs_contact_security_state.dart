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

/// The Forward Secrecy security state for a single
/// `(contactId, identityContext, sessionId)` tuple.
///
/// **Key design rules (spec §7.1):**
/// - The shared `RemoteIdentity` contact record MUST NOT contain FS state.
/// - State is keyed by `(contactId, identityContext, sessionId)` — not just
///   `contactId`.  The same contact can have different FS states in the primary
///   context and in a passphrase-derived context.
/// - Passphrase-derived state is visible only while that passphrase context is
///   active.  On expel, the in-memory state for that context is discarded.
///
/// Spec reference: §7 — Contact-Card Security State Model.
class FsContactSecurityState {
  const FsContactSecurityState({
    required this.contactId,
    required this.identityContext,
    required this.sessionId,
    required this.fsState,
    this.remoteDeviceId,
  });

  /// The persistent contact identifier (matches `RemoteIdentity.identityId`).
  final String contactId;

  /// The effective identity context: `'primary'` for the device-derived
  /// identity; a stable context tag for passphrase-derived identities.
  ///
  /// Passphrase contexts MUST use an opaque, non-guessable tag — NOT the
  /// passphrase itself or a human-readable string.
  final String identityContext;

  /// The FS session identifier, or `null` when no active session exists yet.
  final String? sessionId;

  /// The current FS state for this `(contactId, identityContext, sessionId)`.
  final FsSessionState fsState;

  /// Optional: remote device / session identifier reported by the remote party.
  final String? remoteDeviceId;

  /// Returns true if this entry represents an active FS session
  /// (at least [FsSessionState.fsActive]).
  bool get isActive =>
      fsState == FsSessionState.fsActive ||
      fsState == FsSessionState.strictFsActive;

  /// Returns true if the session is in a warning / broken state.
  bool get isBroken => fsState == FsSessionState.fsBroken;

  /// Returns true if Strict FS is active.
  bool get isStrict => fsState == FsSessionState.strictFsActive;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is FsContactSecurityState &&
          other.contactId == contactId &&
          other.identityContext == identityContext &&
          other.sessionId == sessionId &&
          other.fsState == fsState &&
          other.remoteDeviceId == remoteDeviceId;

  @override
  int get hashCode => Object.hash(
        contactId,
        identityContext,
        sessionId,
        fsState,
        remoteDeviceId,
      );

  FsContactSecurityState copyWith({
    String? contactId,
    String? identityContext,
    String? sessionId,
    FsSessionState? fsState,
    String? remoteDeviceId,
  }) =>
      FsContactSecurityState(
        contactId: contactId ?? this.contactId,
        identityContext: identityContext ?? this.identityContext,
        sessionId: sessionId ?? this.sessionId,
        fsState: fsState ?? this.fsState,
        remoteDeviceId: remoteDeviceId ?? this.remoteDeviceId,
      );

  @override
  String toString() =>
      'FsContactSecurityState($contactId, ctx=$identityContext, '
      'session=$sessionId, state=$fsState)';
}

// ---------------------------------------------------------------------------
// In-memory registry
// ---------------------------------------------------------------------------

/// In-memory registry of [FsContactSecurityState] entries.
///
/// One entry per `(contactId, identityContext, sessionId)` tuple.
///
/// **Lifecycle rules:**
/// - Passphrase context entries are removed by [clearContext] on passphrase
///   expel — they are never persisted in a way that survives without the
///   passphrase.
/// - Primary context entries survive across app restarts (loaded from aux
///   records by the caller).
/// - The shared `RemoteIdentity` record is NEVER modified by this registry.
///
/// Spec reference: §7.1.3 — state key model.
class FsContactSecurityRegistry {
  // Key: (contactId, identityContext, sessionId?) → FsContactSecurityState
  final Map<_StateKey, FsContactSecurityState> _entries = {};

  /// Registers or replaces the security state for a specific tuple.
  void upsert(FsContactSecurityState state) {
    final key = _StateKey(
      state.contactId,
      state.identityContext,
      state.sessionId,
    );
    _entries[key] = state;
  }

  /// Returns the security state for a specific
  /// `(contactId, identityContext, sessionId)` tuple, or `null` if absent.
  FsContactSecurityState? lookup({
    required String contactId,
    required String identityContext,
    String? sessionId,
  }) {
    return _entries[_StateKey(contactId, identityContext, sessionId)];
  }

  /// Removes the security state for a specific
  /// `(contactId, identityContext, sessionId)` tuple.
  void remove({
    required String contactId,
    required String identityContext,
    String? sessionId,
  }) {
    _entries.remove(_StateKey(contactId, identityContext, sessionId));
  }

  /// Returns all security states for [contactId] in [identityContext].
  ///
  /// Returns an empty list if no entries exist.
  List<FsContactSecurityState> forContact({
    required String contactId,
    required String identityContext,
  }) {
    return _entries.entries
        .where((e) =>
            e.key.contactId == contactId &&
            e.key.identityContext == identityContext)
        .map((e) => e.value)
        .toList(growable: false);
  }

  /// Returns all security states for [contactId] across ALL identity contexts.
  ///
  /// Used by the contact card to show the union view when presenting to the
  /// user (each context shown separately, not merged).
  List<FsContactSecurityState> forContactAllContexts(String contactId) {
    return _entries.entries
        .where((e) => e.key.contactId == contactId)
        .map((e) => e.value)
        .toList(growable: false);
  }

  /// Removes all entries for [identityContext].
  ///
  /// Called when a passphrase is expelled or a context is torn down.
  /// Primary context entries are NOT affected.
  void clearContext(String identityContext) {
    _entries.removeWhere((k, _) => k.identityContext == identityContext);
  }

  /// Removes all entries for [contactId] in [identityContext].
  void clearContact({
    required String contactId,
    required String identityContext,
  }) {
    _entries.removeWhere(
      (k, _) =>
          k.contactId == contactId && k.identityContext == identityContext,
    );
  }

  /// Removes all entries. Used only in tests or full reset scenarios.
  void clearAll() => _entries.clear();

  /// Marks all entries in [identityContext] as [FsSessionState.fsBroken].
  ///
  /// Called when the identity is reset to suspend all active FS sessions.
  /// Per spec §8.6.3: Reset marks all sessions as broken/suspended.
  void markAllBroken(String identityContext) {
    for (final key in _entries.keys.toList()) {
      if (key.identityContext == identityContext) {
        final entry = _entries[key]!;
        _entries[key] = FsContactSecurityState(
          contactId: entry.contactId,
          identityContext: entry.identityContext,
          sessionId: entry.sessionId,
          fsState: FsSessionState.fsBroken,
        );
      }
    }
  }

  /// Returns the number of registered entries.
  int get length => _entries.length;

  /// Returns true if there are no registered entries.
  bool get isEmpty => _entries.isEmpty;
}

// ---------------------------------------------------------------------------
// Internal key type
// ---------------------------------------------------------------------------

class _StateKey {
  const _StateKey(this.contactId, this.identityContext, this.sessionId);

  final String contactId;
  final String identityContext;
  final String? sessionId;

  @override
  bool operator ==(Object other) =>
      other is _StateKey &&
      other.contactId == contactId &&
      other.identityContext == identityContext &&
      other.sessionId == sessionId;

  @override
  int get hashCode => Object.hash(contactId, identityContext, sessionId);
}
