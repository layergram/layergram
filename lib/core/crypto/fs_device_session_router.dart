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

/// Routes FS messages to per-device [FsSessionManager] instances.
///
/// In Opportunistic FS, a contact may use multiple devices (or restore the
/// same identity on a second device). Each remote device needs its own FS
/// session state (spec §7.3, §7.9).
///
/// The router maintains:
/// - A "current" session manager for the most recently active device.
/// - A set of previous session managers whose ratchets may still be needed
///   to decrypt in-flight messages from an older device.
///
/// **Device identification**: In Layergram, devices restored from the same
/// seed have identical IK/DK. We therefore distinguish "devices" by their
/// FS session ID (initId/replyId), not by DK alone.
///
/// Spec reference: §7.3, §7.9 — Per-device sessions.
class FsDeviceSessionRouter {
  FsDeviceSessionRouter({
    FsClock? clock,
    FsSessionManager? initialSession,
  }) : _clock = clock {
    _currentSession = initialSession ?? FsSessionManager(clock: clock);
  }

  final FsClock? _clock;

  /// The currently active session manager (most recently established session).
  late FsSessionManager _currentSession;

  /// Previous session managers, keyed by their activeSessionId.
  /// These are kept so that in-flight messages encrypted with an older
  /// ratchet can still be decrypted. They are NOT used for sending.
  final Map<String, FsSessionManager> _previousSessions = {};

  /// Returns the current (most recently active) session manager.
  FsSessionManager get currentSession => _currentSession;

  /// Returns the session manager that owns [sessionId], or null.
  ///
  /// This is used during decryption when the incoming message's `fs_session`
  /// field identifies which ratchet to use.
  FsSessionManager? sessionForId(String sessionId) {
    if (_currentSession.activeSessionId == sessionId) return _currentSession;
    return _previousSessions[sessionId];
  }

  /// Returns the "best" FS state across all device sessions.
  ///
  /// Priority: active/strict > handshake-in-progress > broken > legacy.
  FsSessionState get bestState {
    final currentState = _currentSession.state;
    // The current session's state is almost always the most relevant.
    // Only return a previous session's state if the current is legacyOnly
    // and a previous session is still active (rare edge case).
    if (currentState == FsSessionState.fsActive ||
        currentState == FsSessionState.strictFsActive) {
      return currentState;
    }
    // Check previous sessions for any still-active ones
    for (final prev in _previousSessions.values) {
      if (prev.state == FsSessionState.fsActive ||
          prev.state == FsSessionState.strictFsActive) {
        return prev.state;
      }
    }
    return currentState;
  }

  /// Returns all active session IDs (current + previous that are still active).
  List<String> get allActiveSessionIds {
    final ids = <String>[];
    final currentId = _currentSession.activeSessionId;
    if (currentId != null) ids.add(currentId);
    for (final entry in _previousSessions.entries) {
      if (entry.value.state == FsSessionState.fsActive ||
          entry.value.state == FsSessionState.strictFsActive) {
        ids.add(entry.key);
      }
    }
    return ids;
  }

  /// Called when a new `fs_init` arrives while the current session is in a
  /// terminal state (fsActive, fsBroken, fsSuspended).
  ///
  /// Instead of resetting the current session (which would destroy its ratchet
  /// state), this method:
  /// 1. Archives the current session manager (keyed by its activeSessionId).
  /// 2. Creates a new session manager for the incoming handshake.
  ///
  /// Returns the new session manager, ready to process the `fs_init`.
  FsSessionManager rotateForNewDevice() {
    // Archive the current session if it has an active session ID
    final currentId = _currentSession.activeSessionId;
    if (currentId != null) {
      _previousSessions[currentId] = _currentSession;
    }

    // Create a fresh session manager for the new device
    _currentSession = FsSessionManager(clock: _clock);
    return _currentSession;
  }

  /// Resets all sessions (current + previous).
  ///
  /// Called on identity reset to wipe all FS state.
  void resetAll() {
    _currentSession.reset();
    for (final prev in _previousSessions.values) {
      prev.reset();
    }
    _previousSessions.clear();
  }

  /// Marks all sessions as broken.
  void markAllBroken() {
    _currentSession.markBroken();
    for (final prev in _previousSessions.values) {
      prev.markBroken();
    }
  }

  /// Returns the number of tracked sessions (current + previous).
  int get sessionCount => 1 + _previousSessions.length;

  /// Returns the number of previous (archived) sessions.
  int get previousSessionCount => _previousSessions.length;

  /// Removes stale previous sessions that are no longer needed.
  ///
  /// A session is considered stale when it has been broken or
  /// in legacyOnly state (ratchet is gone anyway).
  void cleanupStaleSessions() {
    _previousSessions.removeWhere((_, session) =>
        session.state == FsSessionState.legacyOnly ||
        session.state == FsSessionState.fsBroken);
  }

  /// For testing: directly set the current session manager.
  void setCurrentSessionForTesting(FsSessionManager session) {
    _currentSession = session;
  }

  /// For testing: add a previous session.
  void addPreviousSessionForTesting(String sessionId, FsSessionManager session) {
    _previousSessions[sessionId] = session;
  }
}
