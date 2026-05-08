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

import 'fs_contact_security_state.dart';
import 'fs_session_manager.dart';

/// Manages the lifecycle of passphrase-derived FS context state.
///
/// **Key invariants (spec §8):**
/// - All passphrase-derived state is RAM-only.
/// - On passphrase expel ([deactivate]), all in-memory state for the active
///   passphrase context is cleared from [FsContactSecurityRegistry] and from
///   [_activeSessionManagers].
/// - No global `has_passphrase` flag is written to storage.
/// - No `passphrase_settings` box or key is created.
/// - The passphrase context tag is derived from the passphrase public key —
///   never from the passphrase text itself, and never from a persistent
///   sequence number.
///
/// Spec reference: §8 — Passphrase-Derived Context Integration.
class FsPassphraseContextService {
  FsPassphraseContextService({
    required FsContactSecurityRegistry registry,
  }) : _registry = registry;

  final FsContactSecurityRegistry _registry;

  /// The currently-active passphrase context tag, or `null` when inactive.
  ///
  /// Derived from `PassphraseState.keyTag` (8-char base64url SHA-256 prefix).
  String? _activeContextTag;

  /// In-memory session managers for contacts under the active passphrase context.
  ///
  /// Keyed by `contactId`.  Cleared entirely on [deactivate].
  final Map<String, FsSessionManager> _activeSessionManagers = {};

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /// Activates the passphrase FS context with the given [contextTag].
  ///
  /// [contextTag] must be the `PassphraseState.keyTag` value — an opaque 8-char
  /// base64url string derived from the passphrase public key.
  ///
  /// Any previously-active passphrase context is cleanly deactivated first.
  void activate(String contextTag) {
    if (_activeContextTag != null && _activeContextTag != contextTag) {
      deactivate();
    }
    _activeContextTag = contextTag;
  }

  /// Deactivates the passphrase context and wipes all in-memory state.
  ///
  /// This is the "expel passphrase" action.  After this call:
  /// - [isActive] returns false.
  /// - All session managers for the passphrase context are gone.
  /// - The [FsContactSecurityRegistry] no longer contains any entries for this
  ///   context.
  void deactivate() {
    if (_activeContextTag != null) {
      _registry.clearContext(_activeContextTag!);
      _activeSessionManagers.clear();
      _activeContextTag = null;
    }
  }

  // ---------------------------------------------------------------------------
  // State access
  // ---------------------------------------------------------------------------

  /// Whether a passphrase context is currently active.
  bool get isActive => _activeContextTag != null;

  /// The active context tag, or `null` if inactive.
  String? get activeContextTag => _activeContextTag;

  /// Returns the [FsSessionManager] for [contactId] in the active passphrase
  /// context, creating one on demand if needed.
  ///
  /// Returns `null` if no passphrase context is active.
  FsSessionManager? sessionManagerForContact(
    String contactId, {
    FsClock? clock,
  }) {
    if (_activeContextTag == null) return null;
    return _activeSessionManagers.putIfAbsent(
      contactId,
      () => FsSessionManager(clock: clock),
    );
  }

  /// Records an FS security state update for [contactId] under the active
  /// passphrase context.
  ///
  /// No-op if no passphrase context is active.
  void updateSecurityState({
    required String contactId,
    required FsSessionState fsState,
    String? sessionId,
    String? remoteDeviceId,
  }) {
    final ctx = _activeContextTag;
    if (ctx == null) return;
    _registry.upsert(FsContactSecurityState(
      contactId: contactId,
      identityContext: ctx,
      sessionId: sessionId,
      fsState: fsState,
      remoteDeviceId: remoteDeviceId,
    ));
  }

  /// Returns the current FS security state for [contactId] in the active
  /// passphrase context and [sessionId], or `null` if absent or inactive.
  FsContactSecurityState? securityStateFor({
    required String contactId,
    String? sessionId,
  }) {
    final ctx = _activeContextTag;
    if (ctx == null) return null;
    return _registry.lookup(
      contactId: contactId,
      identityContext: ctx,
      sessionId: sessionId,
    );
  }

  /// Returns all FS security states for [contactId] under the active passphrase
  /// context.
  List<FsContactSecurityState> allStatesFor(String contactId) {
    final ctx = _activeContextTag;
    if (ctx == null) return const [];
    return _registry.forContact(
      contactId: contactId,
      identityContext: ctx,
    );
  }
}
