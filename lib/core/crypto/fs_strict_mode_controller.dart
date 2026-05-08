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

/// Per-contact Maximum / Strict FS policy controller.
///
/// **Key design rules (spec §11):**
/// - Maximum FS cannot be enabled globally — only per-contact, per-context.
/// - Requesting Maximum FS sets state to [FsSessionState.strictRequested],
///   NOT directly to [FsSessionState.strictFsActive].
/// - [FsSessionState.strictFsActive] is set only after a confirmed handshake.
/// - Once [FsSessionState.strictFsActive], sending pauses if an unexpected
///   device is detected ([canSendMessage] returns false).
/// - Disabling Maximum FS resets state to [FsSessionState.fsActive] and
///   allows legacy fallback again.
/// - Passphrase-context consent is stored only in opaque aux records (the
///   caller's responsibility; this class never persists anything).
/// - No global Maximum FS flag exists: each `(contactId, identityContext)`
///   pair has independent policy.
///
/// Spec reference: §11 — Maximum / Strict FS Per Contact.
class FsStrictModeController {
  FsStrictModeController({
    required String contactId,
    required String identityContext,
    required FsSessionManager sessionManager,
    required FsContactSecurityRegistry registry,
  })  : _contactId = contactId,
        _identityContext = identityContext,
        _sessionManager = sessionManager,
        _registry = registry;

  final String _contactId;
  final String _identityContext;
  final FsSessionManager _sessionManager;
  final FsContactSecurityRegistry _registry;

  // ---------------------------------------------------------------------------
  // Policy state
  // ---------------------------------------------------------------------------

  bool _strictRequested = false;

  /// Whether Maximum FS has been requested for this contact.
  bool get isStrictRequested => _strictRequested;

  // ---------------------------------------------------------------------------
  // User actions
  // ---------------------------------------------------------------------------

  /// User requests Maximum FS for this contact.
  ///
  /// Sets [FsSessionState.strictRequested] and returns [FsStrictModeResult.ok]
  /// if the current state allows it.
  ///
  /// Preconditions:
  /// - Maximum FS cannot be requested globally: this controller is per-contact.
  /// - The session must be at least in [FsSessionState.fsActive].
  ///   If not, the result is [FsStrictModeResult.notYetActive].
  FsStrictModeResult requestMaximum(String sessionId) {
    final state = _sessionManager.state;
    if (state != FsSessionState.fsActive) {
      return FsStrictModeResult._(
        success: false,
        reason: 'Maximum FS can only be requested in fsActive state '
            '(current: $state)',
        code: FsStrictModeResultCode.notYetActive,
      );
    }

    _strictRequested = true;
    _sessionManager.requestStrict();
    _updateRegistry(
      sessionId: sessionId,
      state: FsSessionState.strictRequested,
    );
    return const FsStrictModeResult._(
      success: true,
      code: FsStrictModeResultCode.ok,
    );
  }

  /// Called when the confirmed handshake completes under a strict request.
  ///
  /// Transitions state to [FsSessionState.strictFsActive].
  /// Returns [FsStrictModeResult.notRequested] if [requestMaximum] was never
  /// called for this session.
  FsStrictModeResult activateStrict(String sessionId) {
    if (!_strictRequested) {
      return const FsStrictModeResult._(
        success: false,
        reason: 'activateStrict: Maximum FS was not requested',
        code: FsStrictModeResultCode.notRequested,
      );
    }

    final state = _sessionManager.state;
    if (state != FsSessionState.strictRequested) {
      return FsStrictModeResult._(
        success: false,
        reason: 'activateStrict: state must be strictRequested (current: $state)',
        code: FsStrictModeResultCode.invalidState,
      );
    }

    _sessionManager.activateStrictSession(sessionId);
    _updateRegistry(
      sessionId: sessionId,
      state: FsSessionState.strictFsActive,
    );
    return const FsStrictModeResult._(
      success: true,
      code: FsStrictModeResultCode.ok,
    );
  }

  /// Disables Maximum FS and reverts to [FsSessionState.fsActive].
  ///
  /// After this call:
  /// - [FsSessionState.fsActive] is restored.
  /// - Legacy fallback is allowed again.
  /// - [_strictRequested] is cleared.
  FsStrictModeResult disableStrict(String sessionId) {
    _strictRequested = false;
    _sessionManager.disableStrict();
    _updateRegistry(
      sessionId: sessionId,
      state: FsSessionState.fsActive,
    );
    return const FsStrictModeResult._(
      success: true,
      code: FsStrictModeResultCode.ok,
    );
  }

  // ---------------------------------------------------------------------------
  // Policy checks
  // ---------------------------------------------------------------------------

  /// Returns true if a message can be sent in the current state.
  ///
  /// In [FsSessionState.strictFsActive], sending is blocked unless the
  /// session is healthy (i.e., no device change detected).
  ///
  /// [deviceChanged] must be set to true by the caller if the remote device
  /// ID has changed since the last confirmed session — this triggers a pause.
  bool canSendMessage({bool deviceChanged = false}) {
    final state = _sessionManager.state;
    if (state == FsSessionState.fsBroken) return false;

    if (state == FsSessionState.strictFsActive) {
      if (deviceChanged) return false; // Must repair before sending.
      return true;
    }

    // Legacy fallback allowed in non-strict states.
    return state != FsSessionState.fsBroken;
  }

  /// Returns the reason why [canSendMessage] returned false, or null.
  String? sendBlockReason({bool deviceChanged = false}) {
    final state = _sessionManager.state;
    if (state == FsSessionState.fsBroken) {
      return 'Session is broken and cannot be used';
    }
    if (state == FsSessionState.strictFsActive && deviceChanged) {
      return 'Unexpected device detected — repair required before sending';
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  void _updateRegistry({
    required String? sessionId,
    required FsSessionState state,
  }) {
    _registry.upsert(FsContactSecurityState(
      contactId: _contactId,
      identityContext: _identityContext,
      sessionId: sessionId,
      fsState: state,
    ));
  }
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

class FsStrictModeResult {
  const FsStrictModeResult._({
    required this.success,
    this.reason,
    required this.code,
  });

  final bool success;
  final String? reason;
  final FsStrictModeResultCode code;

  @override
  String toString() => 'FsStrictModeResult($code${reason != null ? ': $reason' : ''})';
}

enum FsStrictModeResultCode {
  ok,

  /// The session is not yet in [FsSessionState.fsActive] to allow the request.
  notYetActive,

  /// [requestMaximum] was never called before [activateStrict].
  notRequested,

  /// The FSM was in an unexpected state for this operation.
  invalidState,
}
