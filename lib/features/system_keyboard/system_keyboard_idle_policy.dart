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

/// Pure, clock-injected inactivity policy for the **SYSTEM keyboard**.
///
/// This library is portable policy only: no wall clock (`DateTime`), no timers,
/// no I/O, no keys, no identity and no platform channel. It answers two
/// independent questions. Preference selection ([SystemKeyboardIdlePolicy])
/// says how long the keyboard may stay idle once the app-lock ceiling is taken
/// into account, so settings can explain the clamp. One in-memory session
/// ([SystemKeyboardIdleSession]) says whether an already-authorized keyboard
/// window is still active at an explicit monotonic reading.
///
/// What it deliberately never does:
/// * never renews on a poll, on a heartbeat or on a generic draft mutation:
///   only an explicit [SystemKeyboardIdleSession.recordUserInteraction] with a
///   monotonic reading sampled from a **physically intentional user touch**
///   extends a window. Callers must wire real touch, never a refresh loop;
/// * never revives an expired, revoked or clock-regressed session;
/// * never grants, unlocks, admits an identity or extends operating-system
///   background execution: the autonomous runtime enforces this policy only
///   after a separate live authorization grant;
/// * never disables or widens the app lock: an app lock configured as
///   immediate (`<= 0` seconds) denies the keyboard instead;
/// * never keeps a secret: the exposed state is a status, a deadline and a
///   remaining duration only.
library;

/// Status of one in-memory keyboard idle session.
enum SystemKeyboardIdleState {
  /// The authorized window may still be used; its remaining time is positive.
  active,

  /// The deadline passed. Terminal: no poll or touch can revive the session.
  expired,

  /// Explicitly revoked, or invalidated by a backwards monotonic reading or by
  /// an overflowing renewal. Terminal.
  revoked,
}

/// One read-only view of a session at an explicit monotonic reading.
///
/// Only non-secret status information is exposed: state, absolute deadline and
/// remaining idle time.
final class SystemKeyboardIdleObservation {
  /// Creates an observation.
  const SystemKeyboardIdleObservation({
    required this.state,
    required this.deadlineMonotonicMillis,
    required this.remainingMillis,
  });

  /// Session status at the sampled instant.
  final SystemKeyboardIdleState state;

  /// Absolute monotonic deadline of the current idle window.
  final int deadlineMonotonicMillis;

  /// Milliseconds left before [deadlineMonotonicMillis]; `0` when terminal.
  final int remainingMillis;

  /// True only while the session is still [SystemKeyboardIdleState.active].
  bool get isActive => state == SystemKeyboardIdleState.active;
}

/// Fail-safe validation and app-lock clamping of the idle preference.
///
/// Selected durations are immutable and enumerable so a settings surface can
/// explain them; there is deliberately no unlimited option.
abstract final class SystemKeyboardIdlePolicy {
  /// Default preference for a missing or malformed stored value.
  static const int defaultIdleSeconds = 60;

  /// The only selectable preference durations, in seconds.
  static const List<int> supportedIdleSeconds = <int>[20, 30, 60, 120, 300];

  /// Largest monotonic millisecond value, shared with the Swift `Int64` peer.
  static const int maxSafeMonotonicMillis = 9007199254740991;

  /// The requested preference, or [defaultIdleSeconds] for any malformed or
  /// unsupported value. Validation never mutates the stored preference.
  static int validatedPreferenceSeconds(Object? raw) {
    if (raw is! int) return defaultIdleSeconds;
    return supportedIdleSeconds.contains(raw) ? raw : defaultIdleSeconds;
  }

  /// Effective idle seconds, or `null` when the keyboard must be denied.
  ///
  /// With [appLockEnabled] false the validated request is used unchanged. With
  /// the app lock enabled the value is clamped **down** to
  /// [appLockTimeoutSeconds]; an immediate app lock (`<= 0`) denies the
  /// keyboard rather than disabling or widening that lock. The clamp is a
  /// separate call from [validatedPreferenceSeconds] so settings can compare
  /// the two and explain a shortened window.
  static int? effectiveIdleSeconds({
    required int requestedIdleSeconds,
    required bool appLockEnabled,
    required int appLockTimeoutSeconds,
  }) {
    final int requested = validatedPreferenceSeconds(requestedIdleSeconds);
    if (!appLockEnabled) return requested;
    if (appLockTimeoutSeconds <= 0) return null;
    return requested < appLockTimeoutSeconds
        ? requested
        : appLockTimeoutSeconds;
  }

  /// [effectiveIdleSeconds] in milliseconds, or `null` when denied.
  static int? effectiveIdleMillis({
    required int requestedIdleSeconds,
    required bool appLockEnabled,
    required int appLockTimeoutSeconds,
  }) {
    final int? seconds = effectiveIdleSeconds(
      requestedIdleSeconds: requestedIdleSeconds,
      appLockEnabled: appLockEnabled,
      appLockTimeoutSeconds: appLockTimeoutSeconds,
    );
    if (seconds == null) return null;
    return seconds * 1000;
  }
}

/// One in-memory keyboard idle window.
///
/// [start] is the authority boundary: it is the only way to create a session
/// and it requires the authorized start reading plus the already-clamped
/// effective duration. An arbitrary touch handler, heartbeat or poll can never
/// construct a session; it may only report a physical touch through
/// [recordUserInteraction], and it can never revive a terminal one.
final class SystemKeyboardIdleSession {
  SystemKeyboardIdleSession._({
    required int startMonotonicMillis,
    required this.authorizedDurationMillis,
    required int deadlineMonotonicMillis,
  })  : _deadlineMonotonicMillis = deadlineMonotonicMillis,
        _lastObservedMonotonicMillis = startMonotonicMillis;

  /// Starts a session, or returns `null` when it must be denied.
  ///
  /// Denied when [authorizedDurationMillis] is `null` (no authorized window),
  /// nonpositive or larger than the shared safe range, and when
  /// [startMonotonicMillis] is negative. A denied start is never repaired into
  /// a shorter session.
  static SystemKeyboardIdleSession? start({
    required int startMonotonicMillis,
    required int? authorizedDurationMillis,
  }) {
    if (startMonotonicMillis < 0) return null;
    final int? duration = authorizedDurationMillis;
    if (duration == null || duration <= 0) return null;
    if (duration >
        SystemKeyboardIdlePolicy.maxSafeMonotonicMillis -
            startMonotonicMillis) {
      return null;
    }
    return SystemKeyboardIdleSession._(
      startMonotonicMillis: startMonotonicMillis,
      authorizedDurationMillis: duration,
      deadlineMonotonicMillis: startMonotonicMillis + duration,
    );
  }

  /// Effective idle duration authorized at start. Never renewed.
  final int authorizedDurationMillis;

  /// Absolute monotonic deadline; it moves forward only on an accepted touch.
  int _deadlineMonotonicMillis;
  int get deadlineMonotonicMillis => _deadlineMonotonicMillis;

  SystemKeyboardIdleState _state = SystemKeyboardIdleState.active;
  int _lastObservedMonotonicMillis;

  /// Current status.
  SystemKeyboardIdleState get state => _state;

  /// True once the session can never become active again.
  bool get isTerminal => _state != SystemKeyboardIdleState.active;

  /// Reads the session at [nowMonotonicMillis] **without renewing it**.
  ///
  /// A reading below the previous accepted reading permanently revokes the
  /// session (time moved backwards). A reading equal to the deadline expires
  /// it. Polling, heartbeats and `observe` loops never extend the deadline, so
  /// a quiet keyboard expires exactly at its deadline.
  SystemKeyboardIdleObservation observe(int nowMonotonicMillis) {
    if (isTerminal) return _observation(nowMonotonicMillis);
    if (nowMonotonicMillis < _lastObservedMonotonicMillis) {
      _state = SystemKeyboardIdleState.revoked;
      return _observation(nowMonotonicMillis);
    }
    if (nowMonotonicMillis >= deadlineMonotonicMillis) {
      _state = SystemKeyboardIdleState.expired;
      return _observation(nowMonotonicMillis);
    }
    _lastObservedMonotonicMillis = nowMonotonicMillis;
    return _observation(nowMonotonicMillis);
  }

  /// Reports one physically intentional user touch sampled at
  /// [nowMonotonicMillis], renewing the window only when the session was
  /// **active before** the event.
  ///
  /// Renewal requires a nondecreasing reading strictly before the deadline; a
  /// reading exactly at the deadline expires the session. A backwards reading
  /// and an overflowing renewal revoke it permanently. The caller must pass
  /// real touch input: a heartbeat, a poll or a generic draft mutation is not
  /// user activity and must call [observe] instead.
  SystemKeyboardIdleObservation recordUserInteraction(int nowMonotonicMillis) {
    if (isTerminal) return _observation(nowMonotonicMillis);
    if (nowMonotonicMillis < _lastObservedMonotonicMillis) {
      _state = SystemKeyboardIdleState.revoked;
      return _observation(nowMonotonicMillis);
    }
    if (nowMonotonicMillis >= deadlineMonotonicMillis) {
      _state = SystemKeyboardIdleState.expired;
      return _observation(nowMonotonicMillis);
    }
    if (authorizedDurationMillis >
        SystemKeyboardIdlePolicy.maxSafeMonotonicMillis - nowMonotonicMillis) {
      // Invalidate instead of wrapping into a bogus near-term deadline.
      _state = SystemKeyboardIdleState.revoked;
      return _observation(nowMonotonicMillis);
    }
    _deadlineMonotonicMillis = nowMonotonicMillis + authorizedDurationMillis;
    _lastObservedMonotonicMillis = nowMonotonicMillis;
    return _observation(nowMonotonicMillis);
  }

  /// Permanently revokes the session. Idempotent, and it never rewrites an
  /// already expired terminal state.
  void revoke() {
    if (_state == SystemKeyboardIdleState.active) {
      _state = SystemKeyboardIdleState.revoked;
    }
  }

  SystemKeyboardIdleObservation _observation(int nowMonotonicMillis) {
    if (_state != SystemKeyboardIdleState.active) {
      return SystemKeyboardIdleObservation(
        state: _state,
        deadlineMonotonicMillis: deadlineMonotonicMillis,
        remainingMillis: 0,
      );
    }
    return SystemKeyboardIdleObservation(
      state: _state,
      deadlineMonotonicMillis: deadlineMonotonicMillis,
      remainingMillis: deadlineMonotonicMillis - nowMonotonicMillis,
    );
  }
}
