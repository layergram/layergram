import Foundation

/// Pure, clock-injected inactivity policy for the iOS keyboard extension.
///
/// This file is portable policy only: no wall clock (`Date`), no `Timer`, no
/// I/O, no keys, no identity and no UIKit. It mirrors the Dart peer
/// `system_keyboard_idle_policy.dart` exactly. Preference selection
/// (`KeyboardIdlePolicy`) says how long the keyboard may stay idle once the
/// app-lock ceiling is taken into account; one in-memory session
/// (`KeyboardIdleSession`) says whether an already-authorized window is still
/// active at an explicit monotonic reading.
///
/// What it deliberately never does:
/// * never renews on a poll, on a heartbeat or on a generic draft mutation:
///   only an explicit `recordUserInteraction` with a monotonic reading sampled
///   from a **physically intentional user touch** extends a window. Callers
///   must wire real touch, never a refresh loop;
/// * never revives an expired, revoked or clock-regressed session;
/// * never grants, unlocks, admits an identity or extends operating-system
///   background execution: the autonomous runtime enforces this policy only
///   after a separate live authorization grant;
/// * never disables or widens the app lock: an app lock configured as
///   immediate (`<= 0` seconds) denies the keyboard instead;
/// * never keeps a secret: the exposed state is a status, a deadline and a
///   remaining duration only.

/// Status of one in-memory keyboard idle session.
public enum KeyboardIdleState: Equatable {
    /// The authorized window may still be used; its remaining time is positive.
    case active
    /// The deadline passed. Terminal: no poll or touch can revive the session.
    case expired
    /// Explicitly revoked, or invalidated by a backwards monotonic reading or
    /// by an overflowing renewal. Terminal.
    case revoked
}

/// One read-only view of a session at an explicit monotonic reading.
///
/// Only non-secret status information is exposed: state, absolute deadline and
/// remaining idle time.
public struct KeyboardIdleObservation: Equatable {
    public let state: KeyboardIdleState
    public let deadlineMonotonicMillis: Int64
    public let remainingMillis: Int64

    public init(
        state: KeyboardIdleState,
        deadlineMonotonicMillis: Int64,
        remainingMillis: Int64
    ) {
        self.state = state
        self.deadlineMonotonicMillis = deadlineMonotonicMillis
        self.remainingMillis = remainingMillis
    }

    /// True only while the session is still `.active`.
    public var isActive: Bool { state == .active }
}

/// Fail-safe validation and app-lock clamping of the idle preference.
///
/// Selected durations are immutable and enumerable so a settings surface can
/// explain them; there is deliberately no unlimited option.
public enum KeyboardIdlePolicy {
    /// Default preference for a missing or malformed stored value.
    public static let defaultIdleSeconds: Int64 = 60

    /// The only selectable preference durations, in seconds.
    public static let supportedIdleSeconds: [Int64] = [20, 30, 60, 120, 300]

    /// Largest monotonic millisecond value, shared with the Dart peer.
    public static let maxSafeMonotonicMillis: Int64 = 9_007_199_254_740_991

    /// The requested preference, or `defaultIdleSeconds` for a `nil`
    /// (malformed) or unsupported value.
    public static func validatedPreferenceSeconds(_ raw: Int64?) -> Int64 {
        guard let raw, supportedIdleSeconds.contains(raw) else {
            return defaultIdleSeconds
        }
        return raw
    }

    /// Effective idle seconds, or `nil` when the keyboard must be denied.
    ///
    /// With `appLockEnabled` false the validated request is used unchanged. With
    /// the app lock enabled the value is clamped **down** to
    /// `appLockTimeoutSeconds`; an immediate app lock (`<= 0`) denies the
    /// keyboard rather than disabling or widening that lock. The clamp is a
    /// separate call from `validatedPreferenceSeconds` so settings can compare
    /// the two and explain a shortened window.
    public static func effectiveIdleSeconds(
        requestedIdleSeconds: Int64,
        appLockEnabled: Bool,
        appLockTimeoutSeconds: Int64
    ) -> Int64? {
        let requested = validatedPreferenceSeconds(requestedIdleSeconds)
        guard appLockEnabled else { return requested }
        guard appLockTimeoutSeconds > 0 else { return nil }
        return min(requested, appLockTimeoutSeconds)
    }

    /// `effectiveIdleSeconds` in milliseconds, or `nil` when denied.
    public static func effectiveIdleMillis(
        requestedIdleSeconds: Int64,
        appLockEnabled: Bool,
        appLockTimeoutSeconds: Int64
    ) -> Int64? {
        guard let seconds = effectiveIdleSeconds(
            requestedIdleSeconds: requestedIdleSeconds,
            appLockEnabled: appLockEnabled,
            appLockTimeoutSeconds: appLockTimeoutSeconds
        ) else { return nil }
        return seconds * 1_000
    }
}

/// One in-memory keyboard idle window.
///
/// `start` is the authority boundary: it is the only way to create a session
/// and it requires the authorized start reading plus the already-clamped
/// effective duration. An arbitrary touch handler, heartbeat or poll can never
/// construct a session; it may only report a physical touch through
/// `recordUserInteraction`, and it can never revive a terminal one.
public final class KeyboardIdleSession {
    /// Effective idle duration authorized at start. Never renewed.
    public let authorizedDurationMillis: Int64
    /// Absolute monotonic deadline; it moves forward only on an accepted touch.
    public private(set) var deadlineMonotonicMillis: Int64
    /// Current status.
    public private(set) var state: KeyboardIdleState = .active

    private var lastObservedMonotonicMillis: Int64

    private init(
        startMonotonicMillis: Int64,
        authorizedDurationMillis: Int64,
        deadlineMonotonicMillis: Int64
    ) {
        self.authorizedDurationMillis = authorizedDurationMillis
        self.deadlineMonotonicMillis = deadlineMonotonicMillis
        self.lastObservedMonotonicMillis = startMonotonicMillis
    }

    /// Starts a session, or returns `nil` when it must be denied.
    ///
    /// Denied when `authorizedDurationMillis` is `nil` (no authorized window),
    /// nonpositive or larger than the shared safe range, and when
    /// `startMonotonicMillis` is negative. A denied start is never repaired
    /// into a shorter session.
    public static func start(
        startMonotonicMillis: Int64,
        authorizedDurationMillis: Int64?
    ) -> KeyboardIdleSession? {
        guard startMonotonicMillis >= 0 else { return nil }
        guard let duration = authorizedDurationMillis, duration > 0 else {
            return nil
        }
        guard duration <= KeyboardIdlePolicy.maxSafeMonotonicMillis - startMonotonicMillis else {
            return nil
        }
        return KeyboardIdleSession(
            startMonotonicMillis: startMonotonicMillis,
            authorizedDurationMillis: duration,
            deadlineMonotonicMillis: startMonotonicMillis + duration
        )
    }

    /// True once the session can never become active again.
    public var isTerminal: Bool { state != .active }

    /// Reads the session at `nowMonotonicMillis` **without renewing it**.
    ///
    /// A reading below the previous accepted reading permanently revokes the
    /// session (time moved backwards). A reading equal to the deadline expires
    /// it. Polling, heartbeats and `observe` loops never extend the deadline, so
    /// a quiet keyboard expires exactly at its deadline.
    public func observe(nowMonotonicMillis: Int64) -> KeyboardIdleObservation {
        if isTerminal { return observation(at: nowMonotonicMillis) }
        if nowMonotonicMillis < lastObservedMonotonicMillis {
            state = .revoked
            return observation(at: nowMonotonicMillis)
        }
        if nowMonotonicMillis >= deadlineMonotonicMillis {
            state = .expired
            return observation(at: nowMonotonicMillis)
        }
        lastObservedMonotonicMillis = nowMonotonicMillis
        return observation(at: nowMonotonicMillis)
    }

    /// Reports one physically intentional user touch sampled at
    /// `nowMonotonicMillis`, renewing the window only when the session was
    /// **active before** the event.
    ///
    /// Renewal requires a nondecreasing reading strictly before the deadline; a
    /// reading exactly at the deadline expires the session. A backwards reading
    /// and an overflowing renewal revoke it permanently. The caller must pass
    /// real touch input: a heartbeat, a poll or a generic draft mutation is not
    /// user activity and must call `observe` instead.
    @discardableResult
    public func recordUserInteraction(nowMonotonicMillis: Int64) -> KeyboardIdleObservation {
        if isTerminal { return observation(at: nowMonotonicMillis) }
        if nowMonotonicMillis < lastObservedMonotonicMillis {
            state = .revoked
            return observation(at: nowMonotonicMillis)
        }
        if nowMonotonicMillis >= deadlineMonotonicMillis {
            state = .expired
            return observation(at: nowMonotonicMillis)
        }
        let (renewed, overflow) = nowMonotonicMillis.addingReportingOverflow(
            authorizedDurationMillis
        )
        guard !overflow, renewed <= KeyboardIdlePolicy.maxSafeMonotonicMillis else {
            // Invalidate instead of wrapping into a bogus near-term deadline.
            state = .revoked
            return observation(at: nowMonotonicMillis)
        }
        deadlineMonotonicMillis = renewed
        lastObservedMonotonicMillis = nowMonotonicMillis
        return observation(at: nowMonotonicMillis)
    }

    /// Permanently revokes the session. Idempotent, and it never rewrites an
    /// already expired terminal state.
    public func revoke() {
        if state == .active { state = .revoked }
    }

    private func observation(at nowMonotonicMillis: Int64) -> KeyboardIdleObservation {
        guard state == .active else {
            return KeyboardIdleObservation(
                state: state,
                deadlineMonotonicMillis: deadlineMonotonicMillis,
                remainingMillis: 0
            )
        }
        return KeyboardIdleObservation(
            state: .active,
            deadlineMonotonicMillis: deadlineMonotonicMillis,
            remainingMillis: deadlineMonotonicMillis - nowMonotonicMillis
        )
    }
}
