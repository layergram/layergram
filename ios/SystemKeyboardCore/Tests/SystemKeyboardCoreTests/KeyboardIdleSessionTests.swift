import XCTest

@testable import SystemKeyboardCore

/// Behavioural tests for the clock-injected keyboard idle policy.
///
/// Every test drives the policy with fake integer monotonic readings: no wall
/// clock, no timers, no sleeps and no platform runtime.
final class KeyboardIdleSessionTests: XCTestCase {
    private let startAt: Int64 = 500_000
    private let twentySeconds: Int64 = 20_000

    private func liveSession(
        startAt: Int64 = 500_000,
        duration: Int64? = 20_000
    ) -> KeyboardIdleSession {
        let session = KeyboardIdleSession.start(
            startMonotonicMillis: startAt,
            authorizedDurationMillis: duration
        )
        XCTAssertNotNil(session)
        return session!
    }

    // MARK: - Preference and app lock

    func testAcceptsExactlyTheSupportedDurations() {
        XCTAssertEqual(KeyboardIdlePolicy.supportedIdleSeconds, [20, 30, 60, 120, 300])
        for seconds in KeyboardIdlePolicy.supportedIdleSeconds {
            XCTAssertEqual(KeyboardIdlePolicy.validatedPreferenceSeconds(seconds), seconds)
        }
    }

    func testFailsSafeToTheDefaultForMalformedOrUnsupportedValues() {
        XCTAssertEqual(KeyboardIdlePolicy.defaultIdleSeconds, 60)
        for raw: Int64? in [nil, 0, -20, 19, 45, 301, Int64.max] {
            XCTAssertEqual(KeyboardIdlePolicy.validatedPreferenceSeconds(raw), 60)
        }
    }

    func testDisabledAppLockKeepsTheValidatedRequest() {
        XCTAssertEqual(
            KeyboardIdlePolicy.effectiveIdleSeconds(
                requestedIdleSeconds: 300,
                appLockEnabled: false,
                appLockTimeoutSeconds: 60
            ),
            300
        )
        XCTAssertEqual(
            KeyboardIdlePolicy.effectiveIdleMillis(
                requestedIdleSeconds: 120,
                appLockEnabled: false,
                appLockTimeoutSeconds: 60
            ),
            120_000
        )
    }

    func testEnabledAppLockClampsDownAndNeverWidensIt() {
        XCTAssertEqual(
            KeyboardIdlePolicy.effectiveIdleSeconds(
                requestedIdleSeconds: 300,
                appLockEnabled: true,
                appLockTimeoutSeconds: 120
            ),
            120
        )
        XCTAssertEqual(
            KeyboardIdlePolicy.effectiveIdleSeconds(
                requestedIdleSeconds: 20,
                appLockEnabled: true,
                appLockTimeoutSeconds: 120
            ),
            20
        )
        XCTAssertEqual(
            KeyboardIdlePolicy.effectiveIdleMillis(
                requestedIdleSeconds: 60,
                appLockEnabled: true,
                appLockTimeoutSeconds: 5
            ),
            5_000
        )
    }

    func testImmediateAppLockDeniesTheKeyboard() {
        for timeout: Int64 in [0, -1] {
            XCTAssertNil(
                KeyboardIdlePolicy.effectiveIdleSeconds(
                    requestedIdleSeconds: 300,
                    appLockEnabled: true,
                    appLockTimeoutSeconds: timeout
                )
            )
            XCTAssertNil(
                KeyboardIdlePolicy.effectiveIdleMillis(
                    requestedIdleSeconds: 300,
                    appLockEnabled: true,
                    appLockTimeoutSeconds: timeout
                )
            )
        }
    }

    // MARK: - Start

    func testStartDeniesMissingNonpositiveNegativeAndUnsafeInputs() {
        XCTAssertNil(
            KeyboardIdleSession.start(
                startMonotonicMillis: startAt,
                authorizedDurationMillis: nil
            )
        )
        XCTAssertNil(
            KeyboardIdleSession.start(
                startMonotonicMillis: startAt,
                authorizedDurationMillis: 0
            )
        )
        XCTAssertNil(
            KeyboardIdleSession.start(
                startMonotonicMillis: startAt,
                authorizedDurationMillis: -twentySeconds
            )
        )
        XCTAssertNil(
            KeyboardIdleSession.start(
                startMonotonicMillis: -1,
                authorizedDurationMillis: twentySeconds
            )
        )
        XCTAssertNil(
            KeyboardIdleSession.start(
                startMonotonicMillis: startAt,
                authorizedDurationMillis: KeyboardIdlePolicy.maxSafeMonotonicMillis
            )
        )
    }

    func testExposesOnlyStatusDeadlineAndRemaining() {
        let session = liveSession()
        XCTAssertEqual(session.state, .active)
        XCTAssertFalse(session.isTerminal)
        XCTAssertEqual(session.authorizedDurationMillis, twentySeconds)
        XCTAssertEqual(session.deadlineMonotonicMillis, startAt + twentySeconds)
        XCTAssertEqual(session.observe(nowMonotonicMillis: startAt + 5_000).remainingMillis, 15_000)
    }

    // MARK: - Idle expiry

    func testSixtySecondPreferenceRenewsOnlyOnKeyboardActivity() {
        let session = liveSession(duration: 60_000)
        XCTAssertTrue(session.observe(nowMonotonicMillis: startAt + 59_000).isActive)
        XCTAssertEqual(
            session.recordUserInteraction(nowMonotonicMillis: startAt + 59_000).remainingMillis,
            60_000
        )
        XCTAssertTrue(session.observe(nowMonotonicMillis: startAt + 118_999).isActive)
        XCTAssertEqual(session.observe(nowMonotonicMillis: startAt + 119_000).state, .expired)
    }

    func testTwoMinutesOfContinuousTouchNeverExpire() {
        let session = liveSession()
        var now = startAt
        for _ in 1...120 {
            now += 1_000
            let observation = session.recordUserInteraction(nowMonotonicMillis: now)
            XCTAssertTrue(observation.isActive)
            XCTAssertEqual(observation.remainingMillis, twentySeconds)
        }
        XCTAssertEqual(now - startAt, 120_000)
        // Quiet polling inside the renewed window never extends the deadline.
        XCTAssertTrue(session.observe(nowMonotonicMillis: now + 1_000).isActive)
        XCTAssertEqual(session.deadlineMonotonicMillis, now + twentySeconds)
    }

    func testQuietPollingExpiresExactlyAtTheDeadline() {
        let session = liveSession()
        for second in 1..<20 {
            XCTAssertTrue(
                session.observe(nowMonotonicMillis: startAt + Int64(second) * 1_000).isActive
            )
        }
        let expired = session.observe(nowMonotonicMillis: startAt + twentySeconds)
        XCTAssertEqual(expired.state, .expired)
        XCTAssertEqual(expired.remainingMillis, 0)
        XCTAssertEqual(expired.deadlineMonotonicMillis, startAt + twentySeconds)
        XCTAssertTrue(session.isTerminal)
    }

    func testTouchExactlyAtTheDeadlineCannotReviveTheSession() {
        let session = liveSession()
        XCTAssertEqual(
            session.observe(nowMonotonicMillis: startAt + twentySeconds).state,
            .expired
        )
        XCTAssertEqual(
            session.recordUserInteraction(nowMonotonicMillis: startAt + twentySeconds).state,
            .expired
        )
        XCTAssertEqual(
            session.recordUserInteraction(nowMonotonicMillis: startAt + twentySeconds + 1).state,
            .expired
        )
        XCTAssertEqual(session.deadlineMonotonicMillis, startAt + twentySeconds)
    }

    func testBackwardsReadingRevokesAnActiveSessionPermanently() {
        let session = liveSession()
        XCTAssertTrue(session.observe(nowMonotonicMillis: startAt + 1_000).isActive)
        XCTAssertEqual(session.observe(nowMonotonicMillis: startAt).state, .revoked)
        XCTAssertEqual(
            session.recordUserInteraction(nowMonotonicMillis: startAt + 2_000).state,
            .revoked
        )
        XCTAssertTrue(session.isTerminal)
    }

    func testBackwardsReadingNeverClearsAPriorExpiry() {
        let session = liveSession()
        XCTAssertEqual(
            session.observe(nowMonotonicMillis: startAt + twentySeconds).state,
            .expired
        )
        XCTAssertEqual(session.observe(nowMonotonicMillis: startAt).state, .expired)
        session.revoke()
        XCTAssertEqual(session.state, .expired)
        XCTAssertEqual(
            session.recordUserInteraction(nowMonotonicMillis: startAt + 1).state,
            .expired
        )
    }

    func testExplicitRevokeIsTerminalAndIdempotent() {
        let session = liveSession()
        session.revoke()
        session.revoke()
        XCTAssertEqual(session.state, .revoked)
        XCTAssertEqual(session.observe(nowMonotonicMillis: startAt + 1).state, .revoked)
        XCTAssertEqual(session.observe(nowMonotonicMillis: startAt + 1).remainingMillis, 0)
        XCTAssertEqual(
            session.recordUserInteraction(nowMonotonicMillis: startAt + 1).state,
            .revoked
        )
    }

    func testOverflowingRenewalRevokesInsteadOfWrapping() {
        let session = liveSession(
            startAt: 0,
            duration: KeyboardIdlePolicy.maxSafeMonotonicMillis
        )
        XCTAssertTrue(session.observe(nowMonotonicMillis: 0).isActive)
        let revoked = session.recordUserInteraction(nowMonotonicMillis: 1)
        XCTAssertEqual(revoked.state, .revoked)
        XCTAssertEqual(revoked.remainingMillis, 0)
        XCTAssertEqual(
            session.deadlineMonotonicMillis,
            KeyboardIdlePolicy.maxSafeMonotonicMillis
        )
        XCTAssertEqual(session.observe(nowMonotonicMillis: 2).state, .revoked)
    }
}
