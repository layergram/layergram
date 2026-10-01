import XCTest
@testable import SystemKeyboardCore

final class KeyboardAutonomousSessionTests: XCTestCase {
    private func sample(_ time: Int64, document: String = "note", access: Bool = true,
                        captured: Bool = false, visible: Bool = true) -> KeyboardEditorSnapshot {
        KeyboardEditorSnapshot(isViewVisible: visible, hasFullAccess: access,
            isCaptured: captured, documentIdentifier: document, monotonicMillis: time)
    }

    func testContinuousTypingRenewsForMinutesButPollingAloneExpires() throws {
        let session = try XCTUnwrap(KeyboardAutonomousSession(snapshot: sample(0), authorizedIdleMillis: 20_000))
        for time in stride(from: Int64(1_000), through: 180_000, by: 1_000) {
            XCTAssertTrue(session.validate(sample(time), hasCustody: true))
            if time % 10_000 == 0 {
                XCTAssertTrue(session.recordUserInteraction(sample(time), hasCustody: true))
            }
        }
        XCTAssertEqual(session.deadlineMonotonicMillis, 200_000)
        for time in stride(from: Int64(181_000), through: 199_000, by: 1_000) {
            XCTAssertTrue(session.validate(sample(time), hasCustody: true))
        }
        XCTAssertFalse(session.recordUserInteraction(sample(200_000), hasCustody: true))
        XCTAssertFalse(session.recordUserInteraction(sample(200_001), hasCustody: true))
    }

    func testMissedLifecycleNotificationCannotResumeAfterSuspension() throws {
        let session = try XCTUnwrap(KeyboardAutonomousSession(snapshot: sample(0), authorizedIdleMillis: 300_000))
        XCTAssertTrue(session.validate(sample(500), hasCustody: true))
        XCTAssertFalse(session.recordUserInteraction(sample(2_001), hasCustody: true))
        XCTAssertEqual(session.lastValidationFailure, .observationGap)
        XCTAssertTrue(session.isTerminal)
        XCTAssertFalse(session.validate(sample(2_002), hasCustody: true))
    }

    func testValidationFailureIdentifiesWhyActiveTypingWasInterrupted() throws {
        let cases: [(KeyboardEditorSnapshot, Bool, KeyboardAutonomousSession.ValidationFailure)] = [
            (sample(100, visible: false), true, .hidden),
            (sample(100, access: false), true, .fullAccess),
            (sample(100, captured: true), true, .capture),
            (sample(100, document: "other"), true, .document),
            (sample(100), false, .custody),
            (sample(-1), true, .clockRegression),
            (sample(1_501), true, .observationGap),
        ]
        for (snapshot, custody, expected) in cases {
            let session = try XCTUnwrap(KeyboardAutonomousSession(snapshot: sample(0), authorizedIdleMillis: 20_000))
            XCTAssertFalse(session.validate(snapshot, hasCustody: custody))
            XCTAssertEqual(session.lastValidationFailure, expected)
        }
        let expired = try XCTUnwrap(KeyboardAutonomousSession(snapshot: sample(0), authorizedIdleMillis: 100))
        XCTAssertFalse(expired.validate(sample(100), hasCustody: true))
        XCTAssertEqual(expired.lastValidationFailure, .idleExpired)
    }

    func testAllAdmissionLossesAndClockRegressionAreTerminal() throws {
        let bad = [sample(10, document: "other"), sample(10, access: false),
                   sample(10, captured: true), sample(10, visible: false), sample(-1)]
        for snapshot in bad {
            let session = try XCTUnwrap(KeyboardAutonomousSession(snapshot: sample(0), authorizedIdleMillis: 20_000))
            XCTAssertFalse(session.validate(snapshot, hasCustody: true))
            XCTAssertFalse(session.recordUserInteraction(sample(11), hasCustody: true))
        }
        let revoked = try XCTUnwrap(KeyboardAutonomousSession(snapshot: sample(0), authorizedIdleMillis: 20_000))
        XCTAssertFalse(revoked.validate(sample(1), hasCustody: false))
        XCTAssertFalse(revoked.validate(sample(2), hasCustody: true))
    }

    func testInvalidAdmissionCannotStart() {
        for duration: Int64 in [0, -1, 300_001, Int64.max] {
            XCTAssertNil(KeyboardAutonomousSession(snapshot: sample(0), authorizedIdleMillis: duration))
        }
        XCTAssertNil(KeyboardAutonomousSession(snapshot: sample(0, access: false), authorizedIdleMillis: 20_000))
    }
}
