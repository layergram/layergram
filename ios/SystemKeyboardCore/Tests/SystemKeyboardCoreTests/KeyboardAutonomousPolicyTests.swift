import Foundation
import XCTest
@testable import SystemKeyboardCore

final class KeyboardAutonomousPolicyTests: XCTestCase {
    private var now: Int64 = 1_000
    private func snapshot(document: String = "note", access: Bool = true) -> KeyboardEditorSnapshot {
        .init(isViewVisible: true, hasFullAccess: access, isCaptured: false,
              documentIdentifier: document, monotonicMillis: now)
    }

    private func reply() throws -> Data {
        try JSONSerialization.data(withJSONObject: ["status": "ok",
            "processingMillis": 1, "leaseMillis": 500, "data": ["scramble": false]])
    }

    func testColdStartMayTakeMoreThanOneSecondButRemainsBounded() throws {
        let autonomous = KeyboardEditorPolicy(now: { self.now })
        XCTAssertTrue(autonomous.beginAutonomous(snapshot: snapshot(), editorNonce: "fresh-nonce") {
            _ in 30_000
        })
        _ = try autonomous.beginRequestData()
        now += 1_500
        XCTAssertNotNil(autonomous.acceptResponse(try reply(), snapshot: snapshot()))

        let ordinary = KeyboardEditorPolicy(now: { self.now })
        XCTAssertTrue(ordinary.begin(documentIdentifier: "note", windowDeadlineMonotonicMillis: 30_000))
        _ = try ordinary.beginRequestData()
        now += 1_500
        XCTAssertNil(ordinary.acceptResponse(try reply(), snapshot: snapshot()))

        let lateAutonomous = KeyboardEditorPolicy(now: { self.now })
        XCTAssertTrue(lateAutonomous.beginAutonomous(snapshot: snapshot(), editorNonce: "another-nonce") {
            _ in 30_000
        })
        _ = try lateAutonomous.beginRequestData()
        now += KeyboardSurfaceBounds.maxAutonomousBootstrapMillis
        XCTAssertNil(lateAutonomous.acceptResponse(try reply(), snapshot: snapshot()))
    }

    func testPhysicalActivityKeepsControlsLiveBeyondParentWindowButPollingDoesNotRenewIdle() throws {
        let session = try XCTUnwrap(KeyboardAutonomousSession(snapshot: snapshot(), authorizedIdleMillis: 20_000))
        let policy = KeyboardEditorPolicy(now: { self.now })
        XCTAssertTrue(policy.beginAutonomous(snapshot: snapshot(), editorNonce: "fresh-nonce") { value in
            session.validate(value, hasCustody: true) ? session.deadlineMonotonicMillis : nil
        })
        _ = try policy.beginRequestData()
        now += 1
        XCTAssertNotNil(policy.acceptResponse(try reply(), snapshot: snapshot()))
        for second in 1...75 {
            now += 1_000
            if second % 5 == 0 { XCTAssertTrue(session.recordUserInteraction(snapshot(), hasCustody: true)) }
            XCTAssertTrue(policy.liveControl(snapshot()))
        }
        let deadline = session.deadlineMonotonicMillis
        while now < deadline - 1_000 {
            now += 1_000
            XCTAssertTrue(policy.liveControl(snapshot()))
            XCTAssertEqual(session.deadlineMonotonicMillis, deadline)
        }
        now = deadline
        XCTAssertFalse(policy.liveControl(snapshot()))
        XCTAssertFalse(session.recordUserInteraction(snapshot(), hasCustody: true))
        XCTAssertFalse(policy.liveControl(snapshot()))
    }

    func testRevocationClearsAuthorityAndCannotBeRevivedByLaterReply() throws {
        var hasCustody = true
        let session = try XCTUnwrap(KeyboardAutonomousSession(snapshot: snapshot(), authorizedIdleMillis: 20_000))
        let policy = KeyboardEditorPolicy(now: { self.now })
        XCTAssertTrue(policy.beginAutonomous(snapshot: snapshot(), editorNonce: "fresh-nonce") { value in
            session.validate(value, hasCustody: hasCustody) ? session.deadlineMonotonicMillis : nil
        })
        _ = try policy.beginRequestData()
        hasCustody = false
        XCTAssertFalse(policy.revalidate(snapshot()))
        hasCustody = true
        XCTAssertNil(policy.acceptResponse(try reply(), snapshot: snapshot()))
        XCTAssertFalse(policy.liveControl(snapshot()))
    }

    func testControlsDenyAfterEditorChangeAndAccessLoss() throws {
        let policy = KeyboardEditorPolicy(now: { self.now })
        XCTAssertTrue(policy.beginAutonomous(snapshot: snapshot(), editorNonce: "fresh-nonce") { _ in self.now + 20_000 })
        _ = try policy.beginRequestData()
        now += 1
        XCTAssertNotNil(policy.acceptResponse(try reply(), snapshot: snapshot()))
        XCTAssertFalse(policy.liveControl(snapshot(document: "different")))
        XCTAssertFalse(policy.liveControl(snapshot(access: false)))
    }
}
