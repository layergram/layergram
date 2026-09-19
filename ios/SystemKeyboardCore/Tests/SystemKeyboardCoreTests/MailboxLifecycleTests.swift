import Foundation
import XCTest

@testable import SystemKeyboardCore

final class MailboxLifecycleTests: MailboxTestCase {
    func testWindowExpiryBlocksOwnerAndClient() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        fixture.clock.advance(monotonicMillis: MailboxConstants.maxWindowMillis + 1)

        assertMailboxError(try owner.pollRequest(), kind: .unavailable, reason: .windowClosed)
        assertMailboxError(
            try session.send(payload: requestPayload()),
            kind: .unavailable,
            reason: .windowClosed
        )
        assertMailboxError(
            try session.pollResponse(),
            kind: .unavailable,
            reason: .windowClosed
        )
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.rendezvousFileName))
    }

    func testOwnerWallClockJumpDoesNotExtendOrBreakWindow() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        fixture.clock.advance(monotonicMillis: 500, epochMillis: 3_600_000)
        let reply = try fixture.deliver(
            owner: owner,
            session: session,
            request: requestPayload(),
            response: responsePayload()
        )
        XCTAssertEqual(reply, responsePayload())
    }

    func testClientAttachRejectsRendezvousWhoseWallDeadlinePassed() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        _ = try owner.openWindow()
        fixture.clock.advance(epochMillis: MailboxConstants.maxWindowMillis + 1)
        assertMailboxError(try fixture.client().attach(), kind: .unavailable, reason: .windowClosed)
        XCTAssertFalse(fixture.client().hasLiveWindow())
    }

    func testBackwardsWallClockDoesNotWidenTheWindow() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        _ = try owner.openWindow()
        fixture.clock.advance(epochMillis: -3_600_000)
        let session = try fixture.client().attach()
        let remaining = session.deadlineMonotonicMillis - fixture.clock.now.monotonicMillis
        XCTAssertGreaterThan(remaining, 0)
        XCTAssertLessThanOrEqual(remaining, MailboxConstants.maxWindowMillis)
    }

    func testLateOwnerResponseIsRejected() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        guard case .request(let pending) = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }
        fixture.clock.advance(monotonicMillis: MailboxConstants.maxLeaseMillis + 1)
        assertMailboxError(
            try owner.respond(to: pending, payload: responsePayload()),
            kind: .unavailable,
            reason: .responseTimeout
        )
    }

    func testOwnerRespondAfterExpiryClosesTheWindow() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        guard case .request(let pending) = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }
        fixture.clock.advance(monotonicMillis: MailboxConstants.maxWindowMillis + 1)
        assertMailboxError(
            try owner.respond(to: pending, payload: responsePayload()),
            kind: .unavailable,
            reason: .windowClosed
        )
        XCTAssertFalse(owner.isWindowOpen)
        assertMailboxError(
            try owner.respond(to: pending, payload: responsePayload()),
            kind: .unavailable,
            reason: .revoked
        )
    }

    func testClientPollTimesOutWithinTheBoundedLease() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        XCTAssertEqual(try session.pollResponse(), .idle)
        XCTAssertTrue(session.isWaitingForResponse)

        fixture.clock.advance(monotonicMillis: MailboxConstants.defaultPendingTimeoutMillis + 1)
        assertMailboxError(
            try session.pollResponse(),
            kind: .unavailable,
            reason: .responseTimeout
        )
        XCTAssertNotNil(owner)
    }

    func testSecondSendWhileRequestIsPendingIsRejected() throws {
        let fixture = try MailboxFixture()
        let (_, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload(marker: "ONE"))
        assertMailboxError(
            try session.send(payload: requestPayload(marker: "TWO")),
            kind: .unavailable,
            reason: .requestPending
        )
    }

    func testRevokedSessionIsClosed() throws {
        let fixture = try MailboxFixture()
        let (_, session) = try fixture.connectedPair()
        session.revoke()
        assertMailboxError(
            try session.send(payload: requestPayload()),
            kind: .unavailable,
            reason: .revoked
        )
        assertMailboxError(
            try session.pollResponse(),
            kind: .unavailable,
            reason: .revoked
        )
    }

    func testMissingRendezvousIsUnavailable() throws {
        let fixture = try MailboxFixture()
        XCTAssertFalse(fixture.client().hasLiveWindow())
        assertMailboxError(
            try fixture.client().attach(),
            kind: .unavailable,
            reason: .noRendezvous
        )
    }

    func testClosedWindowLeavesAttachedClientUnanswered() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try owner.closeWindow()
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.rendezvousFileName))

        try session.send(payload: requestPayload())
        XCTAssertEqual(try session.pollResponse(), .idle)
        fixture.clock.advance(monotonicMillis: MailboxConstants.defaultPendingTimeoutMillis + 1)
        assertMailboxError(
            try session.pollResponse(),
            kind: .unavailable,
            reason: .responseTimeout
        )
    }

    func testOwnerRejectsPollAfterClose() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        try owner.closeWindow()
        XCTAssertFalse(owner.isWindowOpen)
        XCTAssertNil(owner.windowInfo)
        assertMailboxError(
            try owner.pollRequest(),
            kind: .unavailable,
            reason: .revoked
        )
    }

    func testSecondOpenWhileAWindowIsOpenFails() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        _ = try owner.openWindow()
        assertMailboxError(
            try owner.openWindow(),
            kind: .unavailable,
            reason: .windowOpen
        )
    }

    func testReopenAfterCloseUsesAFreshSession() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        let first = try owner.openWindow()
        try owner.closeWindow()
        let second = try owner.openWindow()
        XCTAssertNotEqual(first.sessionId, second.sessionId)
        XCTAssertNotEqual(first.ownerPublicKey, second.ownerPublicKey)
    }

    func testCrossSessionRequestIsRejectedByNewWindow() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        let first = try owner.openWindow()
        let session = try fixture.client().attach()
        XCTAssertEqual(session.sessionId, first.sessionId)

        try owner.closeWindow()
        _ = try owner.openWindow()

        try session.send(payload: requestPayload())
        assertMailboxError(
            try owner.pollRequest(),
            kind: .malformed,
            reason: .wrongSession
        )
    }

    func testExpiredRendezvousAndLeftoversArePurgedBeforeNewWindow() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        _ = try owner.openWindow()
        try owner.closeWindow()

        let stale = try MailboxRendezvous(
            sessionId: MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes),
            ownerPublicKey: try HybridKeyFixture().ownerPublicKey,
            createdAtEpochMillis: fixture.clock.now.epochMillis - 600_000,
            windowMillis: MailboxConstants.maxWindowMillis
        )
        try fixture.writeRawLeaf(MailboxConstants.rendezvousFileName, try stale.encoded())
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, Data("stale".utf8))
        try fixture.writeRawLeaf(MailboxConstants.responseFileName, Data("stale".utf8))

        let info = try owner.openWindow()
        XCTAssertNotEqual(info.sessionId, stale.sessionId)
        let freshData = try XCTUnwrap(fixture.rawLeaf(MailboxConstants.rendezvousFileName))
        let fresh = try MailboxRendezvous.decode(freshData)
        XCTAssertEqual(fresh.sessionId, info.sessionId)
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.requestFileName))
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.responseFileName))
    }

    func testAcceptedRequestIsRemovedSoPollIsIdempotent() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        guard case .request = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.requestFileName))
        XCTAssertEqual(try owner.pollRequest(), .idle)
    }

    func testPurgeStaleFilesRemovesOnlyOldDocuments() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        _ = try owner.pollRequest()
        XCTAssertNotNil(fixture.rawLeaf(MailboxConstants.rendezvousFileName))

        try fixture.storage.purgeStaleFiles(
            nowEpochMillis: fixture.clock.now.epochMillis + MailboxConstants.defaultStaleMillis + 1
        )
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.rendezvousFileName))
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.requestFileName))
    }
}
