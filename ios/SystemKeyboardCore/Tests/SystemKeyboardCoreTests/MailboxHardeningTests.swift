import Darwin
import Foundation
import XCTest

@testable import SystemKeyboardCore

/// Regressions for the hardening pass: strict numeric parsing, overflow-safe
/// constructors and clocks, sticky revocation, exclusive deadlines, a pinned
/// directory descriptor, non-blocking regular-file checks and fresh timestamps.
final class MailboxHardeningTests: MailboxTestCase {
    // MARK: - Strict numbers

    func testNumericZeroAndOneAreAcceptedWhileBooleansAreRejected() throws {
        let object: [String: Any] = [
            "v": MailboxConstants.protocolVersion,
            "s": MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes).base64EncodedString(),
            "o": MailboxRandom.bytes(MailboxConstants.ownerPublicKeyBytes).base64EncodedString(),
            "a": 0,
            "d": 1,
            "w": 1
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let rendezvous = try MailboxRendezvous.decode(data)
        XCTAssertEqual(rendezvous.createdAtEpochMillis, 0)
        XCTAssertEqual(rendezvous.deadlineEpochMillis, 1)
        XCTAssertEqual(rendezvous.windowMillis, 1)
        XCTAssertEqual(rendezvous.version, MailboxConstants.protocolVersion)

        var booleanVersion = object
        booleanVersion["v"] = true
        let booleanData = try JSONSerialization.data(withJSONObject: booleanVersion, options: [.sortedKeys])
        assertMailboxError(try MailboxRendezvous.decode(booleanData), kind: .malformed, reason: .badNumber)

        var booleanWindow = object
        booleanWindow["w"] = false
        let booleanWindowData = try JSONSerialization.data(withJSONObject: booleanWindow, options: [.sortedKeys])
        assertMailboxError(
            try MailboxRendezvous.decode(booleanWindowData),
            kind: .malformed,
            reason: .badNumber
        )
    }

    func testFractionalAndNegativeRendezvousNumbersAreRejected() throws {
        let base: [String: Any] = [
            "v": MailboxConstants.protocolVersion,
            "s": MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes).base64EncodedString(),
            "o": MailboxRandom.bytes(MailboxConstants.ownerPublicKeyBytes).base64EncodedString(),
            "a": NSNumber(value: 1_700_000_000_000),
            "d": NSNumber(value: 1_700_000_000_000 + MailboxConstants.maxWindowMillis),
            "w": NSNumber(value: MailboxConstants.maxWindowMillis)
        ]

        var fractional = base
        fractional["a"] = 1.5
        let fractionalData = try JSONSerialization.data(withJSONObject: fractional, options: [.sortedKeys])
        assertMailboxError(
            try MailboxRendezvous.decode(fractionalData),
            kind: .malformed,
            reason: .badNumber
        )

        var negative = base
        negative["a"] = -1
        let negativeData = try JSONSerialization.data(withJSONObject: negative, options: [.sortedKeys])
        assertMailboxError(try MailboxRendezvous.decode(negativeData), kind: .malformed, reason: .badNumber)
    }

    // MARK: - Overflow and clock sanity

    func testOverflowingRendezvousDeadlineThrowsInsteadOfTrapping() {
        assertMailboxError(
            try MailboxRendezvous(
                sessionId: MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes),
                ownerPublicKey: MailboxRandom.bytes(MailboxConstants.ownerPublicKeyBytes),
                createdAtEpochMillis: Int64.max - 10,
                windowMillis: MailboxConstants.maxWindowMillis
            ),
            kind: .malformed,
            reason: .badNumber
        )
    }

    func testClockAdvanceOverflowAndNegativeResultsThrow() {
        let high = MailboxClock(monotonicMillis: Int64.max - 1, epochMillis: 0)
        assertMailboxError(try high.advanced(byMillis: 10), kind: .malformed, reason: .badNumber)

        let low = MailboxClock(monotonicMillis: 5, epochMillis: 5)
        assertMailboxError(try low.advanced(byMillis: -10), kind: .malformed, reason: .badNumber)

        let step = try? MailboxClock(monotonicMillis: 1_000, epochMillis: 2_000).advanced(byMillis: 25)
        XCTAssertEqual(step?.monotonicMillis, 1_025)
        XCTAssertEqual(step?.epochMillis, 2_025)
    }

    func testOverflowingOwnerCoreDeadlineThrowsInsteadOfTrapping() throws {
        let fixture = try CoreFixture()
        let nearMax = MailboxClock(
            monotonicMillis: Int64.max - 1,
            epochMillis: fixture.rendezvous.createdAtEpochMillis
        )
        assertMailboxError(
            try MailboxOwnerCore(ownerKey: fixture.ownerKey, rendezvous: fixture.rendezvous, now: nearMax),
            kind: .unavailable,
            reason: .unavailable
        )
    }

    func testNegativeClockReadingFailsClosed() throws {
        let fixture = try CoreFixture()
        assertMailboxError(
            try MailboxOwnerCore(
                ownerKey: fixture.ownerKey,
                rendezvous: fixture.rendezvous,
                now: MailboxClock(
                    monotonicMillis: -1,
                    epochMillis: fixture.rendezvous.createdAtEpochMillis
                )
            ),
            kind: .unavailable,
            reason: .unavailable
        )
        assertMailboxError(
            try MailboxClientCore(
                rendezvous: fixture.rendezvous,
                now: MailboxClock(
                    monotonicMillis: fixture.now.monotonicMillis,
                    epochMillis: -1
                )
            ),
            kind: .unavailable,
            reason: .unavailable
        )
    }

    func testRolledBackClockFailsClosed() throws {
        let fixture = try MailboxFixture()
        let (_, session) = try fixture.connectedPair()
        fixture.clock.advance(monotonicMillis: 4_000)
        XCTAssertFalse(session.isExpired())

        fixture.clock.now = MailboxClock(
            monotonicMillis: fixture.clock.now.monotonicMillis - 10_000,
            epochMillis: fixture.clock.now.epochMillis
        )
        XCTAssertTrue(session.isExpired())
        assertMailboxError(
            try session.send(payload: requestPayload()),
            kind: .unavailable,
            reason: .unavailable
        )
    }

    // MARK: - Revocation

    func testRevokedOwnerCoreStaysRevokedAndDropsKeyReferences() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        let envelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: requestPayload()
        )
        _ = try core.acceptRequest(envelope, now: fixture.now)
        XCTAssertNotNil(core.pinnedClient)

        core.revoke()
        XCTAssertTrue(core.isRevoked)
        XCTAssertNil(core.pinnedClient)
        XCTAssertFalse(core.isAwaitingResponse)

        let later = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 2,
            payload: requestPayload()
        )
        assertMailboxError(try core.acceptRequest(later, now: fixture.now), kind: .unavailable, reason: .revoked)
        assertMailboxError(
            try core.sealResponse(
                sessionId: fixture.rendezvous.sessionId,
                requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
                sequence: 1,
                payload: responsePayload(),
                now: fixture.now
            ),
            kind: .unavailable,
            reason: .revoked
        )
    }

    func testRevokedClientCoreStaysRevoked() throws {
        let fixture = try CoreFixture()
        let core = try fixture.clientCore()
        core.revoke()
        XCTAssertTrue(core.isRevoked)
        assertMailboxError(
            try core.makeRequest(
                payload: requestPayload(),
                now: fixture.now,
                timeoutMillis: MailboxConstants.defaultPendingTimeoutMillis
            ),
            kind: .unavailable,
            reason: .revoked
        )
        let envelope = try fixture.responseEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: responsePayload()
        )
        assertMailboxError(
            try core.openResponse(envelope, now: fixture.now),
            kind: .unavailable,
            reason: .revoked
        )
    }

    // MARK: - Exclusive deadlines and fresh timestamps

    func testOwnerWindowDeadlineEqualityIsExpired() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        let info = try owner.openWindow(windowMillis: 1_000)
        fixture.clock.advance(monotonicMillis: 1_000)
        XCTAssertEqual(fixture.clock.now.monotonicMillis, info.deadlineMonotonicMillis)
        assertMailboxError(try owner.pollRequest(), kind: .unavailable, reason: .windowClosed)
        XCTAssertFalse(owner.isWindowOpen)
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.rendezvousFileName))
    }

    func testClientPendingLeaseEqualityIsExpired() throws {
        let fixture = try MailboxFixture()
        let (_, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload(), timeoutMillis: 100)
        XCTAssertEqual(try session.pollResponse(), .idle)
        fixture.clock.advance(monotonicMillis: 100)
        assertMailboxError(
            try session.pollResponse(),
            kind: .unavailable,
            reason: .responseTimeout
        )
    }

    func testSendLeaseUsesTheSendTimeReading() throws {
        let fixture = try MailboxFixture()
        let (_, session) = try fixture.connectedPair()
        fixture.clock.advance(monotonicMillis: 4_000)
        try session.send(payload: requestPayload(), timeoutMillis: 100)
        XCTAssertEqual(
            session.responseDeadlineMonotonicMillis,
            fixture.clock.now.monotonicMillis + 100
        )
    }

    // MARK: - Single pending request and exact handle

    func testCompetingRequestCannotSilentlyReplaceTheLivePendingHandle() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload(marker: "ONE"))
        guard case .request(let pending) = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }

        // A competing document appears while the first handle's lease is live.
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, Data(#"{"v":1}"#.utf8))
        assertMailboxError(
            try owner.pollRequest(),
            kind: .unavailable,
            reason: .requestPending
        )

        // The refusal left the live handle untouched and it still answers.
        try owner.respond(to: pending, payload: responsePayload())
        guard case .response(let reply) = try session.pollResponse() else {
            return XCTFail("expected the response")
        }
        XCTAssertEqual(reply, responsePayload())
    }

    func testOwnerCoreReportsTheLivePendingLease() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        XCTAssertFalse(core.hasLivePendingRequest(at: fixture.now))

        let envelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: requestPayload()
        )
        let accepted = try core.acceptRequest(envelope, now: fixture.now)
        XCTAssertTrue(core.hasLivePendingRequest(at: fixture.now))
        XCTAssertEqual(core.pendingRequestId, accepted.requestId)

        let afterLease = MailboxClock(
            monotonicMillis: accepted.respondByMonotonicMillis,
            epochMillis: fixture.now.epochMillis
        )
        XCTAssertFalse(core.hasLivePendingRequest(at: afterLease))
    }

    func testRespondHandleRequiresTheExactSessionIdentifier() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        guard case .request(let pending) = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }

        let wrongHandle = MailboxPendingRequest(
            sessionId: MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes),
            requestId: pending.requestId,
            sequence: pending.sequence,
            payload: pending.payload,
            respondByMonotonicMillis: pending.respondByMonotonicMillis
        )
        assertMailboxError(
            try owner.respond(to: wrongHandle, payload: responsePayload()),
            kind: .malformed,
            reason: .staleRequest
        )

        // The genuine handle is still usable after the rejected one.
        try owner.respond(to: pending, payload: responsePayload())
        guard case .response(let reply) = try session.pollResponse() else {
            return XCTFail("expected the response")
        }
        XCTAssertEqual(reply, responsePayload())
    }

    // MARK: - Storage hardening

    func testFifoRequestLeafFailsClosedWithoutBlocking() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        let path = fixture.directoryURL
            .appendingPathComponent(MailboxConstants.requestFileName, isDirectory: false)
            .path
        XCTAssertEqual(mkfifo(path, 0o600), 0)

        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .unsafePath)
    }

    func testFifoRendezvousLeafFailsClosedWithoutBlocking() throws {
        let fixture = try MailboxFixture()
        let path = fixture.directoryURL
            .appendingPathComponent(MailboxConstants.rendezvousFileName, isDirectory: false)
            .path
        XCTAssertEqual(mkfifo(path, 0o600), 0)

        assertMailboxError(try fixture.client().attach(), kind: .malformed, reason: .unsafePath)
    }

    func testDirectoryReplacementAfterInitCannotRedirectReads() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()

        let outside = fixture.root.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try Data("not json".utf8).write(
            to: outside.appendingPathComponent(MailboxConstants.requestFileName, isDirectory: false)
        )

        try FileManager.default.removeItem(at: fixture.directoryURL)
        try FileManager.default.createSymbolicLink(at: fixture.directoryURL, withDestinationURL: outside)

        // Every operation stays on the directory descriptor pinned at
        // initialisation, so the replacement is never opened or read.
        assertMailboxError(
            try owner.pollRequest(),
            kind: .unavailable,
            reason: .storageUnavailable
        )
        XCTAssertNil(try fixture.storage.readRequest())
    }

    func testBackupExclusionIsVerifiedOnTheDirectory() throws {
        let fixture = try MailboxFixture()
        XCTAssertTrue(fixture.storage.isBackupExcluded)
        let values = try fixture.directoryURL.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)
    }
    func testCrashStagingFilesAreBoundedAndPurgedWithoutFollowingLinks() throws {
        let fixture = try MailboxFixture()
        let outside = fixture.root.appendingPathComponent("untouched")
        try Data("outside".utf8).write(to: outside)
        let staging = ".client.request.tmp"
        try FileManager.default.createSymbolicLink(
            at: fixture.directoryURL.appendingPathComponent(staging),
            withDestinationURL: outside)
        try fixture.storage.writeRequest(Data("encrypted-envelope".utf8))
        XCTAssertEqual(try Data(contentsOf: outside), Data("outside".utf8))
        XCTAssertNil(fixture.rawLeaf(staging))
        try fixture.writeRawLeaf(".owner.response.tmp", Data("orphan".utf8))
        try fixture.writeRawLeaf(".rendezvous.json.tmp", Data())
        try fixture.storage.purgeStaleFiles(nowEpochMillis: fixture.clock.now.epochMillis)
        XCTAssertFalse(fixture.leafNames().contains { $0.hasSuffix(".tmp") })
    }

}
