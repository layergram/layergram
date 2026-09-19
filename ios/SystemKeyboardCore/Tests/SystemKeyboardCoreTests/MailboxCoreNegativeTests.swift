import Foundation
import XCTest

@testable import SystemKeyboardCore

private func mutateEnvelope(
    _ envelope: Data,
    _ transform: (inout [String: Any]) throws -> Void
) throws -> Data {
    var object = try XCTUnwrap(JSONSerialization.jsonObject(with: envelope) as? [String: Any])
    try transform(&object)
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

private func flipLastByte(_ base64: String) throws -> String {
    var data = try XCTUnwrap(Data(base64Encoded: base64))
    data[data.count - 1] ^= 0x01
    return data.base64EncodedString()
}

final class MailboxCoreNegativeTests: MailboxTestCase {
    func testTamperedCiphertextIsRejected() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        let envelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateEnvelope(envelope) { object in
            object["c"] = try flipLastByte(try XCTUnwrap(object["c"] as? String))
        }
        assertMailboxError(
            try core.acceptRequest(tampered, now: fixture.now),
            kind: .malformed,
            reason: .cryptoFailure
        )
        XCTAssertNil(core.pinnedClient)
    }

    func testTamperedNonceIsRejected() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        let envelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateEnvelope(envelope) { object in
            object["n"] = try flipLastByte(try XCTUnwrap(object["n"] as? String))
        }
        assertMailboxError(
            try core.acceptRequest(tampered, now: fixture.now),
            kind: .malformed,
            reason: .cryptoFailure
        )
    }

    func testTamperedRequestIdentifierIsRejectedByAADBinding() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        let envelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateEnvelope(envelope) { object in
            object["r"] = MailboxRandom.bytes(16).base64EncodedString()
        }
        assertMailboxError(
            try core.acceptRequest(tampered, now: fixture.now),
            kind: .malformed,
            reason: .cryptoFailure
        )
    }

    func testTamperedSequenceIsRejectedByAADBinding() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        let envelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateEnvelope(envelope) { object in
            object["q"] = NSNumber(value: 2)
        }
        assertMailboxError(
            try core.acceptRequest(tampered, now: fixture.now),
            kind: .malformed,
            reason: .cryptoFailure
        )
    }

    func testRequestKeyedDocumentCannotOpenAsResponse() throws {
        let fixture = try CoreFixture()
        let client = try fixture.clientCore()
        _ = try client.makeRequest(
            payload: requestPayload(),
            now: fixture.now,
            timeoutMillis: MailboxConstants.defaultPendingTimeoutMillis
        )
        let requestId = try XCTUnwrap(client.pendingRequestId)
        let crossDirection = try fixture.requestKeyedResponseShapedEnvelope(
            requestId: requestId,
            sequence: 1,
            payload: responsePayload()
        )
        assertMailboxError(
            try client.openResponse(crossDirection, now: fixture.now),
            kind: .malformed,
            reason: .cryptoFailure
        )
    }

    func testResponseKeyedDocumentCannotBeAcceptedAsRequest() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        let crossDirection = try fixture.responseKeyedRequestShapedEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        assertMailboxError(
            try core.acceptRequest(crossDirection, now: fixture.now),
            kind: .malformed,
            reason: .cryptoFailure
        )
    }

    func testWrongSessionIdentifierIsRejected() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        let otherSession = MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes)
        let envelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload(),
            sessionId: otherSession
        )
        assertMailboxError(
            try core.acceptRequest(envelope, now: fixture.now),
            kind: .malformed,
            reason: .wrongSession
        )
    }

    func testClientRejectsResponseFromAnotherSession() throws {
        let fixture = try CoreFixture()
        let client = try fixture.clientCore()
        _ = try client.makeRequest(
            payload: requestPayload(),
            now: fixture.now,
            timeoutMillis: MailboxConstants.defaultPendingTimeoutMillis
        )
        let requestId = try XCTUnwrap(client.pendingRequestId)
        let otherSession = MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes)
        let envelope = try fixture.responseEnvelope(
            requestId: requestId,
            sequence: 1,
            payload: responsePayload(),
            sessionId: otherSession
        )
        assertMailboxError(
            try client.openResponse(envelope, now: fixture.now),
            kind: .malformed,
            reason: .wrongSession
        )
    }

    func testReplayedRequestIsRejected() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        let envelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        _ = try core.acceptRequest(envelope, now: fixture.now)
        assertMailboxError(
            try core.acceptRequest(envelope, now: fixture.now),
            kind: .malformed,
            reason: .replay
        )
    }

    func testReplayedResponseIsRejected() throws {
        let fixture = try CoreFixture()
        let client = try fixture.clientCore()
        _ = try client.makeRequest(
            payload: requestPayload(),
            now: fixture.now,
            timeoutMillis: MailboxConstants.defaultPendingTimeoutMillis
        )
        let requestId = try XCTUnwrap(client.pendingRequestId)
        let envelope = try fixture.responseEnvelope(
            requestId: requestId,
            sequence: 1,
            payload: responsePayload()
        )
        XCTAssertEqual(try client.openResponse(envelope, now: fixture.now), responsePayload())
        assertMailboxError(
            try client.openResponse(envelope, now: fixture.now),
            kind: .malformed,
            reason: .notPending
        )
    }

    func testResponseForDifferentRequestIsRejected() throws {
        let fixture = try CoreFixture()
        let client = try fixture.clientCore()
        _ = try client.makeRequest(
            payload: requestPayload(),
            now: fixture.now,
            timeoutMillis: MailboxConstants.defaultPendingTimeoutMillis
        )
        let envelope = try fixture.responseEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: responsePayload()
        )
        assertMailboxError(
            try client.openResponse(envelope, now: fixture.now),
            kind: .malformed,
            reason: .requestMismatch
        )
    }

    func testResponseSequenceMustStrictlyIncrease() throws {
        let fixture = try CoreFixture()
        let client = try fixture.clientCore()

        _ = try client.makeRequest(
            payload: requestPayload(marker: "ONE"),
            now: fixture.now,
            timeoutMillis: MailboxConstants.defaultPendingTimeoutMillis
        )
        let firstId = try XCTUnwrap(client.pendingRequestId)
        let first = try fixture.responseEnvelope(requestId: firstId, sequence: 1, payload: responsePayload())
        XCTAssertEqual(try client.openResponse(first, now: fixture.now), responsePayload())

        _ = try client.makeRequest(
            payload: requestPayload(marker: "TWO"),
            now: fixture.now,
            timeoutMillis: MailboxConstants.defaultPendingTimeoutMillis
        )
        let secondId = try XCTUnwrap(client.pendingRequestId)
        let staleSequence = try fixture.responseEnvelope(
            requestId: secondId,
            sequence: 1,
            payload: responsePayload()
        )
        assertMailboxError(
            try client.openResponse(staleSequence, now: fixture.now),
            kind: .malformed,
            reason: .replay
        )
    }

    func testSecondClientCannotJoinPinnedWindow() throws {
        let first = try CoreFixture()
        var core = try first.ownerCore()

        let firstEnvelope = try first.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload(marker: "FIRST")
        )
        let accepted = try core.acceptRequest(firstEnvelope, now: first.now)
        XCTAssertEqual(accepted.clientEncapsulation, first.clientEncapsulation)

        // A second, real encapsulator against the same owner key: different
        // 1120 public bytes, so it can never be the pinned client.
        let second = try first.clientCore()
        let secondEnvelope = try first.requestEnvelopeWithEncapsulation(
            second.clientEncapsulation,
            requestId: MailboxRandom.bytes(16),
            sequence: 2,
            payload: requestPayload(marker: "INTRUDER")
        )
        assertMailboxError(
            try core.acceptRequest(secondEnvelope, now: first.now),
            kind: .malformed,
            reason: .wrongClient
        )

        // The pinned client keeps working after the rejected attempt.
        let nextEnvelope = try first.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 2,
            payload: requestPayload(marker: "FIRST-AGAIN")
        )
        let next = try core.acceptRequest(nextEnvelope, now: first.now)
        XCTAssertEqual(next.sequence, 2)
        XCTAssertEqual(next.payload, requestPayload(marker: "FIRST-AGAIN"))
    }

    func testStaleResponseHandleIsRejectedAtServiceLevel() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()

        try session.send(payload: requestPayload())
        guard case .request(let pending) = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }
        try owner.respond(to: pending, payload: responsePayload())
        assertMailboxError(
            try owner.respond(to: pending, payload: responsePayload()),
            kind: .malformed,
            reason: .staleRequest
        )
    }

    func testUnrelatedResponseWithoutPendingRequestIsRejected() throws {
        let fixture = try MailboxFixture()
        let (_, session) = try fixture.connectedPair()
        let core = try CoreFixture(now: fixture.clock.now)
        let envelope = try core.responseEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: responsePayload()
        )
        try fixture.writeRawLeaf(MailboxConstants.responseFileName, envelope)

        assertMailboxError(
            try session.pollResponse(),
            kind: .malformed,
            reason: .notPending
        )
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.responseFileName))
    }

    func testPollWithoutAnyResponseIsIdle() throws {
        let fixture = try MailboxFixture()
        let (_, session) = try fixture.connectedPair()
        XCTAssertEqual(try session.pollResponse(), .idle)
    }

    func testResponseWithoutPendingRequestIsRejectedAtClientCore() throws {
        let fixture = try CoreFixture()
        let client = try fixture.clientCore()
        let envelope = try fixture.responseEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: responsePayload()
        )
        assertMailboxError(
            try client.openResponse(envelope, now: fixture.now),
            kind: .malformed,
            reason: .notPending
        )
    }
}
