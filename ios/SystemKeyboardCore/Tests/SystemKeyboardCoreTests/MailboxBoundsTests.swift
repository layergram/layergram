import Foundation
import XCTest

@testable import SystemKeyboardCore

final class MailboxBoundsTests: MailboxTestCase {
    func testOversizedRequestFileIsRejectedBeforeParsing() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        let oversized = Data(repeating: 0x41, count: MailboxConstants.maxEnvelopeBytes + 1)
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, oversized)

        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .tooLarge)
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.requestFileName))
    }

    func testOversizedResponseFileIsRejectedBeforeParsing() throws {
        let fixture = try MailboxFixture()
        let (_, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        try fixture.writeRawLeaf(
            MailboxConstants.responseFileName,
            Data(repeating: 0x42, count: MailboxConstants.maxEnvelopeBytes + 1)
        )
        assertMailboxError(try session.pollResponse(), kind: .malformed, reason: .tooLarge)
    }

    func testNonJSONRequestIsRejected() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, Data("not json at all".utf8))
        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .badJSON)
    }

    func testEmptyRequestFileIsRejected() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, Data())
        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .badJSON)
    }

    func testWrongProtocolVersionIsRejected() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        let core = try CoreFixture(now: fixture.clock.now)
        let envelope = try core.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload(),
            version: MailboxConstants.protocolVersion + 1
        )
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, envelope)
        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .badVersion)
    }

    func testExtraEnvelopeFieldIsRejected() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        let core = try CoreFixture(now: fixture.clock.now)
        let envelope = try core.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateMailboxEnvelope(envelope) { object in
            object["extra"] = "value"
        }
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, tampered)
        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .badFields)
    }

    func testMissingEnvelopeFieldIsRejected() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        let core = try CoreFixture(now: fixture.clock.now)
        let envelope = try core.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateMailboxEnvelope(envelope) { object in
            object.removeValue(forKey: "k")
        }
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, tampered)
        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .badFields)
    }

    func testFractionalSequenceIsRejected() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        let core = try CoreFixture(now: fixture.clock.now)
        let envelope = try core.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateMailboxEnvelope(envelope) { object in
            object["q"] = 1.5
        }
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, tampered)
        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .badNumber)
    }

    func testBooleanVersionIsRejected() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        let core = try CoreFixture(now: fixture.clock.now)
        let envelope = try core.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateMailboxEnvelope(envelope) { object in
            object["v"] = true
        }
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, tampered)
        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .badNumber)
    }

    func testZeroSequenceIsRejected() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        let core = try CoreFixture(now: fixture.clock.now)
        let envelope = try core.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateMailboxEnvelope(envelope) { object in
            object["q"] = 0
        }
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, tampered)
        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .badNumber)
    }

    func testNonCanonicalBase64IsRejected() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        let core = try CoreFixture(now: fixture.clock.now)
        let envelope = try core.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateMailboxEnvelope(envelope) { object in
            object["s"] = "!!!!"
        }
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, tampered)
        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .badBase64)
    }

    func testWrongBase64LengthIsRejected() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        let core = try CoreFixture(now: fixture.clock.now)
        let envelope = try core.requestEnvelope(
            requestId: MailboxRandom.bytes(16),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateMailboxEnvelope(envelope) { object in
            object["r"] = MailboxRandom.bytes(8).base64EncodedString()
        }
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, tampered)
        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .badLength)
    }

    func testPayloadAbovePlaintextBoundIsRejectedByClient() throws {
        let fixture = try MailboxFixture()
        let (_, session) = try fixture.connectedPair()
        let oversized = Data(repeating: 0x41, count: MailboxConstants.maxPlaintextBytes + 1)
        assertMailboxError(try session.send(payload: oversized), kind: .malformed, reason: .tooLarge)
    }

    func testPayloadAbovePlaintextBoundIsRejectedByOwner() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        guard case .request(let pending) = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }
        let oversized = Data(repeating: 0x41, count: MailboxConstants.maxPlaintextBytes + 1)
        assertMailboxError(
            try owner.respond(to: pending, payload: oversized),
            kind: .malformed,
            reason: .tooLarge
        )
    }

    func testRendezvousWindowAboveCeilingIsRejected() throws {
        let fixture = try MailboxFixture()
        let (_, _) = try fixture.connectedPair()
        let now = fixture.clock.now
        let window: Int64 = MailboxConstants.maxWindowMillis + 1
        let object: [String: Any] = [
            "v": MailboxConstants.protocolVersion,
            "s": MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes).base64EncodedString(),
            "o": MailboxRandom.bytes(MailboxConstants.ownerPublicKeyBytes).base64EncodedString(),
            "a": NSNumber(value: now.epochMillis),
            "d": NSNumber(value: now.epochMillis + window),
            "w": NSNumber(value: window)
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        try fixture.writeRawLeaf(MailboxConstants.rendezvousFileName, data)
        assertMailboxError(try fixture.client().attach(), kind: .malformed, reason: .badNumber)
    }

    func testRendezvousDeadlineMismatchIsRejected() throws {
        let now = MailboxClock(monotonicMillis: 1_000_000, epochMillis: 1_700_000_000_000)
        let object: [String: Any] = [
            "v": MailboxConstants.protocolVersion,
            "s": MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes).base64EncodedString(),
            "o": MailboxRandom.bytes(MailboxConstants.ownerPublicKeyBytes).base64EncodedString(),
            "a": NSNumber(value: now.epochMillis),
            "d": NSNumber(value: now.epochMillis + MailboxConstants.maxWindowMillis * 2),
            "w": NSNumber(value: MailboxConstants.maxWindowMillis)
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        assertMailboxError(try MailboxRendezvous.decode(data), kind: .malformed, reason: .badFields)
    }

    func testRendezvousWithWrongFieldTypesIsRejected() throws {
        let now = MailboxClock(monotonicMillis: 1_000_000, epochMillis: 1_700_000_000_000)
        let object: [String: Any] = [
            "v": MailboxConstants.protocolVersion,
            "s": 5,
            "o": MailboxRandom.bytes(MailboxConstants.ownerPublicKeyBytes).base64EncodedString(),
            "a": NSNumber(value: now.epochMillis),
            "d": NSNumber(value: now.epochMillis + MailboxConstants.maxWindowMillis),
            "w": NSNumber(value: MailboxConstants.maxWindowMillis)
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        assertMailboxError(try MailboxRendezvous.decode(data), kind: .malformed, reason: .badFields)
    }

    func testSymlinkedLeafFailsClosed() throws {
        let fixture = try MailboxFixture()
        let (owner, _) = try fixture.connectedPair()
        let target = fixture.root.appendingPathComponent("outside.json")
        try Data("outside".utf8).write(to: target)
        let leaf = fixture.directoryURL.appendingPathComponent(MailboxConstants.requestFileName)
        try FileManager.default.createSymbolicLink(at: leaf, withDestinationURL: target)

        assertMailboxError(try owner.pollRequest(), kind: .malformed, reason: .unsafePath)
        XCTAssertEqual(try Data(contentsOf: target), Data("outside".utf8))
    }

    func testSymlinkedDirectoryFailsClosed() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("SystemKeyboardCoreTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }

        let realDirectory = base.appendingPathComponent("real", isDirectory: true)
        try FileManager.default.createDirectory(at: realDirectory, withIntermediateDirectories: true)
        let link = base.appendingPathComponent("link", isDirectory: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: realDirectory)

        assertMailboxError(
            try MailboxStorage(directoryURL: link),
            kind: .malformed,
            reason: .unsafePath
        )
    }

    func testUnsafePathComponentsAreRejected() {
        XCTAssertFalse(MailboxStorage.isSafePathComponent(""))
        XCTAssertFalse(MailboxStorage.isSafePathComponent(".."))
        XCTAssertFalse(MailboxStorage.isSafePathComponent("."))
        XCTAssertFalse(MailboxStorage.isSafePathComponent("a/b"))
        XCTAssertFalse(MailboxStorage.isSafePathComponent("a\\b"))
        XCTAssertTrue(MailboxStorage.isSafePathComponent(MailboxConstants.directoryName))
    }

    func testOutOfRangePendingTimeoutIsRejected() throws {
        let fixture = try MailboxFixture()
        let (_, session) = try fixture.connectedPair()
        assertMailboxError(
            try session.send(
                payload: requestPayload(),
                timeoutMillis: MailboxConstants.maxPendingTimeoutMillis + 1
            ),
            kind: .malformed,
            reason: .badNumber
        )
        assertMailboxError(
            try session.send(payload: requestPayload(), timeoutMillis: 0),
            kind: .malformed,
            reason: .badNumber
        )
    }

    func testOpenWindowAboveCeilingIsRejected() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        assertMailboxError(
            try owner.openWindow(windowMillis: MailboxConstants.maxWindowMillis + 1),
            kind: .malformed,
            reason: .badNumber
        )
        XCTAssertFalse(owner.isWindowOpen)
    }
}
