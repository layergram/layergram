import Foundation
import XCTest

@testable import SystemKeyboardCore

final class MailboxRoundTripTests: MailboxTestCase {
    func testSealedRoundTripAcrossSeparateStorageHandles() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()

        let request = requestPayload(marker: "ROUNDTRIP")
        let response = responsePayload(marker: "ROUNDTRIP-REPLY")

        try session.send(payload: request)
        let pending: MailboxPendingRequest
        switch try owner.pollRequest() {
        case .idle:
            return XCTFail("expected a pending request")
        case .request(let value):
            pending = value
        }
        XCTAssertEqual(pending.payload, request)
        XCTAssertEqual(pending.sessionId, session.sessionId)

        try owner.respond(to: pending, payload: response)
        switch try session.pollResponse() {
        case .idle:
            XCTFail("expected a response")
        case .response(let reply):
            XCTAssertEqual(reply, response)
        }
    }

    func testSequentialRequestsShareOneWindowWithIncreasingSequence() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()

        var sequences: [UInt64] = []
        for index in 0..<3 {
            let request = requestPayload(marker: "SEQ-\(index)")
            let response = responsePayload(marker: "SEQ-REPLY-\(index)")
            try session.send(payload: request)
            guard case .request(let pending) = try owner.pollRequest() else {
                return XCTFail("expected request \(index)")
            }
            XCTAssertEqual(pending.payload, request)
            sequences.append(pending.sequence)
            try owner.respond(to: pending, payload: response)
            guard case .response(let reply) = try session.pollResponse() else {
                return XCTFail("expected response \(index)")
            }
            XCTAssertEqual(reply, response)
        }
        XCTAssertEqual(sequences, [1, 2, 3])
    }

    func testOwnerAcceptsRealisticCarrierSizedPayload() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()

        // Comparable to the existing carrier budget (262144 UTF-16 units).
        let request = Data(repeating: 0x41, count: 300_000)
        let response = Data(repeating: 0x42, count: 200_000)
        let reply = try fixture.deliver(owner: owner, session: session, request: request, response: response)
        XCTAssertEqual(reply, response)
    }

    func testSharedFilesNeverContainPlaintextOrContactReferences() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()

        let secret = "CONTACT-NAME-DO-NOT-LEAK-9f3a"
        let request = requestPayload(marker: secret)
        let response = responsePayload(marker: secret + "-REPLY")

        try session.send(payload: request)
        guard case .request(let pending) = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }
        try owner.respond(to: pending, payload: response)

        let marker = Data(secret.utf8)
        for name in fixture.leafNames() {
            guard let data = fixture.rawLeaf(name) else { continue }
            XCTAssertNil(
                data.range(of: marker),
                "\(name) contains plaintext material"
            )
            XCTAssertNil(
                data.range(of: Data("begin".utf8)),
                "\(name) contains a plaintext method-channel op name"
            )
        }
        // The ciphertext must still decrypt, proving encryption rather than omission.
        guard case .response(let reply) = try session.pollResponse() else {
            return XCTFail("expected a response")
        }
        XCTAssertEqual(reply, response)
    }

    func testRendezvousCarriesOnlyPublicRendezvousFields() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        _ = try owner.openWindow()

        guard let data = fixture.rawLeaf(MailboxConstants.rendezvousFileName) else {
            return XCTFail("missing rendezvous")
        }
        let object = try JSONSerialization.jsonObject(with: data)
        let dictionary = try XCTUnwrap(object as? [String: Any])
        XCTAssertEqual(Set(dictionary.keys), ["v", "s", "o", "a", "d", "w"])

        let rendezvous = try MailboxRendezvous.decode(data)
        XCTAssertEqual(rendezvous.sessionId.count, MailboxConstants.sessionIdentifierBytes)
        XCTAssertEqual(rendezvous.ownerPublicKey.count, MailboxConstants.ownerPublicKeyBytes)
        XCTAssertLessThanOrEqual(rendezvous.windowMillis, MailboxConstants.maxWindowMillis)
        XCTAssertEqual(
            rendezvous.deadlineEpochMillis,
            rendezvous.createdAtEpochMillis + rendezvous.windowMillis
        )
    }

    func testWritesAreAtomicAndLeaveNoTemporaryFiles() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        guard case .request(let pending) = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }
        try owner.respond(to: pending, payload: responsePayload())
        _ = try session.pollResponse()

        let allowed = Set([
            MailboxConstants.rendezvousFileName,
            MailboxConstants.requestFileName,
            MailboxConstants.responseFileName,
            MailboxConstants.lockFileName
        ])
        for name in fixture.leafNames() {
            XCTAssertTrue(allowed.contains(name), "unexpected leaf \(name)")
        }
        XCTAssertFalse(fixture.leafNames().contains { $0.hasSuffix(".tmp") })
    }

    func testSharedDirectoryIsExcludedFromBackup() throws {
        let fixture = try MailboxFixture()
        let url = fixture.directoryURL
        let values = try url.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)
        XCTAssertTrue(fixture.storage.isBackupExcluded)
    }

    func testRemoveAllClearsSharedDocumentsButKeepsDirectory() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        try fixture.storage.removeAll()

        XCTAssertNil(fixture.rawLeaf(MailboxConstants.rendezvousFileName))
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.requestFileName))
        XCTAssertNil(fixture.rawLeaf(MailboxConstants.responseFileName))
        var isDirectory: ObjCBool = false
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: fixture.directoryURL.path, isDirectory: &isDirectory)
        )
        XCTAssertTrue(isDirectory.boolValue)
        _ = owner
    }
}
