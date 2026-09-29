import CryptoKit
import Foundation
import XCTest

@testable import SystemKeyboardCore

/// Positive and negative coverage of the hybrid post-quantum transport
/// (`XWingMLKEM768X25519`, wire protocol version 2).
///
/// Everything here uses real CryptoKit hybrid material: a genuine owner key, a
/// genuine encapsulation and the production key schedule. There is no test-only
/// classical or fake-secret path.
final class MailboxPostQuantumTests: MailboxTestCase {
    private func flipLastBase64Byte(_ base64: String) throws -> String {
        var data = try XCTUnwrap(Data(base64Encoded: base64))
        data[data.count - 1] ^= 0x01
        return data.base64EncodedString()
    }

    private func object(_ envelope: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: envelope) as? [String: Any])
    }

    // MARK: - Real hybrid round trip

    func testHybridEncapsulationAndDecapsulationAgreeOnTheSameSecret() throws {
        XCTAssertTrue(MailboxCryptoAvailability.isSupported)
        let owner = try HybridKeyFixture()
        XCTAssertEqual(owner.ownerPublicKey.count, MailboxConstants.ownerPublicKeyBytes)

        let first = try MailboxKEMAgreement.encapsulate(ownerPublicKey: owner.ownerPublicKey)
        let second = try MailboxKEMAgreement.encapsulate(ownerPublicKey: owner.ownerPublicKey)
        XCTAssertEqual(first.encapsulated.count, MailboxConstants.clientEncapsulationBytes)
        XCTAssertEqual(second.encapsulated.count, MailboxConstants.clientEncapsulationBytes)
        // A fresh encapsulation every time: the same public key is not reusable
        // as a deterministic shared secret.
        XCTAssertNotEqual(first.encapsulated, second.encapsulated)

        let decapsulated = try owner.ownerKey.decapsulating(first.encapsulated)
        XCTAssertEqual(decapsulated, first.sharedSecret)
        XCTAssertEqual(decapsulated.bitCount, MailboxConstants.kemSharedSecretBytes * 8)
        // The second encapsulation decapsulates to its own secret, not the first.
        let secondDecapsulated = try owner.ownerKey.decapsulating(second.encapsulated)
        XCTAssertEqual(secondDecapsulated, second.sharedSecret)
        XCTAssertNotEqual(first.sharedSecret, second.sharedSecret)
    }

    func testFullHybridRoundTripAcrossSeparateStorageHandles() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()

        let request = requestPayload(marker: "HYBRID")
        let response = responsePayload(marker: "HYBRID-REPLY")
        let reply = try fixture.deliver(owner: owner, session: session, request: request, response: response)
        XCTAssertEqual(reply, response)
    }

    func testRendezvousAndRequestCarryHybridLengthsNotClassicalKeys() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()

        // Rendezvous: exactly the 1216-byte hybrid owner public key.
        let rendezvousData = try XCTUnwrap(fixture.rawLeaf(MailboxConstants.rendezvousFileName))
        let rendezvous = try MailboxRendezvous.decode(rendezvousData)
        XCTAssertEqual(rendezvous.ownerPublicKey.count, MailboxConstants.ownerPublicKeyBytes)
        XCTAssertEqual(rendezvous.version, 2)
        XCTAssertNotEqual(rendezvous.ownerPublicKey.count, 32)

        // Request: exactly the 1120-byte hybrid encapsulation in `k`.
        try session.send(payload: requestPayload())
        let requestData = try XCTUnwrap(fixture.rawLeaf(MailboxConstants.requestFileName))
        let fields = try object(requestData)
        XCTAssertEqual(try XCTUnwrap(fields["v"] as? Int), 2)
        let k = try XCTUnwrap(fields["k"] as? String)
        XCTAssertEqual(Data(base64Encoded: k)?.count, MailboxConstants.clientEncapsulationBytes)
        XCTAssertNotEqual(Data(base64Encoded: k)?.count, 32)

        // The document still decrypts, so the lengths above are not an omission.
        guard case .request(let pending) = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }
        XCTAssertEqual(pending.payload, requestPayload())
    }

    // MARK: - Changed encapsulation / tag

    func testChangedEncapsulationIsRejectedOnceAClientIsPinned() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()

        let firstEnvelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: requestPayload(marker: "REAL")
        )
        let accepted = try core.acceptRequest(firstEnvelope, now: fixture.now)
        XCTAssertEqual(accepted.clientEncapsulation, fixture.clientEncapsulation)
        XCTAssertEqual(core.pinnedClient, fixture.clientEncapsulation)
        XCTAssertEqual(accepted.payload, requestPayload(marker: "REAL"))

        // A different 1120-byte encapsulation (real KEM output against the same
        // owner key) must be refused before any decapsulation.
        let other = try fixture.clientCore()
        XCTAssertNotEqual(other.clientEncapsulation, fixture.clientEncapsulation)
        let intruder = try fixture.requestEnvelopeWithEncapsulation(
            other.clientEncapsulation,
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 2,
            payload: requestPayload(marker: "INTRUDER")
        )
        assertMailboxError(
            try core.acceptRequest(intruder, now: fixture.now),
            kind: .malformed,
            reason: .wrongClient
        )
        // The pinned client is untouched by the refusal.
        XCTAssertEqual(core.pinnedClient, fixture.clientEncapsulation)

        let nextEnvelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 2,
            payload: requestPayload(marker: "REAL-AGAIN")
        )
        let next = try core.acceptRequest(nextEnvelope, now: fixture.now)
        XCTAssertEqual(next.payload, requestPayload(marker: "REAL-AGAIN"))
    }

    func testChangedCiphertextTagIsRejectedWithoutReplacingThePinnedClient() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        let envelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: requestPayload()
        )
        let tampered = try mutateMailboxEnvelope(envelope) { fields in
            fields["c"] = try self.flipLastBase64Byte(try XCTUnwrap(fields["c"] as? String))
        }
        assertMailboxError(
            try core.acceptRequest(tampered, now: fixture.now),
            kind: .malformed,
            reason: .cryptoFailure
        )
        // Nothing was pinned by the forged document: a genuine one still works.
        XCTAssertNil(core.pinnedClient)
        let genuine = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: requestPayload()
        )
        XCTAssertEqual(try core.acceptRequest(genuine, now: fixture.now).payload, requestPayload())
    }

    func testClientRejectsTamperedResponseTag() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        guard case .request(let pending) = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }
        try owner.respond(to: pending, payload: responsePayload())

        let stored = try XCTUnwrap(fixture.rawLeaf(MailboxConstants.responseFileName))
        let tampered = try mutateMailboxEnvelope(stored) { fields in
            fields["c"] = try self.flipLastBase64Byte(try XCTUnwrap(fields["c"] as? String))
        }
        try fixture.writeRawLeaf(MailboxConstants.responseFileName, tampered)
        assertMailboxError(
            try session.pollResponse(),
            kind: .malformed,
            reason: .cryptoFailure
        )
    }

    // MARK: - Classical / version downgrade rejection

    func testClassicalVersion1EnvelopeIsRejectedAsUnsupported() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        let envelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: requestPayload(),
            version: 1
        )
        assertMailboxError(
            try core.acceptRequest(envelope, now: fixture.now),
            kind: .malformed,
            reason: .unsupportedVersion
        )
        XCTAssertNil(core.pinnedClient)
    }

    func testVersion1RendezvousIsRejected() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        _ = try owner.openWindow()
        let rendezvousData = try XCTUnwrap(fixture.rawLeaf(MailboxConstants.rendezvousFileName))
        var fields = try object(rendezvousData)
        fields["v"] = 1
        // A genuine 1216-byte hybrid key with the old version number: still
        // refused, so version 1 can never be resurrected by a field rewrite.
        let forged = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
        try fixture.writeRawLeaf(MailboxConstants.rendezvousFileName, forged)
        assertMailboxError(try fixture.client().attach(), kind: .malformed, reason: .badVersion)
    }

    func testVersion2EnvelopeWithClassical32ByteKeyIsRejectedByLength() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()
        let envelope = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: requestPayload()
        )
        let downgraded = try mutateMailboxEnvelope(envelope) { fields in
            fields["k"] = MailboxRandom.bytes(32).base64EncodedString()
        }
        assertMailboxError(
            try core.acceptRequest(downgraded, now: fixture.now),
            kind: .malformed,
            reason: .badLength
        )
        XCTAssertNil(core.pinnedClient)
    }

    func testRendezvousWithClassical32ByteOwnerKeyIsRejectedByLength() throws {
        let now = MailboxClock(monotonicMillis: 1_000_000, epochMillis: 1_700_000_000_000)
        assertMailboxError(
            try MailboxRendezvous(
                sessionId: MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes),
                ownerPublicKey: MailboxRandom.bytes(32),
                createdAtEpochMillis: now.epochMillis,
                windowMillis: MailboxConstants.maxWindowMillis
            ),
            kind: .malformed,
            reason: .badLength
        )

        let fields: [String: Any] = [
            "v": 2,
            "s": MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes).base64EncodedString(),
            "o": MailboxRandom.bytes(32).base64EncodedString(),
            "a": NSNumber(value: now.epochMillis),
            "d": NSNumber(value: now.epochMillis + MailboxConstants.maxWindowMillis),
            "w": NSNumber(value: MailboxConstants.maxWindowMillis)
        ]
        let data = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
        assertMailboxError(try MailboxRendezvous.decode(data), kind: .malformed, reason: .badLength)
    }

    func testEncapsulationAgainstWrongLengthOwnerKeyFailsClosed() throws {
        assertMailboxError(
            try MailboxKEMAgreement.encapsulate(ownerPublicKey: MailboxRandom.bytes(32)),
            kind: .malformed,
            reason: .badLength
        )
        assertMailboxError(
            try MailboxKEMAgreement.encapsulate(ownerPublicKey: MailboxRandom.bytes(1215)),
            kind: .malformed,
            reason: .badLength
        )
    }

    func testClientAttachmentToAClassicalRendezvousFailsClosed() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        _ = try owner.openWindow()
        let rendezvousData = try XCTUnwrap(fixture.rawLeaf(MailboxConstants.rendezvousFileName))
        var fields = try object(rendezvousData)
        fields["o"] = MailboxRandom.bytes(32).base64EncodedString()
        let forged = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
        try fixture.writeRawLeaf(MailboxConstants.rendezvousFileName, forged)
        // Decoding the rendezvous already fails by length: no encapsulation is
        // ever attempted against a classical key.
        assertMailboxError(try fixture.client().attach(), kind: .malformed, reason: .badLength)
        XCTAssertFalse(fixture.client().hasLiveWindow())
    }

    // MARK: - Per-window unlinkability

    func testTwoWindowsOfTheSameOwnerShareNoPublicKeyCiphertextOrNonce() throws {
        let fixture = try MailboxFixture()
        let owner = fixture.owner()
        let payload = requestPayload(marker: "UNLINKABLE")

        func capture() throws -> Data {
            _ = try owner.openWindow()
            let session = try fixture.client().attach()
            try session.send(payload: payload)
            let data = try XCTUnwrap(fixture.rawLeaf(MailboxConstants.requestFileName))
            guard case .request(let pending) = try owner.pollRequest() else {
                throw MailboxError.unavailable(.requestPending)
            }
            XCTAssertEqual(pending.payload, payload)
            try owner.closeWindow()
            return data
        }

        let first = try capture()
        let second = try capture()

        let firstFields = try object(first)
        let secondFields = try object(second)
        XCTAssertNotEqual(firstFields["s"] as? String, secondFields["s"] as? String)
        XCTAssertNotEqual(firstFields["n"] as? String, secondFields["n"] as? String)
        XCTAssertNotEqual(firstFields["c"] as? String, secondFields["c"] as? String)
        XCTAssertNotEqual(firstFields["k"] as? String, secondFields["k"] as? String)

        // Nothing from the first window reappears anywhere in the second.
        for value in firstFields.values {
            guard let text = value as? String, text.utf8.count >= 16 else { continue }
            XCTAssertNil(
                second.range(of: Data(text.utf8)),
                "second window reused public material from the first"
            )
        }
        // Both documents still carry the same plaintext, encrypted differently.
        XCTAssertFalse(Array(first).elementsEqual(Array(second)))
    }

    // MARK: - Directional separation and revoke

    func testDirectionalKeysAreSeparatedAndRevokeClearsTheOwnerMaterial() throws {
        let fixture = try CoreFixture()
        var core = try fixture.ownerCore()

        // A document sealed with the response key never opens as a request.
        let crossDirection = try fixture.responseKeyedRequestShapedEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: requestPayload()
        )
        assertMailboxError(
            try core.acceptRequest(crossDirection, now: fixture.now),
            kind: .malformed,
            reason: .cryptoFailure
        )
        XCTAssertNil(core.pinnedClient)

        // A genuine request still works, then revocation drops everything.
        let genuine = try fixture.requestEnvelope(
            requestId: MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes),
            sequence: 1,
            payload: requestPayload()
        )
        _ = try core.acceptRequest(genuine, now: fixture.now)
        XCTAssertNotNil(core.pinnedClient)
        XCTAssertNotNil(core.ownerPublicKey)

        core.revoke()
        XCTAssertTrue(core.isRevoked)
        XCTAssertNil(core.pinnedClient)
        XCTAssertNil(core.ownerPublicKey)
        XCTAssertFalse(core.isAwaitingResponse)
        assertMailboxError(
            try core.acceptRequest(genuine, now: fixture.now),
            kind: .unavailable,
            reason: .revoked
        )
    }

    func testRevokedClientSessionDropsTheHybridSecretAndStopsDecrypting() throws {
        let fixture = try MailboxFixture()
        let (owner, session) = try fixture.connectedPair()
        try session.send(payload: requestPayload())
        guard case .request(let pending) = try owner.pollRequest() else {
            return XCTFail("expected a pending request")
        }
        try owner.respond(to: pending, payload: responsePayload())

        XCTAssertEqual(try session.pollResponse(), .response(responsePayload()))
        session.revoke()
        XCTAssertFalse(session.isWaitingForResponse)
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

    // MARK: - No secret ever written

    func testSharedFilesNeverContainTheHybridSessionSecretOrPlaintext() throws {
        let fixture = try MailboxFixture()
        // A core-level pair whose owner key lives in the fixture directory, so
        // the exact session secret is known and can be searched for on disk.
        let core = try CoreFixture()
        let now = MailboxClock.system()
        let ownerKey = try HybridKeyFixture().ownerKey
        let rendezvous = try MailboxRendezvous(
            sessionId: MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes),
            ownerPublicKey: ownerKey.publicKeyBytes,
            createdAtEpochMillis: now.epochMillis,
            windowMillis: MailboxConstants.maxWindowMillis
        )
        let client = try MailboxClientCore(rendezvous: rendezvous, now: now)
        let marker = "PQ-SECRET-MARKER-77c1"
        let request = requestPayload(marker: marker)
        let made = try client.makeRequest(
            payload: request,
            now: now,
            timeoutMillis: MailboxConstants.defaultPendingTimeoutMillis
        )
        try fixture.writeRawLeaf(MailboxConstants.requestFileName, made.data)

        // The document is the real protocol-2 envelope and still decrypts.
        var ownerCore = try MailboxOwnerCore(ownerKey: ownerKey, rendezvous: rendezvous, now: now)
        let accepted = try ownerCore.acceptRequest(made.data, now: now)
        XCTAssertEqual(accepted.payload, request)

        let response = responsePayload(marker: marker + "-REPLY")
        let sealedResponse = try ownerCore.sealResponse(
            sessionId: accepted.sessionId,
            requestId: accepted.requestId,
            sequence: accepted.sequence,
            payload: response,
            now: now
        )
        try fixture.writeRawLeaf(MailboxConstants.responseFileName, sealedResponse)

        let secret = try ownerKey.decapsulating(client.clientEncapsulation)
        let secretBytes = secret.withUnsafeBytes { Data($0) }
        let derived = MailboxKeySet.derive(sharedSecret: secret, sessionId: rendezvous.sessionId,
            clientEncapsulation: client.clientEncapsulation, ownerPublicKey: rendezvous.ownerPublicKey)
        let requestKeyBytes = derived.requestKey.withUnsafeBytes { Data($0) }
        let responseKeyBytes = derived.responseKey.withUnsafeBytes { Data($0) }
        XCTAssertEqual(secretBytes.count, MailboxConstants.kemSharedSecretBytes)
        for name in fixture.leafNames() {
            guard let data = fixture.rawLeaf(name) else { continue }
            XCTAssertNil(data.range(of: Data(marker.utf8)), "\(name) contains plaintext material")
            XCTAssertNil(data.range(of: Data("begin".utf8)), "\(name) contains an op name")
            XCTAssertNil(data.range(of: secretBytes), "\(name) contains the KEM session secret")
            XCTAssertNil(data.range(of: requestKeyBytes), "\(name) contains request AEAD key material")
            XCTAssertNil(data.range(of: responseKeyBytes), "\(name) contains derived AEAD key material")
            if name == MailboxConstants.rendezvousFileName {
                let rendezvous = try MailboxRendezvous.decode(data)
                XCTAssertEqual(rendezvous.ownerPublicKey.count, MailboxConstants.ownerPublicKeyBytes)
            }
        }

        // The sealed response the owner produced still opens on the client.
        XCTAssertEqual(try client.openResponse(sealedResponse, now: now), response)
    }
}
