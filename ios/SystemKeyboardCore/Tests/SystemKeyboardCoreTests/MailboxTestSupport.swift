import CryptoKit
import Foundation
import XCTest

@testable import SystemKeyboardCore

/// Deterministic clock: both readings are advanced explicitly by the test.
final class MutableClock {
    var now: MailboxClock

    init(monotonicMillis: Int64 = 1_000_000, epochMillis: Int64 = 1_700_000_000_000) {
        now = MailboxClock(monotonicMillis: monotonicMillis, epochMillis: epochMillis)
    }

    func advance(monotonicMillis: Int64 = 0, epochMillis: Int64 = 0) {
        now = MailboxClock(
            monotonicMillis: now.monotonicMillis + monotonicMillis,
            epochMillis: now.epochMillis + epochMillis
        )
    }
}

/// Two independent storage handles over the same directory, standing in for the
/// owner process and the extension process.
final class MailboxFixture {
    let root: URL
    let directoryURL: URL
    let storage: MailboxStorage
    let peerStorage: MailboxStorage
    let clock = MutableClock()

    init() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("SystemKeyboardCoreTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        let directory = base.appendingPathComponent(MailboxConstants.directoryName, isDirectory: true)
        let primary = try MailboxStorage(directoryURL: directory)
        let secondary = try MailboxStorage(directoryURL: directory)
        root = base
        directoryURL = directory
        storage = primary
        peerStorage = secondary
    }

    deinit {
        try? FileManager.default.removeItem(at: root)
    }

    func owner() -> MailboxOwner {
        MailboxOwner(storage: storage, clock: { [clock] in clock.now })
    }

    func client() -> MailboxClient {
        MailboxClient(storage: peerStorage, clock: { [clock] in clock.now })
    }

    func rawLeaf(_ name: String) -> Data? {
        FileManager.default.contents(atPath: directoryURL.appendingPathComponent(name).path)
    }

    func writeRawLeaf(_ name: String, _ data: Data) throws {
        try data.write(to: directoryURL.appendingPathComponent(name))
    }

    func leafNames() -> [String] {
        let names = try? FileManager.default.contentsOfDirectory(atPath: directoryURL.path)
        return (names ?? []).sorted()
    }

    /// Open a window and attach a client to it.
    func connectedPair(windowMillis: Int64 = MailboxConstants.maxWindowMillis) throws -> (MailboxOwner, MailboxClientSession) {
        let owner = self.owner()
        try owner.openWindow(windowMillis: windowMillis)
        let session = try client().attach()
        return (owner, session)
    }

    /// Full sealed round trip, asserting the decrypted payloads match.
    @discardableResult
    func deliver(
        owner: MailboxOwner,
        session: MailboxClientSession,
        request: Data,
        response: Data
    ) throws -> Data {
        try session.send(payload: request)
        let pending: MailboxPendingRequest
        switch try owner.pollRequest() {
        case .idle:
            throw MailboxError.unavailable(.requestPending)
        case .request(let value):
            pending = value
        }
        XCTAssertEqual(pending.payload, request)
        try owner.respond(to: pending, payload: response)
        switch try session.pollResponse() {
        case .idle:
            throw MailboxError.unavailable(.responseTimeout)
        case .response(let value):
            return value
        }
    }
}

/// Manual envelope construction on both sides of one session, used for precise
/// negative cases that the public services cannot produce.
///
/// Both sides use real `XWingMLKEM768X25519` material: the owner fixture holds a
/// genuine hybrid private key and the client fixture encapsulates against its
/// public key. There is no test-only classical or fake-secret path, so every
/// negative case below exercises the production key schedule.
final class CoreFixture {
    let ownerKey: MailboxOwnerPrivateKey
    let rendezvous: MailboxRendezvous
    let now: MailboxClock
    /// The client side of one real hybrid encapsulation against this owner key.
    let secret: MailboxClientSecret
    /// The production key schedule derived from that encapsulation.
    let keys: MailboxKeySet
    private var responseKeys: MailboxKeySet?

    init(
        now: MailboxClock = MailboxClock(monotonicMillis: 1_000_000, epochMillis: 1_700_000_000_000),
        windowMillis: Int64 = MailboxConstants.maxWindowMillis,
        sessionId: Data = MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes)
    ) throws {
        let owner = try HybridKeyFixture()
        let document = try MailboxRendezvous(
            sessionId: sessionId,
            ownerPublicKey: owner.ownerPublicKey,
            createdAtEpochMillis: now.epochMillis,
            windowMillis: windowMillis
        )
        let agreed = try MailboxKEMAgreement.encapsulate(ownerPublicKey: owner.ownerPublicKey)
        ownerKey = owner.ownerKey
        rendezvous = document
        self.now = now
        secret = agreed
        keys = MailboxKeySet.derive(
            sharedSecret: agreed.sharedSecret,
            sessionId: sessionId,
            clientEncapsulation: agreed.encapsulated,
            ownerPublicKey: owner.ownerPublicKey
        )
    }

    /// The encapsulation bytes this fixture's client puts on the wire.
    var clientEncapsulation: Data { secret.encapsulated }

    func ownerCore() throws -> MailboxOwnerCore {
        try MailboxOwnerCore(ownerKey: ownerKey, rendezvous: rendezvous, now: now)
    }

    /// A client core that has really encapsulated against this fixture's owner
    /// public key. The matching secret is recoverable only by the owner core.
    func clientCore() throws -> MailboxClientCore {
        let client = try MailboxClientCore(rendezvous: rendezvous, now: now)
        let secret = try ownerKey.decapsulating(client.clientEncapsulation)
        responseKeys = MailboxKeySet.derive(sharedSecret: secret,
            sessionId: rendezvous.sessionId, clientEncapsulation: client.clientEncapsulation,
            ownerPublicKey: rendezvous.ownerPublicKey)
        return client
    }

    func requestEnvelope(
        requestId: Data,
        sequence: UInt64,
        payload: Data,
        sessionId: Data? = nil,
        version: Int = MailboxConstants.protocolVersion
    ) throws -> Data {
        let session = sessionId ?? rendezvous.sessionId
        let aad = MailboxAAD.make(
            kind: .request,
            version: version,
            sessionId: session,
            requestId: requestId,
            sequence: sequence
        )
        let sealed = try keys.seal(payload, kind: .request, aad: aad)
        return try MailboxEnvelope(
            version: version,
            sessionId: session,
            requestId: requestId,
            sequence: sequence,
            clientEncapsulation: clientEncapsulation,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext
        ).encoded()
    }

    /// Request envelope that carries a different (still real, still 1120-byte)
    /// encapsulation than this fixture's own, sealed with this fixture's keys:
    /// used to prove the pinned window rejects a second encapsulator.
    func requestEnvelopeWithEncapsulation(
        _ encapsulation: Data,
        requestId: Data,
        sequence: UInt64,
        payload: Data
    ) throws -> Data {
        let aad = MailboxAAD.make(
            kind: .request,
            version: MailboxConstants.protocolVersion,
            sessionId: rendezvous.sessionId,
            requestId: requestId,
            sequence: sequence
        )
        let sealed = try keys.seal(payload, kind: .request, aad: aad)
        return try MailboxEnvelope(
            version: MailboxConstants.protocolVersion,
            sessionId: rendezvous.sessionId,
            requestId: requestId,
            sequence: sequence,
            clientEncapsulation: encapsulation,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext
        ).encoded()
    }

    func responseEnvelope(
        requestId: Data,
        sequence: UInt64,
        payload: Data,
        sessionId: Data? = nil,
        version: Int = MailboxConstants.protocolVersion
    ) throws -> Data {
        let session = sessionId ?? rendezvous.sessionId
        let aad = MailboxAAD.make(
            kind: .response,
            version: version,
            sessionId: session,
            requestId: requestId,
            sequence: sequence
        )
        let sealed = try (responseKeys ?? keys).seal(payload, kind: .response, aad: aad)
        return try MailboxEnvelope(
            version: version,
            sessionId: session,
            requestId: requestId,
            sequence: sequence,
            clientEncapsulation: nil,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext
        ).encoded()
    }

    /// Response-shaped document sealed with the request key and request AAD:
    /// must never open as a response.
    func requestKeyedResponseShapedEnvelope(
        requestId: Data,
        sequence: UInt64,
        payload: Data
    ) throws -> Data {
        let aad = MailboxAAD.make(
            kind: .request,
            version: MailboxConstants.protocolVersion,
            sessionId: rendezvous.sessionId,
            requestId: requestId,
            sequence: sequence
        )
        let sealed = try keys.seal(payload, kind: .request, aad: aad)
        return try MailboxEnvelope(
            version: MailboxConstants.protocolVersion,
            sessionId: rendezvous.sessionId,
            requestId: requestId,
            sequence: sequence,
            clientEncapsulation: nil,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext
        ).encoded()
    }

    /// Request-shaped document sealed with the response key and response AAD:
    /// must never be accepted as a request.
    func responseKeyedRequestShapedEnvelope(
        requestId: Data,
        sequence: UInt64,
        payload: Data
    ) throws -> Data {
        let aad = MailboxAAD.make(
            kind: .response,
            version: MailboxConstants.protocolVersion,
            sessionId: rendezvous.sessionId,
            requestId: requestId,
            sequence: sequence
        )
        let sealed = try (responseKeys ?? keys).seal(payload, kind: .response, aad: aad)
        return try MailboxEnvelope(
            version: MailboxConstants.protocolVersion,
            sessionId: rendezvous.sessionId,
            requestId: requestId,
            sequence: sequence,
            clientEncapsulation: clientEncapsulation,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext
        ).encoded()
    }
}

func requestPayload(marker: String = "REQUEST") -> Data {
    Data(#"{"op":"begin","marker":"\#(marker)"}"#.utf8)
}

func mutateMailboxEnvelope(
    _ envelope: Data,
    _ transform: (inout [String: Any]) throws -> Void
) throws -> Data {
    var object = try XCTUnwrap(JSONSerialization.jsonObject(with: envelope) as? [String: Any])
    try transform(&object)
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

func responsePayload(marker: String = "RESPONSE") -> Data {
    Data(#"{"op":"begin","status":"ok","marker":"\#(marker)"}"#.utf8)
}

extension XCTestCase {
    func assertMailboxError(
        _ expression: @autoclosure () throws -> Any,
        kind: MailboxErrorKind,
        reason: MailboxFailureReason? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        do {
            _ = try expression()
            XCTFail("expected MailboxError", file: file, line: line)
        } catch let error as MailboxError {
            XCTAssertEqual(error.kind, kind, file: file, line: line)
            if let reason = reason {
                XCTAssertEqual(error.reason, reason, file: file, line: line)
            }
        } catch {
            XCTFail("expected MailboxError, got \(error)", file: file, line: line)
        }
    }
}

/// Hybrid cryptography is intentionally unavailable on older operating systems.
class MailboxTestCase: XCTestCase {
    override func setUpWithError() throws {
        try super.setUpWithError()
        try XCTSkipUnless(MailboxCryptoAvailability.isSupported, "Requires native hybrid KEM")
    }
}

struct HybridKeyFixture {
    let ownerKey: MailboxOwnerPrivateKey
    var ownerPublicKey: Data { ownerKey.publicKeyBytes }
    init() throws { ownerKey = try MailboxKEMAgreement.generateOwnerKey() }
}
