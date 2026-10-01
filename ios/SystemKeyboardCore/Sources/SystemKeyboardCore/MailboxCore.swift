import CryptoKit
import Foundation

/// A request that the owner accepted and decrypted. Internal: hosts only ever
/// see the public `MailboxPendingRequest`.
struct MailboxAcceptedRequest: Equatable {
    let sessionId: Data
    let requestId: Data
    let sequence: UInt64
    let payload: Data
    let respondByMonotonicMillis: Int64
    /// The client's hybrid KEM encapsulation. Public data, pinned after the first
    /// valid AEAD tag exactly like the classical client key used to be.
    let clientEncapsulation: Data
}

/// Pure owner-side session state. No storage, no clock reads: `now` is always
/// supplied by the caller.
///
/// The first client that presents a well-formed protocol-2 request with a valid
/// AEAD tag is pinned for the whole window. Every later request must carry that
/// exact encapsulation, the same session id, and a strictly greater sequence.
/// Keys live only in this value; `revoke()` drops every reference to them,
/// including the hybrid private-key wrapper and its decapsulation closure, and
/// cannot be undone: a revoked core never derives or accepts anything again.
struct MailboxOwnerCore {
    let rendezvous: MailboxRendezvous
    let deadlineMonotonicMillis: Int64

    private var ownerKey: MailboxOwnerPrivateKey?
    private var pinnedClientEncapsulation: Data?
    private var keys: MailboxKeySet?
    private var lastRequestSequence: UInt64 = 0
    private var trackedRequestIdentifiers: [Data] = []
    private var pending: MailboxAcceptedRequest?
    private var lastResponseSequence: UInt64 = 0
    private var lastObservedMonotonicMillis: Int64 = 0
    private var revoked = false

    init(
        ownerKey: MailboxOwnerPrivateKey,
        rendezvous: MailboxRendezvous,
        now: MailboxClock
    ) throws {
        guard rendezvous.ownerPublicKey == ownerKey.publicKeyBytes else {
            throw MailboxError.malformed(.badFields)
        }
        guard now.isSane else { throw MailboxError.unavailable(.unavailable) }
        let remaining = rendezvous.deadlineEpochMillis - now.epochMillis
        guard remaining > 0 else { throw MailboxError.unavailable(.windowClosed) }
        let window = min(remaining, rendezvous.windowMillis)
        let (deadline, overflow) = now.monotonicMillis.addingReportingOverflow(window)
        guard !overflow else { throw MailboxError.unavailable(.unavailable) }
        self.ownerKey = ownerKey
        self.rendezvous = rendezvous
        self.deadlineMonotonicMillis = deadline
        self.lastObservedMonotonicMillis = now.monotonicMillis
    }

    var ownerPublicKey: Data? { ownerKey?.publicKeyBytes }
    /// The pinned client encapsulation, once a request has proved possession of
    /// the matching hybrid secret.
    var pinnedClient: Data? { pinnedClientEncapsulation }
    var isAwaitingResponse: Bool { pending != nil }
    var pendingRequestId: Data? { pending?.requestId }
    var isRevoked: Bool { revoked }

    /// True while a pending request's freshness lease has not ended. The public
    /// owner service refuses to accept a competing request while this holds; an
    /// authenticated replacement after the lease ended is still allowed.
    func hasLivePendingRequest(at now: MailboxClock) -> Bool {
        guard let pending = pending else { return false }
        return now.monotonicMillis < pending.respondByMonotonicMillis
    }

    /// The deadline is exclusive: a reading exactly at the deadline is expired.
    /// A negative or rolled-back reading is treated as expired so a broken clock
    /// can only shorten, never extend, a window.
    func isExpired(at now: MailboxClock) -> Bool {
        guard now.isSane else { return true }
        guard now.monotonicMillis >= lastObservedMonotonicMillis else { return true }
        return now.monotonicMillis >= deadlineMonotonicMillis
    }

    /// Accept, authenticate and decrypt one request envelope.
    mutating func acceptRequest(_ envelopeData: Data, now: MailboxClock) throws -> MailboxAcceptedRequest {
        try ensureOpen(now)
        let envelope = try MailboxEnvelope.decode(envelopeData, kind: .request)
        guard envelope.sessionId == rendezvous.sessionId else { throw MailboxError.malformed(.wrongSession) }
        guard let clientEncapsulation = envelope.clientEncapsulation else {
            throw MailboxError.malformed(.badFields)
        }
        guard envelope.sequence > lastRequestSequence else { throw MailboxError.malformed(.replay) }
        guard !trackedRequestIdentifiers.contains(envelope.requestId) else {
            throw MailboxError.malformed(.replay)
        }
        // Computed before any state changes so a failed accept leaves the core
        // exactly as it was.
        let (lease, overflow) = now.monotonicMillis.addingReportingOverflow(MailboxConstants.maxLeaseMillis)
        guard !overflow else { throw MailboxError.unavailable(.unavailable) }
        let respondBy = min(lease, deadlineMonotonicMillis)

        let keySet: MailboxKeySet
        let isFirstPinnedClient: Bool
        if let pinned = pinnedClientEncapsulation {
            // The encapsulation itself is public, so the discriminator here is
            // the exact 1120 bytes: a different encapsulator is a different
            // client and cannot join the window even if it is otherwise
            // well-formed.
            guard pinned == clientEncapsulation else { throw MailboxError.malformed(.wrongClient) }
            guard let existing = keys else { throw MailboxError.unavailable(.revoked) }
            keySet = existing
            isFirstPinnedClient = false
        } else {
            keySet = try deriveKeys(clientEncapsulation: clientEncapsulation)
            isFirstPinnedClient = true
        }

        let aad = MailboxAAD.make(
            kind: .request,
            version: envelope.version,
            sessionId: envelope.sessionId,
            requestId: envelope.requestId,
            sequence: envelope.sequence
        )
        let payload = try keySet.open(
            nonce: envelope.nonce,
            ciphertext: envelope.ciphertext,
            kind: .request,
            aad: aad
        )

        // Pin only after the encapsulation proved possession with a valid AEAD
        // tag, so a forged or malformed document can never occupy the window.
        if isFirstPinnedClient {
            pinnedClientEncapsulation = clientEncapsulation
            keys = keySet
        }

        lastRequestSequence = envelope.sequence
        rememberRequestIdentifier(envelope.requestId)
        let accepted = MailboxAcceptedRequest(
            sessionId: envelope.sessionId,
            requestId: envelope.requestId,
            sequence: envelope.sequence,
            payload: payload,
            respondByMonotonicMillis: respondBy,
            clientEncapsulation: clientEncapsulation
        )
        pending = accepted
        return accepted
    }

    /// Seal a response for exactly the pending request. A stale handle, a
    /// mismatched session, an expired window or a missed freshness lease fails
    /// closed, and the deadline is exclusive at both ends.
    mutating func sealResponse(
        sessionId: Data,
        requestId: Data,
        sequence: UInt64,
        payload: Data,
        now: MailboxClock
    ) throws -> Data {
        try ensureOpen(now)
        guard sessionId == rendezvous.sessionId else { throw MailboxError.malformed(.staleRequest) }
        guard payload.count <= MailboxConstants.maxPlaintextBytes else {
            throw MailboxError.malformed(.tooLarge)
        }
        guard let current = pending, current.requestId == requestId, current.sequence == sequence else {
            throw MailboxError.malformed(.staleRequest)
        }
        guard now.monotonicMillis < current.respondByMonotonicMillis else {
            throw MailboxError.unavailable(.responseTimeout)
        }
        guard let keySet = keys else { throw MailboxError.unavailable(.revoked) }
        guard lastResponseSequence < MailboxConstants.maxSequence else {
            throw MailboxError.unavailable(.windowClosed)
        }
        let sequence = lastResponseSequence + 1
        let aad = MailboxAAD.make(
            kind: .response,
            version: MailboxConstants.protocolVersion,
            sessionId: rendezvous.sessionId,
            requestId: current.requestId,
            sequence: sequence
        )
        let sealed = try keySet.seal(payload, kind: .response, aad: aad)
        let envelope = MailboxEnvelope(
            version: MailboxConstants.protocolVersion,
            sessionId: rendezvous.sessionId,
            requestId: current.requestId,
            sequence: sequence,
            clientEncapsulation: nil,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext
        )
        let encoded = try envelope.encoded()
        lastResponseSequence = sequence
        pending = nil
        return encoded
    }

    /// Drop every key and peer reference, including the hybrid private-key
    /// wrapper and its decapsulation closure, and stay revoked. No zeroization is
    /// promised.
    mutating func revoke() {
        ownerKey = nil
        keys = nil
        pending = nil
        pinnedClientEncapsulation = nil
        trackedRequestIdentifiers.removeAll()
        revoked = true
    }

    private mutating func ensureOpen(_ now: MailboxClock) throws {
        guard !revoked else { throw MailboxError.unavailable(.revoked) }
        guard now.isSane else { throw MailboxError.unavailable(.unavailable) }
        guard now.monotonicMillis >= lastObservedMonotonicMillis else {
            throw MailboxError.unavailable(.unavailable)
        }
        lastObservedMonotonicMillis = now.monotonicMillis
        guard now.monotonicMillis < deadlineMonotonicMillis else {
            throw MailboxError.unavailable(.windowClosed)
        }
    }

    private mutating func rememberRequestIdentifier(_ identifier: Data) {
        trackedRequestIdentifiers.append(identifier)
        if trackedRequestIdentifiers.count > MailboxConstants.maxTrackedRequestIdentifiers {
            trackedRequestIdentifiers.removeFirst(
                trackedRequestIdentifiers.count - MailboxConstants.maxTrackedRequestIdentifiers
            )
        }
    }

    private func deriveKeys(clientEncapsulation: Data) throws -> MailboxKeySet {
        guard let ownerKey = ownerKey else { throw MailboxError.unavailable(.revoked) }
        let secret = try ownerKey.decapsulating(clientEncapsulation)
        return MailboxKeySet.derive(
            sharedSecret: secret,
            sessionId: rendezvous.sessionId,
            clientEncapsulation: clientEncapsulation,
            ownerPublicKey: rendezvous.ownerPublicKey
        )
    }
}

/// Pure client-side session state. Holds at most one outstanding request, so a
/// response can only ever be matched against the exact request that is pending.
///
/// The hybrid encapsulation happens exactly once, at construction: the resulting
/// 32-byte symmetric key is kept in RAM for the session and only the public
/// encapsulation bytes reach the wire.
final class MailboxClientCore {
    let rendezvous: MailboxRendezvous
    let deadlineMonotonicMillis: Int64

    private struct Pending: Equatable {
        let requestId: Data
        let sequence: UInt64
        let deadlineMonotonicMillis: Int64
    }

    private let clientEncapsulationValue: Data
    private var keys: MailboxKeySet?
    private var secret: SymmetricKey?
    private var lastRequestSequence: UInt64 = 0
    private var lastResponseSequence: UInt64 = 0
    private var pending: Pending?
    private var lastObservedMonotonicMillis: Int64 = 0
    private var revoked = false

    /// Encapsulates against the owner public key once. Throws `unavailable` when
    /// the OS has no hybrid post-quantum KEM and `malformed` when the rendezvous
    /// public key is not a 1216-byte hybrid key.
    init(rendezvous: MailboxRendezvous, now: MailboxClock) throws {
        guard now.isSane else { throw MailboxError.unavailable(.unavailable) }
        let remaining = rendezvous.deadlineEpochMillis - now.epochMillis
        guard remaining > 0 else { throw MailboxError.unavailable(.windowClosed) }
        let window = min(remaining, rendezvous.windowMillis)
        let (deadline, overflow) = now.monotonicMillis.addingReportingOverflow(window)
        guard !overflow else { throw MailboxError.unavailable(.unavailable) }
        let agreed = try MailboxKEMAgreement.encapsulate(ownerPublicKey: rendezvous.ownerPublicKey)
        self.rendezvous = rendezvous
        self.deadlineMonotonicMillis = deadline
        self.clientEncapsulationValue = agreed.encapsulated
        self.secret = agreed.sharedSecret
        self.lastObservedMonotonicMillis = now.monotonicMillis
    }

    /// The client's public encapsulation bytes, exactly as they appear on the
    /// wire. Not secret.
    var clientEncapsulation: Data { clientEncapsulationValue }
    var pendingRequestId: Data? { pending?.requestId }
    var responseDeadlineMonotonicMillis: Int64? { pending?.deadlineMonotonicMillis }
    var isRevoked: Bool { revoked }
    var isWaitingForResponse: Bool { pending != nil }

    /// See `MailboxOwnerCore.isExpired(at:)`: the deadline is exclusive and a
    /// broken or rolled-back reading fails closed.
    func isExpired(at now: MailboxClock) -> Bool {
        guard now.isSane else { return true }
        guard now.monotonicMillis >= lastObservedMonotonicMillis else { return true }
        return now.monotonicMillis >= deadlineMonotonicMillis
    }

    /// The pending lease is exclusive at its end as well.
    func pendingTimedOut(at now: MailboxClock) -> Bool {
        guard let pending = pending else { return false }
        guard now.isSane else { return true }
        guard now.monotonicMillis >= lastObservedMonotonicMillis else { return true }
        return now.monotonicMillis >= pending.deadlineMonotonicMillis
    }

    /// Build the next request envelope. Only one request may be outstanding.
    func makeRequest(
        payload: Data,
        now: MailboxClock,
        timeoutMillis: Int64
    ) throws -> (data: Data, requestId: Data, respondByMonotonicMillis: Int64) {
        guard !revoked else { throw MailboxError.unavailable(.revoked) }
        guard now.isSane else { throw MailboxError.unavailable(.unavailable) }
        guard now.monotonicMillis >= lastObservedMonotonicMillis else {
            throw MailboxError.unavailable(.unavailable)
        }
        lastObservedMonotonicMillis = now.monotonicMillis
        guard now.monotonicMillis < deadlineMonotonicMillis else {
            throw MailboxError.unavailable(.windowClosed)
        }
        guard payload.count <= MailboxConstants.maxPlaintextBytes else {
            throw MailboxError.malformed(.tooLarge)
        }
        guard timeoutMillis >= 1, timeoutMillis <= MailboxConstants.maxPendingTimeoutMillis else {
            throw MailboxError.malformed(.badNumber)
        }
        if let pending = pending, now.monotonicMillis < pending.deadlineMonotonicMillis {
            throw MailboxError.unavailable(.requestPending)
        }

        let keySet: MailboxKeySet
        if let existing = keys {
            keySet = existing
        } else {
            guard let secret = secret else { throw MailboxError.unavailable(.revoked) }
            let derived = MailboxKeySet.derive(
                sharedSecret: secret,
                sessionId: rendezvous.sessionId,
                clientEncapsulation: clientEncapsulationValue,
                ownerPublicKey: rendezvous.ownerPublicKey
            )
            keys = derived
            self.secret = nil
            keySet = derived
        }

        guard lastRequestSequence < MailboxConstants.maxSequence else {
            throw MailboxError.unavailable(.windowClosed)
        }
        let sequence = lastRequestSequence + 1
        let requestId = MailboxRandom.bytes(MailboxConstants.requestIdentifierBytes)
        let aad = MailboxAAD.make(
            kind: .request,
            version: MailboxConstants.protocolVersion,
            sessionId: rendezvous.sessionId,
            requestId: requestId,
            sequence: sequence
        )
        let sealed = try keySet.seal(payload, kind: .request, aad: aad)
        let envelope = MailboxEnvelope(
            version: MailboxConstants.protocolVersion,
            sessionId: rendezvous.sessionId,
            requestId: requestId,
            sequence: sequence,
            clientEncapsulation: clientEncapsulationValue,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext
        )
        let encoded = try envelope.encoded()
        lastRequestSequence = sequence
        let (lease, overflow) = now.monotonicMillis.addingReportingOverflow(timeoutMillis)
        guard !overflow else { throw MailboxError.unavailable(.unavailable) }
        let respondBy = min(lease, deadlineMonotonicMillis)
        pending = Pending(
            requestId: requestId,
            sequence: sequence,
            deadlineMonotonicMillis: respondBy
        )
        return (encoded, requestId, respondBy)
    }

    /// Decrypt a response only when it matches the exact pending request, comes
    /// from the live session, is still inside the freshness lease, and carries a
    /// strictly increasing response sequence.
    func openResponse(_ envelopeData: Data, now: MailboxClock) throws -> Data {
        guard !revoked else { throw MailboxError.unavailable(.revoked) }
        guard let pending = pending else { throw MailboxError.malformed(.notPending) }
        guard now.isSane else { throw MailboxError.unavailable(.unavailable) }
        guard now.monotonicMillis >= lastObservedMonotonicMillis else {
            throw MailboxError.unavailable(.unavailable)
        }
        lastObservedMonotonicMillis = now.monotonicMillis
        guard now.monotonicMillis < deadlineMonotonicMillis else {
            throw MailboxError.unavailable(.windowClosed)
        }
        guard now.monotonicMillis < pending.deadlineMonotonicMillis else {
            throw MailboxError.unavailable(.responseTimeout)
        }
        let envelope = try MailboxEnvelope.decode(envelopeData, kind: .response)
        guard envelope.sessionId == rendezvous.sessionId else {
            throw MailboxError.malformed(.wrongSession)
        }
        guard envelope.requestId == pending.requestId else {
            throw MailboxError.malformed(.requestMismatch)
        }
        guard envelope.sequence > lastResponseSequence else {
            throw MailboxError.malformed(.replay)
        }
        guard let keySet = keys else { throw MailboxError.unavailable(.revoked) }
        let aad = MailboxAAD.make(
            kind: .response,
            version: envelope.version,
            sessionId: envelope.sessionId,
            requestId: envelope.requestId,
            sequence: envelope.sequence
        )
        let payload = try keySet.open(
            nonce: envelope.nonce,
            ciphertext: envelope.ciphertext,
            kind: .response,
            aad: aad
        )
        lastResponseSequence = envelope.sequence
        self.pending = nil
        return payload
    }

    /// Drop every key and pending reference, including the session secret and the
    /// derived AES keys, and stay revoked. No zeroization is promised.
    func revoke() {
        secret = nil
        keys = nil
        pending = nil
        revoked = true
    }
}
