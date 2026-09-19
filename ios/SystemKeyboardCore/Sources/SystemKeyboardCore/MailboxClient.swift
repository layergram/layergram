import Foundation

/// Result of a client poll.
public enum MailboxClientPoll: Equatable {
    case idle
    case response(Data)
}

/// Client side of the mailbox. Runs in the keyboard extension process.
///
/// Usage:
/// ```swift
/// let session = try MailboxClient(storage: try MailboxStorage()).attach()
/// _ = try session.send(payload: beginJSON)                    // sealed request
/// while Date() < deadline {
///     if case .response(let reply) = try session.pollResponse() { break }
/// }
/// session.revoke()                                            // drop key references
/// ```
public final class MailboxClient {
    private let storage: MailboxStorage
    private let clock: () -> MailboxClock

    public init(storage: MailboxStorage, clock: @escaping () -> MailboxClock = MailboxClock.system) {
        self.storage = storage
        self.clock = clock
    }

    /// True only when a well-formed rendezvous exists and has not expired.
    public func hasLiveWindow() -> Bool {
        var live = false
        do {
            try storage.withExclusiveLock { () throws -> Void in
                let now = clock()
                guard now.isSane else { return }
                guard let data = try storage.readRendezvous() else { return }
                guard let rendezvous = try? MailboxRendezvous.decode(data) else { return }
                live = now.epochMillis <= rendezvous.deadlineEpochMillis
            }
        } catch {
            return false
        }
        return live
    }

    /// Attach to the current window and hybrid-encapsulate against the owner's
    /// post-quantum public key. The encapsulation happens exactly once here; only
    /// the public encapsulated bytes reach the wire and the session secret exists
    /// only in the returned session. The clock is read under the storage lock so
    /// the converted deadline cannot be computed from a stale timestamp.
    ///
    /// Fails closed with `unavailable` on an OS without the hybrid post-quantum
    /// KEM: there is no classical fallback.
    public func attach() throws -> MailboxClientSession {
        guard MailboxCryptoAvailability.isSupported else {
            throw MailboxError.unavailable(.cryptoUnavailable)
        }
        let core = try storage.withExclusiveLock { () throws -> MailboxClientCore in
            let now = clock()
            guard now.isSane else { throw MailboxError.unavailable(.unavailable) }
            guard let data = try storage.readRendezvous() else {
                throw MailboxError.unavailable(.noRendezvous)
            }
            let rendezvous = try MailboxRendezvous.decode(data)
            return try MailboxClientCore(rendezvous: rendezvous, now: now)
        }
        return MailboxClientSession(storage: storage, clock: clock, core: core)
    }
}

/// One attached client session: one live window, one pinned identity, at most
/// one outstanding request, and one response that must match it exactly.
public final class MailboxClientSession {
    public let sessionId: Data
    public let deadlineMonotonicMillis: Int64

    private let storage: MailboxStorage
    private let clock: () -> MailboxClock
    private let core: MailboxClientCore

    init(storage: MailboxStorage, clock: @escaping () -> MailboxClock, core: MailboxClientCore) {
        self.storage = storage
        self.clock = clock
        self.core = core
        self.sessionId = core.rendezvous.sessionId
        self.deadlineMonotonicMillis = core.deadlineMonotonicMillis
    }

    public var pendingRequestId: Data? { core.pendingRequestId }
    public var responseDeadlineMonotonicMillis: Int64? { core.responseDeadlineMonotonicMillis }
    public var isWaitingForResponse: Bool { core.isWaitingForResponse }

    public func isExpired(at clock: MailboxClock? = nil) -> Bool {
        core.isExpired(at: clock ?? self.clock())
    }

    /// Seal one request and publish it for the owner. Returns the new request id
    /// that the matching response must carry.
    ///
    /// Only one request may be outstanding: a second `send` before the response
    /// is polled fails with `unavailable`.
    @discardableResult
    public func send(
        payload: Data,
        timeoutMillis: Int64 = MailboxConstants.defaultPendingTimeoutMillis
    ) throws -> Data {
        var requestId = Data()
        try storage.withExclusiveLock { () throws -> Void in
            // Seal, clear the previous response and publish the request under one
            // lock with a freshly sampled clock, so the lease and the write agree.
            let now = clock()
            let request = try core.makeRequest(payload: payload, now: now, timeoutMillis: timeoutMillis)
            try storage.removeResponse()
            try storage.writeRequest(request.data)
            requestId = request.requestId
        }
        return requestId
    }

    /// Read, authenticate and remove the response for the pending request.
    ///
    /// `.idle` means the owner has not answered yet and the lease is still
    /// running. Once the lease or the window elapses this throws `unavailable`.
    /// A mismatched, replayed or unauthenticated document is deleted and throws
    /// `malformed`.
    public func pollResponse() throws -> MailboxClientPoll {
        try storage.withExclusiveLock { () throws -> MailboxClientPoll in
            // A revoked session is closed for reading as well as writing.
            guard !core.isRevoked else { throw MailboxError.unavailable(.revoked) }
            // Read, authenticate and remove under the same exclusive lock: a
            // newer response written by the owner can never be deleted by this
            // caller, and the lease decision uses a fresh timestamp.
            let now = clock()
            guard let stored = try storage.readResponse() else {
                if core.pendingTimedOut(at: now) { throw MailboxError.unavailable(.responseTimeout) }
                if core.isExpired(at: now) { throw MailboxError.unavailable(.windowClosed) }
                return .idle
            }
            do {
                let payload = try core.openResponse(stored, now: now)
                try storage.removeResponse()
                return .response(payload)
            } catch {
                try? storage.removeResponse()
                throw error
            }
        }
    }

    /// Drop all key and pending references. No zeroization is promised.
    public func revoke() {
        core.revoke()
    }
}
