import CryptoKit
import Foundation

/// Public description of one open mailbox window.
public struct MailboxWindowInfo: Equatable {
    public let sessionId: Data
    /// The hybrid post-quantum owner public key (`XWingMLKEM768X25519`,
    /// 1216 bytes). Public data; the matching private key never leaves the owner.
    public let ownerPublicKey: Data
    public let createdAtEpochMillis: Int64
    public let deadlineEpochMillis: Int64
    public let windowMillis: Int64
    public let deadlineMonotonicMillis: Int64
}

/// A request that the owner already decrypted and handed to the Dart service.
///
/// The handle is only valid for the window that produced it and only until
/// `respondByMonotonicMillis`; `MailboxOwner.respond(to:payload:)` re-validates
/// both before any response is sealed or written.
public struct MailboxPendingRequest: Equatable {
    public let sessionId: Data
    public let requestId: Data
    public let sequence: UInt64
    public let payload: Data
    public let respondByMonotonicMillis: Int64
}

/// Result of an owner poll.
public enum MailboxHostPoll: Equatable {
    case idle
    case request(MailboxPendingRequest)
}

/// Owner side of the mailbox. Runs in the live Layergram app process.
///
/// Usage:
/// ```swift
/// let owner = MailboxOwner(storage: try MailboxStorage())
/// let window = try owner.openWindow()                    // <= 20 s, non-renewable
/// switch try owner.pollRequest() {
/// case .idle: break
/// case .request(let pending):
///     let reply = try await dartService.handle(pending.payload)   // existing service
///     try owner.respond(to: pending, payload: reply)
/// }
/// try owner.closeWindow()
/// ```
public final class MailboxOwner {
    private let storage: MailboxStorage
    private let clock: () -> MailboxClock
    private var core: MailboxOwnerCore?
    private var info: MailboxWindowInfo?

    public init(storage: MailboxStorage, clock: @escaping () -> MailboxClock = MailboxClock.system) {
        self.storage = storage
        self.clock = clock
    }

    public var windowInfo: MailboxWindowInfo? { info }
    public var isWindowOpen: Bool { core != nil }
    /// True between a successful `pollRequest()` and the matching `respond`.
    public var isAwaitingResponse: Bool { core?.isAwaitingResponse ?? false }

    /// Open exactly one window. A second call while a window is open fails
    /// closed: windows are never renewed or extended, and the owner must close
    /// the current one first.
    ///
    /// Fails closed with `unavailable` on an OS without the hybrid post-quantum
    /// KEM: there is no classical fallback. Hosts gate the UI on
    /// `MailboxCryptoAvailability.isSupported`.
    @discardableResult
    public func openWindow(windowMillis: Int64 = MailboxConstants.maxWindowMillis) throws -> MailboxWindowInfo {
        guard windowMillis >= 1, windowMillis <= MailboxConstants.maxWindowMillis else {
            throw MailboxError.malformed(.badNumber)
        }
        guard core == nil else { throw MailboxError.unavailable(.windowOpen) }
        guard MailboxCryptoAvailability.isSupported else {
            throw MailboxError.unavailable(.cryptoUnavailable)
        }

        let ownerKey = try MailboxKEMAgreement.generateOwnerKey()
        let sessionId = MailboxRandom.bytes(MailboxConstants.sessionIdentifierBytes)

        var newCore: MailboxOwnerCore?
        var newInfo: MailboxWindowInfo?
        try storage.withExclusiveLock { () throws -> Void in
            // The clock reading is taken under the storage lock, immediately
            // before the rendezvous is derived and written, so no stale
            // timestamp can widen the window.
            let now = clock()
            guard now.isSane else { throw MailboxError.unavailable(.unavailable) }
            let rendezvous = try MailboxRendezvous(
                sessionId: sessionId,
                ownerPublicKey: ownerKey.publicKeyBytes,
                createdAtEpochMillis: now.epochMillis,
                windowMillis: windowMillis
            )
            let created = try MailboxOwnerCore(ownerKey: ownerKey, rendezvous: rendezvous, now: now)
            let encoded = try rendezvous.encoded()
            try storage.purgeStaleFiles(nowEpochMillis: now.epochMillis)
            try storage.removeRequest()
            try storage.removeResponse()
            try storage.writeRendezvous(encoded)
            newCore = created
            newInfo = MailboxWindowInfo(
                sessionId: rendezvous.sessionId,
                ownerPublicKey: rendezvous.ownerPublicKey,
                createdAtEpochMillis: rendezvous.createdAtEpochMillis,
                deadlineEpochMillis: rendezvous.deadlineEpochMillis,
                windowMillis: rendezvous.windowMillis,
                deadlineMonotonicMillis: created.deadlineMonotonicMillis
            )
        }

        guard let created = newCore, let windowInfo = newInfo else {
            throw MailboxError.unavailable(.storageUnavailable)
        }
        core = created
        info = windowInfo
        return windowInfo
    }

    /// Read, authenticate and decrypt at most one pending request.
    ///
    /// `.idle` means nothing is waiting. A request that fails parsing,
    /// authentication or replay checks is deleted and reported as `malformed`.
    public func pollRequest() throws -> MailboxHostPoll {
        guard var current = core else { throw MailboxError.unavailable(.revoked) }
        do {
            let result = try storage.withExclusiveLock { () throws -> MailboxHostPoll in
                // Re-sampled under the lock so the read and the accept decision
                // use one timestamp that cannot be stale.
                let now = clock()
                guard !current.isExpired(at: now) else {
                    throw MailboxError.unavailable(.windowClosed)
                }
                guard let data = try storage.readRequest() else { return .idle }
                // A second request must never silently replace the handle the
                // host is still about to answer. The competing document is left
                // in place and reported, so the host decides what happens next.
                guard !current.hasLivePendingRequest(at: now) else {
                    throw MailboxError.unavailable(.requestPending)
                }
                let accepted = try current.acceptRequest(data, now: now)
                try storage.removeRequest()
                return .request(
                    MailboxPendingRequest(
                        sessionId: accepted.sessionId,
                        requestId: accepted.requestId,
                        sequence: accepted.sequence,
                        payload: accepted.payload,
                        respondByMonotonicMillis: accepted.respondByMonotonicMillis
                    )
                )
            }
            core = current
            return result
        } catch let error as MailboxError {
            if error.reason == .windowClosed {
                closeWindowState()
                try? clearSharedFiles()
            } else {
                core = current
                // A live pending handle is a refusal, not a malformed document:
                // the competing request is kept for the next poll.
                if error.reason != .requestPending {
                    try? storage.withExclusiveLock { try storage.removeRequest() }
                }
            }
            throw error
        } catch {
            core = current
            try? storage.withExclusiveLock { try storage.removeRequest() }
            throw error
        }
    }

    /// Seal and publish the response for exactly the pending request.
    ///
    /// Fails with `unavailable` when the window closed or the freshness lease
    /// elapsed, and with `malformed` when the handle does not match the current
    /// pending request (stale or duplicated reply).
    public func respond(to request: MailboxPendingRequest, payload: Data) throws {
        guard var current = core else { throw MailboxError.unavailable(.revoked) }
        do {
            try storage.withExclusiveLock { () throws -> Void in
                // Seal and publish under one lock with a freshly sampled clock,
                // so the lease decision and the write cannot disagree.
                let now = clock()
                guard !current.isExpired(at: now) else {
                    throw MailboxError.unavailable(.windowClosed)
                }
                let encoded = try current.sealResponse(
                    sessionId: request.sessionId,
                    requestId: request.requestId,
                    sequence: request.sequence,
                    payload: payload,
                    now: now
                )
                try storage.writeResponse(encoded)
            }
            core = current
        } catch let error as MailboxError {
            if error.reason == .windowClosed {
                closeWindowState()
                try? clearSharedFiles()
            } else {
                core = current
            }
            throw error
        } catch {
            core = current
            throw error
        }
    }

    /// Close the window: drop every key reference and remove the shared
    /// rendezvous, request and response documents.
    public func closeWindow() throws {
        closeWindowState()
        try clearSharedFiles()
    }

    private func closeWindowState() {
        core?.revoke()
        core = nil
        info = nil
    }

    private func clearSharedFiles() throws {
        try storage.withExclusiveLock {
            try storage.removeRequest()
            try storage.removeResponse()
            try storage.removeRendezvous()
        }
    }
}
