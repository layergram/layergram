import Foundation

/// The only failure information that crosses the public API.
///
/// Callers get a generic `unavailable` for admission, deadline, storage and
/// peer-state problems and a generic `malformed` for anything that fails
/// parsing, bounds or authentication. No identity, lock, key or reason detail is
/// exposed.
public enum MailboxErrorKind: String, Equatable {
    case unavailable
    case malformed
}

/// Internal, non-public diagnostic. Never logged, never surfaced to hosts.
enum MailboxFailureReason: String, Equatable {
    case unavailable
    case malformed
    /// The hybrid post-quantum KEM is not available on this OS, so the mailbox
    /// fails closed instead of downgrading to a classical key agreement.
    case cryptoUnavailable
    case noApplicationGroup
    case storageUnavailable
    case unsafePath
    case locked
    case windowClosed
    case windowOpen
    case responseTimeout
    case requestPending
    case noRendezvous
    case revoked
    case tooLarge
    case badJSON
    case badVersion
    /// A document used the superseded classical version 1 wire format.
    case unsupportedVersion
    case badFields
    case badNumber
    case badBase64
    case badLength
    case wrongSession
    case wrongClient
    case replay
    case requestMismatch
    case staleRequest
    case notPending
    case cryptoFailure
}

/// Generic, non-leaking mailbox error.
public struct MailboxError: Error, Equatable, CustomStringConvertible {
    public let kind: MailboxErrorKind
    let reason: MailboxFailureReason

    init(kind: MailboxErrorKind, reason: MailboxFailureReason) {
        self.kind = kind
        self.reason = reason
    }

    /// Equality is deliberately kind-only so callers can compare generically.
    public static func == (lhs: MailboxError, rhs: MailboxError) -> Bool {
        lhs.kind == rhs.kind
    }

    public var description: String { kind.rawValue }
}

extension MailboxError {
    static func unavailable(_ reason: MailboxFailureReason = .unavailable) -> MailboxError {
        MailboxError(kind: .unavailable, reason: reason)
    }

    static func malformed(_ reason: MailboxFailureReason = .malformed) -> MailboxError {
        MailboxError(kind: .malformed, reason: reason)
    }
}
