import Foundation

/// Public rendezvous document.
///
/// This is the only thing the owner ever writes in the clear, and it contains
/// exactly two pieces of public data: the hybrid post-quantum owner public key
/// (`XWingMLKEM768X25519`, 1216 bytes) and an unpredictable session id, plus the
/// window bounds. It never contains a payload, a contact reference, an identity,
/// a private key or the encapsulation secret. A 32-byte classical X25519 key is
/// rejected here by length before any cryptography runs.
public struct MailboxRendezvous: Equatable {
    public let version: Int
    public let sessionId: Data
    public let ownerPublicKey: Data
    public let createdAtEpochMillis: Int64
    public let deadlineEpochMillis: Int64
    public let windowMillis: Int64

    /// Owner-side construction. The deadline is derived, never supplied, and the
    /// window is hard-capped at `MailboxConstants.maxWindowMillis`.
    public init(
        sessionId: Data,
        ownerPublicKey: Data,
        createdAtEpochMillis: Int64,
        windowMillis: Int64
    ) throws {
        guard sessionId.count == MailboxConstants.sessionIdentifierBytes,
              ownerPublicKey.count == MailboxConstants.ownerPublicKeyBytes else {
            throw MailboxError.malformed(.badLength)
        }
        guard createdAtEpochMillis >= 0 else { throw MailboxError.malformed(.badNumber) }
        guard windowMillis >= 1, windowMillis <= MailboxConstants.maxWindowMillis else {
            throw MailboxError.malformed(.badNumber)
        }
        let (deadline, overflow) = createdAtEpochMillis.addingReportingOverflow(windowMillis)
        guard !overflow else { throw MailboxError.malformed(.badNumber) }
        try self.init(
            version: MailboxConstants.protocolVersion,
            sessionId: sessionId,
            ownerPublicKey: ownerPublicKey,
            createdAtEpochMillis: createdAtEpochMillis,
            deadlineEpochMillis: deadline,
            windowMillis: windowMillis
        )
    }

    /// Storage-side construction; every field is validated, including the
    /// invariant that the deadline is exactly creation plus the window.
    init(
        version: Int,
        sessionId: Data,
        ownerPublicKey: Data,
        createdAtEpochMillis: Int64,
        deadlineEpochMillis: Int64,
        windowMillis: Int64
    ) throws {
        guard version == MailboxConstants.protocolVersion else {
            throw MailboxError.malformed(.badVersion)
        }
        guard sessionId.count == MailboxConstants.sessionIdentifierBytes,
              ownerPublicKey.count == MailboxConstants.ownerPublicKeyBytes else {
            throw MailboxError.malformed(.badLength)
        }
        guard windowMillis >= 1, windowMillis <= MailboxConstants.maxWindowMillis else {
            throw MailboxError.malformed(.badNumber)
        }
        guard createdAtEpochMillis >= 0 else { throw MailboxError.malformed(.badNumber) }
        let (expectedDeadline, overflow) = createdAtEpochMillis.addingReportingOverflow(windowMillis)
        guard !overflow, deadlineEpochMillis == expectedDeadline else {
            throw MailboxError.malformed(.badFields)
        }
        self.version = version
        self.sessionId = sessionId
        self.ownerPublicKey = ownerPublicKey
        self.createdAtEpochMillis = createdAtEpochMillis
        self.deadlineEpochMillis = deadlineEpochMillis
        self.windowMillis = windowMillis
    }

    public func encoded() throws -> Data {
        let object: [String: Any] = [
            "v": version,
            "s": sessionId.base64EncodedString(),
            "o": ownerPublicKey.base64EncodedString(),
            "a": NSNumber(value: createdAtEpochMillis),
            "d": NSNumber(value: deadlineEpochMillis),
            "w": NSNumber(value: windowMillis)
        ]
        let data: Data
        do {
            data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        } catch {
            throw MailboxError.malformed(.badJSON)
        }
        guard data.count <= MailboxConstants.maxRendezvousBytes else {
            throw MailboxError.malformed(.tooLarge)
        }
        return data
    }

    public static func decode(_ data: Data) throws -> MailboxRendezvous {
        let dictionary = try StrictJSON.dictionary(data, maxBytes: MailboxConstants.maxRendezvousBytes)
        guard Set(dictionary.keys) == ["v", "s", "o", "a", "d", "w"] else {
            throw MailboxError.malformed(.badFields)
        }
        let version = try StrictJSON.integer(
            dictionary["v"],
            minimum: 0,
            maximum: 1_000_000
        )
        guard version == Int64(MailboxConstants.protocolVersion) else {
            throw MailboxError.malformed(.badVersion)
        }
        let sessionId = try StrictJSON.base64(
            dictionary["s"],
            exactBytes: MailboxConstants.sessionIdentifierBytes
        )
        let ownerPublicKey = try StrictJSON.base64(
            dictionary["o"],
            exactBytes: MailboxConstants.ownerPublicKeyBytes
        )
        let createdAt = try StrictJSON.integer(
            dictionary["a"],
            minimum: 0,
            maximum: Int64.max / 4
        )
        let deadline = try StrictJSON.integer(
            dictionary["d"],
            minimum: 0,
            maximum: Int64.max / 4
        )
        let window = try StrictJSON.integer(
            dictionary["w"],
            minimum: 1,
            maximum: MailboxConstants.maxWindowMillis
        )
        return try MailboxRendezvous(
            version: Int(version),
            sessionId: sessionId,
            ownerPublicKey: ownerPublicKey,
            createdAtEpochMillis: createdAt,
            deadlineEpochMillis: deadline,
            windowMillis: window
        )
    }
}
