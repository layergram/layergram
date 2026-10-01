import CryptoKit
import Foundation

/// Direction of a mailbox message. Request keys and response keys are derived
/// separately, and the direction string is also authenticated as AAD, so a
/// message sealed for one direction cannot be replayed in the other.
enum MailboxEnvelopeKind {
    case request
    case response

    var wireName: String {
        switch self {
        case .request: return "request"
        case .response: return "response"
        }
    }
}

/// AAD format: version, direction, session binding, request binding, sequence.
/// Every field is fixed-width or canonical, so the encoding is unambiguous.
enum MailboxAAD {
    static func make(
        kind: MailboxEnvelopeKind,
        version: Int,
        sessionId: Data,
        requestId: Data,
        sequence: UInt64
    ) -> Data {
        let text = "layergram.system-keyboard.mailbox"
            + "|v\(version)"
            + "|\(kind.wireName)"
            + "|\(sessionId.base64EncodedString())"
            + "|\(requestId.base64EncodedString())"
            + "|\(sequence)"
        return Data(text.utf8)
    }
}

/// Wire envelope (protocol version 2).
///
/// Requests carry the client's hybrid KEM encapsulation in the clear; responses
/// do not (the owner hybrid public key is pinned at window open by the
/// rendezvous). The encapsulation is public data by construction: only the owner
/// hybrid private key can decapsulate it into the session secret.
struct MailboxEnvelope: Equatable {
    let version: Int
    let sessionId: Data
    let requestId: Data
    let sequence: UInt64
    let clientEncapsulation: Data?
    let nonce: Data
    let ciphertext: Data

    func encoded() throws -> Data {
        var object: [String: Any] = [
            "v": version,
            "s": sessionId.base64EncodedString(),
            "r": requestId.base64EncodedString(),
            "q": NSNumber(value: sequence),
            "n": nonce.base64EncodedString(),
            "c": ciphertext.base64EncodedString()
        ]
        if let clientEncapsulation = clientEncapsulation {
            // The wire field name stays `k` for compatibility with the two
            // in-tree readers; its content is now the 1120-byte hybrid KEM
            // encapsulation, never a 32-byte classical public key.
            object["k"] = clientEncapsulation.base64EncodedString()
        }
        let data: Data
        do {
            data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        } catch {
            throw MailboxError.malformed(.badJSON)
        }
        guard data.count <= MailboxConstants.maxEnvelopeBytes else {
            throw MailboxError.malformed(.tooLarge)
        }
        return data
    }

    static func decode(_ data: Data, kind: MailboxEnvelopeKind) throws -> MailboxEnvelope {
        let dictionary = try StrictJSON.dictionary(data, maxBytes: MailboxConstants.maxEnvelopeBytes)
        let allowed: Set<String>
        switch kind {
        case .request: allowed = ["v", "s", "r", "q", "k", "n", "c"]
        case .response: allowed = ["v", "s", "r", "q", "n", "c"]
        }
        guard Set(dictionary.keys) == allowed else { throw MailboxError.malformed(.badFields) }

        let version = try StrictJSON.integer(
            dictionary["v"],
            minimum: 0,
            maximum: 1_000_000
        )
        guard version == Int64(MailboxConstants.protocolVersion) else {
            // Version 1 is the superseded classical X25519 format: it is not
            // decodable here at all, so a downgraded document never reaches the
            // key schedule.
            let reason: MailboxFailureReason = version < Int64(MailboxConstants.protocolVersion)
                ? .unsupportedVersion
                : .badVersion
            throw MailboxError.malformed(reason)
        }
        let sessionId = try StrictJSON.base64(
            dictionary["s"],
            exactBytes: MailboxConstants.sessionIdentifierBytes
        )
        let requestId = try StrictJSON.base64(
            dictionary["r"],
            exactBytes: MailboxConstants.requestIdentifierBytes
        )
        let sequence = try StrictJSON.unsignedInteger(
            dictionary["q"],
            minimum: 1,
            maximum: MailboxConstants.maxSequence
        )
        let clientEncapsulation: Data?
        switch kind {
        case .request:
            // Strict 1120 bytes: a 32-byte classical client key fails here.
            clientEncapsulation = try StrictJSON.base64(
                dictionary["k"],
                exactBytes: MailboxConstants.clientEncapsulationBytes
            )
        case .response:
            clientEncapsulation = nil
        }
        let nonce = try StrictJSON.base64(dictionary["n"], exactBytes: MailboxConstants.nonceBytes)
        let ciphertext = try StrictJSON.base64(
            dictionary["c"],
            minBytes: MailboxConstants.authenticationTagBytes,
            maxBytes: MailboxConstants.maxPlaintextBytes + MailboxConstants.authenticationTagBytes
        )

        return MailboxEnvelope(
            version: Int(version),
            sessionId: sessionId,
            requestId: requestId,
            sequence: sequence,
            clientEncapsulation: clientEncapsulation,
            nonce: nonce,
            ciphertext: ciphertext
        )
    }
}
