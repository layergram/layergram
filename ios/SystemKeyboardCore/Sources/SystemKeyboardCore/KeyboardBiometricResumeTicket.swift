import Foundation
import CryptoKit

/// Policy independent of Keychain/UI. The biometric read only permits trying
/// to construct a fresh native session; custody and editor checks remain live.
/// Version 1 had a ten-minute absolute deadline. Version 2 keeps the sealed
/// capability until the app revokes custody or the biometric set changes:
/// the actual editor session still expires after its configured idle interval.
public struct KeyboardBiometricResumeTicket {
    /// Legacy v1 bound; do not silently make already-issued tickets permanent.
    public static let lifetimeMillis: Int64 = 600_000
    public static let revocableDeadlineMillis: Int64 = Int64.max
    public let key: Data
    public let epoch: Data
    public let configuration: [String: Any]

    /// Construct the sealed-ticket payload from one clock reading. Reading the
    /// clock separately for `created` and `expires` can exceed the maximum
    /// lifetime by milliseconds and make every new ticket fail validation.
    public static func encode(document: String, key: Data,
                              configuration: [String: Any], createdAt: Int64) -> Data? {
        guard !document.isEmpty, key.count == 32, createdAt >= 0 else { return nil }
        let row: [String: Any] = [
            "v": 2, "document": document, "key": key.base64EncodedString(),
            "configuration": configuration, "created": createdAt,
            "expires": revocableDeadlineMillis
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: row),
              Self(data: data, document: document, now: createdAt) != nil else { return nil }
        return data
    }

    /// Editor rebinding is permitted only by the caller after a fresh Face ID
    /// read of the sealed Keychain item. It never revives the previous draft,
    /// contact selection or runtime; native custody admission still runs.
    public init?(data: Data, document: String, now: Int64,
                 allowBiometricEditorRebind: Bool = false) {
        guard !document.isEmpty, data.count <= 65_536,
              let row = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              row.count == 6, let version = row["v"] as? Int,
              version == 1 || version == 2,
              let originalDocument = row["document"] as? String,
              !originalDocument.isEmpty,
              (originalDocument == document || allowBiometricEditorRebind),
              let created = row["created"] as? Int64,
              let expires = row["expires"] as? Int64,
              created >= 0, now >= 0, now < expires,
              (version == 1
                ? created <= Int64.max - Self.lifetimeMillis &&
                    created <= now && expires > created &&
                    expires <= created + Self.lifetimeMillis
                : expires == Self.revocableDeadlineMillis),
              let keyText = row["key"] as? String,
              let key = Data(base64Encoded: keyText), key.count == 32,
              let config = row["configuration"] as? [String: Any],
              config["biometricResume"] as? Bool == true,
              let epochText = config["epoch"] as? String,
              let epoch = Data(base64Encoded: epochText), epoch.count == 16
        else { return nil }
        self.key = key
        self.epoch = epoch
        self.configuration = config
    }
}

/// Non-secret admission hint for a fresh keyboard extension process. The
/// actual custody key remains in the biometric Keychain item; this hash only
/// decides whether showing a Face ID prompt is appropriate for this editor.
public struct KeyboardBiometricResumeHint {
    public let expiresAt: Int64

    public enum Admission: Equatable {
        case matched(Int64)
        case differentEditor(Int64)
        case invalid
    }

    public static func encode(ticketData: Data) -> Data? {
        guard let row = try? JSONSerialization.jsonObject(with: ticketData) as? [String: Any],
              let version = row["v"] as? Int,
              let document = row["document"] as? String,
              let created = row["created"] as? Int64,
              let expires = row["expires"] as? Int64,
              KeyboardBiometricResumeTicket(data: ticketData, document: document,
                                            now: created) != nil else { return nil }
        let hash = Data(SHA256.hash(data: Data(document.utf8))).base64EncodedString()
        return try? JSONSerialization.data(withJSONObject: [
            "v": version, "documentHash": hash, "expires": expires
        ])
    }

    public static func admission(data: Data, document: String, now: Int64) -> Admission {
        guard !document.isEmpty, data.count <= 256,
              let row = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              row.count == 3, let version = row["v"] as? Int,
              version == 1 || version == 2,
              let hash = row["documentHash"] as? String,
              Data(base64Encoded: hash)?.count == 32,
              let expires = row["expires"] as? Int64,
              now >= 0, now < expires,
              (version == 1 || expires == KeyboardBiometricResumeTicket.revocableDeadlineMillis)
        else { return .invalid }
        guard hash == Data(SHA256.hash(data: Data(document.utf8))).base64EncodedString()
        else { return .differentEditor(expires) }
        return .matched(expires)
    }

    public init?(data: Data, document: String, now: Int64) {
        guard case .matched(let expires) = Self.admission(
            data: data, document: document, now: now) else { return nil }
        expiresAt = expires
    }
}

/// A touch can be consumed by the biometric prompt only for the same visible
/// editor, before expiry, with Full Access and capture protection intact. A
/// failed ordinary edit must not delete this still-valid recovery capability.
public enum KeyboardBiometricResumeGate {
    public enum ReconnectAction: Equatable {
        case keepRuntime
        case waitForAuthentication
        case expireShortcut
        case seekAppWindow
    }

    /// The sealed shortcut deadline is not the active session's idle deadline.
    /// Reconnect polling must neither close a runtime at ticket expiry nor
    /// attach an app window while a deliberate biometric read is pending.
    public static func reconnectAction(hasRuntime: Bool, authenticationPending: Bool,
                                       expiresAt: Int64?, now: Int64) -> ReconnectAction {
        if hasRuntime { return .keepRuntime }
        if authenticationPending { return .waitForAuthentication }
        if let expiresAt, now >= expiresAt { return .expireShortcut }
        return .seekAppWindow
    }

    /// Biometric reopening is independent of the optional screenshot setting.
    /// Only a sealed hint is retained here; it grants no live operation. When
    /// protection is enabled, its secure surface must still be available.
    public static func mayKeepSealedHint(protectionEnabled: Bool,
                                         secureHostReady: Bool,
                                         fullAccess: Bool, captured: Bool) -> Bool {
        fullAccess && !captured && (!protectionEnabled || secureHostReady)
    }

    /// A newly constructed keyboard can receive a memory warning before it
    /// has loaded the hint. Keeping the sealed Keychain item in this narrow
    /// state grants no use without a later deliberate biometric check.
    public static func mayDeferSealedTicketRevocationBeforeAppearance(
        hasRuntime: Bool, hasOwnerSession: Bool, hasAppeared: Bool,
        protectionEnabled: Bool, secureHostReady: Bool,
        fullAccess: Bool, captured: Bool) -> Bool {
        !hasRuntime && !hasOwnerSession && !hasAppeared &&
            mayKeepSealedHint(protectionEnabled: protectionEnabled,
                secureHostReady: secureHostReady, fullAccess: fullAccess, captured: captured)
    }

    public static func mayAttempt(available: Bool, expectedDocument: String?,
                                  expiresAt: Int64?, snapshot: KeyboardEditorSnapshot) -> Bool {
        guard available, let expectedDocument, !expectedDocument.isEmpty,
              let expiresAt, snapshot.monotonicMillis < expiresAt,
              snapshot.isViewVisible, snapshot.hasFullAccess, !snapshot.isCaptured,
              snapshot.documentIdentifier == expectedDocument else { return false }
        return true
    }
}
