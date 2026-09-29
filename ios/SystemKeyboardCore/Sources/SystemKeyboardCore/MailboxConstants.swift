import Foundation

/// Fixed sizes, file names and time bounds of the iOS system-keyboard mailbox.
///
/// Everything here is a hard bound: the mailbox never grows past these limits and
/// never extends the window. `maxWindowMillis` is the absolute ceiling for a
/// single, non-renewable opt-in window.
///
/// The wire protocol is version 2: the key agreement is Apple CryptoKit's built-in
/// hybrid post-quantum KEM `XWingMLKEM768X25519` (ML-KEM-768 + X25519), so the
/// persisted encrypted mailbox payloads keep the V3 post-quantum confidentiality
/// level. Version 1 (32-byte classical X25519) messages are rejected outright.
public enum MailboxConstants {
    /// Wire version of the encrypted transport. Bumped only with a format change.
    ///
    /// Version 2 is the hybrid post-quantum format; a document that carries the
    /// old version 1 value is rejected as `badVersion` before any key material is
    /// touched.
    public static let protocolVersion = 2

    /// Dedicated App Group of the Layergram app and keyboard extension.
    public static let appGroupIdentifier = "group.app.layergram.app.keyboard"

    /// Dedicated subdirectory inside the App Group container.
    public static let directoryName = "SystemKeyboardMailbox"

    public static let rendezvousFileName = "rendezvous.json"
    public static let requestFileName = "client.request"
    public static let responseFileName = "owner.response"
    public static let lockFileName = "mailbox.lock"

    public static let sessionIdentifierBytes = 16
    public static let requestIdentifierBytes = 16
    public static let nonceBytes = 12
    public static let authenticationTagBytes = 16
    public static let symmetricKeyBytes = 32

    /// Raw `XWingMLKEM768X25519.PublicKey` length. The rendezvous `o` field and
    /// owner public-key field must be exactly this long; any other length is
    /// rejected as a length error, which is also what rejects 32-byte classical
    /// X25519 documents.
    public static let ownerPublicKeyBytes = 1216
    /// Raw `KEM.EncapsulationResult.encapsulated` length, carried in the clear by
    /// the requesting client so the owner can decapsulate it.
    public static let clientEncapsulationBytes = 1120
    /// Length of the symmetric key a hybrid encapsulation/decapsulation yields.
    public static let kemSharedSecretBytes = 32

    /// Hard window ceiling: 20 seconds, never renewed.
    public static let maxWindowMillis: Int64 = 20_000
    /// A fresh operation response must be produced within 1 second.
    public static let maxLeaseMillis: Int64 = 1_000
    /// Client-side wait for a response is bounded by the same 1 second.
    public static let maxPendingTimeoutMillis: Int64 = 1_000
    public static let defaultPendingTimeoutMillis: Int64 = 900
    public static let lockTimeoutMillis: Int64 = 250
    /// Age after which leftover shared files are purged.
    public static let defaultStaleMillis: Int64 = 300_000

    /// Total serialized file bound (2 MiB).
    public static let maxEnvelopeBytes = 2 * 1024 * 1024
    /// Plaintext bound for one encrypted method-channel payload (1 MiB).
    public static let maxPlaintextBytes = 1024 * 1024
    /// Rendezvous document bound: the 1216-byte hybrid public key is base64 in
    /// here, so 4 KiB still leaves ample room for the other fields.
    public static let maxRendezvousBytes = 4096
    /// JSON-safe strictly increasing sequence ceiling.
    public static let maxSequence: UInt64 = 9_007_199_254_740_991
    /// Bounded replay memory inside one window.
    public static let maxTrackedRequestIdentifiers = 128
}

/// Runtime availability of the post-quantum key agreement.
///
/// The package still deploys to iOS 15 / macOS 11, but
/// `XWingMLKEM768X25519` only exists from iOS 26 / macOS 26. Hosts and the
/// keyboard extension gate the mailbox UI on `MailboxCryptoAvailability.isSupported`;
/// every transport entry point (`MailboxOwner.openWindow()`,
/// `MailboxClient.attach()`) additionally fails closed with `unavailable` when it
/// is false, so there is never a classical downgrade path. The constant itself is
/// evaluated with `#available` and therefore compiles and runs on every
/// deployment target.
public enum MailboxCryptoAvailability {
    /// True only on an OS that provides the hybrid post-quantum KEM.
    public static let isSupported: Bool = {
        #if compiler(>=6.2)
        if #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *) {
            return true
        }
        #endif
        return false
    }()
}
