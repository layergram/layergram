import CoreFoundation
import Foundation

/// Pure, UI-free policy for the iOS keyboard extension.
///
/// The extension owns no cryptography, no identity and no plaintext of the host
/// application. Everything it is allowed to do is decided here, from values it
/// already has: the live editor nonce it generated, the opaque
/// `textDocumentProxy.documentIdentifier` string, the process screen-capture
/// flag, the keyboard `hasFullAccess` flag, the monotonic clock and the
/// `processingMillis` / `leaseMillis` grant the app owner returned.
///
/// The type contains no UIKit import and no reference to `UIInputViewController`,
/// so it compiles and is testable on macOS. The view controller owns all UI and
/// asks this policy before every sensitive read, every request and the single
/// `insertText` call.
///
/// Two independent deadlines are tracked and never confused:
/// * the **owner window** (`windowDeadlineMonotonicMillis`) is the fixed, absolute
///   deadline of the app-owned mailbox window. It never renews.
/// * the **freshness lease** (`freshLeaseDeadlineMonotonicMillis`) is the short
///   (<= 1 s) proof that the owner is still answering. It is refreshed by every
///   accepted grant, including a fresh heartbeat, and never extends the window.
///
/// What it deliberately never does:
/// * never reads surrounding text, document context or the selected text;
/// * never accepts a non-integer, boolean, fractional or out-of-range grant;
/// * never derives freshness from response arrival time;
/// * never revives a value (draft, preview, contact, carrier) for a stale
///   editor generation, a closed window or a lapsed freshness lease;
/// * never lets a payload override `operation`, `editorNonce` or `requestId`.

// MARK: - Channel status

/// Status strings of the native coordination contract v1.
///
/// Only `ok` carries data. Every other value is a closed failure: the extension
/// clears sensitive UI and never retries the old request.
public enum KeyboardChannelStatus {
    public static let ok = "ok"
    public static let unavailable = "unavailable"
    public static let busy = "busy"
    public static let noMessage = "noMessage"
    public static let invalidSelection = "invalidSelection"
    public static let oversize = "oversize"
    public static let unsupportedExport = "unsupportedExport"
    public static let invalidRequest = "invalidRequest"
    public static let noPendingExport = "noPendingExport"
    public static let openAppRequired = "openAppRequired"
    public static let duplicateRequest = "duplicateRequest"
    public static let backendError = "backendError"

    /// True when the status string is one this contract defines.
    public static func isKnown(_ status: String) -> Bool {
        switch status {
        case ok, unavailable, busy, noMessage, invalidSelection, oversize,
             unsupportedExport, invalidRequest, noPendingExport,
             openAppRequired, duplicateRequest, backendError:
            return true
        default:
            return false
        }
    }
}

// MARK: - Bounds

/// Hard bounds shared by the native UI and the app-owner channel contract.
public enum KeyboardSurfaceBounds {
    /// Opaque identifiers (`editorNonce`, `requestId`, `pendingId`).
    public static let maxIdentifierUTF16 = 128
    /// Display names and fingerprints.
    public static let maxLabelUTF16 = 128
    /// Outbound carrier handed to `textDocumentProxy.insertText`.
    public static let maxOutboundCarrierUTF16 = 4_000
    public static let maxAutonomousOutboundCarrierUTF16 = 32_768
    /// Inbound carrier read from an explicit user paste.
    public static let maxInboundCarrierUTF16 = 262_144
    /// Outbound draft accepted by `prepare`.
    public static let maxDraftUTF16 = 4_000
    /// `processingMillis` ceiling reported by the owner.
    public static let maxProcessingMillis: Int64 = 30_000
    /// `leaseMillis` ceiling reported by the owner.
    public static let maxLeaseMillis: Int64 = 1_000
    /// The bootstrap wait before the first accepted `begin` is abandoned.
    public static let maxBootstrapMillis: Int64 = 1_000
    /// A headless Flutter engine needs a bounded cold-start window after the
    /// native grant. Custody and the editor are still checked on every sample.
    public static let maxAutonomousBootstrapMillis: Int64 = 10_000
}

// MARK: - Failures

/// Closed failure taxonomy of the native policy. No case carries a payload, so
/// no owner detail can leak into a label or an accessibility value.
public enum KeyboardPolicyError: Error, Equatable, CustomStringConvertible {
    /// The extension is not the active input view, a different editor is bound,
    /// the session was revoked or a deadline already passed.
    case unavailable
    /// The owner reply or the local input is malformed, mismatched or oversized.
    case malformed
    /// Full Access is missing, the draft is oversized or the payload is illegal.
    case invalid

    public var description: String {
        switch self {
        case .unavailable: return "unavailable"
        case .malformed: return "malformed"
        case .invalid: return "invalid"
        }
    }
}

// MARK: - Operation

/// The bounded operation set of the coordination contract.
public enum KeyboardOperation: String, Equatable {
    case begin
    case heartbeat
    case contacts
    case select
    case prepare
    case authorize
    case ack
    case decode
    case end

    /// Only a `heartbeat` may run while another operation is pending, and only
    /// because it is issued when nothing is pending at all.
    public var isHeartbeat: Bool { self == .heartbeat }
}

// MARK: - Typed request values

/// The closed set of JSON value shapes a request payload may carry.
///
/// Bounded request fields are typed so a boolean can never be encoded as the
/// string `"true"`: the Dart owner validates `select.confirm` and
/// `ack.commitText` with `is bool` and rejects anything else.
public enum KeyboardRequestValue: Equatable {
    case string(String)
    case bool(Bool)

    /// The exact `JSONSerialization` value this case encodes to.
    public var jsonObject: Any {
        switch self {
        case .string(let value): return value
        case .bool(let value): return value
        }
    }
}

// MARK: - Grant

/// One validated `ok` reply: the exact integer grant plus the absolute local
/// deadline derived from the request start.
public struct KeyboardGrant: Equatable {
    public let operation: KeyboardOperation
    public let processingMillis: Int64
    public let leaseMillis: Int64
    /// `requestStart + processingMillis + leaseMillis`, capped by the client
    /// window deadline. Never derived from the response arrival time.
    public let deadlineMonotonicMillis: Int64
    /// Whole validated `data` object. The policy only returns typed, bounded
    /// projections of it; callers never decode the raw map themselves.
    let data: [String: Any]

    public static func == (lhs: KeyboardGrant, rhs: KeyboardGrant) -> Bool {
        lhs.operation == rhs.operation &&
            lhs.processingMillis == rhs.processingMillis &&
            lhs.leaseMillis == rhs.leaseMillis &&
            lhs.deadlineMonotonicMillis == rhs.deadlineMonotonicMillis &&
            NSDictionary(dictionary: lhs.data).isEqual(to: rhs.data)
    }

    public func isExpired(at nowMillis: Int64) -> Bool {
        // Exclusive: a reading exactly at the deadline is already expired.
        nowMillis >= deadlineMonotonicMillis
    }
}

// MARK: - Owner replies

/// Bounded view of one decrypted app-owner reply.
public enum KeyboardResponse: Equatable {
    /// `status == "ok"` with an exact integer grant.
    case granted(KeyboardGrant)
    /// Any closed failure status other than `ok`.
    case failed(String)

    public var isGranted: Bool {
        if case .granted = self { return true }
        return false
    }

    public var failureStatus: String? {
        if case .failed(let status) = self { return status }
        return nil
    }
}

// MARK: - Editor snapshot

/// The minimal, non-secret facts the policy re-checks before every sensitive
/// step. The view controller builds it from `viewIfLoaded?.window`,
/// `hasFullAccess`, the window screen capture flag and
/// `textDocumentProxy.documentIdentifier`.
public struct KeyboardEditorSnapshot: Equatable {
    /// The input view is attached and visible right now.
    public let isViewVisible: Bool
    /// `UIInputViewController.hasFullAccess`: required before any group read.
    public let hasFullAccess: Bool
    /// The screen is being captured or mirrored right now.
    public let isCaptured: Bool
    /// Opaque editor binding. `nil` only when the proxy exposes none.
    public let documentIdentifier: String?
    /// Monotonic reading sampled with the rest of the snapshot.
    public let monotonicMillis: Int64
    /// Test/integration seam. Production always passes the live values.
    public init(
        isViewVisible: Bool,
        hasFullAccess: Bool,
        isCaptured: Bool,
        documentIdentifier: String?,
        monotonicMillis: Int64
    ) {
        self.isViewVisible = isViewVisible
        self.hasFullAccess = hasFullAccess
        self.isCaptured = isCaptured
        self.documentIdentifier = documentIdentifier
        self.monotonicMillis = monotonicMillis
    }
}

// MARK: - Typed, bounded projections

/// One selectable saved contact.
public struct KeyboardContact: Equatable {
    public let id: String
    public let name: String
    public let fingerprint: String
    public let securityPhase: KeyboardSecurityPhase?

    public init(id: String, name: String, fingerprint: String,
                securityPhase: KeyboardSecurityPhase? = nil) {
        self.id = id
        self.name = name
        self.fingerprint = fingerprint
        self.securityPhase = securityPhase
    }
}

/// A display-only V3 status, never an authorization to send.
public enum KeyboardSecurityPhase: String {
    case setupRequired, setupPending, normalActive, maximumActive, recoveryRequired
    case maximumSetupRequired, maximumSetupPending, maximumRecoveryRequired
}

/// One explicit insertion authorization as projected for callers.
public struct KeyboardAuthorization: Equatable {
    public let carrier: String
    public let deadlineMonotonicMillis: Int64
}

/// One decoded inbound preview. Preview-only: it is never inserted into the host
/// and never copied to the clipboard.
public struct KeyboardPreview: Equatable {
    public let contactId: String
    public let contactName: String
    public let fingerprint: String
    public let text: String
}

// MARK: - Insertion permit

/// Proof that the single `insertText` call is still allowed.
///
/// The value exists only between `insertionPermit` and the view controller's
/// immediate use of `carrier`. `insertText` itself returns `Void`, so this
/// permit promises "the API may be called now", never "the host accepted it".
/// The permit is one-use: producing it consumes the stored authorization, so it
/// can never be replayed or re-inserted.
public struct KeyboardInsertionPermit: Equatable {
    public let carrier: String
    /// The `prepare` pending id this carrier belongs to, for the follow-up `ack`.
    public let pendingId: String
    /// The original `authorize` deadline. A later heartbeat refreshes the
    /// freshness lease but can never extend this value.
    public let authorizeDeadlineMonotonicMillis: Int64
}

// MARK: - Listener

/// Receives typed, bounded projections. Implemented by the view controller.
public protocol KeyboardPolicyListener: AnyObject {
    /// The session went live. `begin.data.scramble` is a neutral display
    /// capability: `true` only permits local key shuffling.
    func keyboardPolicyReady(scramble: Bool)
    /// A grant or a closed failure for `operation`.
    func keyboardPolicyResponse(_ response: KeyboardResponse, operation: KeyboardOperation)
    /// Sensitive UI must be cleared now (deadline, capture, host change, end).
    func keyboardPolicyCleared()
}

// MARK: - Policy

/// Stateful, single-editor policy. One instance belongs to one
/// `KeyboardViewController`.
public final class KeyboardEditorPolicy {
    /// Whole client window ceiling when the owner reports no shorter window.
    public static let clientWindowMillis: Int64 = 20_000

    private let now: () -> Int64
    public weak var listener: KeyboardPolicyListener?

    // Editor binding.
    private var editorNonce: String?
    private var documentIdentifier: String?
    private var generation: Int64 = 0
    private var sessionActive = false
    private var autonomousMode = false
    private var outboundCarrierLimit: Int {
        autonomousMode ? KeyboardSurfaceBounds.maxAutonomousOutboundCarrierUTF16 : KeyboardSurfaceBounds.maxOutboundCarrierUTF16
    }
    private var autonomousAuthorization: ((KeyboardEditorSnapshot) -> Int64?)?
    /// Fixed, absolute deadline of the app-owned window. Never renewed.
    private var windowDeadlineMonotonicMillis: Int64 = 0
    /// Short freshness proof. Refreshed by every accepted grant, including a
    /// fresh heartbeat; never extends the window.
    private var freshLeaseDeadlineMonotonicMillis: Int64 = 0
    /// Bounded wait for the first accepted `begin`.
    private var bootstrapDeadlineMonotonicMillis: Int64 = 0
    /// Set only once an `ok` `begin` reply has been accepted.
    private var beginAccepted = false

    /// Last accepted non-heartbeat operation projection. A heartbeat never
    /// replaces it, so selection and preview survive a refresh.
    private var grant: KeyboardGrant?
    private var pending: PendingOperation?
    private var selectedContact: KeyboardContact?
    private var lastPreparedPendingId: String?
    private var lastAuthorizedPendingId: String?
    private var authorized: AuthorizedInsertion?
    private var decodedPreview: KeyboardPreview?

    private struct PendingOperation {
        let requestId: String
        let operation: KeyboardOperation
        let startedAtMonotonicMillis: Int64
        /// Opaque editor binding captured when the request was issued.
        let documentIdentifier: String?
        /// Editor generation captured when the request was issued.
        let generation: Int64
        /// The exact validated payload the request was sealed with.
        let payload: [String: KeyboardRequestValue]
    }

    /// One-use result of an accepted `authorize`, bound to the editor it belongs
    /// to and to the recipient that was confirmed at that moment.
    private struct AuthorizedInsertion {
        let carrier: String
        let deadlineMonotonicMillis: Int64
        let pendingId: String
        let recipientId: String
        let generation: Int64
        let documentIdentifier: String?
    }

    public init(now: @escaping () -> Int64 = { MailboxClock.system().monotonicMillis }) {
        self.now = now
    }

    // MARK: admission

    /// Full admission for a request or a sensitive local read: the view is
    /// visible, Full Access is granted, the screen is not captured, the document
    /// binding is unchanged and the owner window has not passed. It does not
    /// require a stored grant or a freshness lease, so it is the gate for the
    /// bounded `begin` bootstrap only.
    public func revalidate(_ snapshot: KeyboardEditorSnapshot) -> Bool {
        guard snapshot.isViewVisible, snapshot.hasFullAccess, !snapshot.isCaptured else {
            return false
        }
        guard sessionActive else { return false }
        guard snapshot.documentIdentifier == self.documentIdentifier else { return false }
        if autonomousMode {
            guard let deadline = autonomousAuthorization?(snapshot), deadline > snapshot.monotonicMillis,
                  deadline <= KeyboardIdlePolicy.maxSafeMonotonicMillis else {
                clearSensitive(); return false
            }
            windowDeadlineMonotonicMillis = deadline
            // Native custody and live inactivity are the liveness authority.
            // This refresh never changes the native inactivity deadline itself.
            freshLeaseDeadlineMonotonicMillis = min(deadline, snapshot.monotonicMillis + 1_000)
        }
        return snapshot.monotonicMillis < windowDeadlineMonotonicMillis
    }

    /// True as soon as the host editor binding no longer matches the bound one.
    /// `nil` on both sides counts as unchanged: the opaque identifier is only
    /// ever compared, never read or logged.
    public func documentChanged(_ snapshot: KeyboardEditorSnapshot) -> Bool {
        guard sessionActive else { return true }
        return snapshot.documentIdentifier != documentIdentifier
    }

    /// True while the short freshness lease is live. `false` before the first
    /// accepted `begin`, so no sensitive work can happen during bootstrap.
    public func hasLiveLease(at monotonicMillis: Int64) -> Bool {
        guard sessionActive, beginAccepted else { return false }
        return monotonicMillis < freshLeaseDeadlineMonotonicMillis
    }

    /// The gate for **every** local draft/edit/preview/contact read and every
    /// request: full admission of the bound editor **plus** a live freshness
    /// lease. The fixed owner window alone is never enough, so the local draft,
    /// preview and selection clear within the <= 1 s lease when the owner stops
    /// answering.
    public func liveControl(_ snapshot: KeyboardEditorSnapshot) -> Bool {
        guard revalidate(snapshot), beginAccepted else { return false }
        return snapshot.monotonicMillis < freshLeaseDeadlineMonotonicMillis
    }

    /// The gate immediately before the single `insertText` call: live control,
    /// the one-use authorization still bound to this generation, document and
    /// confirmed recipient, and the original `authorize` deadline not passed.
    public func isAuthorizationLive(_ snapshot: KeyboardEditorSnapshot) -> Bool {
        guard liveControl(snapshot), let authorized else { return false }
        return authorizationMatches(authorized, snapshot: snapshot)
    }

    private func authorizationMatches(
        _ authorized: AuthorizedInsertion,
        snapshot: KeyboardEditorSnapshot
    ) -> Bool {
        guard authorized.generation == generation,
              authorized.documentIdentifier == documentIdentifier,
              snapshot.documentIdentifier == documentIdentifier,
              authorized.deadlineMonotonicMillis > snapshot.monotonicMillis,
              let recipientId = selectedContact?.id,
              recipientId == authorized.recipientId else { return false }
        return true
    }

    /// Number of samples that invalidated the session. Tests assert this grows
    /// when a late callback arrives after a host change.
    public private(set) var revision: Int64 = 0

    // MARK: lifecycle

    /// Bind a fresh editor. The caller must already have checked Full Access;
    /// this creates a new nonce and a new editor generation and invalidates
    /// anything left from the previous editor. It does not open or renew the
    /// app-owner window.
    @discardableResult
    public func begin(
        documentIdentifier: String?,
        windowDeadlineMonotonicMillis: Int64,
        bootstrapMillis: Int64 = KeyboardSurfaceBounds.maxBootstrapMillis
    ) -> Bool {
        clearSensitive(notify: false)
        autonomousMode = false
        generation += 1
        let nowMillis = now()
        let (bootstrapDeadline, overflow) = nowMillis.addingReportingOverflow(bootstrapMillis)
        guard nowMillis >= 0, bootstrapMillis > 0,
              bootstrapMillis <= KeyboardSurfaceBounds.maxAutonomousBootstrapMillis,
              !overflow, windowDeadlineMonotonicMillis > nowMillis else {
            sessionActive = false
            return false
        }
        editorNonce = UUID().uuidString
        self.documentIdentifier = documentIdentifier
        self.windowDeadlineMonotonicMillis = windowDeadlineMonotonicMillis
        bootstrapDeadlineMonotonicMillis = min(
            windowDeadlineMonotonicMillis,
            bootstrapDeadline
        )
        beginAccepted = false
        sessionActive = true
        return true
    }

    /// Bind only after a fresh native grant has started its headless runtime.
    /// The callback must validate custody, visibility, capture and inactivity on
    /// every call. It returns that native session's deadline and never renews it.
    @discardableResult
    public func beginAutonomous(snapshot: KeyboardEditorSnapshot, editorNonce: String,
                                authorization: @escaping (KeyboardEditorSnapshot) -> Int64?) -> Bool {
        guard !editorNonce.isEmpty, editorNonce.utf16.count <= 128,
              let deadline = authorization(snapshot), deadline > snapshot.monotonicMillis,
              begin(documentIdentifier: snapshot.documentIdentifier,
                    windowDeadlineMonotonicMillis: deadline,
                    bootstrapMillis: KeyboardSurfaceBounds.maxAutonomousBootstrapMillis) else { return false }
        self.editorNonce = editorNonce
        autonomousMode = true
        autonomousAuthorization = authorization
        return revalidate(snapshot)
    }

    /// The live editor nonce, for callers that must build an `end` request.
    public var currentEditorNonce: String? { editorNonce }

    /// True once an `ok` `begin` reply has been accepted for this editor.
    public var isBeginAccepted: Bool { beginAccepted }

    /// True when no `begin` has been accepted and the bounded bootstrap wait has
    /// already elapsed. The caller must clear all sensitive UI and drop the
    /// transport.
    public var isBootstrapExpired: Bool {
        guard sessionActive, !beginAccepted else { return false }
        return now() >= bootstrapDeadlineMonotonicMillis
    }

    /// A well-formed bounded request id for the next operation.
    public static func newRequestId() -> String { UUID().uuidString }

    /// True while a request is still waiting for its matching reply.
    public var isAwaitingResponse: Bool { pending != nil }

    // MARK: requests

    /// Seal the `begin` request and record its exact start, generation, document
    /// and operation, so the matching reply can be accepted and correlated.
    /// Allowed without Full Access so the missing-Full-Access state can be
    /// explained, but it still needs a bound editor and a live window.
    public func beginRequestData() throws -> Data {
        guard sessionActive, let nonce = editorNonce, !beginAccepted else {
            throw KeyboardPolicyError.unavailable
        }
        guard !isAwaitingResponse else { throw KeyboardPolicyError.unavailable }
        let nowMillis = now()
        guard nowMillis < windowDeadlineMonotonicMillis else {
            clearSensitive()
            throw KeyboardPolicyError.unavailable
        }
        let requestId = Self.newRequestId()
        let encoded = try Self.encode(.begin, editorNonce: nonce, requestId: requestId)
        pending = PendingOperation(
            requestId: requestId,
            operation: .begin,
            startedAtMonotonicMillis: nowMillis,
            documentIdentifier: documentIdentifier,
            generation: generation,
            payload: [:]
        )
        return encoded
    }

    /// Seal one operation request. Fails closed unless live control holds and no
    /// other request is outstanding. A heartbeat is only issued while nothing is
    /// pending; it refreshes freshness but never renews the window or the lease,
    /// and it never extends an existing one-use `authorize` permit.
    public func requestData(
        _ operation: KeyboardOperation,
        payload: [String: KeyboardRequestValue] = [:],
        snapshot: KeyboardEditorSnapshot
    ) throws -> Data {
        guard operation != .begin, operation != .end else {
            throw KeyboardPolicyError.invalid
        }
        guard liveControl(snapshot), !isAwaitingResponse else {
            clearSensitive()
            throw KeyboardPolicyError.unavailable
        }
        try Self.validatePayload(operation, payload)
        if operation == .prepare, selectedContact == nil {
            throw KeyboardPolicyError.invalid
        }
        if operation == .authorize {
            guard let requested = Self.stringValue(payload, "pendingId"),
                  requested == lastPreparedPendingId else {
                throw KeyboardPolicyError.invalid
            }
        }
        if operation == .ack {
            guard let requested = Self.stringValue(payload, "pendingId"),
                  requested == lastAuthorizedPendingId else {
                throw KeyboardPolicyError.invalid
            }
        }
        if operation == .decode {
            // An explicit decode can never inherit a previously confirmed
            // recipient.
            selectedContact = nil
        }
        guard let nonce = editorNonce else { throw KeyboardPolicyError.unavailable }
        let requestId = Self.newRequestId()
        let encoded = try Self.encode(
            operation,
            editorNonce: nonce,
            requestId: requestId,
            payload: payload
        )
        pending = PendingOperation(
            requestId: requestId,
            operation: operation,
            startedAtMonotonicMillis: snapshot.monotonicMillis,
            documentIdentifier: snapshot.documentIdentifier,
            generation: generation,
            payload: payload
        )
        return encoded
    }

    /// Seal `end` for the current editor. Never required to have a live grant:
    /// an editor must always be able to tear itself down. It can never close a
    /// newer editor, because the app owner compares the nonce.
    public func endRequestData(editorNonce: String) throws -> Data {
        guard editorNonce.utf16.count <= KeyboardSurfaceBounds.maxIdentifierUTF16,
              !editorNonce.isEmpty else {
            throw KeyboardPolicyError.invalid
        }
        return try Self.encode(.end, editorNonce: editorNonce, requestId: Self.newRequestId())
    }

    // MARK: replies

    /// Consume one reply for the outstanding request and turn it into a typed
    /// projection.
    ///
    /// Before applying **any** data it verifies the actual current snapshot: the
    /// view is visible, Full Access is granted, the screen is not captured, the
    /// document identifier is exactly the bound one and the pending request's
    /// captured generation is still current. It fails closed for a
    /// heartbeat-shaped reply whose `processingMillis` is not exactly zero, for
    /// any grant that would already be expired at the current reading, and for a
    /// deadline that overflows.
    @discardableResult
    public func acceptResponse(
        _ data: Data,
        snapshot: KeyboardEditorSnapshot
    ) -> KeyboardResponse? {
        if autonomousMode && !revalidate(snapshot) { return nil }
        guard sessionActive,
              let pending,
              pending.generation == generation,
              pending.documentIdentifier == documentIdentifier,
              snapshot.isViewVisible,
              snapshot.hasFullAccess,
              !snapshot.isCaptured,
              snapshot.documentIdentifier == documentIdentifier,
              snapshot.monotonicMillis >= pending.startedAtMonotonicMillis,
              snapshot.monotonicMillis < windowDeadlineMonotonicMillis,
              (pending.operation == .begin
                ? snapshot.monotonicMillis < bootstrapDeadlineMonotonicMillis
                : liveControl(snapshot)),
              let response = Self.decodeResponse(data, operation: pending.operation) else {
            clearSensitive()
            return nil
        }
        self.pending = nil
        switch response {
        case .failed:
            grant = nil
            selectedContact = nil
            authorized = nil
            decodedPreview = nil
            lastPreparedPendingId = nil
            lastAuthorizedPendingId = nil
            freshLeaseDeadlineMonotonicMillis = 0
            listener?.keyboardPolicyResponse(response, operation: pending.operation)
            return response
        case .granted(let rawGrant):
            let responseStart = autonomousMode ? snapshot.monotonicMillis : pending.startedAtMonotonicMillis
            guard let computedDeadline = Self.deadline(
                startedAtMonotonicMillis: responseStart,
                processingMillis: rawGrant.processingMillis,
                leaseMillis: rawGrant.leaseMillis,
                windowDeadlineMonotonicMillis: windowDeadlineMonotonicMillis
            ), computedDeadline > snapshot.monotonicMillis else {
                // A grant that cannot reach the future is never stored: this
                // editor is already past its lease or its window.
                clearSensitive()
                return nil
            }
            // Transport replies have a one-second budget. A processing-time
            // field must never widen the proof of owner liveness beyond it.
            let (transportDeadline, overflow) = responseStart
                .addingReportingOverflow(KeyboardSurfaceBounds.maxLeaseMillis)
            guard !overflow else { clearSensitive(); return nil }
            let deadline = min(computedDeadline, transportDeadline)
            guard deadline > snapshot.monotonicMillis else {
                clearSensitive(); return nil
            }
            let validated = KeyboardGrant(
                operation: pending.operation,
                processingMillis: rawGrant.processingMillis,
                leaseMillis: rawGrant.leaseMillis,
                deadlineMonotonicMillis: deadline,
                data: rawGrant.data
            )
            if pending.operation.isHeartbeat {
                // A fresh heartbeat refreshes the freshness lease only: it never
                // renews the window and never replaces the operation projection,
                // so selection and preview survive it.
                freshLeaseDeadlineMonotonicMillis = max(
                    freshLeaseDeadlineMonotonicMillis,
                    deadline
                )
                listener?.keyboardPolicyResponse(response, operation: pending.operation)
                return .granted(validated)
            }
            grant = validated
            freshLeaseDeadlineMonotonicMillis = max(
                freshLeaseDeadlineMonotonicMillis,
                deadline
            )
            if pending.operation == .begin { beginAccepted = true }
            applyGrantData(
                validated.data,
                operation: pending.operation,
                deadline: deadline,
                payload: pending.payload
            )
            if pending.operation == .begin, let ready = readyState() {
                listener?.keyboardPolicyReady(scramble: ready)
            }
            listener?.keyboardPolicyResponse(response, operation: pending.operation)
            return .granted(validated)
        }
    }

    /// Absolute local deadline of one grant. Freshness is never derived from the
    /// response arrival time, and the client window is never extended. Overflow
    /// is a denial (`nil`), never a silent window deadline.
    static func deadline(
        startedAtMonotonicMillis: Int64,
        processingMillis: Int64,
        leaseMillis: Int64,
        windowDeadlineMonotonicMillis: Int64
    ) -> Int64? {
        guard processingMillis >= 0,
              processingMillis <= KeyboardSurfaceBounds.maxProcessingMillis,
              leaseMillis >= 1,
              leaseMillis <= KeyboardSurfaceBounds.maxLeaseMillis else { return nil }
        let (afterProcessing, firstOverflow) =
            startedAtMonotonicMillis.addingReportingOverflow(processingMillis)
        guard !firstOverflow else { return nil }
        let (afterLease, secondOverflow) = afterProcessing.addingReportingOverflow(leaseMillis)
        guard !secondOverflow else { return nil }
        return min(afterLease, windowDeadlineMonotonicMillis)
    }

    /// Validated, bounded projections of the last `ok` reply.
    ///
    /// A projection is dropped by `clearSensitive()`; a late transport callback
    /// can never resurrect one, because the caller's generation, document
    /// binding and freshness lease are re-checked before the projection is
    /// applied and again before it is used. `nil` means "not present".
    private static func strictBoolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }

    public func readyState() -> Bool? {
        guard let grant, grant.operation == .begin else { return nil }
        return Self.strictBoolean(grant.data["scramble"]) ?? false
    }

    public func contacts() -> [KeyboardContact]? {
        guard let grant, grant.operation == .contacts else { return nil }
        return Self.contacts(from: grant.data)
    }

    public func selection() -> KeyboardContact? {
        guard let grant, grant.operation == .select else { return nil }
        return selectedContact
    }

    public func pendingId() -> String? {
        guard let grant, grant.operation == .prepare else { return nil }
        return Self.boundedIdentifier(grant.data["pendingId"])
    }

    /// The one-use authorization as projected for callers. It is `nil` once the
    /// single insertion permit has consumed it, so it can never be replayed.
    public func authorization() -> KeyboardAuthorization? {
        guard let authorized else { return nil }
        return KeyboardAuthorization(
            carrier: authorized.carrier,
            deadlineMonotonicMillis: authorized.deadlineMonotonicMillis
        )
    }

    public func preview() -> KeyboardPreview? {
        guard let grant, grant.operation == .decode else { return nil }
        return decodedPreview
    }

    public func lastExported() -> Bool? {
        guard let grant, grant.operation == .ack else { return nil }
        return Self.strictBoolean(grant.data["exported"])
    }

    /// True while an explicit recipient confirmation is held for this editor.
    public var hasSelection: Bool { selectedContact != nil }

    /// Drop the confirmed recipient without touching anything else.
    public func clearSelection() { selectedContact = nil }

    /// Merge the `authorize` / `decode` / `prepare` data of an `ok` reply into
    /// the typed projections. Called only by `acceptResponse`, with the grant's
    /// own deadline and the exact request payload, so these values stay bound to
    /// the request that produced them.
    func applyGrantData(
        _ data: [String: Any],
        operation: KeyboardOperation,
        deadline: Int64,
        payload: [String: KeyboardRequestValue]
    ) {
        switch operation {
        case .select:
            if let id = Self.boundedIdentifier(data["id"]),
               id == Self.stringValue(payload, "contactId"),
               let name = Self.boundedLabel(data["name"]),
               let fingerprint = Self.boundedLabel(data["fingerprint"]) {
                selectedContact = KeyboardContact(
                    id: id, name: name, fingerprint: fingerprint,
                    securityPhase: (data["securityPhase"] as? String)
                        .flatMap(KeyboardSecurityPhase.init(rawValue:)))
            } else {
                selectedContact = nil
            }
        case .prepare:
            lastPreparedPendingId = Self.boundedIdentifier(data["pendingId"])
            lastAuthorizedPendingId = nil
            authorized = nil
        case .authorize:
            // Bound to the confirmed recipient and to the exact pending id of
            // this request; an arbitrary or replayed carrier is never accepted.
            if let carrier = data["carrier"] as? String,
               !carrier.isEmpty,
               carrier.utf16.count <= outboundCarrierLimit,
               let pendingId = Self.stringValue(payload, "pendingId"),
               let recipientId = selectedContact?.id {
                authorized = AuthorizedInsertion(
                    carrier: carrier,
                    deadlineMonotonicMillis: deadline,
                    pendingId: pendingId,
                    recipientId: recipientId,
                    generation: generation,
                    documentIdentifier: documentIdentifier
                )
                lastAuthorizedPendingId = pendingId
                lastPreparedPendingId = nil
            } else {
                authorized = nil
                lastAuthorizedPendingId = nil
            }
        case .decode:
            decodedPreview = Self.preview(from: data)
        case .ack:
            lastAuthorizedPendingId = nil
        default:
            break
        }
    }

    /// The only path that can produce a carrier for `textDocumentProxy.insertText`.
    ///
    /// It re-checks live control, the live freshness lease, the correlated
    /// one-use authorization, the editor generation and document, the confirmed
    /// recipient and the original `authorize` deadline. The authorization is
    /// consumed here, so the permit cannot be produced twice. The caller must
    /// clear the draft, the recipient and its own labels immediately after the
    /// API call, whether or not it is certain the host accepted anything.
    public func insertionPermit(
        snapshot: KeyboardEditorSnapshot
    ) throws -> KeyboardInsertionPermit {
        guard liveControl(snapshot), let authorized else {
            clearSensitive()
            throw KeyboardPolicyError.unavailable
        }
        guard authorizationMatches(authorized, snapshot: snapshot) else {
            clearSensitive()
            throw KeyboardPolicyError.unavailable
        }
        let carrier = authorized.carrier
        guard !carrier.isEmpty,
              carrier.utf16.count <= outboundCarrierLimit else {
            clearSensitive()
            throw KeyboardPolicyError.malformed
        }
        // One-use: consuming before returning makes a replay impossible.
        self.authorized = nil
        return KeyboardInsertionPermit(
            carrier: carrier,
            pendingId: authorized.pendingId,
            authorizeDeadlineMonotonicMillis: authorized.deadlineMonotonicMillis
        )
    }

    // MARK: invalidation

    /// Drop every sensitive value and the freshness proof. Idempotent; safe from
    /// any callback.
    public func clearSensitive(notify: Bool = true) {
        autonomousAuthorization = nil
        revision += 1
        pending = nil
        grant = nil
        selectedContact = nil
        authorized = nil
        decodedPreview = nil
        lastPreparedPendingId = nil
        lastAuthorizedPendingId = nil
        freshLeaseDeadlineMonotonicMillis = 0
        if notify { listener?.keyboardPolicyCleared() }
    }

    /// Fail closed when the freshness lease has lapsed: drop every projection so
    /// no local draft, preview, contact or carrier survives even while the fixed
    /// owner window is still open. Returns `true` when it expired now, so the
    /// caller can drop the transport too.
    @discardableResult
    public func clearIfLeaseExpired(at monotonicMillis: Int64) -> Bool {
        guard sessionActive, beginAccepted else { return false }
        guard monotonicMillis >= freshLeaseDeadlineMonotonicMillis else { return false }
        clearSensitive(notify: false)
        return true
    }

    /// End the editor: drop the binding first, then every sensitive value. The
    /// returned nonce lets the caller queue the best-effort `end` request.
    @discardableResult
    public func endEditor() -> String? {
        let nonce = editorNonce
        editorNonce = nil
        sessionActive = false
        autonomousMode = false
        beginAccepted = false
        documentIdentifier = nil
        windowDeadlineMonotonicMillis = 0
        bootstrapDeadlineMonotonicMillis = 0
        generation += 1
        clearSensitive()
        return nonce
    }

    /// Current in-memory editor generation. Tests and the view controller use it
    /// to prove a late callback cannot act on a newer editor.
    public var editorGeneration: Int64 { generation }

    public var currentDocumentIdentifier: String? { documentIdentifier }

    // MARK: payload validation

    /// The exact field whitelist of every operation. A payload key outside the
    /// set — including a reserved `operation`, `editorNonce` or `requestId` — is
    /// rejected outright.
    static func allowedFields(_ operation: KeyboardOperation) -> Set<String>? {
        switch operation {
        case .contacts, .heartbeat: return []
        case .select: return ["contactId", "confirm"]
        case .prepare: return ["text"]
        case .authorize: return ["pendingId"]
        case .ack: return ["pendingId", "commitText"]
        case .decode: return ["carrier"]
        case .begin, .end: return nil
        }
    }

    static func validatePayload(
        _ operation: KeyboardOperation,
        _ payload: [String: KeyboardRequestValue]
    ) throws {
        guard let allowed = allowedFields(operation),
              Set(payload.keys) == allowed else {
            throw KeyboardPolicyError.invalid
        }
        switch operation {
        case .select:
            guard let contactId = stringValue(payload, "contactId"),
                  boundedIdentifier(contactId) != nil,
                  isTrue(payload, "confirm") else {
                throw KeyboardPolicyError.invalid
            }
        case .prepare:
            guard let text = stringValue(payload, "text"),
                  !text.isEmpty,
                  text.utf16.count <= KeyboardSurfaceBounds.maxDraftUTF16 else {
                throw KeyboardPolicyError.invalid
            }
        case .authorize, .ack:
            guard let pendingId = stringValue(payload, "pendingId"),
                  boundedIdentifier(pendingId) != nil else {
                throw KeyboardPolicyError.invalid
            }
            if operation == .ack, !isTrue(payload, "commitText") {
                throw KeyboardPolicyError.invalid
            }
        case .decode:
            guard let carrier = stringValue(payload, "carrier"),
                  !carrier.isEmpty,
                  carrier.utf16.count <= KeyboardSurfaceBounds.maxInboundCarrierUTF16 else {
                throw KeyboardPolicyError.invalid
            }
        default:
            break
        }
    }

    static func stringValue(_ payload: [String: KeyboardRequestValue], _ key: String) -> String? {
        guard let value = payload[key], case .string(let text) = value else { return nil }
        return text
    }

    static func isTrue(_ payload: [String: KeyboardRequestValue], _ key: String) -> Bool {
        guard let value = payload[key], case .bool(let flag) = value else { return false }
        return flag
    }

    // MARK: encoding

    static func encode(
        _ operation: KeyboardOperation,
        editorNonce: String,
        requestId: String,
        payload: [String: KeyboardRequestValue] = [:]
    ) throws -> Data {
        guard !editorNonce.isEmpty,
              editorNonce.utf16.count <= KeyboardSurfaceBounds.maxIdentifierUTF16,
              !requestId.isEmpty,
              requestId.utf16.count <= KeyboardSurfaceBounds.maxIdentifierUTF16 else {
            throw KeyboardPolicyError.invalid
        }
        var object: [String: Any] = [
            "operation": operation.rawValue,
            "editorNonce": editorNonce,
            "requestId": requestId
        ]
        for (key, value) in payload {
            guard key != "operation", key != "editorNonce", key != "requestId" else {
                throw KeyboardPolicyError.invalid
            }
            object[key] = value.jsonObject
        }
        guard JSONSerialization.isValidJSONObject(object) else {
            throw KeyboardPolicyError.invalid
        }
        do {
            return try JSONSerialization.data(withJSONObject: object, options: [])
        } catch {
            throw KeyboardPolicyError.malformed
        }
    }

    // MARK: decoding

    /// Strict decode of one decrypted reply.
    ///
    /// Junk bytes decode as `nil`, never as a thrown owner detail. A non-`ok`
    /// status is a closed failure: only its bounded status string is kept, and a
    /// non-`ok` reply without the bare `status` string is rejected outright.
    public static func decodeResponse(
        _ data: Data,
        operation: KeyboardOperation
    ) -> KeyboardResponse? {
        guard !data.isEmpty,
              data.count <= MailboxConstants.maxPlaintextBytes,
              let object = try? JSONSerialization.jsonObject(with: data, options: []),
              let dictionary = object as? [String: Any],
              let status = dictionary["status"] as? String,
              KeyboardChannelStatus.isKnown(status) else { return nil }
        guard status == KeyboardChannelStatus.ok else { return .failed(status) }
        guard let processingMillis = strictInteger(
                dictionary["processingMillis"],
                minimum: 0,
                maximum: KeyboardSurfaceBounds.maxProcessingMillis
              ),
              let leaseMillis = strictInteger(
                dictionary["leaseMillis"],
                minimum: 1,
                maximum: KeyboardSurfaceBounds.maxLeaseMillis
              ) else { return nil }
        if operation == .heartbeat, processingMillis != 0 { return nil }
        // `deadlineMonotonicMillis` is a placeholder here: decoding never sees a
        // request start, so `acceptResponse` recomputes it from
        // `start + processingMillis + leaseMillis` capped by the client window.
        return .granted(
            KeyboardGrant(
                operation: operation,
                processingMillis: processingMillis,
                leaseMillis: leaseMillis,
                deadlineMonotonicMillis: 0,
                data: dictionary["data"] as? [String: Any] ?? [:]
            )
        )
    }

    /// Integer JSON numbers only: booleans, fractional values, strings and
    /// out-of-range values are rejected. `value is Bool` is true for `NSNumber`
    /// `0` and `1` as well, so the CoreFoundation type id is used instead.
    static func strictInteger(_ value: Any?, minimum: Int64, maximum: Int64) -> Int64? {
        guard let value, let number = value as? NSNumber else { return nil }
        guard CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let encodings: Set<String> = ["c", "i", "s", "l", "q", "C", "I", "S", "L", "Q"]
        guard encodings.contains(String(cString: number.objCType)) else { return nil }
        let decimal = number.decimalValue
        guard decimal >= Decimal(minimum), decimal <= Decimal(maximum) else { return nil }
        let converted = number.int64Value
        guard Decimal(converted) == decimal else { return nil }
        return converted
    }

    static func boundedLabel(_ value: Any?) -> String? {
        guard let value = value as? String,
              !value.isEmpty,
              value.utf16.count <= KeyboardSurfaceBounds.maxLabelUTF16 else { return nil }
        return value
    }

    static func boundedIdentifier(_ value: Any?) -> String? {
        guard let value = value as? String,
              !value.isEmpty,
              value.utf16.count <= KeyboardSurfaceBounds.maxIdentifierUTF16 else { return nil }
        return value
    }

    /// Bounded `contacts` projection. A single malformed entry drops only itself.
    static func contacts(from data: [String: Any]) -> [KeyboardContact] {
        guard let raw = data["contacts"] as? [Any] else { return [] }
        var contacts: [KeyboardContact] = []
        contacts.reserveCapacity(raw.count)
        for entry in raw {
            guard let dictionary = entry as? [String: Any],
                  let id = boundedIdentifier(dictionary["id"]),
                  let name = boundedLabel(dictionary["name"]),
                  let fingerprint = boundedLabel(dictionary["fingerprint"]) else { continue }
            contacts.append(KeyboardContact(id: id, name: name, fingerprint: fingerprint))
        }
        return contacts
    }

    /// Bounded `decode` projection: preview text is 1...262144 UTF-16 units and
    /// never leaves this keyboard.
    static func preview(from data: [String: Any]) -> KeyboardPreview? {
        guard let contactId = boundedIdentifier(data["contactId"]),
              let contactName = boundedLabel(data["contactName"]),
              let fingerprint = boundedLabel(data["fingerprint"]),
              let text = data["text"] as? String,
              !text.isEmpty,
              text.utf16.count <= KeyboardSurfaceBounds.maxInboundCarrierUTF16 else { return nil }
        return KeyboardPreview(
            contactId: contactId,
            contactName: contactName,
            fingerprint: fingerprint,
            text: text
        )
    }
}

// MARK: - Local text editing

/// Pure editing helpers for the local draft. The extension never uses a
/// `UITextField`/`UITextView` responder, never reads host surrounding text and
/// never runs autocorrect, so grapheme handling is explicit here.
public enum KeyboardTextEdit {
    /// Append one locally typed character.
    public static func append(_ character: String, to text: String) -> String? {
        guard !character.isEmpty else { return nil }
        return bounded(text + character, limit: KeyboardSurfaceBounds.maxDraftUTF16)
    }

    /// Delete one user-perceived character from the end.
    public static func backspace(_ text: String) -> String {
        guard !text.isEmpty else { return text }
        return String(text.dropLast())
    }

    /// Clamp to the UTF-16 ceiling without splitting a grapheme cluster.
    public static func bounded(_ text: String, limit: Int) -> String? {
        guard limit > 0 else { return nil }
        guard text.utf16.count > limit else { return text }
        var kept = ""
        kept.reserveCapacity(min(text.count, limit))
        for character in text {
            let candidate = kept + String(character)
            if candidate.utf16.count > limit { break }
            kept = candidate
        }
        return kept.isEmpty ? nil : kept
    }

    /// Whether the draft is a legal `prepare` input.
    public static func isValidDraft(_ text: String) -> Bool {
        !text.isEmpty && text.utf16.count <= KeyboardSurfaceBounds.maxDraftUTF16
    }
}
