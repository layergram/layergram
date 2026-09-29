import Foundation

/// Authorization kept only in the live extension. Construction is reserved for
/// a freshly authenticated app grant; neither disk state nor a touch can create
/// or revive a session. The caller must check native custody on EVERY sample.
public final class KeyboardAutonomousSession {
    public enum ValidationFailure: String {
        case terminal, hidden, fullAccess, capture, document, custody
        case clockRegression, observationGap, idleExpired
    }

    public static let maximumObservationGapMillis: Int64 = 1_500
    public let documentIdentifier: String
    private let idle: KeyboardIdleSession
    private var lastObservation: Int64
    public private(set) var lastValidationFailure: ValidationFailure?

    public var deadlineMonotonicMillis: Int64 { idle.deadlineMonotonicMillis }
    public var isTerminal: Bool { idle.isTerminal }

    public init?(snapshot: KeyboardEditorSnapshot, authorizedIdleMillis: Int64) {
        guard snapshot.isViewVisible, snapshot.hasFullAccess, !snapshot.isCaptured,
              let document = snapshot.documentIdentifier, !document.isEmpty,
              authorizedIdleMillis > 0, authorizedIdleMillis <= 300_000,
              let idle = KeyboardIdleSession.start(
                startMonotonicMillis: snapshot.monotonicMillis,
                authorizedDurationMillis: authorizedIdleMillis) else { return nil }
        self.idle = idle
        documentIdentifier = document
        lastObservation = snapshot.monotonicMillis
    }

    /// Polls, rendering and crypto callbacks never renew the idle deadline.
    /// A suspension/long scheduling gap permanently revokes even if lifecycle
    /// notification delivery was missed and the device is already unlocked.
    public func validate(_ snapshot: KeyboardEditorSnapshot, hasCustody: Bool) -> Bool {
        let failure: ValidationFailure?
        if idle.isTerminal { failure = .terminal }
        else if !snapshot.isViewVisible { failure = .hidden }
        else if !snapshot.hasFullAccess { failure = .fullAccess }
        else if snapshot.isCaptured { failure = .capture }
        else if snapshot.documentIdentifier != documentIdentifier { failure = .document }
        else if !hasCustody { failure = .custody }
        else if snapshot.monotonicMillis < lastObservation { failure = .clockRegression }
        else if snapshot.monotonicMillis - lastObservation > Self.maximumObservationGapMillis {
            failure = .observationGap
        } else if !idle.observe(nowMonotonicMillis: snapshot.monotonicMillis).isActive {
            failure = .idleExpired
        } else { failure = nil }
        if let failure {
            lastValidationFailure = failure
            revoke()
            return false
        }
        lastValidationFailure = nil
        lastObservation = snapshot.monotonicMillis
        return true
    }

    /// Call only for intentional physical input, after sampling current native
    /// visibility/protection/custody. A late tap is rejected before renewal.
    public func recordUserInteraction(_ snapshot: KeyboardEditorSnapshot, hasCustody: Bool) -> Bool {
        guard validate(snapshot, hasCustody: hasCustody) else { return false }
        return idle.recordUserInteraction(nowMonotonicMillis: snapshot.monotonicMillis).isActive
    }

    public func revoke() { idle.revoke() }
}
