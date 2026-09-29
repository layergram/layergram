import Foundation
import XCTest

@testable import SystemKeyboardCore

/// Behavioural tests for the pure keyboard-extension policy.
///
/// Every test drives the policy through its public seam with an explicit
/// monotonic clock: no wall clock, no UIKit, no Xcode target and no real mailbox.
/// Grants are never seeded directly: each projection exists only because an `ok`
/// reply was accepted for a correlated request, exactly as the view controller
/// does it.
final class KeyboardPolicyTests: XCTestCase {
    private var clock: Int64 = 1_000_000

    private final class ClearProbe: KeyboardPolicyListener {
        var onClear: (() -> Void)?
        func keyboardPolicyReady(scramble: Bool) {}
        func keyboardPolicyResponse(_ response: KeyboardResponse, operation: KeyboardOperation) {}
        func keyboardPolicyCleared() { onClear?() }
    }

    // MARK: - Harness

    /// A policy bound to a live editor at the current clock reading. Binding does
    /// not accept a `begin`: `beginAccepted` is still false.
    private func livePolicy(
        document: String? = "editor-1",
        windowMillis: Int64 = 20_000
    ) -> KeyboardEditorPolicy {
        let policy = KeyboardEditorPolicy(now: { [weak self] in self?.clock ?? 0 })
        XCTAssertTrue(policy.begin(
            documentIdentifier: document,
            windowDeadlineMonotonicMillis: clock + windowMillis
        ))
        return policy
    }

    private func snapshot(
        document: String? = "editor-1",
        visible: Bool = true,
        fullAccess: Bool = true,
        captured: Bool = false,
        at: Int64? = nil
    ) -> KeyboardEditorSnapshot {
        KeyboardEditorSnapshot(
            isViewVisible: visible,
            hasFullAccess: fullAccess,
            isCaptured: captured,
            documentIdentifier: document,
            monotonicMillis: at ?? clock
        )
    }

    private func reply(
        status: String = "ok",
        processingMillis: Any = 5,
        leaseMillis: Any = 500,
        data: [String: Any] = [:]
    ) -> Data {
        let object: [String: Any] = [
            "status": status,
            "processingMillis": processingMillis,
            "leaseMillis": leaseMillis,
            "data": data
        ]
        return try! JSONSerialization.data(withJSONObject: object, options: [])
    }

    /// Seal one operation request through the public API.
    @discardableResult
    private func request(
        _ policy: KeyboardEditorPolicy,
        _ operation: KeyboardOperation,
        payload: [String: KeyboardRequestValue] = [:],
        snapshot current: KeyboardEditorSnapshot? = nil
    ) throws -> Data {
        try policy.requestData(
            operation,
            payload: payload,
            snapshot: current ?? snapshot()
        )
    }

    private func plaintext(_ data: Data) throws -> [String: Any] {
        let object = try JSONSerialization.jsonObject(with: data, options: [])
        return object as? [String: Any] ?? [:]
    }

    private func granted(_ response: KeyboardResponse?) -> KeyboardGrant? {
        guard let response, case .granted(let grant) = response else { return nil }
        return grant
    }

    /// Accept the `begin` reply the same way the UI does: seal the request,
    /// advance the clock past the owner processing time, then consume the reply.
    @discardableResult
    private func acceptBegin(
        _ policy: KeyboardEditorPolicy,
        document: String? = "editor-1",
        scramble: Any = false
    ) -> Bool {
        do {
            _ = try policy.beginRequestData()
        } catch {
            return false
        }
        clock += 5
        return granted(policy.acceptResponse(
            reply(processingMillis: 5, leaseMillis: 500, data: ["scramble": scramble]),
            snapshot: snapshot(document: document, at: clock)
        )) != nil
    }

    /// One request/reply cycle with the owner taking `processingMillis`.
    private func cycle(
        _ policy: KeyboardEditorPolicy,
        _ operation: KeyboardOperation,
        payload: [String: KeyboardRequestValue] = [:],
        data: [String: Any] = [:],
        processingMillis: Any = 5,
        leaseMillis: Any = 500,
        document: String? = "editor-1"
    ) -> KeyboardResponse? {
        do {
            _ = try policy.requestData(
                operation,
                payload: payload,
                snapshot: snapshot(document: document)
            )
        } catch {
            return nil
        }
        clock += 5
        return policy.acceptResponse(
            reply(processingMillis: processingMillis, leaseMillis: leaseMillis, data: data),
            snapshot: snapshot(document: document, at: clock)
        )
    }

    /// A policy with a live lease and a confirmed recipient, ready for
    /// `prepare` / `authorize`, built only through the public request flow.
    private func policyAfterAuthorize(carrier: String = "carrier-1") -> KeyboardEditorPolicy {
        let policy = livePolicy()
        _ = acceptBegin(policy)
        _ = cycle(policy, .contacts, data: [
            "contacts": [["id": "id-1", "name": "Alice", "fingerprint": "ABCD"]]
        ])
        _ = cycle(policy, .select, payload: [
            "contactId": .string("id-1"),
            "confirm": .bool(true)
        ], data: ["id": "id-1", "name": "Alice", "fingerprint": "ABCD"])
        _ = cycle(policy, .prepare, payload: ["text": .string("hello")], data: [
            "pendingId": "skp-1"
        ])
        _ = cycle(policy, .authorize, payload: ["pendingId": .string("skp-1")], data: [
            "carrier": carrier
        ])
        return policy
    }

    func testSelectedShieldPhaseIsBoundedDisplayDataNotASendPermit() {
        for raw in ["setupPending", "normalActive", "maximumSetupPending",
                    "maximumActive", "recoveryRequired",
                    "forged-green"] {
            let policy = livePolicy()
            XCTAssertTrue(acceptBegin(policy))
            _ = cycle(policy, .contacts, data: [
                "contacts": [["id": "id-1", "name": "Alice", "fingerprint": "ABCD"]]
            ])
            _ = cycle(policy, .select, payload: [
                "contactId": .string("id-1"), "confirm": .bool(true)
            ], data: ["id": "id-1", "name": "Alice", "fingerprint": "ABCD",
                      "securityPhase": raw])
            XCTAssertEqual(policy.selection()?.securityPhase?.rawValue,
                           raw == "forged-green" ? nil : raw)
            XCTAssertNil(policy.readyState(), "shield data cannot authorize insertion")
        }
    }

    // MARK: - Request shape

    func testBeginRequestSealsPendingNonceAndRequestId() throws {
        let policy = livePolicy()
        let data = try policy.beginRequestData()
        let object = try plaintext(data)
        XCTAssertEqual(object["operation"] as? String, "begin")
        let nonce = object["editorNonce"] as? String
        let requestId = object["requestId"] as? String
        XCTAssertEqual(nonce, policy.currentEditorNonce)
        XCTAssertNotNil(requestId)
        XCTAssertLessThanOrEqual((requestId ?? "").utf16.count, 128)
        XCTAssertEqual(object.count, 3)
        // The begin request is recorded, so its reply can be correlated.
        XCTAssertTrue(policy.isAwaitingResponse)
    }

    func testBeginRequestIsRefusedOnceTheWindowHasPassed() {
        let policy = livePolicy(windowMillis: 1_000)
        clock += 1_000
        XCTAssertThrowsError(try policy.beginRequestData()) { error in
            XCTAssertEqual(error as? KeyboardPolicyError, .unavailable)
        }
    }

    func testBootstrapWaitIsBoundedToOneSecond() {
        let policy = livePolicy()
        XCTAssertFalse(policy.isBootstrapExpired)
        clock += 999
        XCTAssertFalse(policy.isBootstrapExpired)
        clock += 1
        XCTAssertTrue(policy.isBootstrapExpired)
        XCTAssertFalse(policy.isBeginAccepted)
    }

    func testOperationsAreRefusedBeforeAnAcceptedBegin() {
        let policy = livePolicy()
        XCTAssertFalse(policy.isBeginAccepted)
        XCTAssertFalse(policy.hasLiveLease(at: clock))
        XCTAssertThrowsError(try request(policy, .contacts)) {
            XCTAssertEqual($0 as? KeyboardPolicyError, .unavailable)
        }
        XCTAssertThrowsError(try request(policy, .heartbeat)) {
            XCTAssertEqual($0 as? KeyboardPolicyError, .unavailable)
        }
    }

    func testPreparePayloadIsBoundedAndRejectsEmptyOrOversizedDrafts() throws {
        let policy = livePolicy()
        _ = acceptBegin(policy)

        XCTAssertThrowsError(
            try request(policy, .prepare, payload: ["text": .string("")])
        ) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }

        let oversized = String(repeating: "a", count: 4_001)
        XCTAssertThrowsError(
            try request(policy, .prepare, payload: ["text": .string(oversized)])
        ) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
    }

    func testInboundCarrierIsBoundedBeforeAnyDecodeRequest() throws {
        let policy = livePolicy()
        _ = acceptBegin(policy)
        XCTAssertThrowsError(
            try request(policy, .decode, payload: ["carrier": .string("")])
        ) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }

        let oversized = String(repeating: "b", count: 262_145)
        XCTAssertThrowsError(
            try request(policy, .decode, payload: ["carrier": .string(oversized)])
        ) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
    }

    func testSecondRequestIsRefusedWhileOneIsOutstanding() throws {
        let policy = livePolicy()
        _ = acceptBegin(policy)
        _ = try request(policy, .contacts)
        XCTAssertThrowsError(try request(policy, .heartbeat)) {
            XCTAssertEqual($0 as? KeyboardPolicyError, .unavailable)
        }
    }

    // MARK: - Admission

    func testDeniedFullAccessCaptureAndHiddenViewAllFailClosed() throws {
        let policy = livePolicy()
        _ = acceptBegin(policy)
        XCTAssertFalse(policy.revalidate(snapshot(fullAccess: false)))
        XCTAssertFalse(policy.revalidate(snapshot(captured: true)))
        XCTAssertFalse(policy.revalidate(snapshot(visible: false)))
        XCTAssertFalse(policy.liveControl(snapshot(fullAccess: false)))
        XCTAssertFalse(policy.liveControl(snapshot(captured: true)))
        XCTAssertFalse(policy.liveControl(snapshot(visible: false)))
        XCTAssertThrowsError(
            try request(policy, .contacts, snapshot: snapshot(captured: true))
        ) { XCTAssertEqual($0 as? KeyboardPolicyError, .unavailable) }
    }

    func testCrossDocumentInteractionsAreRejected() throws {
        let policy = livePolicy(document: "editor-1")
        _ = acceptBegin(policy, document: "editor-1")
        XCTAssertTrue(policy.documentChanged(snapshot(document: "editor-2")))
        XCTAssertFalse(policy.revalidate(snapshot(document: "editor-2")))
        XCTAssertThrowsError(
            try request(policy, .contacts, snapshot: snapshot(document: "editor-2"))
        ) { XCTAssertEqual($0 as? KeyboardPolicyError, .unavailable) }
    }

    func testNilDocumentBindingsStillBindAndChange() {
        let policy = livePolicy(document: nil)
        XCTAssertTrue(policy.revalidate(snapshot(document: nil)))
        XCTAssertFalse(policy.documentChanged(snapshot(document: nil)))
        XCTAssertTrue(policy.documentChanged(snapshot(document: "editor-2")))
    }

    func testWindowDeadlineIsExclusive() {
        let policy = livePolicy(windowMillis: 1_000)
        clock += 999
        XCTAssertTrue(policy.revalidate(snapshot()))
        clock += 1
        XCTAssertFalse(policy.revalidate(snapshot()))
    }

    // MARK: - Granted replies

    func testGrantDeadlineUsesProcessingPlusLeaseAndNotArrivalTime() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        let start = clock
        _ = try request(policy, .contacts)
        // The owner took 300 ms and granted a 400 ms lease; the reply is read
        // 100 ms later. Freshness must come from the request start.
        clock = start + 100
        guard let grant = granted(policy.acceptResponse(
            reply(processingMillis: 300, leaseMillis: 400),
            snapshot: snapshot(at: clock)
        )) else {
            return XCTFail("expected a granted response")
        }
        XCTAssertEqual(grant.processingMillis, 300)
        XCTAssertEqual(grant.leaseMillis, 400)
        XCTAssertEqual(grant.deadlineMonotonicMillis, start + 700)
        // An arrival-time derivation would have produced `clock + 700`.
        XCTAssertNotEqual(grant.deadlineMonotonicMillis, clock + 700)
    }

    func testGrantThatCannotReachTheFutureIsDropped() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        let start = clock
        _ = try request(policy, .contacts)
        clock = start + 701
        XCTAssertNil(policy.acceptResponse(
            reply(processingMillis: 300, leaseMillis: 400),
            snapshot: snapshot(at: clock)
        ))
        XCTAssertFalse(policy.isAwaitingResponse)
        XCTAssertFalse(policy.hasLiveLease(at: clock))
    }

    func testGrantIsCappedByTheRemainingClientWindow() throws {
        let windowStart = clock
        let policy = livePolicy(windowMillis: 1_000)
        XCTAssertTrue(acceptBegin(policy))
        let start = clock
        _ = try request(policy, .contacts)
        clock = start + 100
        guard let grant = granted(policy.acceptResponse(
            reply(processingMillis: 0, leaseMillis: 1_000),
            snapshot: snapshot(at: clock)
        )) else {
            return XCTFail("expected a granted response")
        }
        XCTAssertEqual(grant.deadlineMonotonicMillis, windowStart + 1_000)
    }

    // MARK: - Freshness lease

    func testLeaseIsExclusiveAndExpiryClearsEveryProjection() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        guard granted(cycle(policy, .contacts, data: [
            "contacts": [["id": "id-1", "name": "Alice", "fingerprint": "ABCD"]]
        ])) != nil else {
            return XCTFail("expected a granted contacts")
        }
        let expireAt = clock + 500
        XCTAssertNotNil(policy.contacts())
        XCTAssertTrue(policy.hasLiveLease(at: expireAt - 1))
        XCTAssertFalse(policy.hasLiveLease(at: expireAt))
        // The fixed window is still open, but the freshness lease is not.
        XCTAssertTrue(policy.revalidate(snapshot(at: expireAt)))
        XCTAssertFalse(policy.liveControl(snapshot(at: expireAt)))
        XCTAssertTrue(policy.clearIfLeaseExpired(at: expireAt))
        XCTAssertNil(policy.contacts())
        XCTAssertNil(policy.readyState())
        XCTAssertFalse(policy.hasSelection)
    }

    func testHeartbeatRefreshesTheFreshnessLeaseButNeverTheWindow() throws {
        let windowStart = clock
        let policy = livePolicy(windowMillis: 1_500)
        XCTAssertTrue(acceptBegin(policy))
        _ = try request(policy, .contacts)
        clock += 100
        guard let contactsGrant = granted(policy.acceptResponse(
            reply(processingMillis: 100, leaseMillis: 500, data: ["contacts": []]),
            snapshot: snapshot(at: clock)
        )) else {
            return XCTFail("expected a granted contacts")
        }
        let operationDeadline = contactsGrant.deadlineMonotonicMillis
        XCTAssertTrue(policy.hasLiveLease(at: operationDeadline - 1))

        // An idle heartbeat is issued just before the real lease lapses. It
        // refreshes freshness, but the fixed window caps it: the owner window is
        // never renewed by a heartbeat.
        clock = operationDeadline - 10
        guard let beat = granted(cycle(
            policy,
            .heartbeat,
            processingMillis: 0,
            leaseMillis: 1_000
        )) else {
            return XCTFail("expected a granted heartbeat")
        }
        XCTAssertEqual(beat.processingMillis, 0)
        XCTAssertEqual(beat.deadlineMonotonicMillis, windowStart + 1_500)
        XCTAssertTrue(policy.hasLiveLease(at: windowStart + 1_499))
        XCTAssertFalse(policy.hasLiveLease(at: windowStart + 1_500))
        XCTAssertFalse(policy.revalidate(snapshot(at: windowStart + 1_500)))
    }

    func testHeartbeatPreservesSelectionAndPreviewProjections() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        guard granted(cycle(policy, .contacts, data: [
            "contacts": [["id": "id-1", "name": "Alice", "fingerprint": "ABCD"]]
        ])) != nil else {
            return XCTFail("expected a granted contacts")
        }
        let before = policy.contacts()
        XCTAssertNotNil(before)
        XCTAssertNotNil(granted(cycle(policy, .heartbeat, processingMillis: 0, leaseMillis: 1_000)))
        XCTAssertEqual(policy.contacts(), before)
    }

    func testHeartbeatWhoseOwnDeadlineAlreadyPassedIsRejected() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        _ = try request(policy, .heartbeat)
        clock += 1_001
        XCTAssertNil(policy.acceptResponse(
            reply(processingMillis: 0, leaseMillis: 1_000),
            snapshot: snapshot(at: clock)
        ))
        XCTAssertFalse(policy.hasLiveLease(at: clock))
    }

    func testHeartbeatResponseMustReportExactlyZeroProcessing() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        _ = try request(policy, .heartbeat)
        clock += 5
        XCTAssertNil(policy.acceptResponse(
            reply(processingMillis: 1, leaseMillis: 10),
            snapshot: snapshot(at: clock)
        ))
    }

    func testPendingRequestDoesNotSuspendTheLeaseCheck() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        let start = clock
        _ = try request(policy, .contacts)
        clock = start + 600
        XCTAssertTrue(policy.isAwaitingResponse)
        XCTAssertFalse(policy.liveControl(snapshot(at: clock)))
        XCTAssertTrue(policy.clearIfLeaseExpired(at: clock))
        XCTAssertFalse(policy.isAwaitingResponse)
    }

    func testLateReplyCannotReviveAfterLeaseExpiry() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        let start = clock
        _ = try request(policy, .contacts)
        clock = start + 600
        XCTAssertNil(policy.acceptResponse(
            reply(processingMillis: 5, leaseMillis: 500, data: ["contacts": []]),
            snapshot: snapshot(at: clock)
        ))
        XCTAssertFalse(policy.isAwaitingResponse)
        XCTAssertNil(policy.contacts())
    }

    // MARK: - Malformed grants

    func testNonIntegerFractionalBooleanAndOutOfRangeGrantsAreRejected() {
        let cases: [[String: Any]] = [
            ["status": "ok", "processingMillis": true, "leaseMillis": 500, "data": [:]],
            ["status": "ok", "processingMillis": 0, "leaseMillis": true, "data": [:]],
            ["status": "ok", "processingMillis": 0.5, "leaseMillis": 500, "data": [:]],
            ["status": "ok", "processingMillis": 0, "leaseMillis": 1_001, "data": [:]],
            ["status": "ok", "processingMillis": 30_001, "leaseMillis": 500, "data": [:]],
            ["status": "ok", "processingMillis": 0, "leaseMillis": 0, "data": [:]],
            ["status": "ok", "processingMillis": 0, "leaseMillis": -1, "data": [:]],
            ["status": "ok", "processingMillis": 0, "leaseMillis": "500", "data": [:]],
            ["status": "ok", "processingMillis": 0, "data": [:]],
            ["status": "ok", "leaseMillis": 500, "data": [:]],
            ["status": 7, "processingMillis": 0, "leaseMillis": 500, "data": [:]],
            ["status": "invented", "processingMillis": 0, "leaseMillis": 500, "data": [:]],
            ["processingMillis": 0, "leaseMillis": 500, "data": [:]]
        ]
        for object in cases {
            let policy = livePolicy()
            _ = acceptBegin(policy)
            do {
                _ = try request(policy, .contacts)
            } catch {
                XCTFail("expected a sealed request for \(object)")
                continue
            }
            let data = try! JSONSerialization.data(withJSONObject: object, options: [])
            XCTAssertNil(
                policy.acceptResponse(data, snapshot: snapshot()),
                "unexpected grant for \(object)"
            )
            XCTAssertFalse(policy.hasLiveLease(at: clock))
        }
    }

    func testNonJsonAndEmptyRepliesAreRejected() throws {
        let first = livePolicy()
        XCTAssertTrue(acceptBegin(first))
        _ = try request(first, .contacts)
        XCTAssertNil(first.acceptResponse(Data("not json".utf8), snapshot: snapshot()))

        let second = livePolicy()
        XCTAssertTrue(acceptBegin(second))
        _ = try request(second, .contacts)
        XCTAssertNil(second.acceptResponse(Data(), snapshot: snapshot()))
    }

    func testClosedStatusIsBoundedAndClearsTheSession() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        _ = try request(policy, .contacts)
        let failed = policy.acceptResponse(reply(status: "openAppRequired"), snapshot: snapshot())
        XCTAssertEqual(failed, .failed("openAppRequired"))
        XCTAssertFalse(policy.hasLiveLease(at: clock))
    }

    func testOversizedReplyDocumentIsRejectedBeforeParsing() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        _ = try request(policy, .contacts)
        let padded = String(
            repeating: "x",
            count: MailboxConstants.maxPlaintextBytes + 1
        )
        XCTAssertNil(policy.acceptResponse(Data(padded.utf8), snapshot: snapshot()))
    }

    // MARK: - Positive flow and insertion permit

    func testPositiveFlowThroughPermitAndAck() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy, scramble: true))
        XCTAssertTrue(policy.isBeginAccepted)
        XCTAssertEqual(policy.readyState(), true)

        XCTAssertNotNil(granted(cycle(policy, .heartbeat, processingMillis: 0, leaseMillis: 1_000)))

        guard granted(cycle(policy, .contacts, data: [
            "contacts": [["id": "id-1", "name": "Alice", "fingerprint": "ABCD"]]
        ])) != nil else {
            return XCTFail("expected a granted contacts")
        }
        XCTAssertEqual(policy.contacts()?.first?.id, "id-1")

        guard granted(cycle(policy, .select, payload: [
            "contactId": .string("id-1"),
            "confirm": .bool(true)
        ], data: ["id": "id-1", "name": "Alice", "fingerprint": "ABCD"])) != nil else {
            return XCTFail("expected a granted select")
        }
        XCTAssertTrue(policy.hasSelection)
        XCTAssertEqual(policy.selection()?.id, "id-1")

        guard granted(cycle(policy, .prepare, payload: ["text": .string("hello")], data: [
            "pendingId": "skp-1"
        ])) != nil else {
            return XCTFail("expected a granted prepare")
        }
        XCTAssertEqual(policy.pendingId(), "skp-1")

        guard granted(cycle(policy, .authorize, payload: ["pendingId": .string("skp-1")], data: [
            "carrier": "carrier-1"
        ])) != nil else {
            return XCTFail("expected a granted authorize")
        }

        // The single permit exists exactly once and consumes the authorization.
        let permit = try policy.insertionPermit(snapshot: snapshot())
        XCTAssertEqual(permit.carrier, "carrier-1")
        XCTAssertEqual(permit.pendingId, "skp-1")
        XCTAssertNil(policy.authorization())

        // The export-attempt ack carries a real JSON boolean.
        let ack = try request(policy, .ack, payload: [
            "pendingId": .string("skp-1"),
            "commitText": .bool(true)
        ])
        let object = try plaintext(ack)
        XCTAssertEqual(object["operation"] as? String, "ack")
        XCTAssertEqual(object["commitText"] as? Bool, true)
        XCTAssertFalse(object["commitText"] is String)
    }

    func testInsertionPermitWithoutAuthorizationIsRefused() {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        XCTAssertThrowsError(try policy.insertionPermit(snapshot: snapshot())) {
            XCTAssertEqual($0 as? KeyboardPolicyError, .unavailable)
        }
    }

    func testInsertionPermitIsOneUseAndCannotBeReplayed() throws {
        let policy = policyAfterAuthorize()
        _ = try policy.insertionPermit(snapshot: snapshot())
        XCTAssertThrowsError(try policy.insertionPermit(snapshot: snapshot())) {
            XCTAssertEqual($0 as? KeyboardPolicyError, .unavailable)
        }
    }

    func testInsertionPermitIsBoundToTheConfirmedRecipient() throws {
        let policy = policyAfterAuthorize()
        XCTAssertTrue(policy.hasSelection)
        policy.clearSelection()
        XCTAssertThrowsError(try policy.insertionPermit(snapshot: snapshot())) {
            XCTAssertEqual($0 as? KeyboardPolicyError, .unavailable)
        }
    }

    func testInsertionIsRefusedAfterTheLeaseLapses() throws {
        let policy = policyAfterAuthorize()
        let authorizeClock = clock
        clock = authorizeClock + 501
        XCTAssertFalse(policy.hasLiveLease(at: clock))
        XCTAssertThrowsError(try policy.insertionPermit(snapshot: snapshot(at: clock))) {
            XCTAssertEqual($0 as? KeyboardPolicyError, .unavailable)
        }
    }

    func testOversizedOrEmptyCarrierIsNeverPermitted() throws {
        let policy = policyAfterAuthorize(carrier: String(repeating: "z", count: 4_001))
        // The oversized carrier is dropped during projection, so there is
        // nothing to permit.
        XCTAssertNil(policy.authorization())
        XCTAssertThrowsError(try policy.insertionPermit(snapshot: snapshot())) {
            XCTAssertEqual($0 as? KeyboardPolicyError, .unavailable)
        }
    }

    func testAuthorizeRequiresThePreparedPendingId() {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        XCTAssertThrowsError(try request(policy, .authorize, payload: [
            "pendingId": .string("skp-1")
        ])) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
    }

    func testAckRequiresCommitTextTrueAndTheAuthorizedPendingId() throws {
        let policy = policyAfterAuthorize()
        XCTAssertThrowsError(try request(policy, .ack, payload: [
            "pendingId": .string("other"),
            "commitText": .bool(true)
        ])) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
        XCTAssertThrowsError(try request(policy, .ack, payload: [
            "pendingId": .string("skp-1"),
            "commitText": .string("true")
        ])) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
    }

    func testDecodeRequestDropsAPreviouslyConfirmedRecipient() throws {
        let policy = policyAfterAuthorize()
        XCTAssertTrue(policy.hasSelection)
        _ = try request(policy, .decode, payload: ["carrier": .string("cipher")])
        XCTAssertFalse(policy.hasSelection)
    }

    func testSelectRequiresABooleanConfirmOfTrue() {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        XCTAssertThrowsError(try request(policy, .select, payload: [
            "contactId": .string("id-1"),
            "confirm": .string("true")
        ])) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
        XCTAssertThrowsError(try request(policy, .select, payload: [
            "contactId": .string("id-1"),
            "confirm": .bool(false)
        ])) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
    }

    func testReservedAndUnknownFieldsCannotBeInjected() {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        XCTAssertThrowsError(try request(policy, .select, payload: [
            "contactId": .string("id-1"),
            "confirm": .bool(true),
            "operation": .string("end")
        ])) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
        XCTAssertThrowsError(try request(policy, .contacts, payload: [
            "requestId": .string("x")
        ])) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
        XCTAssertThrowsError(try KeyboardEditorPolicy.encode(
            .begin,
            editorNonce: "n",
            requestId: "r",
            payload: ["editorNonce": .string("other")]
        )) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
    }

    // MARK: - Late callbacks and invalidation

    func testEndEditorNotifiesClearSynchronouslyDuringRebind() {
        let policy = livePolicy()
        let probe = ClearProbe()
        var endingForRebind = true
        var callbackCount = 0
        probe.onClear = {
            XCTAssertTrue(endingForRebind,
                          "the controller must preserve its native runtime during this callback")
            callbackCount += 1
        }
        policy.listener = probe
        _ = policy.endEditor()
        endingForRebind = false
        XCTAssertEqual(callbackCount, 1)
    }

    func testStaleGenerationCannotInsertAfterAnEnd() throws {
        let policy = policyAfterAuthorize()
        let nonce = policy.currentEditorNonce
        XCTAssertNotNil(nonce)

        XCTAssertEqual(policy.endEditor(), nonce ?? "")
        XCTAssertNil(policy.currentEditorNonce)
        XCTAssertThrowsError(try policy.insertionPermit(snapshot: snapshot())) {
            XCTAssertEqual($0 as? KeyboardPolicyError, .unavailable)
        }

        // A late transport reply for the dead editor is refused, not applied.
        XCTAssertNil(policy.acceptResponse(
            reply(processingMillis: 10, leaseMillis: 500, data: ["carrier": "late"]),
            snapshot: snapshot()
        ))
        XCTAssertNil(policy.authorization())
    }

    func testSameDocumentNewGenerationRefusesALateReply() throws {
        let policy = livePolicy(document: "editor-1")
        XCTAssertTrue(acceptBegin(policy, document: "editor-1"))
        _ = try request(policy, .contacts)
        let late = reply(processingMillis: 5, leaseMillis: 500, data: ["contacts": []])
        clock += 5
        // iOS can reuse the same document identifier for a different host
        // conversation. The editor generation changed, so the reply is stale.
        XCTAssertTrue(policy.begin(
            documentIdentifier: "editor-1",
            windowDeadlineMonotonicMillis: clock + 20_000
        ))
        XCTAssertNil(policy.acceptResponse(late, snapshot: snapshot(at: clock)))
    }

    func testStaleBeginReplyAfterBootstrapIsRefused() throws {
        let policy = livePolicy()
        _ = try policy.beginRequestData()
        clock += 1_001
        XCTAssertTrue(policy.isBootstrapExpired)
        XCTAssertNil(policy.acceptResponse(
            reply(processingMillis: 5, leaseMillis: 500, data: ["scramble": true]),
            snapshot: snapshot(at: clock)
        ))
        XCTAssertFalse(policy.isBeginAccepted)
    }

    func testIncomingSnapshotIsVerifiedBeforeAnyDataIsApplied() throws {
        let invisible = snapshot(visible: false)
        let deniedAccess = snapshot(fullAccess: false)
        let captured = snapshot(captured: true)
        let wrongDocument = snapshot(document: "editor-2")
        for bad in [invisible, deniedAccess, captured, wrongDocument] {
            let policy = livePolicy()
            XCTAssertTrue(acceptBegin(policy))
            _ = try request(policy, .contacts)
            XCTAssertNil(policy.acceptResponse(
                reply(processingMillis: 0, leaseMillis: 500, data: [
                    "contacts": [["id": "id-1", "name": "Alice", "fingerprint": "ABCD"]]
                ]),
                snapshot: bad
            ))
            XCTAssertNil(policy.contacts())
        }
    }

    func testStaleReplyForADifferentDocumentIsRefused() throws {
        let policy = livePolicy(document: "editor-1")
        XCTAssertTrue(acceptBegin(policy, document: "editor-1"))
        _ = try request(policy, .contacts)
        clock += 10
        XCTAssertNil(policy.acceptResponse(
            reply(processingMillis: 0, leaseMillis: 500, data: ["contacts": []]),
            snapshot: snapshot(document: "editor-2", at: clock)
        ))
        XCTAssertFalse(policy.isAwaitingResponse)
        XCTAssertGreaterThan(policy.revision, 0)
    }

    func testClearSensitiveDropsEveryProjection() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        guard granted(cycle(policy, .decode, payload: ["carrier": .string("cipher")], data: [
            "contactId": "id-1",
            "contactName": "Alice",
            "fingerprint": "ABCD",
            "text": "hello"
        ])) != nil else {
            return XCTFail("expected a granted decode")
        }
        XCTAssertNotNil(policy.preview())
        policy.clearSensitive(notify: false)
        XCTAssertNil(policy.preview())
        XCTAssertNil(policy.pendingId())
        XCTAssertNil(policy.readyState())
        XCTAssertNil(policy.contacts())
        XCTAssertNil(policy.selection())
        XCTAssertNil(policy.authorization())
        XCTAssertFalse(policy.hasSelection)
    }

    func testContactsProjectionDropsMalformedEntriesOnly() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        let oversized = String(repeating: "n", count: 129)
        guard granted(cycle(policy, .contacts, data: [
            "contacts": [
                ["id": "id-1", "name": "Alice", "fingerprint": "ABCD"],
                ["id": "id-2", "name": oversized, "fingerprint": "ABCD"],
                ["id": "", "name": "Bob", "fingerprint": "ABCD"],
                ["name": "NoId", "fingerprint": "ABCD"],
                "not-a-map"
            ]
        ])) != nil else {
            return XCTFail("expected a granted contacts")
        }
        let contacts = policy.contacts()
        XCTAssertEqual(contacts?.count, 1)
        XCTAssertEqual(contacts?.first?.id, "id-1")
    }

    func testScrambleCapabilityDefaultsToFalseAndIsOnlyABoolean() {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy, scramble: true))
        XCTAssertEqual(policy.readyState(), true)

        let second = livePolicy()
        XCTAssertTrue(acceptBegin(second, scramble: "yes"))
        XCTAssertEqual(second.readyState(), false)

        let third = livePolicy()
        XCTAssertTrue(acceptBegin(third))
        XCTAssertEqual(third.readyState(), false)
    }

    // MARK: - Encoder, deadline arithmetic and local editing

    func testEncoderRejectsUnboundedIdentifiersAndMergesTypedPayload() throws {
        XCTAssertThrowsError(
            try KeyboardEditorPolicy.encode(.begin, editorNonce: "", requestId: "r")
        ) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
        XCTAssertThrowsError(
            try KeyboardEditorPolicy.encode(
                .begin,
                editorNonce: String(repeating: "n", count: 129),
                requestId: "r"
            )
        ) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }
        XCTAssertThrowsError(
            try KeyboardEditorPolicy.encode(.begin, editorNonce: "n", requestId: "")
        ) { XCTAssertEqual($0 as? KeyboardPolicyError, .invalid) }

        let data = try KeyboardEditorPolicy.encode(
            .select,
            editorNonce: "n",
            requestId: "r",
            payload: ["contactId": .string("id-1"), "confirm": .bool(true)]
        )
        let object = try plaintext(data)
        XCTAssertEqual(object["operation"] as? String, "select")
        XCTAssertEqual(object["contactId"] as? String, "id-1")
        XCTAssertEqual(object["confirm"] as? Bool, true)
        XCTAssertFalse(object["confirm"] is String)
    }

    func testDeadlineArithmeticIsOverflowSafeAndWindowCapped() {
        XCTAssertEqual(
            KeyboardEditorPolicy.deadline(
                startedAtMonotonicMillis: 1_000,
                processingMillis: 30_000,
                leaseMillis: 1_000,
                windowDeadlineMonotonicMillis: 100_000
            ) ?? -1,
            32_000
        )
        XCTAssertEqual(
            KeyboardEditorPolicy.deadline(
                startedAtMonotonicMillis: 1_000,
                processingMillis: 30_000,
                leaseMillis: 1_000,
                windowDeadlineMonotonicMillis: 5_000
            ) ?? -1,
            5_000
        )
        // Overflow and out-of-range grants fail closed instead of silently
        // falling back to the window deadline.
        XCTAssertNil(KeyboardEditorPolicy.deadline(
            startedAtMonotonicMillis: Int64.max - 1,
            processingMillis: 30_000,
            leaseMillis: 1_000,
            windowDeadlineMonotonicMillis: 7
        ))
        XCTAssertNil(KeyboardEditorPolicy.deadline(
            startedAtMonotonicMillis: 0,
            processingMillis: 30_001,
            leaseMillis: 1_000,
            windowDeadlineMonotonicMillis: 100_000
        ))
        XCTAssertNil(KeyboardEditorPolicy.deadline(
            startedAtMonotonicMillis: 0,
            processingMillis: 0,
            leaseMillis: 0,
            windowDeadlineMonotonicMillis: 100_000
        ))
    }

    func testLocalEditingIsGraphemeAwareAndBounded() {
        var draft = ""
        for character in "Ciao 🇮🇹" {
            draft = KeyboardTextEdit.append(String(character), to: draft) ?? draft
        }
        XCTAssertEqual(draft, "Ciao 🇮🇹")
        XCTAssertEqual(KeyboardTextEdit.backspace(draft), "Ciao ")
        // A regional-indicator pair is one user-perceived character, so dropping
        // it in one step never leaves half a flag behind.
        XCTAssertEqual(KeyboardTextEdit.backspace(KeyboardTextEdit.backspace(draft)), "Ciao")

        XCTAssertNil(KeyboardTextEdit.append("", to: draft))
        XCTAssertEqual(KeyboardTextEdit.bounded("", limit: 4), "")
        XCTAssertFalse(KeyboardTextEdit.isValidDraft(""))
        XCTAssertTrue(KeyboardTextEdit.isValidDraft("hello"))
    }

    func testDraftClampNeverSplitsAGraphemeCluster() {
        let draft = String(repeating: "🇮🇹", count: 3)
        let clamped = KeyboardTextEdit.bounded(draft, limit: 5)
        XCTAssertEqual(clamped, "🇮🇹")
        XCTAssertLessThanOrEqual(clamped?.utf16.count ?? 0, 5)
    }

    func testRevalidationIsRefusedAfterTheEditorEnds() {
        let policy = livePolicy()
        XCTAssertTrue(policy.revalidate(snapshot()))
        _ = policy.endEditor()
        XCTAssertFalse(policy.revalidate(snapshot()))
        XCTAssertTrue(policy.documentChanged(snapshot()))
        XCTAssertNil(policy.currentEditorNonce)
        XCTAssertFalse(policy.isBeginAccepted)
    }
    func testReplyCannotReviveAnExpiredLeaseWithoutTimerTick() throws {
        let policy = livePolicy()
        XCTAssertTrue(acceptBegin(policy))
        _ = try request(policy, .contacts)
        clock += 501
        XCTAssertNil(policy.acceptResponse(
            reply(processingMillis: 500, leaseMillis: 1000, data: ["contacts": []]),
            snapshot: snapshot()))
        XCTAssertFalse(policy.hasLiveLease(at: clock))
    }

    func testReportedProcessingCannotWidenTransportFreshness() throws {
        let policy = livePolicy()
        _ = try policy.beginRequestData()
        let started = clock
        clock += 5
        let grant = granted(policy.acceptResponse(
            reply(processingMillis: 30_000, leaseMillis: 1000), snapshot: snapshot()))
        XCTAssertEqual(grant?.deadlineMonotonicMillis, started + 1000)
        clock = started + 1000
        XCTAssertFalse(policy.liveControl(snapshot()))
    }

    func testLateBootstrapDeniedWithoutTimerTick() throws {
        let policy = livePolicy()
        _ = try policy.beginRequestData()
        clock += 1000
        XCTAssertNil(policy.acceptResponse(reply(processingMillis: 1000, leaseMillis: 1000),
                                          snapshot: snapshot()))
    }

    func testNumericCapabilityDoesNotEnableScramble() {
        for value in [0, 1] {
            let policy = livePolicy()
            XCTAssertTrue(acceptBegin(policy, scramble: value))
            XCTAssertEqual(policy.readyState(), false)
        }
    }

}
