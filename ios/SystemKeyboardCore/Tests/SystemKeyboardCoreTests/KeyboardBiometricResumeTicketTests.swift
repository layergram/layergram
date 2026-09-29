import Foundation
import XCTest
@testable import SystemKeyboardCore

final class KeyboardBiometricResumeTicketTests: XCTestCase {
    private func ticket(_ changes: [String: Any] = [:]) throws -> Data {
        var row: [String: Any] = [
            "v": 1, "document": "editor-A", "created": 100,
            "expires": 600_100, "key": Data(repeating: 7, count: 32).base64EncodedString(),
            "configuration": [
                "biometricResume": true,
                "epoch": Data(repeating: 2, count: 16).base64EncodedString()
            ]
        ]
        row.merge(changes) { _, newer in newer }
        return try JSONSerialization.data(withJSONObject: row)
    }

    func testExactEditorAndShortLifetime() throws {
        let data = try ticket()
        XCTAssertNotNil(KeyboardBiometricResumeTicket(data: data, document: "editor-A", now: 101))
        XCTAssertNil(KeyboardBiometricResumeTicket(data: data, document: "editor-B", now: 101))
        XCTAssertNotNil(KeyboardBiometricResumeTicket(
            data: data, document: "editor-B", now: 101, allowBiometricEditorRebind: true))
        XCTAssertNil(KeyboardBiometricResumeTicket(data: data, document: "editor-A", now: 99))
        XCTAssertNil(KeyboardBiometricResumeTicket(data: data, document: "editor-A", now: 600_100))
        XCTAssertNil(KeyboardBiometricResumeTicket(
            data: data, document: "editor-B", now: 600_100,
            allowBiometricEditorRebind: true))
        XCTAssertNil(KeyboardBiometricResumeTicket(data: try ticket(["expires": 600_101]),
                                                    document: "editor-A", now: 101))
    }

    func testReconnectDoesNotConfuseShortcutExpiryWithLiveSessionIdle() {
        let deadline: Int64 = 600_100
        for now in [deadline - 1, deadline, deadline + 60_000] {
            for authenticating in [false, true] {
                XCTAssertEqual(KeyboardBiometricResumeGate.reconnectAction(
                    hasRuntime: true, authenticationPending: authenticating,
                    expiresAt: deadline, now: now), .keepRuntime)
            }
        }
        XCTAssertEqual(KeyboardBiometricResumeGate.reconnectAction(
            hasRuntime: false, authenticationPending: true,
            expiresAt: deadline, now: deadline), .waitForAuthentication)
        XCTAssertEqual(KeyboardBiometricResumeGate.reconnectAction(
            hasRuntime: false, authenticationPending: false,
            expiresAt: deadline, now: deadline), .expireShortcut)
        XCTAssertEqual(KeyboardBiometricResumeGate.reconnectAction(
            hasRuntime: false, authenticationPending: false,
            expiresAt: deadline, now: deadline - 1), .seekAppWindow)
        XCTAssertEqual(KeyboardBiometricResumeGate.reconnectAction(
            hasRuntime: false, authenticationPending: false,
            expiresAt: nil, now: deadline), .seekAppWindow)
        // A reconnect decision grants nothing: the expired ticket remains
        // unusable even while a different live session is kept running.
        XCTAssertFalse(KeyboardBiometricResumeGate.mayAttempt(available: true,
            expectedDocument: "editor-A", expiresAt: deadline,
            snapshot: KeyboardEditorSnapshot(isViewVisible: true, hasFullAccess: true,
                isCaptured: false, documentIdentifier: "editor-A", monotonicMillis: deadline)))
    }

    func testFactoryIssuesRevocableBiometricCapabilityForLongIdle() throws {
        let configuration: [String: Any] = [
            "biometricResume": true,
            "epoch": Data(repeating: 2, count: 16).base64EncodedString()
        ]
        let data = try XCTUnwrap(KeyboardBiometricResumeTicket.encode(
            document: "editor-A", key: Data(repeating: 7, count: 32),
            configuration: configuration, createdAt: 100))
        let row = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(row["v"] as? Int, 2)
        XCTAssertEqual(row["created"] as? Int64, 100)
        XCTAssertEqual(row["expires"] as? Int64,
                       KeyboardBiometricResumeTicket.revocableDeadlineMillis)
        XCTAssertNotNil(KeyboardBiometricResumeTicket(
            data: data, document: "editor-A", now: 100 + 9 * 60 * 60 * 1_000))
        XCTAssertNotNil(KeyboardBiometricResumeTicket(
            data: data, document: "editor-A", now: 1))
        XCTAssertNil(KeyboardBiometricResumeTicket(
            data: data, document: "editor-B", now: 200))
        let hint = try XCTUnwrap(KeyboardBiometricResumeHint.encode(ticketData: data))
        XCTAssertEqual(KeyboardBiometricResumeHint.admission(
            data: hint, document: "editor-A", now: 100 + 9 * 60 * 60 * 1_000),
            .matched(KeyboardBiometricResumeTicket.revocableDeadlineMillis))
        XCTAssertEqual(KeyboardBiometricResumeHint.admission(
            data: hint, document: "editor-B", now: 200),
            .differentEditor(KeyboardBiometricResumeTicket.revocableDeadlineMillis))
        XCTAssertTrue(KeyboardBiometricResumeGate.mayAttempt(
            available: true, expectedDocument: "editor-A",
            expiresAt: KeyboardBiometricResumeTicket.revocableDeadlineMillis,
            snapshot: KeyboardEditorSnapshot(isViewVisible: true, hasFullAccess: true,
                isCaptured: false, documentIdentifier: "editor-A",
                monotonicMillis: 100 + 9 * 60 * 60 * 1_000)))
        XCTAssertFalse(KeyboardBiometricResumeGate.mayAttempt(
            available: true, expectedDocument: "editor-A",
            expiresAt: KeyboardBiometricResumeTicket.revocableDeadlineMillis,
            snapshot: KeyboardEditorSnapshot(isViewVisible: true, hasFullAccess: true,
                isCaptured: true, documentIdentifier: "editor-A",
                monotonicMillis: 100 + 9 * 60 * 60 * 1_000)))
        XCTAssertNil(KeyboardBiometricResumeTicket.encode(
            document: "editor-A", key: Data(repeating: 7, count: 31),
            configuration: configuration, createdAt: 100))
        XCTAssertNil(KeyboardBiometricResumeTicket.encode(
            document: "editor-A", key: Data(repeating: 7, count: 32),
            configuration: configuration, createdAt: Int64.max))
    }

    func testRevocableVersionRejectsForgedDeadlineAndDisabledSetting() throws {
        let configuration: [String: Any] = [
            "biometricResume": true,
            "epoch": Data(repeating: 2, count: 16).base64EncodedString()
        ]
        let data = try XCTUnwrap(KeyboardBiometricResumeTicket.encode(
            document: "editor-A", key: Data(repeating: 7, count: 32),
            configuration: configuration, createdAt: 100))
        var row = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        row["expires"] = Int64.max - 1
        let shortened = try JSONSerialization.data(withJSONObject: row)
        XCTAssertNil(KeyboardBiometricResumeTicket(data: shortened,
                                                    document: "editor-A", now: 200))
        XCTAssertNil(KeyboardBiometricResumeHint.encode(ticketData: shortened))
        row["expires"] = Int64.max
        row["configuration"] = ["biometricResume": false,
                                "epoch": Data(repeating: 2, count: 16).base64EncodedString()]
        XCTAssertNil(KeyboardBiometricResumeTicket(
            data: try JSONSerialization.data(withJSONObject: row),
            document: "editor-A", now: 200))
    }

    func testMalformedOrDisabledCapabilityIsRejected() throws {
        XCTAssertNil(KeyboardBiometricResumeTicket(data: try ticket(["key": "bad"]),
                                                    document: "editor-A", now: 101))
        XCTAssertNil(KeyboardBiometricResumeTicket(data: try ticket(["configuration": [
            "biometricResume": false,
            "epoch": Data(repeating: 2, count: 16).base64EncodedString()]]),
            document: "editor-A", now: 101))
        XCTAssertNil(KeyboardBiometricResumeTicket(data: try ticket(["configuration": [
            "biometricResume": true, "epoch": "AA=="]]),
            document: "editor-A", now: 101))
    }

    func testOnlyExactVisibleUncapturedEditorMayConsumeResumeTouch() {
        func snapshot(document: String?, visible: Bool = true, fullAccess: Bool = true,
                      captured: Bool = false, now: Int64 = 200) -> KeyboardEditorSnapshot {
            KeyboardEditorSnapshot(isViewVisible: visible, hasFullAccess: fullAccess,
                                   isCaptured: captured, documentIdentifier: document,
                                   monotonicMillis: now)
        }
        func admits(_ current: KeyboardEditorSnapshot) -> Bool {
            KeyboardBiometricResumeGate.mayAttempt(available: true,
                expectedDocument: "editor-A", expiresAt: 600_100, snapshot: current)
        }
        XCTAssertTrue(admits(snapshot(document: "editor-A")))
        XCTAssertFalse(admits(snapshot(document: "editor-B")))
        XCTAssertFalse(admits(snapshot(document: nil)))
        XCTAssertFalse(admits(snapshot(document: "editor-A", visible: false)))
        XCTAssertFalse(admits(snapshot(document: "editor-A", fullAccess: false)))
        XCTAssertFalse(admits(snapshot(document: "editor-A", captured: true)))
        XCTAssertFalse(admits(snapshot(document: "editor-A", now: 600_100)))
        XCTAssertFalse(KeyboardBiometricResumeGate.mayAttempt(available: false,
            expectedDocument: "editor-A", expiresAt: 600_100,
            snapshot: snapshot(document: "editor-A")))
    }

    func testPreAppearanceWarningMayKeepOnlyASealedTicketWithIndependentPrivacySetting() {
        func admits(runtime: Bool = false, owner: Bool = false, appeared: Bool = false,
                    protected: Bool = true, host: Bool = true, access: Bool = true,
                    captured: Bool = false) -> Bool {
            KeyboardBiometricResumeGate.mayDeferSealedTicketRevocationBeforeAppearance(
                hasRuntime: runtime, hasOwnerSession: owner, hasAppeared: appeared,
                protectionEnabled: protected, secureHostReady: host,
                fullAccess: access, captured: captured)
        }
        XCTAssertTrue(admits())
        XCTAssertFalse(admits(runtime: true))
        XCTAssertFalse(admits(owner: true))
        XCTAssertFalse(admits(appeared: true))
        XCTAssertTrue(admits(protected: false, host: false))
        XCTAssertFalse(admits(host: false))
        XCTAssertFalse(admits(access: false))
        XCTAssertFalse(admits(captured: true))
    }

    func testSealedBiometricHintDoesNotRequireScreenshotProtectionButStillDeniesCapture() {
        for protected in [false, true] {
            XCTAssertTrue(KeyboardBiometricResumeGate.mayKeepSealedHint(
                protectionEnabled: protected, secureHostReady: true, fullAccess: true, captured: false))
            XCTAssertFalse(KeyboardBiometricResumeGate.mayKeepSealedHint(
                protectionEnabled: protected, secureHostReady: true, fullAccess: false, captured: false))
            XCTAssertFalse(KeyboardBiometricResumeGate.mayKeepSealedHint(
                protectionEnabled: protected, secureHostReady: true, fullAccess: true, captured: true))
        }
        XCTAssertFalse(KeyboardBiometricResumeGate.mayKeepSealedHint(
            protectionEnabled: true, secureHostReady: false, fullAccess: true, captured: false))
    }

    func testResumeHintContainsOnlyEditorHashAndStillRequiresExactEditor() throws {
        let hint = try XCTUnwrap(KeyboardBiometricResumeHint.encode(ticketData: ticket()))
        let text = try XCTUnwrap(String(data: hint, encoding: .utf8))
        let row = try XCTUnwrap(JSONSerialization.jsonObject(with: hint) as? [String: Any])
        XCTAssertEqual(Set(row.keys), Set(["v", "documentHash", "expires"]))
        XCTAssertFalse(text.contains("editor-A"))
        XCTAssertEqual(KeyboardBiometricResumeHint(data: hint, document: "editor-A",
                                                   now: 200)?.expiresAt, 600_100)
        XCTAssertNil(KeyboardBiometricResumeHint(data: hint, document: "editor-B", now: 200))
        XCTAssertEqual(KeyboardBiometricResumeHint.admission(
            data: hint, document: "editor-B", now: 200), .differentEditor(600_100))
        XCTAssertEqual(KeyboardBiometricResumeHint.admission(
            data: hint, document: "editor-A", now: 200), .matched(600_100))
        XCTAssertEqual(KeyboardBiometricResumeHint.admission(
            data: hint, document: "editor-A", now: 600_100), .invalid)
        XCTAssertNil(KeyboardBiometricResumeHint(data: hint, document: "editor-A", now: 600_100))
        XCTAssertNil(KeyboardBiometricResumeHint.encode(ticketData: try ticket(["key": "bad"])))
    }
}
