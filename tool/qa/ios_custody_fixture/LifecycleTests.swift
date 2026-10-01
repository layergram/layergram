import Foundation
import Security
import XCTest
@testable import SystemKeyboardCore

/// Real installation boundaries; synthetic encrypted protocol snapshots.
/// Does not attest an enabled keyboard or a biometric system prompt.
final class CustodyInstallationTests: XCTestCase {
    private let group = "group.app.layergram.keyboardvalidation.qa"
    private let account = "qa-installation-lifecycle"
    private let epoch = Data(repeating: 0x91, count: 16)
    private let latest = Data("synthetic-ratchet-revision-9".utf8)
    private var journal: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("qa-recovery-key")
    }
    private func mirror() -> KeyboardKeychainCustodyMirror {
        KeyboardKeychainCustodyMirror(group: group, epoch: epoch, account: account)
    }
    private func storage(_ name: String = "qa-lifecycle") throws -> MailboxStorage {
        try MailboxStorage(appGroupIdentifier: group, directoryName: name)
    }
    private func store(key: Data, name: String = "qa-lifecycle") throws -> KeyboardCustodyStore {
        try KeyboardCustodyStore(storage: storage(name), epoch: epoch, key: key, mirror: mirror())
    }

    func testInstallationStage() throws {
        guard Bundle.main.bundleIdentifier == "app.layergram.keyboardvalidation.qa" else {
            throw XCTSkip("Lifecycle removal is confined to the disposable QA identifier")
        }
        let stage = ProcessInfo.processInfo.environment["LAYERGRAM_CUSTODY_STAGE"] ?? "none"
        switch stage {
        case "seed":
            XCTAssertFalse(FileManager.default.fileExists(atPath: journal.path))
            // Clear only this fixture's account left by an interrupted QA run.
            try mirror().remove()
            var key = Data(count: 32)
            let status = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
            XCTAssertEqual(status, errSecSuccess)
            try FileManager.default.createDirectory(at: journal.deletingLastPathComponent(), withIntermediateDirectories: true)
            try key.write(to: journal, options: [.atomic, .completeFileProtection])
            let owner = try store(key: key)
            try owner.prepare(Data("synthetic-initial".utf8)); try owner.activate()
            for revision in 0..<9 {
                _ = try owner.commitForKeyboard(revision == 8 ? latest : Data("synthetic-\(revision)".utf8),
                                                 expectedRevision: UInt64(revision))
            }
            XCTAssertEqual(try owner.loadForKeyboard().revision, 9)
            owner.close()
            // Simulate process death: no reclaim or cleanup before the update.
        case "upgrade":
            let key = try Data(contentsOf: journal)
            let owner = try store(key: key)
            let continued = try owner.loadForKeyboard()
            XCTAssertEqual(continued.revision, 9); XCTAssertEqual(continued.plaintext, latest)
            _ = try owner.commitForKeyboard(latest, expectedRevision: 9)
            owner.close()
            // A replacement App Group directory cannot grant access. Its only
            // valid recovery is the latest authenticated independent copy.
            let replaced = try store(key: key, name: "qa-replacement-\(UUID().uuidString)")
            XCTAssertFalse(replaced.isKeyboardCustodian())
            let recovered = try replaced.reclaimForApp()
            XCTAssertEqual(recovered.revision, 10); XCTAssertEqual(recovered.plaintext, latest)
            replaced.close() // Keep the independent copy for uninstall checks.
        case "fresh":
            XCTAssertFalse(FileManager.default.fileExists(atPath: journal.path), "Uninstall must remove the app-private recovery key")
            // Keychain ciphertext may survive uninstall. It is not a grant,
            // and a fresh installation cannot recover it using a different key.
            XCTAssertNotNil(try mirror().load())
            let fresh = try store(key: Data(repeating: 0x92, count: 32))
            XCTAssertFalse(fresh.isKeyboardCustodian())
            XCTAssertThrowsError(try fresh.reclaimForApp())
            fresh.close()
            // This dedicated test account is disposable; no production mirror
            // is retired implicitly by a new install or a failed recovery.
            try mirror().remove()
            XCTAssertNil(try mirror().load())
        default:
            throw XCTSkip("Set the explicit lifecycle stage to seed, upgrade or fresh")
        }
    }
}
