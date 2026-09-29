import Foundation
import XCTest
@testable import SystemKeyboardCore

final class KeyboardCustodyStoreTests: XCTestCase {
    private final class MemoryMirror: KeyboardCustodyMirror {
        var data: Data?
        var failNextSave = false
        func load() throws -> Data? { data }
        func save(_ sealedState: Data) throws {
            if failNextSave {
                failNextSave = false
                throw KeyboardCustodyStore.Failure.unavailable
            }
            data = sealedState
        }
        func remove() throws { data = nil }
    }
    private var directory: URL!
    private var storage: MailboxStorage!
    private let epoch = Data(repeating: 0x41, count: 16)
    private let key = Data(repeating: 0x52, count: 32)

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        storage = try MailboxStorage(directoryURL: directory)
    }
    override func tearDownWithError() throws {
        storage = nil
        try? FileManager.default.removeItem(at: directory)
    }
    private func owner() throws -> KeyboardCustodyStore {
        try KeyboardCustodyStore(storage: storage, epoch: epoch, key: key)
    }

    func testPrepareDoesNotGrantAndActivationCannotRepeat() throws {
        let app = try owner()
        try app.prepare(Data("initial".utf8))
        XCTAssertFalse(app.isKeyboardCustodian())
        XCTAssertThrowsError(try app.loadForKeyboard())
        try app.activate()
        XCTAssertTrue(app.isKeyboardCustodian())
        XCTAssertThrowsError(try app.activate())
        XCTAssertThrowsError(try app.prepare(Data("overwrite".utf8)))
    }

    func testCompareAndSwapAndReclaimRejectStaleWriters() throws {
        let app = try owner()
        try app.prepare(Data("initial".utf8))
        try app.activate()
        let keyboard = try owner()
        XCTAssertEqual(try keyboard.loadForKeyboard().revision, 0)
        XCTAssertEqual(try keyboard.commitForKeyboard(Data("committed".utf8), expectedRevision: 0), 1)
        XCTAssertThrowsError(try app.commitForKeyboard(Data("stale".utf8), expectedRevision: 0))
        let recovered = try app.reclaimForApp()
        XCTAssertEqual(recovered.revision, 1)
        XCTAssertEqual(String(decoding: recovered.plaintext, as: UTF8.self), "committed")
        XCTAssertFalse(keyboard.isKeyboardCustodian())
        XCTAssertThrowsError(try keyboard.commitForKeyboard(Data(), expectedRevision: 1))
        XCTAssertThrowsError(try keyboard.loadForKeyboard())
        XCTAssertThrowsError(try keyboard.activate())
        XCTAssertEqual(try app.reclaimForApp().revision, 1)
    }

    func testKeyFreeRevocationRetainsDurableRecovery() throws {
        let app = try owner()
        try app.prepare(Data("durable".utf8))
        try app.activate()
        try KeyboardCustodyStore.revoke(storage: storage)
        XCTAssertFalse(app.isKeyboardCustodian())
        XCTAssertEqual(try app.reclaimForApp().plaintext, Data("durable".utf8))
        XCTAssertThrowsError(try app.removeAfterImport(expectedRevision: 1))
        try app.removeAfterImport(expectedRevision: 0)
        XCTAssertNil(try storage.readCustodyState())
        XCTAssertNil(try storage.readCustodyControl())
    }

    func testInterruptedPrepareCanOnlyBeRecoveredByApp() throws {
        let app = try owner()
        try app.prepare(Data("prepared".utf8))
        // Crash after durable state but before the initial control write.
        try FileManager.default.removeItem(at: directory.appendingPathComponent("custody.control"))
        XCTAssertThrowsError(try app.prepare(Data("replacement".utf8)))
        XCTAssertThrowsError(try app.activate())
        XCTAssertThrowsError(try app.loadForKeyboard())
        XCTAssertEqual(try app.reclaimForApp().plaintext, Data("prepared".utf8))
    }

    func testMissingWorkingStateNeverFallsBackToInitialState() throws {
        let app = try owner()
        try app.prepare(Data("old".utf8))
        try app.activate()
        _ = try app.commitForKeyboard(Data("new".utf8), expectedRevision: 0)
        try FileManager.default.removeItem(at: directory.appendingPathComponent("custody.state"))
        XCTAssertThrowsError(try app.reclaimForApp())
        XCTAssertThrowsError(try app.loadForKeyboard())
    }

    func testCiphertextAuthenticatesEpochRevisionAndKey() throws {
        let app = try owner()
        let secret = Data("TEST DATA MUST NOT BE PRESENT IN CLEAR".utf8)
        try app.prepare(secret)
        try app.activate()
        let sealed = try XCTUnwrap(storage.readCustodyState())
        XCTAssertNil(sealed.range(of: secret))
        let wrongKey = try KeyboardCustodyStore(storage: storage, epoch: epoch, key: Data(repeating: 0, count: 32))
        XCTAssertThrowsError(try wrongKey.loadForKeyboard())
        let wrongEpoch = try KeyboardCustodyStore(storage: storage, epoch: Data(repeating: 0, count: 16), key: key)
        XCTAssertThrowsError(try wrongEpoch.reclaimForApp())
        var tampered = sealed
        tampered[24] ^= 1
        try storage.writeCustodyState(tampered)
        XCTAssertThrowsError(try app.loadForKeyboard())
    }

    func testClosedKeyAndOversizeCommitCannotAdvanceState() throws {
        let app = try owner()
        try app.prepare(Data())
        try app.activate()
        XCTAssertThrowsError(try app.commitForKeyboard(Data(count: KeyboardCustodyStore.maxPlaintextBytes + 1), expectedRevision: 0))
        XCTAssertEqual(try app.loadForKeyboard().revision, 0)
        app.close()
        XCTAssertFalse(app.isKeyboardCustodian())
        XCTAssertThrowsError(try app.loadForKeyboard())
        XCTAssertThrowsError(try app.reclaimForApp())
    }

    func testImportCleanupResumesAfterStateRemovalAndCannotDeleteAnotherEpoch() throws {
        let app = try owner()
        try app.prepare(Data("committed".utf8))
        _ = try app.reclaimForApp()
        try FileManager.default.removeItem(at: directory.appendingPathComponent("custody.state"))
        let wrongEpoch = try KeyboardCustodyStore(storage: storage,
            epoch: Data(repeating: 99, count: 16), key: key)
        XCTAssertThrowsError(try wrongEpoch.removeAfterImport(expectedRevision: 0))
        XCTAssertNotNil(try storage.readCustodyControl())
        try app.removeAfterImport(expectedRevision: 0)
        XCTAssertNil(try storage.readCustodyControl())
        // A new recovery instance can repeat a fully completed cleanup.
        try owner().removeAfterImport(expectedRevision: 0)
    }

    func testTransientMailboxCleanupPreservesCustodyState() throws {
        let app = try owner()
        try app.prepare(Data("must survive".utf8))
        try storage.removeAll()
        try storage.purgeStaleFiles(nowEpochMillis: Int64.max)
        XCTAssertEqual(try app.reclaimForApp().plaintext, Data("must survive".utf8))
    }

    func testCustodySurvivesIndependentAppAndKeyboardReopens() throws {
        let firstApp = try owner()
        try firstApp.prepare(Data("before".utf8))
        try firstApp.activate()
        firstApp.close()

        let reopenedKeyboardStorage = try MailboxStorage(directoryURL: directory)
        let keyboard = try KeyboardCustodyStore(
            storage: reopenedKeyboardStorage, epoch: epoch, key: key)
        XCTAssertEqual(try keyboard.loadForKeyboard().plaintext, Data("before".utf8))
        XCTAssertEqual(try keyboard.commitForKeyboard(
            Data("after".utf8), expectedRevision: 0), 1)
        keyboard.close()

        let reopenedAppStorage = try MailboxStorage(directoryURL: directory)
        let reopenedApp = try KeyboardCustodyStore(
            storage: reopenedAppStorage, epoch: epoch, key: key)
        let latest = try reopenedApp.reclaimForApp()
        XCTAssertEqual(latest.revision, 1)
        XCTAssertEqual(latest.plaintext, Data("after".utf8))
        try reopenedApp.removeAfterImport(expectedRevision: 1)
        XCTAssertNil(try reopenedAppStorage.readCustodyState())
        XCTAssertNil(try reopenedAppStorage.readCustodyControl())
    }

    func testMirrorRecoversExactLatestStateWhenAppGroupDirectoryIsReplaced() throws {
        let mirror = MemoryMirror()
        let app = try KeyboardCustodyStore(storage: storage, epoch: epoch, key: key,
                                           mirror: mirror)
        try app.prepare(Data("before".utf8))
        try app.activate()
        XCTAssertEqual(try app.commitForKeyboard(Data("latest".utf8),
                                                 expectedRevision: 0), 1)
        let replacement = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: replacement) }
        let newStorage = try MailboxStorage(directoryURL: replacement)
        let reopened = try KeyboardCustodyStore(storage: newStorage, epoch: epoch,
                                                key: key, mirror: mirror)
        XCTAssertFalse(reopened.isKeyboardCustodian())
        let recovered = try reopened.reclaimForApp()
        XCTAssertEqual(recovered.revision, 1)
        XCTAssertEqual(recovered.plaintext, Data("latest".utf8))
        try reopened.removeAfterImport(expectedRevision: 1)
        XCTAssertNil(try mirror.load())
    }

    func testMirrorAheadOfInterruptedFileWriteWinsWithoutRollback() throws {
        let mirror = MemoryMirror()
        let app = try KeyboardCustodyStore(storage: storage, epoch: epoch, key: key,
                                           mirror: mirror)
        try app.prepare(Data("before".utf8))
        try app.activate()
        let oldFile = try XCTUnwrap(storage.readCustodyState())
        XCTAssertEqual(try app.commitForKeyboard(Data("after".utf8),
                                                 expectedRevision: 0), 1)
        try storage.writeCustodyState(oldFile)
        let recovered = try app.reclaimForApp()
        XCTAssertEqual(recovered.revision, 1)
        XCTAssertEqual(recovered.plaintext, Data("after".utf8))
    }

    func testMirrorFailureDoesNotPublishKeyboardCommit() throws {
        let mirror = MemoryMirror()
        let app = try KeyboardCustodyStore(storage: storage, epoch: epoch, key: key,
                                           mirror: mirror)
        try app.prepare(Data("before".utf8))
        try app.activate()
        mirror.failNextSave = true
        XCTAssertThrowsError(try app.commitForKeyboard(Data("unpublished".utf8),
                                                       expectedRevision: 0))
        XCTAssertEqual(try app.reclaimForApp().plaintext, Data("before".utf8))
    }

    func testInterruptedPrepareCanRecoverFromMirrorBeforeActivation() throws {
        let mirror = MemoryMirror()
        let app = try KeyboardCustodyStore(storage: storage, epoch: epoch, key: key,
                                           mirror: mirror)
        try app.prepare(Data("prepared".utf8))
        try FileManager.default.removeItem(at: directory.appendingPathComponent("custody.control"))
        let replacement = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: replacement) }
        let reopened = try KeyboardCustodyStore(
            storage: MailboxStorage(directoryURL: replacement), epoch: epoch,
            key: key, mirror: mirror)
        XCTAssertFalse(reopened.isKeyboardCustodian())
        XCTAssertEqual(try reopened.reclaimForApp().plaintext, Data("prepared".utf8))
        try reopened.removeAfterImport(expectedRevision: 0)
        XCTAssertNil(try mirror.load())
    }

    func testCompletedImportCleansMirrorAndPermitsNewDelegation() throws {
        let mirror = MemoryMirror()
        let app = try KeyboardCustodyStore(storage: storage, epoch: epoch, key: key,
                                           mirror: mirror)
        try app.prepare(Data("one".utf8))
        try app.activate()
        XCTAssertEqual(try app.reclaimForApp().plaintext, Data("one".utf8))
        try app.removeAfterImport(expectedRevision: 0)
        XCTAssertNil(try mirror.load())
        let next = try KeyboardCustodyStore(storage: storage,
            epoch: Data(repeating: 0x72, count: 16), key: key, mirror: mirror)
        try next.prepare(Data("two".utf8))
        XCTAssertNotNil(try mirror.load())
    }

    func testMissingOrBehindMirrorCannotExposeStaleFile() throws {
        let mirror = MemoryMirror()
        let app = try KeyboardCustodyStore(storage: storage, epoch: epoch, key: key,
                                           mirror: mirror)
        try app.prepare(Data("before".utf8))
        try app.activate()
        let oldMirror = try XCTUnwrap(mirror.load())
        XCTAssertEqual(try app.commitForKeyboard(Data("after".utf8),
                                                 expectedRevision: 0), 1)
        mirror.data = oldMirror
        XCTAssertThrowsError(try app.reclaimForApp())
        mirror.data = nil
        XCTAssertThrowsError(try app.reclaimForApp())
    }
}
