import Flutter
@testable import SystemKeyboardCore
import UIKit
import XCTest
@testable import Runner

/// Exercises the actual UIKit host, method-channel codec and protected mailbox.
/// The Dart peer is synthetic; V3/history behavior has separate Dart tests.
final class SystemKeyboardHostTests: XCTestCase {
  private final class CaptureProbe { var active = false }
  private var fixtureDirectories: [URL] = []
  override func tearDownWithError() throws {
    // Only unique synthetic fixture directories, never the live keyboard state.
    for directory in fixtureDirectories { try FileManager.default.removeItem(at: directory) }
    fixtureDirectories.removeAll()
    try super.tearDownWithError()
  }
  private final class Messenger: NSObject, FlutterBinaryMessenger {
    let codec = FlutterStandardMethodCodec.sharedInstance()
    var handlers: [String: FlutterBinaryMessageHandler] = [:]
    var received: [[String: Any]] = []
    var pendingReply: FlutterBinaryReply?
    var delayReply = false
    var replyBody: [String: Any]?

    func send(onChannel channel: String, message: Data?) {
      send(onChannel: channel, message: message, binaryReply: nil)
    }
    func send(onChannel channel: String, message: Data?, binaryReply callback: FlutterBinaryReply?) {
      guard let message else { callback?(nil); return }
      let call = codec.decodeMethodCall(message)
      guard call.method == "request", let request = call.arguments as? [String: Any] else {
        callback?(nil); return
      }
      received.append(request)
      if delayReply { pendingReply = callback } else { callback?(success()) }
    }
    func setMessageHandlerOnChannel(_ channel: String,
                                   binaryMessageHandler handler: FlutterBinaryMessageHandler?) -> FlutterBinaryMessengerConnection {
      handlers[channel] = handler
      return 1
    }
    func cleanUpConnection(_ connection: FlutterBinaryMessengerConnection) { handlers.removeAll() }
    func success() -> Data {
      codec.encodeSuccessEnvelope(replyBody ?? ["status": "ok", "processingMillis": 0,
                                   "leaseMillis": 1000, "data": ["scramble": false]])
    }
    func call(_ method: String, arguments: Any? = nil, channel: String = "layergram/system_keyboard") throws -> Any? {
      var value: Any?
      var answered = false
      let request = codec.encode(FlutterMethodCall(methodName: method, arguments: arguments))
      handlers[channel]?(request) { reply in
        answered = true
        if let reply { value = self.codec.decodeEnvelope(reply) }
      }
      XCTAssertTrue(answered)
      return value
    }
  }

  private func fixture(captureActive: @escaping () -> Bool = { UIScreen.main.isCaptured }) throws
    -> (SystemKeyboardHost, Messenger, MailboxStorage, UserDefaults) {
    guard MailboxCryptoAvailability.isSupported else { throw XCTSkip("Requires iOS 26 or later") }
    var hostBundle = Bundle.main
    // The isolated signed QA host has its own real App Group. Its channel
    // tests need only embedded-target metadata, not a live keyboard extension.
    // Never borrow the group or files of the real UI conversation.
    if Bundle.main.bundleIdentifier == "app.layergram.keyboardvalidation.qa" {
      let url = FileManager.default.temporaryDirectory.appendingPathComponent("KeyboardHostFixture-\(UUID().uuidString).app")
      let plugin = url.appendingPathComponent("PlugIns/LayergramKeyboard.appex")
      try FileManager.default.createDirectory(at: plugin, withIntermediateDirectories: true)
      let group = try XCTUnwrap(Bundle.main.object(forInfoDictionaryKey: "KeyboardAppGroupId") as? String)
      let info: [String: Any] = ["CFBundleIdentifier": "app.layergram.keyboardvalidation.qa.hostfixture",
                                "CFBundlePackageType": "APPL", "KeyboardAppGroupId": group]
      try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        .write(to: url.appendingPathComponent("Info.plist"))
      try Data().write(to: plugin.appendingPathComponent("Info.plist"))
      fixtureDirectories.append(url)
      hostBundle = try XCTUnwrap(Bundle(url: url))
    }
    guard let plugins = hostBundle.builtInPlugInsURL,
          FileManager.default.fileExists(atPath: plugins.appendingPathComponent("LayergramKeyboard.appex/Info.plist").path)
    else { throw XCTSkip("Use the experimental embedded-keyboard build for host integration tests") }
    let group = try XCTUnwrap(Bundle.main.object(forInfoDictionaryKey: "KeyboardAppGroupId") as? String)
    let suffix = UUID().uuidString
    let mailboxDirectory = "test-mailbox-\(suffix)"
    let custodyDirectory = "test-custody-\(suffix)"
    let storage: MailboxStorage
    do { storage = try MailboxStorage(appGroupIdentifier: group, directoryName: mailboxDirectory) }
    catch let error as MailboxError {
      XCTFail("Mailbox setup failed: \(error.reason)")
      throw error
    }
    let defaults = try XCTUnwrap(UserDefaults(suiteName: "keyboard-host-tests.\(UUID().uuidString)"))
    defaults.set(custodyDirectory, forKey: "testCustodyDirectory")
    fixtureDirectories.append(storage.directoryURL)
    let custodyStorage = try MailboxStorage(appGroupIdentifier: group, directoryName: custodyDirectory)
    fixtureDirectories.append(custodyStorage.directoryURL)
    let messenger = Messenger()
    let host = SystemKeyboardHost(messenger: messenger, bundle: hostBundle, defaults: defaults,
                                  mailboxDirectoryName: mailboxDirectory,
                                  custodyDirectoryName: custodyDirectory,
                                  captureActive: captureActive)
    XCTAssertEqual(try messenger.call("configure", arguments: ["enabled": true]) as? Bool, true)
    return (host, messenger, storage, defaults)
  }

  func testExpiredDelegationDeliveryGetsFreshLeaseWithoutSecondGrant() throws {
    let (host, messenger, storage, _) = try fixture()
    defer { host.disconnect() }
    host.willResignActive()
    let session = try MailboxClient(storage: storage).attach()
    let deadline = session.deadlineMonotonicMillis
    let grant: [String: Any] = ["status": "ok", "mode": "autonomous-v1",
                              "key": Data(repeating: 7, count: 32).base64EncodedString(),
                              "configuration": ["editorNonce": "same-editor"]]
    messenger.replyBody = grant
    messenger.delayReply = true
    func send(_ id: String, nonce: String = "same-editor", operation: String = "delegate") throws {
      try session.send(payload: JSONSerialization.data(withJSONObject: [
        "operation": operation, "editorNonce": nonce, "requestId": id]))
    }
    try send("first")
    try waitFor { messenger.pendingReply != nil }
    // Simulate a stalled platform reply after the exclusive request lease.
    Thread.sleep(forTimeInterval: 1.05)
    messenger.pendingReply?(messenger.success())
    messenger.pendingReply = nil
    XCTAssertThrowsError(try session.pollResponse())
    XCTAssertTrue(session.canReplaceExpiredRequest)
    XCTAssertEqual(session.deadlineMonotonicMillis, deadline)
    try send("fresh")
    var reply: Data?
    try waitFor {
      if reply != nil { return true }
      if case .response(let bytes) = try session.pollResponse() { reply = bytes; return true }
      return false
    }
    let decoded = try JSONSerialization.jsonObject(with: try XCTUnwrap(reply)) as! [String: Any]
    XCTAssertEqual(decoded["key"] as? String, grant["key"] as? String)
    XCTAssertEqual(messenger.received.count, 1, "The custody grant is consumed exactly once")
    XCTAssertEqual(session.deadlineMonotonicMillis, deadline)
    try send("ack", operation: "delegateAck")
    try waitFor { try storage.readRendezvous() == nil }
    XCTAssertEqual(messenger.received.count, 1)
  }

  func testCachedDelegationCannotMoveToAnotherEditor() throws {
    let (host, messenger, storage, _) = try fixture()
    defer { host.disconnect() }
    host.willResignActive()
    let session = try MailboxClient(storage: storage).attach()
    messenger.replyBody = ["status": "ok", "mode": "autonomous-v1", "key": "sealed-fixture",
                           "configuration": ["editorNonce": "first-editor"]]
    try session.send(payload: JSONSerialization.data(withJSONObject: [
      "operation": "delegate", "editorNonce": "first-editor", "requestId": "first"]))
    var received = false
    try waitFor {
      if received { return true }
      if case .response = try session.pollResponse() { received = true; return true }
      return false
    }
    try session.send(payload: JSONSerialization.data(withJSONObject: [
      "operation": "delegate", "editorNonce": "different-editor", "requestId": "second"]))
    try waitFor { try storage.readRendezvous() == nil }
    XCTAssertEqual(messenger.received.count, 1)
  }

  func testClientReplacementBeforeOwnerDeadlineKeepsOneGrant() throws {
    let (host, messenger, storage, _) = try fixture()
    defer { host.disconnect() }
    host.willResignActive()
    let session = try MailboxClient(storage: storage).attach()
    let deadline = session.deadlineMonotonicMillis
    messenger.replyBody = ["status": "ok", "mode": "autonomous-v1", "key": "one-grant",
                           "configuration": ["editorNonce": "same-editor"]]
    messenger.delayReply = true
    func send(_ id: String) throws {
      try session.send(payload: JSONSerialization.data(withJSONObject: [
        "operation": "delegate", "editorNonce": "same-editor", "requestId": id]))
    }
    try send("first")
    try waitFor { messenger.pendingReply != nil }
    Thread.sleep(forTimeInterval: 0.92)
    XCTAssertTrue(session.canReplaceExpiredRequest)
    try send("replacement")
    // The old owner handle can still be live. Its response must not poison
    // the unread replacement and must not revoke the original window.
    messenger.pendingReply?(messenger.success())
    messenger.pendingReply = nil
    XCTAssertEqual(try session.pollResponse(), .idle)
    var reply: Data?
    try waitFor {
      if reply != nil { return true }
      if case .response(let bytes) = try session.pollResponse() { reply = bytes; return true }
      return false
    }
    let value = try JSONSerialization.jsonObject(with: try XCTUnwrap(reply)) as! [String: Any]
    XCTAssertEqual(value["key"] as? String, "one-grant")
    XCTAssertEqual(messenger.received.count, 1)
    XCTAssertEqual(session.deadlineMonotonicMillis, deadline)
  }

  private func waitFor(_ condition: () throws -> Bool) throws {
    let deadline = Date().addingTimeInterval(0.6)
    while !(try condition()), Date() < deadline {
      RunLoop.main.run(until: Date().addingTimeInterval(0.01))
    }
    XCTAssertTrue(try condition())
  }

  func testStalledMainThreadCanOnlyReturnBusyWithinTheOriginalLease() throws {
    let (host, messenger, storage, _) = try fixture()
    defer { host.disconnect() }
    host.willResignActive()
    let session = try MailboxClient(storage: storage).attach()
    let originalDeadline = session.deadlineMonotonicMillis
    messenger.replyBody = ["status": "busy"]
    try session.send(payload: JSONSerialization.data(withJSONObject: [
      "operation": "delegate", "editorNonce": "stalled-editor", "requestId": "stalled-request"
    ]))
    var preparing = false
    try waitFor {
      if case .response = try session.pollResponse() { preparing = true }
      return preparing
    }
    try session.send(payload: JSONSerialization.data(withJSONObject: [
      "operation": "delegate", "editorNonce": "stalled-editor", "requestId": "stalled-request-2"
    ]))
    // Intentionally block the main run loop, like the observed cold handoff.
    Thread.sleep(forTimeInterval: 0.5)
    guard case .response(let bytes) = try session.pollResponse() else {
      return XCTFail("The busy responder must not need the main run loop")
    }
    let reply = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    XCTAssertEqual(reply.count, 1)
    XCTAssertEqual(reply["status"] as? String, "busy")
    XCTAssertEqual(session.deadlineMonotonicMillis, originalDeadline)
    XCTAssertEqual(messenger.received.count, 1, "the worker must never call Dart or grant authority")
    host.didBecomeActive()
    XCTAssertFalse(MailboxClient(storage: storage).hasLiveWindow())
  }

  func testLiveHostForwardsOnlyThroughExistingChannelAndResumeClosesWindow() throws {
    let (host, messenger, storage, _) = try fixture()
    defer { host.disconnect() }
    host.willResignActive()
    let client = MailboxClient(storage: storage)
    let session = try client.attach()
    let data = try JSONSerialization.data(withJSONObject: [
      "operation": "begin", "editorNonce": "test-editor", "requestId": "test-request"
    ])
    try session.send(payload: data)
    var response: Data?
    try waitFor {
      if response != nil { return true }
      if case .response(let bytes) = try session.pollResponse() { response = bytes }
      return response != nil
    }
    XCTAssertEqual(messenger.received.count, 1)
    XCTAssertEqual(messenger.received.first?["operation"] as? String, "begin")
    let reply = try JSONSerialization.jsonObject(with: XCTUnwrap(response)) as? [String: Any]
    XCTAssertEqual(reply?["status"] as? String, "ok")
    #if !targetEnvironment(simulator)
    let attrs = try FileManager.default.attributesOfItem(atPath: storage.directoryURL.path)
    let protection = (attrs[.protectionKey] as? FileProtectionType)?.rawValue
      ?? (attrs[.protectionKey] as? String)
    XCTAssertEqual(protection, FileProtectionType.complete.rawValue)
    #endif
    host.didBecomeActive()
    XCTAssertFalse(client.hasLiveWindow())
  }

  func testReturningToAppThenLeavingOpensAFreshWindow() throws {
    let (host, _, storage, _) = try fixture()
    defer { host.disconnect() }
    let client = MailboxClient(storage: storage)

    host.willResignActive()
    let first = try readRendezvous(storage).sessionId
    XCTAssertTrue(client.hasLiveWindow())
    host.didBecomeActive()
    XCTAssertFalse(client.hasLiveWindow())

    host.willResignActive()
    let second = try readRendezvous(storage).sessionId
    XCTAssertNotEqual(first, second)
    XCTAssertTrue(client.hasLiveWindow(excluding: first))
  }

  func testRevokedHostCannotPublishDelayedDartReply() throws {
    let (host, messenger, storage, _) = try fixture()
    defer { host.disconnect() }
    messenger.delayReply = true
    host.willResignActive()
    let client = MailboxClient(storage: storage)
    let session = try client.attach()
    try session.send(payload: JSONSerialization.data(withJSONObject: [
      "operation": "begin", "editorNonce": "test-editor", "requestId": "test-request"
    ]))
    try waitFor { messenger.pendingReply != nil }
    let delayed = try XCTUnwrap(messenger.pendingReply)
    _ = try messenger.call("revoke")
    delayed(messenger.success())
    XCTAssertFalse(client.hasLiveWindow())
    do {
      if case .response = try session.pollResponse() {
        XCTFail("Revoked owner published a delayed response")
      }
    } catch let error as MailboxError {
      XCTAssertEqual(error.kind, .unavailable)
    }
    XCTAssertFalse(FileManager.default.fileExists(atPath:
      storage.directoryURL.appendingPathComponent(MailboxConstants.responseFileName).path))
  }

  func testDisabledHostNeverOpensOrRenewsWindow() throws {
    let (host, messenger, storage, _) = try fixture()
    defer { host.disconnect() }
    XCTAssertEqual(try messenger.call("configure", arguments: ["enabled": false]) as? Bool, true)
    host.willResignActive()
    XCTAssertFalse(MailboxClient(storage: storage).hasLiveWindow())
    XCTAssertEqual(try messenger.call("configure", arguments: ["enabled": true]) as? Bool, true)
    host.willResignActive()
    XCTAssertFalse(MailboxClient(storage: storage).hasLiveWindow())
    host.didBecomeActive()
    host.willResignActive()
    XCTAssertTrue(MailboxClient(storage: storage).hasLiveWindow())
  }

  func testAutonomousAcknowledgementClosesBootstrapButManualLockRevokesCustody() throws {
    let (host, messenger, mailbox, defaults) = try fixture()
    defer { host.disconnect() }
    let group = try XCTUnwrap(Bundle.main.object(forInfoDictionaryKey: "KeyboardAppGroupId") as? String)
    let storage = try MailboxStorage(appGroupIdentifier: group, directoryName: XCTUnwrap(defaults.string(forKey: "testCustodyDirectory")))
    if try messenger.call("hasPending", channel: "layergram/keyboard_custody") as? Bool == true {
      throw XCTSkip("Recover the previous keyboard session before this synthetic custody test")
    }
    let epoch = Data(repeating: 1, count: 16)
    let key = Data(repeating: 2, count: 32)
    let bytes = Data("synthetic custody test".utf8)
    let args: [String: Any] = ["epoch": FlutterStandardTypedData(bytes: epoch),
                               "key": FlutterStandardTypedData(bytes: key)]
    let store = try KeyboardCustodyStore(storage: storage, epoch: epoch, key: key,
        mirror: KeyboardKeychainCustodyMirror(group: group, epoch: epoch))
    defer {
      if let recovered = try? store.reclaimForApp() { try? store.removeAfterImport(expectedRevision: recovered.revision) }
      store.close()
    }
    // A parent that has not departed must not create a usable delegation.
    let prepareArgs = args.merging(["snapshot": FlutterStandardTypedData(bytes: bytes)]) { _, new in new }
    XCTAssertTrue(try messenger.call("prepare", arguments: prepareArgs,
                                    channel: "layergram/keyboard_custody") is FlutterError)
    host.willResignActive()
    XCTAssertNil(try messenger.call("prepare", arguments: prepareArgs, channel: "layergram/keyboard_custody"))
    XCTAssertNil(try messenger.call("activate", arguments: args, channel: "layergram/keyboard_custody"))
    XCTAssertTrue(store.isKeyboardCustodian())
    let client = MailboxClient(storage: mailbox)
    let session = try client.attach()
    messenger.replyBody = ["status": "ok", "mode": "autonomous-v1", "key": key.base64EncodedString(),
                           "configuration": ["epoch": epoch.base64EncodedString()]]
    try session.send(payload: JSONSerialization.data(withJSONObject: [
      "operation": "delegate", "editorNonce": "fresh-editor", "requestId": "fresh-delegate"
    ]))
    var answered = false
    try waitFor {
      if answered { return true }
      if case .response = try session.pollResponse() { answered = true }
      return answered
    }
    try session.send(payload: JSONSerialization.data(withJSONObject: [
      "operation": "delegateAck", "editorNonce": "fresh-editor", "requestId": "fresh-ack"
    ]))
    try waitFor { !client.hasLiveWindow() }
    XCTAssertTrue(store.isKeyboardCustodian(), "Bootstrap closure must not revoke an acknowledged handoff")
    XCTAssertEqual(try store.loadForKeyboard().plaintext, bytes)
    _ = try messenger.call("revoke")
    XCTAssertFalse(store.isKeyboardCustodian(), "Manual app lock must revoke an autonomous session")
    XCTAssertTrue(try messenger.call("activate", arguments: args, channel: "layergram/keyboard_custody") is FlutterError)
    XCTAssertFalse(store.isKeyboardCustodian(), "Late activation after lock must fail closed")
    XCTAssertEqual(try store.reclaimForApp().plaintext, bytes)
  }

  // MARK: - Protected storage

  func testKeychainMirrorSurvivesIndependentAppGroupDirectoryReplacement() throws {
    let group = try XCTUnwrap(Bundle.main.object(forInfoDictionaryKey: "KeyboardAppGroupId") as? String)
    let epoch = Data(UUID().uuidString.utf8.prefix(16))
    let key = Data(repeating: 0x62, count: 32)
    let mirror = KeyboardKeychainCustodyMirror(group: group, epoch: epoch,
                                               account: "custody-test-\(UUID().uuidString)")
    defer { try? mirror.remove() }
    let first = try MailboxStorage(appGroupIdentifier: group,
                                   directoryName: "test-custody-\(UUID().uuidString)")
    fixtureDirectories.append(first.directoryURL)
    let app = try KeyboardCustodyStore(storage: first, epoch: epoch, key: key,
                                       mirror: mirror)
    defer { app.close() }
    try app.prepare(Data("old".utf8))
    try app.activate()
    XCTAssertEqual(try app.commitForKeyboard(Data("new".utf8), expectedRevision: 0), 1)
    // This is a different protected directory, as after an App Group container
    // replacement. The Keychain item remains in the independently stored group.
    let second = try MailboxStorage(appGroupIdentifier: group,
                                    directoryName: "test-custody-\(UUID().uuidString)")
    fixtureDirectories.append(second.directoryURL)
    let reopened = try KeyboardCustodyStore(storage: second, epoch: epoch,
                                             key: key, mirror: mirror)
    defer { reopened.close() }
    XCTAssertFalse(reopened.isKeyboardCustodian())
    let recovered = try reopened.reclaimForApp()
    XCTAssertEqual(recovered.revision, 1)
    XCTAssertEqual(recovered.plaintext, Data("new".utf8))
    try reopened.removeAfterImport(expectedRevision: 1)
    XCTAssertNil(try mirror.load())
  }

  /// Reads back the iOS data-protection class of a filesystem item. Returns nil
  /// on the Simulator, where the attribute does not exist and the production
  /// code takes a compile-time no-op branch.
  private func protectionClass(ofItemAt url: URL) throws -> String? {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    return (attributes[.protectionKey] as? FileProtectionType)?.rawValue
      ?? (attributes[.protectionKey] as? String)
  }

  private func readRendezvous(_ storage: MailboxStorage) throws -> MailboxRendezvous {
    let data = try storage.readRendezvous()
    let document = try XCTUnwrap(data, "mailbox rendezvous is missing")
    return try MailboxRendezvous.decode(document)
  }

  /// Exercises the real shared mailbox directory. Every fixed final leaf written
  /// through the public storage API must be `FileProtectionType.complete` on a
  /// physical device, the directory itself must be backup-excluded (files
  /// created inside inherit that exclusion, so a per-leaf exclusion flag is
  /// deliberately not required), and no fixed staging leaf may survive a
  /// successful atomic write.
  func testMailboxStorageProtectsEveryFinalLeafAndLeavesNoStagingFile() throws {
    let (host, _, storage, _) = try fixture()
    defer { host.disconnect() }
    try storage.removeAll()
    defer { try? storage.removeAll() }

    // Harmless synthetic bytes only: this test never handles a real payload and
    // logs no content.
    try storage.writeRendezvous(Data(repeating: 0x52, count: 48))
    try storage.withExclusiveLock {}
    try storage.writeRequest(Data(repeating: 0x51, count: 48))
    try storage.writeResponse(Data(repeating: 0x50, count: 48))

    let directory = storage.directoryURL
    let leafPaths = [
      directory,
      directory.appendingPathComponent(MailboxConstants.rendezvousFileName),
      directory.appendingPathComponent(MailboxConstants.requestFileName),
      directory.appendingPathComponent(MailboxConstants.responseFileName),
      directory.appendingPathComponent(MailboxConstants.lockFileName),
    ]
    for path in leafPaths {
      XCTAssertTrue(FileManager.default.fileExists(atPath: path.path),
                    "\(path.lastPathComponent) was not written")
    }

    #if !targetEnvironment(simulator)
    // Physical device only: iOS data protection is applied and read back by the
    // storage layer. The Simulator has no such attribute, so the device build
    // is the only place this can be asserted.
    for path in leafPaths {
      let protection = try protectionClass(ofItemAt: path)
      XCTAssertEqual(protection, FileProtectionType.complete.rawValue,
                     "\(path.lastPathComponent) is not FileProtectionType.complete")
    }
    #endif

    // Backup exclusion is requested and verified on the dedicated directory. A
    // directory exclusion covers everything written inside it, so leaves are not
    // expected to carry their own flag.
    XCTAssertTrue(storage.isBackupExcluded)
    let values = try directory.resourceValues(forKeys: [.isExcludedFromBackupKey])
    XCTAssertEqual(values.isExcludedFromBackup, true)

    // Three fixed staging leaves exist; none may remain after a successful
    // exclusive-temp-plus-rename write.
    let names = Set(try FileManager.default.contentsOfDirectory(atPath: directory.path))
    for leaf in [MailboxConstants.rendezvousFileName,
                 MailboxConstants.requestFileName,
                 MailboxConstants.responseFileName] {
      XCTAssertFalse(names.contains(".\(leaf).tmp"),
                     "fixed staging leaf .\(leaf).tmp survived a successful atomic write")
    }
  }

  // MARK: - Real-clock window expiry

  /// Outcome of one mail round trip from the test client's point of view.
  private enum RoundTripOutcome: Equatable {
    case answered
    case closed
    case unanswered
  }

  /// Real-clock regression for the finite owner window: one `begin` round trip,
  /// then periodic `heartbeat` operations while the window lives. Live traffic
  /// must never move the initial deadline, the real host must purge the shared
  /// rendezvous at its deadline, and the session must then refuse to seal.
  ///
  /// The budget is a monotonic 21.5 s measured before the window opens; closure
  /// is only asserted at that bound, never that the window was live at 19.9 s,
  /// and a genuinely early fail-closed OS expiration is tolerated. A live lease
  /// that goes unanswered, or any malformed/authentication error, is not.
  func testRealClockWindowExpiresAndRequestsCannotRenewIt() throws {
    let (host, messenger, storage, _) = try fixture()
    defer { host.disconnect() }

    let startMonotonicMillis = Int64((ProcessInfo.processInfo.systemUptime * 1000).rounded(.down))
    let bound = startMonotonicMillis + 21_500
    host.willResignActive()

    let first = try readRendezvous(storage)
    XCTAssertTrue(MailboxClient(storage: storage).hasLiveWindow())
    // The owner is asked for the full ceiling; this asserts the request, not that
    // the OS grants all 20 s.
    XCTAssertEqual(first.windowMillis, MailboxConstants.maxWindowMillis)
    XCTAssertEqual(first.deadlineEpochMillis - first.createdAtEpochMillis,
                   MailboxConstants.maxWindowMillis)

    // Repeated resignations in the same departure must not mint a new window.
    for _ in 0..<3 { host.willResignActive() }
    let afterRepeats = try readRendezvous(storage)
    XCTAssertEqual(afterRepeats.sessionId, first.sessionId)
    XCTAssertEqual(afterRepeats.createdAtEpochMillis, first.createdAtEpochMillis)
    XCTAssertEqual(afterRepeats.deadlineEpochMillis, first.deadlineEpochMillis)

    let client = MailboxClient(storage: storage)
    let session = try client.attach()
    XCTAssertEqual(session.sessionId, first.sessionId)

    func payload(_ operation: String, _ requestId: String) throws -> Data {
      try JSONSerialization.data(withJSONObject: [
        "operation": operation, "editorNonce": "expiry-test", "requestId": requestId,
      ])
    }
    // A live lease that goes unanswered is a failure; only a host that actually
    // closed or revoked the window may end a round trip without an answer.
    func roundTrip(_ operation: String, _ requestId: String) throws -> RoundTripOutcome {
      do {
        try session.send(payload: try payload(operation, requestId),
                         timeoutMillis: MailboxConstants.defaultPendingTimeoutMillis)
      } catch let error as MailboxError
        where error.reason == .windowClosed || error.reason == .revoked {
        return .closed
      }
      let leaseEnd = MailboxClock.system().monotonicMillis
        + MailboxConstants.defaultPendingTimeoutMillis
      while MailboxClock.system().monotonicMillis < leaseEnd {
        if !MailboxClient(storage: storage).hasLiveWindow() { return .closed }
        do {
          if case .response(let bytes) = try session.pollResponse() {
            let reply = try JSONSerialization.jsonObject(with: bytes) as? [String: Any]
            XCTAssertEqual(reply?["status"] as? String, "ok", "\(operation) reply was not ok")
            return .answered
          }
        } catch let error as MailboxError
          where error.reason == .windowClosed || error.reason == .revoked {
          return .closed
        }
        RunLoop.main.run(until: Date().addingTimeInterval(0.02))
      }
      return .unanswered
    }

    // Exactly one begin, and it must succeed while the window is live.
    XCTAssertEqual(try roundTrip("begin", "expiry-begin"), .answered,
                   "the initial begin round trip must be answered while live")
    let afterBegin = try readRendezvous(storage)
    XCTAssertEqual(afterBegin.sessionId, first.sessionId)
    XCTAssertEqual(afterBegin.deadlineEpochMillis, first.deadlineEpochMillis)

    // Periodic heartbeats every second. Each keeps a full 900 ms transport
    // lease, so a final heartbeat cannot straddle the deadline and disguise a
    // real timeout.
    var heartbeatsSent = 0
    while true {
      let now = MailboxClock.system()
      guard now.monotonicMillis < bound,
            MailboxClient(storage: storage).hasLiveWindow(),
            first.deadlineEpochMillis - now.epochMillis
              > MailboxConstants.defaultPendingTimeoutMillis + 250 else { break }
      let outcome = try roundTrip("heartbeat", "expiry-heartbeat-\(heartbeatsSent)")
      if outcome == .closed { break }
      XCTAssertEqual(outcome, .answered, "a live heartbeat must be answered within its 900 ms lease")
      heartbeatsSent += 1
      if MailboxClient(storage: storage).hasLiveWindow() {
        let live = try readRendezvous(storage)
        XCTAssertEqual(live.sessionId, first.sessionId)
        XCTAssertEqual(live.deadlineEpochMillis, first.deadlineEpochMillis)
      }
      let periodEnd = MailboxClock.system().monotonicMillis + 1_000
      while MailboxClock.system().monotonicMillis < periodEnd,
            MailboxClock.system().monotonicMillis < bound,
            MailboxClient(storage: storage).hasLiveWindow() {
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
      }
    }
    let beginsReceived = messenger.received.filter { $0["operation"] as? String == "begin" }.count
    let heartbeatsReceived = messenger.received.filter {
      $0["operation"] as? String == "heartbeat"
    }.count
    XCTAssertEqual(beginsReceived, 1, "exactly one begin operation must reach the host")
    XCTAssertGreaterThanOrEqual(heartbeatsSent, 1, "the fixture must stay live long enough for heartbeats")
    XCTAssertGreaterThanOrEqual(heartbeatsReceived, heartbeatsSent,
                                "every answered heartbeat must have reached the host")

    // Wait for the host's own exclusive deadline, pumping the run loop that
    // drives its 50 ms poll, inside the monotonic budget.
    while MailboxClock.system().monotonicMillis < bound {
      if !MailboxClient(storage: storage).hasLiveWindow() { break }
      RunLoop.main.run(until: Date().addingTimeInterval(0.05))
    }
    XCTAssertFalse(MailboxClient(storage: storage).hasLiveWindow(),
                   "the host must close the window at or before its 20 s deadline")

    // hasLiveWindow can turn false on metadata expiry alone: give the real host a
    // short bounded poll, then require that it actually purged the document.
    var remainingRendezvous = try storage.readRendezvous()
    while remainingRendezvous != nil, MailboxClock.system().monotonicMillis < bound {
      RunLoop.main.run(until: Date().addingTimeInterval(0.05))
      remainingRendezvous = try storage.readRendezvous()
    }
    XCTAssertNil(remainingRendezvous, "the host must remove the shared rendezvous after its deadline")

    // The exclusive deadline has elapsed locally, so the session must refuse to
    // seal rather than merely polling idle, and no response may be published.
    while !session.isExpired(), MailboxClock.system().monotonicMillis < bound {
      RunLoop.main.run(until: Date().addingTimeInterval(0.02))
    }
    XCTAssertTrue(session.isExpired(), "the owner window must reach its exclusive deadline")
    do {
      try session.send(payload: try payload("heartbeat", "expiry-after-deadline"),
                       timeoutMillis: MailboxConstants.defaultPendingTimeoutMillis)
      XCTFail("session.send succeeded after the exclusive deadline")
    } catch let error as MailboxError {
      XCTAssertEqual(error.kind, .unavailable)
      XCTAssertEqual(error.reason, .windowClosed)
    }
    let publishedResponse = try storage.readResponse()
    XCTAssertNil(publishedResponse, "no response may be published after the window closed")
    do {
      if case .response = try session.pollResponse() {
        XCTFail("a response was delivered after the window closed")
      }
    } catch let error as MailboxError {
      XCTAssertEqual(error.kind, .unavailable)
    }

    // Still the same departure: resignation must not reopen the window.
    host.willResignActive()
    let afterDeadline = try storage.readRendezvous()
    XCTAssertNil(afterDeadline, "a resignation after the deadline must not reopen the window")

    // Only a foreground return re-arms the next departure, with a new identity.
    host.didBecomeActive()
    host.willResignActive()
    let resumed = try readRendezvous(storage)
    XCTAssertTrue(MailboxClient(storage: storage).hasLiveWindow(),
                  "a fresh departure after didBecomeActive must open a new window")
    XCTAssertNotEqual(resumed.sessionId, first.sessionId)
    XCTAssertGreaterThan(resumed.deadlineEpochMillis, first.deadlineEpochMillis)

    XCTAssertLessThanOrEqual(MailboxClock.system().monotonicMillis - startMonotonicMillis, 21_500,
                             "the observation must fit the 21.5 s monotonic budget")
  }

  // MARK: - Synthetic revocation notifications

  /// Synthetic-notification regression only: the test posts the real system
  /// notification by hand. The capture-state probe simulates recording for the
  /// capture case. This proves the host's observer wiring revokes the window
  /// and drops a late owner reply; it is not physical lock/capture attestation.
  func testSyntheticProtectedDataUnavailableNotificationRevokesAndDropsDelayedReply() throws {
    try assertSyntheticNotificationRevokes(
      UIApplication.protectedDataWillBecomeUnavailableNotification,
      label: "protected-data-unavailable")
  }

  /// Synthetic-notification regression only: see the protected-data case above.
  func testSyntheticScreenCaptureNotificationRevokesAndDropsDelayedReply() throws {
    try assertSyntheticNotificationRevokes(
      UIScreen.capturedDidChangeNotification,
      label: "screen-capture")
  }

  func testCaptureStopNotificationDoesNotRevokeFreshDepartureWindow() throws {
    let capture = CaptureProbe()
    let (host, _, storage, _) = try fixture(captureActive: { capture.active })
    defer { host.disconnect() }
    host.willResignActive()
    let client = MailboxClient(storage: storage)
    XCTAssertTrue(client.hasLiveWindow())

    // iOS sends the same notification when recording ends. A delayed end event
    // must not close the newly opened, uncaptured keyboard bootstrap window.
    NotificationCenter.default.post(name: UIScreen.capturedDidChangeNotification, object: nil)
    XCTAssertTrue(client.hasLiveWindow())
  }

  /// Shared body for the synthetic notifications: an owner reply delivered after
  /// the notification must never reach the client, and the shared rendezvous
  /// must be gone.
  private func assertSyntheticNotificationRevokes(
    _ notification: Notification.Name,
    label: String
  ) throws {
    let capture = CaptureProbe()
    let (host, messenger, storage, _) = try fixture(captureActive: { capture.active })
    defer { host.disconnect() }
    messenger.delayReply = true
    host.willResignActive()
    let client = MailboxClient(storage: storage)
    let session = try client.attach()
    let payload = try JSONSerialization.data(withJSONObject: [
      "operation": "begin", "editorNonce": "notify-test", "requestId": "notify-\(label)",
    ])
    try session.send(payload: payload)
    try waitFor { messenger.pendingReply != nil }
    let delayed = try XCTUnwrap(messenger.pendingReply)

    if notification == UIScreen.capturedDidChangeNotification { capture.active = true }
    NotificationCenter.default.post(name: notification, object: nil)
    try waitFor { !client.hasLiveWindow() }

    // The late Dart reply must not be sealed or published by the revoked owner.
    delayed(messenger.success())
    do {
      if case .response = try session.pollResponse() {
        XCTFail("\(label): a notification-revoked owner published a delayed response")
      }
    } catch let error as MailboxError {
      XCTAssertEqual(error.kind, .unavailable)
    }
    XCTAssertFalse(FileManager.default.fileExists(atPath:
      storage.directoryURL.appendingPathComponent(MailboxConstants.responseFileName).path),
      "\(label): a response leaf was written after revocation")
  }
}

#if LAYERGRAM_AUTONOMOUS_KEYBOARD
/// Packaged ML-KEM/SCKA and the production native bridge on a real iOS runtime.
/// The editor snapshot here is synthetic: these tests do not attest a visible
/// third-party keyboard, physical touch, Face ID success or screenshot pixels.
@MainActor
final class KeyboardAutonomousRuntimeTests: XCTestCase {
  func testRuntimeTeardownWaitsForCleanupAndDestroysExactlyOnce() {
    var acknowledge: (() -> Void)?
    var timeout: (() -> Void)?
    var destroyed = 0
    KeyboardRuntimeTeardown.begin(requestClose: { acknowledge = $0 },
      scheduleTimeout: { timeout = $0 }, destroy: { destroyed += 1 })
    XCTAssertEqual(destroyed, 0)
    acknowledge?()
    XCTAssertEqual(destroyed, 1)
    timeout?()
    acknowledge?()
    XCTAssertEqual(destroyed, 1)
  }

  func testRuntimeTeardownBoundsUnresponsiveIsolateAndIgnoresLateReply() {
    var acknowledge: (() -> Void)?
    var timeout: (() -> Void)?
    var destroyed = 0
    KeyboardRuntimeTeardown.begin(requestClose: { acknowledge = $0 },
      scheduleTimeout: { timeout = $0 }, destroy: { destroyed += 1 })
    timeout?()
    XCTAssertEqual(destroyed, 1)
    acknowledge?()
    timeout?()
    XCTAssertEqual(destroyed, 1)
  }

  func testRuntimeTeardownHandlesSynchronousCleanupResponse() {
    var timeout: (() -> Void)?
    var destroyed = 0
    KeyboardRuntimeTeardown.begin(requestClose: { $0() },
      scheduleTimeout: { timeout = $0 }, destroy: { destroyed += 1 })
    XCTAssertEqual(destroyed, 1)
    timeout?()
    XCTAssertEqual(destroyed, 1)
  }

  private var sequence = 0
  private var bridge: KeyboardRuntimeBridge?
  private var fixtureEngine: FlutterEngine?
  private var fixtureChannel: FlutterMethodChannel?
  private var custody: KeyboardCustodyStore?
  private var visible = true
  private var nonce = "qa-native-editor"
  private var remoteNonce = "remote-editor"
  private var captured = false
  private let document = "qa-document"
  private let custodyDirectoryName = ProcessInfo.processInfo.environment["LAYERGRAM_V3_UPDATE_STAGE"] == nil
      ? "test-native-runtime-\(UUID().uuidString)" : "test-native-runtime-update"
  private let mirrorAccount = ProcessInfo.processInfo.environment["LAYERGRAM_V3_UPDATE_STAGE"] == nil
      ? "test-native-runtime-\(UUID().uuidString)" : "test-native-runtime-update"

  private func fixture(_ method: String, _ arguments: Any? = nil) async throws -> Any? {
    let channel = try XCTUnwrap(fixtureChannel)
    return try await withCheckedThrowingContinuation { continuation in
      channel.invokeMethod(method, arguments: arguments) { value in
        if let error = value as? FlutterError {
          continuation.resume(throwing: NSError(domain: "fixture", code: 1,
                                               userInfo: [NSLocalizedDescriptionKey: error.code]))
        } else { continuation.resume(returning: value) }
      }
    }
  }

  private func setupFixture(_ persisted: [String: Any]? = nil) async throws -> [String: Any] {
    guard ["app.layergram.keyboardvalidation.qa", "app.layergram.keyboardvalidation"]
        .contains(Bundle.main.bundleIdentifier ?? "") else {
      throw XCTSkip("Packaged runtime tests require the isolated QA app, never user test chats")
    }
    let bundle = try XCTUnwrap(Bundle(url: Bundle.main.bundleURL.appendingPathComponent("Frameworks/App.framework")))
    let engine = FlutterEngine(name: "layergram.qa.peer", project: FlutterDartProject(precompiledDartBundle: bundle), allowHeadlessExecution: true)
    fixtureEngine = engine
    let ready = expectation(description: "Packaged fixture ready")
    XCTAssertTrue(engine.run(withEntrypoint: "layergramKeyboardValidationMain"))
    let channel = FlutterMethodChannel(name: "layergram/keyboard_validation", binaryMessenger: engine.binaryMessenger)
    fixtureChannel = channel
    channel.setMethodCallHandler { call, result in
      guard call.method == "ready" else { result(FlutterMethodNotImplemented); return }
      result(nil); ready.fulfill()
    }
    await fulfillment(of: [ready], timeout: 20)
    let initialized = try await fixture("initialize", persisted)
    let setup = try XCTUnwrap(initialized as? [String: Any])
    let group = try XCTUnwrap(Bundle.main.object(forInfoDictionaryKey: "KeyboardAppGroupId") as? String)
    let epoch = try XCTUnwrap(setup["epoch"] as? FlutterStandardTypedData).data
    let key = try XCTUnwrap(setup["key"] as? FlutterStandardTypedData).data
    let snapshot = try XCTUnwrap(setup["snapshot"] as? FlutterStandardTypedData).data
    let storage = try MailboxStorage(appGroupIdentifier: group, directoryName: custodyDirectoryName)
    let store = try KeyboardCustodyStore(storage: storage, epoch: epoch, key: key,
                     mirror: KeyboardKeychainCustodyMirror(group: group, epoch: epoch, account: mirrorAccount))
    custody = store
    if persisted == nil { try store.prepare(snapshot); try store.activate() }
    else { XCTAssertEqual(try store.loadForKeyboard().plaintext, snapshot) }
    return setup
  }

  private func start(_ setup: [String: Any]) async throws {
    let granted = try await fixture("grant", nonce)
    let grant = try XCTUnwrap(granted as? [String: Any])
    var config = try XCTUnwrap(grant["configuration"] as? [String: Any])
    config.removeValue(forKey: "biometricResume")
    for field in ["epoch", "publicIdentity", "identityKeyMaterial", "localDeviceId"] {
      let encoded = try XCTUnwrap(config[field] as? String)
      config[field] = FlutterStandardTypedData(bytes: try XCTUnwrap(Data(base64Encoded: encoded)))
    }
    config["contacts"] = try XCTUnwrap(config["contacts"] as? [[String: Any]]).map { row in
      var mapped = row
      mapped["identity"] = FlutterStandardTypedData(bytes: try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(row["identity"] as? String))))
      return mapped
    }
    let group = try XCTUnwrap(Bundle.main.object(forInfoDictionaryKey: "KeyboardAppGroupId") as? String)
    let next = try KeyboardRuntimeBridge(groupIdentifier: group,
        epoch: try XCTUnwrap(setup["epoch"] as? FlutterStandardTypedData).data,
        key: try XCTUnwrap(setup["key"] as? FlutterStandardTypedData).data,
        configuration: config, snapshot: { [unowned self] in
          KeyboardEditorSnapshot(isViewVisible: self.visible, hasFullAccess: true,
              isCaptured: self.captured, documentIdentifier: self.document,
              monotonicMillis: Int64(ProcessInfo.processInfo.systemUptime * 1000))
        }, custodyDirectoryName: custodyDirectoryName, mirrorAccount: mirrorAccount)
    bridge = next
    let accepted = await withCheckedContinuation { continuation in
      next.start { continuation.resume(returning: $0) }
    }
    XCTAssertTrue(accepted, "Real packaged native bridge must open")
  }

  private func request(_ local: Bool, _ operation: String, _ extra: [String: Any] = [:]) async throws -> [String: Any] {
    sequence += 1
    var args: [String: Any] = ["operation": operation,
        "editorNonce": local ? nonce : remoteNonce, "requestId": "qa-\(sequence)"]
    args.merge(extra) { _, latest in latest }
    let raw: Any?
    if local {
      let current = try XCTUnwrap(bridge)
      XCTAssertTrue(current.recordUserInteraction())
      let bytes = try JSONSerialization.data(withJSONObject: args)
      let output: Data? = await withCheckedContinuation { continuation in
        current.request(bytes) { continuation.resume(returning: $0) }
      }
      raw = try JSONSerialization.jsonObject(with: try XCTUnwrap(output))
    } else { raw = try await fixture("remote", args) }
    let reply = try XCTUnwrap(raw as? [String: Any])
    XCTAssertEqual(reply["status"] as? String, "ok", "\(operation) failed")
    return try XCTUnwrap(reply["data"] as? [String: Any])
  }

  private func send(_ local: Bool, _ text: String, _ setup: [String: Any]) async throws {
    let contact = try XCTUnwrap(setup[local ? "contactId" : "remoteContactId"] as? String)
    _ = try await request(local, "select", ["contactId": contact, "confirm": true])
    let prepared = try await request(local, "prepare", ["text": text])
    let pending = try XCTUnwrap(prepared["pendingId"] as? String)
    let exported = try await request(local, "authorize", ["pendingId": pending])
    let carrier = try XCTUnwrap(exported["carrier"] as? String)
    XCTAssertLessThanOrEqual(carrier.utf16.count, 4000)
    XCTAssertFalse(carrier.contains("1/2") || carrier.contains("2/2"))
    _ = try await request(local, "ack", ["pendingId": pending, "commitText": true])
    let decoded = try await request(!local, "decode", ["carrier": carrier])
    XCTAssertEqual(decoded["text"] as? String, text, "Every export must deliver its application text")
  }

  private func rebindEditors() async throws {
    // Match the native keyboard's editor rebind after insertion. The bounded
    // request replay cache must not be mistaken for a long-lived chat limit.
    nonce = "qa-native-rebind-\(sequence)"
    let current = try XCTUnwrap(bridge)
    let accepted = await withCheckedContinuation { continuation in
      current.rebind(editorNonce: nonce) { continuation.resume(returning: $0) }
    }
    XCTAssertTrue(accepted)
    remoteNonce = "qa-remote-rebind-\(sequence)"
    let remoteAccepted = try await fixture("remoteRebind", remoteNonce)
    XCTAssertEqual(remoteAccepted as? Bool, true)
    _ = try await request(true, "begin"); _ = try await request(false, "begin")
  }

  private func reachGreen(_ setup: [String: Any]) async throws {
    var green = false
    for turn in 0..<24 {
      try await send(true, "Readable iOS A \(turn)", setup)
      try await send(false, "Readable iOS B \(turn)", setup)
      let a = try await request(true, "select", ["contactId": setup["contactId"]!, "confirm": true])
      let b = try await request(false, "select", ["contactId": setup["remoteContactId"]!, "confirm": true])
      if a["securityPhase"] as? String == "normalActive" && b["securityPhase"] as? String == "normalActive" {
        green = true; break
      }
      try await rebindEditors()
    }
    XCTAssertTrue(green, "Both peers must reach green with no empty exports")
  }

  func testGreenFsSurvivesInPlaceUpdate() async throws {
    guard let stage = ProcessInfo.processInfo.environment["LAYERGRAM_V3_UPDATE_STAGE"],
          ["seed", "upgrade"].contains(stage) else {
      throw XCTSkip("Run the explicit ios-device-update stage")
    }
    let journal = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("qa-v3-update-recovery.plist")
    var persisted: [String: Any]?
    var savedRevision: UInt64 = 0
    if stage == "upgrade" {
      let saved = try PropertyListSerialization.propertyList(from: Data(contentsOf: journal), format: nil) as! [String: Any]
      savedRevision = (try XCTUnwrap(saved["revision"] as? NSNumber)).uint64Value
      persisted = try ["epoch", "key", "snapshot", "remoteSnapshot"].reduce(into: [String: Any]()) {
        $0[$1] = FlutterStandardTypedData(bytes: try XCTUnwrap(saved[$1] as? Data))
      }
    } else {
      XCTAssertFalse(FileManager.default.fileExists(atPath: journal.path), "An unfinished update fixture must be investigated, not overwritten")
    }
    let setup = try await setupFixture(persisted)
    defer {
      bridge?.close(); bridge = nil
      fixtureChannel?.setMethodCallHandler(nil); fixtureChannel = nil
      fixtureEngine?.destroyContext(); fixtureEngine = nil
      if stage == "upgrade", let custody, let latest = try? custody.reclaimForApp() {
        try? custody.removeAfterImport(expectedRevision: latest.revision)
        try? FileManager.default.removeItem(at: journal)
      }
      custody?.close(); custody = nil
    }
    try await start(setup)
    _ = try await request(true, "begin"); _ = try await request(false, "begin")
    if stage == "seed" {
      try await reachGreen(setup)
      let latest = try XCTUnwrap(custody).loadForKeyboard()
      let rawPeer = try await fixture("exportRemoteSnapshot")
      let peer = try XCTUnwrap(rawPeer as? FlutterStandardTypedData)
      let data = try PropertyListSerialization.data(fromPropertyList: [
        "epoch": try XCTUnwrap(setup["epoch"] as? FlutterStandardTypedData).data,
        "key": try XCTUnwrap(setup["key"] as? FlutterStandardTypedData).data,
        "snapshot": latest.plaintext, "remoteSnapshot": peer.data,
        "revision": latest.revision,
      ], format: .binary, options: 0)
      try FileManager.default.createDirectory(at: journal.deletingLastPathComponent(), withIntermediateDirectories: true)
      try data.write(to: journal, options: [.atomic, .completeFileProtection])
      var excluded = journal; var values = URLResourceValues(); values.isExcludedFromBackup = true
      try excluded.setResourceValues(values)
    } else {
      let a = try await request(true, "select", ["contactId": setup["contactId"]!, "confirm": true])
      let b = try await request(false, "select", ["contactId": setup["remoteContactId"]!, "confirm": true])
      XCTAssertEqual(a["securityPhase"] as? String, "normalActive")
      XCTAssertEqual(b["securityPhase"] as? String, "normalActive")
      XCTAssertEqual(try XCTUnwrap(custody).loadForKeyboard().revision, savedRevision)
      try await send(true, "Green FS after installed app update", setup)
      try await send(false, "Reply on preserved green FS after update", setup)
      XCTAssertGreaterThan(try XCTUnwrap(custody).loadForKeyboard().revision, savedRevision)
    }
  }

  func testFirstMessageGreenFsRestartAndCaptureRevocationPreserveLatestCustody() async throws {
    let setup = try await setupFixture()
    defer {
      bridge?.close(); bridge = nil
      fixtureChannel?.setMethodCallHandler(nil); fixtureChannel = nil
      fixtureEngine?.destroyContext(); fixtureEngine = nil
      if let custody, let latest = try? custody.reclaimForApp() {
        try? custody.removeAfterImport(expectedRevision: latest.revision)
      }
      custody?.close(); custody = nil
    }
    try await start(setup)
    _ = try await request(true, "begin"); _ = try await request(false, "begin")
    try await reachGreen(setup)
    let previous = try XCTUnwrap(custody).loadForKeyboard().revision
    bridge?.close(); bridge = nil
    // Engine destruction is asynchronous, and a new explicit grant is required.
    nonce = "qa-native-after-restart"
    try await start(setup); _ = try await request(true, "begin")
    let selected = try await request(true, "select", ["contactId": setup["contactId"]!, "confirm": true])
    XCTAssertEqual(selected["securityPhase"] as? String, "normalActive")
    try await send(true, "FS intact after engine restart", setup)
    for turn in 0..<18 {
      try await rebindEditors()
      try await send(true, "Continuous iOS export \(turn)", setup)
    }
    XCTAssertGreaterThan(try XCTUnwrap(custody).loadForKeyboard().revision, previous)
    let latest = try XCTUnwrap(custody).loadForKeyboard()
    captured = true
    XCTAssertFalse(try XCTUnwrap(bridge).validate())
    XCTAssertFalse(try XCTUnwrap(bridge).isReady)
    let reclaimed = try XCTUnwrap(custody).reclaimForApp()
    XCTAssertEqual(reclaimed.revision, latest.revision)
    XCTAssertEqual(reclaimed.plaintext, latest.plaintext, "Capture closes access without resetting FS")
  }
}
#endif
