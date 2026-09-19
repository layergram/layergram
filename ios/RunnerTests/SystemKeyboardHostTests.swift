import Flutter
@testable import SystemKeyboardCore
import UIKit
import XCTest
@testable import Runner

/// Exercises the actual UIKit host, method-channel codec and protected mailbox.
/// The Dart peer is synthetic; V3/history behavior has separate Dart tests.
final class SystemKeyboardHostTests: XCTestCase {
  private final class Messenger: NSObject, FlutterBinaryMessenger {
    let codec = FlutterStandardMethodCodec.sharedInstance()
    var handler: FlutterBinaryMessageHandler?
    var received: [[String: Any]] = []
    var pendingReply: FlutterBinaryReply?
    var delayReply = false

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
      self.handler = handler
      return 1
    }
    func cleanUpConnection(_ connection: FlutterBinaryMessengerConnection) { handler = nil }
    func success() -> Data {
      codec.encodeSuccessEnvelope(["status": "ok", "processingMillis": 0,
                                   "leaseMillis": 1000, "data": ["scramble": false]])
    }
    func call(_ method: String, arguments: Any? = nil) throws -> Any? {
      var value: Any?
      var answered = false
      let request = codec.encode(FlutterMethodCall(methodName: method, arguments: arguments))
      handler?(request) { reply in
        answered = true
        if let reply { value = self.codec.decodeEnvelope(reply) }
      }
      XCTAssertTrue(answered)
      return value
    }
  }

  private func fixture() throws -> (SystemKeyboardHost, Messenger, MailboxStorage, UserDefaults) {
    guard MailboxCryptoAvailability.isSupported else { throw XCTSkip("Requires iOS 26 or later") }
    guard let plugins = Bundle.main.builtInPlugInsURL,
          FileManager.default.fileExists(atPath: plugins.appendingPathComponent("LayergramKeyboard.appex/Info.plist").path)
    else { throw XCTSkip("Use the experimental embedded-keyboard build for host integration tests") }
    let group = try XCTUnwrap(Bundle.main.object(forInfoDictionaryKey: "KeyboardAppGroupId") as? String)
    let storage: MailboxStorage
    do { storage = try MailboxStorage(appGroupIdentifier: group) }
    catch let error as MailboxError {
      XCTFail("Mailbox setup failed: \(error.reason)")
      throw error
    }
    let defaults = try XCTUnwrap(UserDefaults(suiteName: "keyboard-host-tests.\(UUID().uuidString)"))
    let messenger = Messenger()
    let host = SystemKeyboardHost(messenger: messenger, defaults: defaults)
    XCTAssertEqual(try messenger.call("configure", arguments: ["enabled": true]) as? Bool, true)
    return (host, messenger, storage, defaults)
  }

  private func waitFor(_ condition: () throws -> Bool) throws {
    let deadline = Date().addingTimeInterval(0.6)
    while !(try condition()), Date() < deadline {
      RunLoop.main.run(until: Date().addingTimeInterval(0.01))
    }
    XCTAssertTrue(try condition())
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

  // MARK: - Protected storage

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
  /// notification by hand on a device that is neither physically locked nor
  /// captured. It proves the host's observer wiring revokes the window and drops
  /// a late owner reply; it is not physical lock/capture attestation.
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

  /// Shared body for the synthetic notifications: an owner reply delivered after
  /// the notification must never reach the client, and the shared rendezvous
  /// must be gone.
  private func assertSyntheticNotificationRevokes(
    _ notification: Notification.Name,
    label: String
  ) throws {
    let (host, messenger, storage, _) = try fixture()
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
