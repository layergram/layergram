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
}
