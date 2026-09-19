import Flutter
import SystemKeyboardCore
import UIKit

/// Sole native bridge to the existing Flutter owner. No engine, vault or identity
/// is created here. The extension cannot start or renew this finite window.
final class SystemKeyboardHost {
  private let channel: FlutterMethodChannel
  private let defaults: UserDefaults
  private let groupIdentifier: String?
  private let isEmbedded: Bool
  private var configured = false
  private var departed = false
  private var epoch: UInt64 = 0
  private var owner: MailboxOwner?
  private var timer: Timer?
  private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
  private var waiting = false
  private var observers: [NSObjectProtocol] = []
  private static let enabledKey = "system_keyboard_enabled"

  init(messenger: FlutterBinaryMessenger, bundle: Bundle = .main,
       defaults: UserDefaults = .standard) {
    self.defaults = defaults
    groupIdentifier = bundle.object(forInfoDictionaryKey: "KeyboardAppGroupId") as? String
    isEmbedded = bundle.builtInPlugInsURL.map {
      FileManager.default.fileExists(atPath:
        $0.appendingPathComponent("LayergramKeyboard.appex/Info.plist").path)
    } ?? false
    channel = FlutterMethodChannel(name: "layergram/system_keyboard", binaryMessenger: messenger)
    channel.setMethodCallHandler { [weak self] call, result in
      guard let self else { result(false); return }
      switch call.method {
      case "readEnabled":
        result(MailboxCryptoAvailability.isSupported && self.isEmbedded && self.defaults.bool(forKey: Self.enabledKey))
      case "configure":
        guard let args = call.arguments as? [String: Any],
              let enabled = args["enabled"] as? Bool else { result(false); return }
        self.revoke()
        let accepted = !enabled || (MailboxCryptoAvailability.isSupported && self.isEmbedded && self.groupIdentifier != nil)
        self.configured = enabled && accepted
        self.defaults.set(self.configured, forKey: Self.enabledKey)
        result(accepted)
      case "revoke":
        self.revoke()
        result(nil)
      case "openSettings":
        guard let url = URL(string: UIApplication.openSettingsURLString) else {
          result(false); return
        }
        UIApplication.shared.open(url, options: [:]) { result($0) }
      default:
        result(FlutterMethodNotImplemented)
      }
    }
    for name in [UIApplication.protectedDataWillBecomeUnavailableNotification,
                 UIScreen.capturedDidChangeNotification] {
      observers.append(NotificationCenter.default.addObserver(
        forName: name, object: nil, queue: .main
      ) { [weak self] _ in self?.revoke() })
    }
  }

  /// Called before the scene leaves the foreground. Repeated inactive/background
  /// notifications cannot extend or reopen this departure's window.
  func willResignActive() {
    guard !departed else { return }
    departed = true
    guard configured, isEmbedded,
          UIApplication.shared.isProtectedDataAvailable,
          !UIScreen.main.isCaptured,
          let groupIdentifier else { return }
    revoke()
    backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "Keyboard session") {
      [weak self] in self?.revoke()
    }
    guard backgroundTask != .invalid else { return }
    do {
      let storage = try MailboxStorage(appGroupIdentifier: groupIdentifier)
      let mailbox = MailboxOwner(storage: storage)
      try mailbox.openWindow()
      owner = mailbox
      let poll = Timer(timeInterval: 0.05, repeats: true) { [weak self] _ in self?.poll() }
      timer = poll
      RunLoop.main.add(poll, forMode: .common)
    } catch {
      revoke()
    }
  }

  func didBecomeActive() {
    revoke()
    departed = false
  }

  func disconnect() {
    departed = true
    configured = false
    revoke()
    channel.setMethodCallHandler(nil)
  }

  private func poll() {
    guard let owner, let info = owner.windowInfo else { revoke(); return }
    guard configured, departed,
          UIApplication.shared.isProtectedDataAvailable,
          !UIScreen.main.isCaptured,
          MailboxClock.system().monotonicMillis < info.deadlineMonotonicMillis else {
      revoke(); return
    }
    guard !waiting else { return }
    do {
      guard case .request(let pending) = try owner.pollRequest() else { return }
      guard let request = try JSONSerialization.jsonObject(with: pending.payload) as? [String: Any]
      else { revoke(); return }
      let capturedEpoch = epoch
      waiting = true
      channel.invokeMethod("request", arguments: request) { [weak self, weak owner] raw in
        guard let self, let owner,
              self.epoch == capturedEpoch, self.owner === owner else { return }
        self.waiting = false
        guard self.configured, self.departed,
              UIApplication.shared.isProtectedDataAvailable,
              !UIScreen.main.isCaptured,
              let info = owner.windowInfo,
              MailboxClock.system().monotonicMillis < info.deadlineMonotonicMillis,
              let reply = raw as? [String: Any], reply["status"] is String,
              JSONSerialization.isValidJSONObject(reply) else { self.revoke(); return }
        do {
          let bytes = try JSONSerialization.data(withJSONObject: reply)
          try owner.respond(to: pending, payload: bytes)
        } catch { self.revoke() }
      }
    } catch { revoke() }
  }

  private func revoke() {
    epoch &+= 1
    timer?.invalidate()
    timer = nil
    let previous = owner
    owner = nil
    waiting = false
    try? previous?.closeWindow()
    let task = backgroundTask
    backgroundTask = .invalid
    if task != .invalid { UIApplication.shared.endBackgroundTask(task) }
  }

  deinit {
    timer?.invalidate()
    try? owner?.closeWindow()
    if backgroundTask != .invalid { UIApplication.shared.endBackgroundTask(backgroundTask) }
    observers.forEach { NotificationCenter.default.removeObserver($0) }
  }
}
