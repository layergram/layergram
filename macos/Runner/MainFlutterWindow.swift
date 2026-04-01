import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  private static let channelName = "layergram/screen_protection"
  private static let defaultsKey = "screen_protection_enabled"

  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    // Ensure initial size is at least the minimum on first launch.
    var windowFrame = self.frame
    if windowFrame.size.width < 800 || windowFrame.size.height < 660 {
      windowFrame.size = NSSize(width: 800, height: 660)
    }
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)
    self.minSize = NSSize(width: 800, height: 660)

    applyScreenProtectionFromDefaults()
    setupMethodChannel(flutterViewController)

    RegisterGeneratedPlugins(registry: flutterViewController)

    super.awakeFromNib()
  }

  private func applyScreenProtectionFromDefaults() {
    let enabled = (UserDefaults.standard.object(forKey: Self.defaultsKey) as? Bool) ?? true
    applySharingType(enabled)
  }

  private func applySharingType(_ enabled: Bool) {
    // macOS can't reliably block system screenshots; this mainly affects window sharing / capture APIs.
    self.sharingType = enabled ? .none : .readWrite
  }

  private func setupMethodChannel(_ flutterViewController: FlutterViewController) {
    let channel = FlutterMethodChannel(
      name: Self.channelName,
      binaryMessenger: flutterViewController.engine.binaryMessenger
    )

    channel.setMethodCallHandler { [weak self] call, result in
      guard let self = self else { return }
      switch call.method {
      case "setEnabled":
        let enabled = call.arguments as? Bool ?? false
        UserDefaults.standard.set(enabled, forKey: Self.defaultsKey)
        self.applySharingType(enabled)
        result(nil)
      case "isSupported":
        result(true)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }
}
