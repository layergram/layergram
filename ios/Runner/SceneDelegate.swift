import Flutter
import UIKit

private final class SecureContentTextField: UITextField {
  override var canBecomeFirstResponder: Bool {
    false
  }

  override func caretRect(for position: UITextPosition) -> CGRect {
    .zero
  }

  override func selectionRects(for range: UITextRange) -> [UITextSelectionRect] {
    []
  }

  override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
    false
  }
}

private final class ScreenProtectedHostingViewController: UIViewController {
  let contentViewController: UIViewController

  private let plainHostView = UIView()
  private let secureTextField = SecureContentTextField()
  private weak var secureHostView: UIView?
  private var protectionEnabled: Bool

  init(contentViewController: UIViewController, protectionEnabled: Bool) {
    self.contentViewController = contentViewController
    self.protectionEnabled = protectionEnabled
    super.init(nibName: nil, bundle: nil)
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    nil
  }

  override func viewDidLoad() {
    super.viewDidLoad()

    view.backgroundColor = .clear

    plainHostView.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(plainHostView)
    NSLayoutConstraint.activate([
      plainHostView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
      plainHostView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
      plainHostView.topAnchor.constraint(equalTo: view.topAnchor),
      plainHostView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
    ])

    secureTextField.translatesAutoresizingMaskIntoConstraints = false
    secureTextField.isSecureTextEntry = true
    secureTextField.borderStyle = .none
    secureTextField.backgroundColor = .clear
    secureTextField.textColor = .clear
    secureTextField.tintColor = .clear
    secureTextField.text = " "
    view.addSubview(secureTextField)
    NSLayoutConstraint.activate([
      secureTextField.leadingAnchor.constraint(equalTo: view.leadingAnchor),
      secureTextField.trailingAnchor.constraint(equalTo: view.trailingAnchor),
      secureTextField.topAnchor.constraint(equalTo: view.topAnchor),
      secureTextField.bottomAnchor.constraint(equalTo: view.bottomAnchor),
    ])

    view.layoutIfNeeded()
    secureHostView = findSecureHostView(in: secureTextField) ?? secureTextField
    secureHostView?.isUserInteractionEnabled = true

    addChild(contentViewController)
    attachContentView(to: plainHostView)
    contentViewController.didMove(toParent: self)
    applyProtectionEnabled()
  }

  func setProtectionEnabled(_ enabled: Bool) {
    protectionEnabled = enabled
    guard isViewLoaded else { return }
    applyProtectionEnabled()
  }

  private func applyProtectionEnabled() {
    let useSecureHost = protectionEnabled && secureHostView != nil
    plainHostView.isHidden = useSecureHost
    secureTextField.isHidden = !useSecureHost

    if useSecureHost, let secureHostView {
      attachContentView(to: secureHostView)
    } else {
      attachContentView(to: plainHostView)
    }
  }

  private func attachContentView(to hostView: UIView) {
    let contentView = contentViewController.view!
    guard contentView.superview !== hostView else { return }

    contentView.removeFromSuperview()
    hostView.addSubview(contentView)
    contentView.translatesAutoresizingMaskIntoConstraints = false
    NSLayoutConstraint.activate([
      contentView.leadingAnchor.constraint(equalTo: hostView.leadingAnchor),
      contentView.trailingAnchor.constraint(equalTo: hostView.trailingAnchor),
      contentView.topAnchor.constraint(equalTo: hostView.topAnchor),
      contentView.bottomAnchor.constraint(equalTo: hostView.bottomAnchor),
    ])
  }

  private func findSecureHostView(in rootView: UIView) -> UIView? {
    for subview in rootView.subviews {
      let className = NSStringFromClass(type(of: subview))
      if className.contains("LayoutCanvasView") || className.contains("CanvasView") {
        return subview
      }

      if let nested = findSecureHostView(in: subview) {
        return nested
      }
    }

    return nil
  }
}

private struct PendingSharedItem: Decodable {
  let path: String
  let type: String
}

class SceneDelegate: FlutterSceneDelegate {

  private static let channelName = "layergram/screen_protection"
  private static let qrBrightnessChannelName = "layergram/screen_brightness"
  private static let qrBrightnessFloor: CGFloat = 0.60
  private static let defaultsKey = "screen_protection_enabled"
  private static let sharingChannelName = "layergram/sharing"
  private static let shareDefaultsKey = "ShareKey"
  private static let shareMessageDefaultsKey = "ShareMessageKey"
  private static let appGroupIdInfoKey = "AppGroupId"

  private var protectionEnabled: Bool = true
  private var privacyShieldView: UIView?
  private weak var flutterViewController: FlutterViewController?
  private var protectedRootViewController: ScreenProtectedHostingViewController?
  private var qrBrightnessRequested = false
  private var previousScreenBrightness: CGFloat?

  override func scene(
    _ scene: UIScene,
    willConnectTo session: UISceneSession,
    options connectionOptions: UIScene.ConnectionOptions
  ) {
    super.scene(scene, willConnectTo: session, options: connectionOptions)

    protectionEnabled = (UserDefaults.standard.object(forKey: Self.defaultsKey) as? Bool) ?? true

    installProtectedRootViewControllerIfNeeded()
    setupMethodChannel()
    setupQrBrightnessChannel()
    setupSharingChannel()
    setupCaptureObservers()
    updatePrivacyShieldForCurrentState()
  }

  override func sceneWillResignActive(_ scene: UIScene) {
    restorePreviousScreenBrightness(clearRequest: false)
    super.sceneWillResignActive(scene)
    showPrivacyShieldIfNeeded()
  }

  override func sceneDidBecomeActive(_ scene: UIScene) {
    super.sceneDidBecomeActive(scene)
    if qrBrightnessRequested {
      applyQrScreenBrightness()
    }
    updatePrivacyShieldForCurrentState()
  }

  override func sceneDidDisconnect(_ scene: UIScene) {
    restorePreviousScreenBrightness(clearRequest: true)
    super.sceneDidDisconnect(scene)
  }

  override func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
    super.scene(scene, openURLContexts: URLContexts)
  }

  private func installProtectedRootViewControllerIfNeeded() {
    guard let window = window else { return }

    if let protectedRootViewController = window.rootViewController as? ScreenProtectedHostingViewController {
      self.protectedRootViewController = protectedRootViewController
      flutterViewController = protectedRootViewController.contentViewController as? FlutterViewController
      protectedRootViewController.setProtectionEnabled(protectionEnabled)
      return
    }

    guard let flutterViewController = window.rootViewController as? FlutterViewController else {
      return
    }

    self.flutterViewController = flutterViewController
    let protectedRootViewController = ScreenProtectedHostingViewController(
      contentViewController: flutterViewController,
      protectionEnabled: protectionEnabled
    )
    self.protectedRootViewController = protectedRootViewController
    window.rootViewController = protectedRootViewController
    window.makeKeyAndVisible()
  }

  private func setupMethodChannel() {
    guard let controller = flutterViewController else {
      return
    }

    let channel = FlutterMethodChannel(
      name: Self.channelName,
      binaryMessenger: controller.binaryMessenger
    )

    channel.setMethodCallHandler { [weak self] call, result in
      guard let self = self else { return }
      switch call.method {
      case "setEnabled":
        let enabled = call.arguments as? Bool ?? false
        self.setProtectionEnabled(enabled)
        result(nil)
      case "isSupported":
        // iOS support is partial: we can't hard-block screenshots, but we can shield.
        result(true)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }

  private func setupQrBrightnessChannel() {
    guard let controller = flutterViewController else {
      return
    }

    let channel = FlutterMethodChannel(
      name: Self.qrBrightnessChannelName,
      binaryMessenger: controller.binaryMessenger
    )

    channel.setMethodCallHandler { [weak self] call, result in
      guard let self = self else { return }
      switch call.method {
      case "setQrDisplayActive":
        self.setQrDisplayActive(call.arguments as? Bool ?? false)
        result(nil)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }

  private func setupSharingChannel() {
    guard let controller = flutterViewController else {
      return
    }

    let channel = FlutterMethodChannel(
      name: Self.sharingChannelName,
      binaryMessenger: controller.binaryMessenger
    )

    channel.setMethodCallHandler { [weak self] call, result in
      guard let self = self else { return }
      switch call.method {
      case "consumePendingText":
        result(self.consumePendingSharedText())
      case "clearPendingShare":
        self.clearPendingShare()
        result(nil)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }

  private func setupCaptureObservers() {
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(onCapturedDidChange),
      name: UIScreen.capturedDidChangeNotification,
      object: nil
    )
  }

  private func consumePendingSharedText() -> String? {
    guard let userDefaults = sharedUserDefaults() else {
      return nil
    }

    let text = pendingSharedText(from: userDefaults)
    clearPendingShare(in: userDefaults)
    return text
  }

  private func clearPendingShare() {
    guard let userDefaults = sharedUserDefaults() else {
      return
    }

    clearPendingShare(in: userDefaults)
  }

  private func pendingSharedText(from userDefaults: UserDefaults) -> String? {
    if let message = userDefaults.string(forKey: Self.shareMessageDefaultsKey) {
      let normalized = message.trimmingCharacters(in: .whitespacesAndNewlines)
      if !normalized.isEmpty && !isShareRedirectMarker(normalized) {
        return normalized
      }
    }

    if let data = userDefaults.data(forKey: Self.shareDefaultsKey),
       let items = try? JSONDecoder().decode([PendingSharedItem].self, from: data) {
      for preferredType in ["text", "url"] {
        for item in items where item.type == preferredType {
          let normalized = item.path.trimmingCharacters(in: .whitespacesAndNewlines)
          if !normalized.isEmpty && !isShareRedirectMarker(normalized) {
            return normalized
          }
        }
      }
    }

    return nil
  }

  private func isShareRedirectMarker(_ text: String) -> Bool {
    let normalized = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    return normalized.hasPrefix("sharemedia-") && normalized.hasSuffix(":share")
  }

  private func clearPendingShare(in userDefaults: UserDefaults) {
    userDefaults.removeObject(forKey: Self.shareDefaultsKey)
    userDefaults.removeObject(forKey: Self.shareMessageDefaultsKey)
    userDefaults.synchronize()
  }

  private func sharedUserDefaults() -> UserDefaults? {
    let customGroupId = Bundle.main.object(forInfoDictionaryKey: Self.appGroupIdInfoKey) as? String

    if let customGroupId {
      return UserDefaults(suiteName: customGroupId)
    }

    guard let bundleIdentifier = Bundle.main.bundleIdentifier else {
      return nil
    }

    return UserDefaults(suiteName: "group.\(bundleIdentifier)")
  }

  private func setProtectionEnabled(_ enabled: Bool) {
    protectionEnabled = enabled
    UserDefaults.standard.set(enabled, forKey: Self.defaultsKey)
    protectedRootViewController?.setProtectionEnabled(enabled)
    updatePrivacyShieldForCurrentState()
  }

  private func setQrDisplayActive(_ active: Bool) {
    if active {
      guard !qrBrightnessRequested else { return }
      previousScreenBrightness = UIScreen.main.brightness
      qrBrightnessRequested = true
      applyQrScreenBrightness()
    } else {
      restorePreviousScreenBrightness(clearRequest: true)
    }
  }

  private func applyQrScreenBrightness() {
    let baseline = previousScreenBrightness ?? UIScreen.main.brightness
    UIScreen.main.brightness = max(baseline, Self.qrBrightnessFloor)
  }

  private func restorePreviousScreenBrightness(clearRequest: Bool) {
    if let previousScreenBrightness {
      UIScreen.main.brightness = previousScreenBrightness
    }

    if clearRequest {
      qrBrightnessRequested = false
      previousScreenBrightness = nil
    }
  }

  @objc private func onCapturedDidChange() {
    updatePrivacyShieldForCurrentState()
  }

  private func showPrivacyShieldIfNeeded() {
    guard protectionEnabled else { return }
    showPrivacyShield()
  }

  private func updatePrivacyShieldForCurrentState() {
    guard protectionEnabled else {
      hidePrivacyShield()
      return
    }

    // If screen recording / mirroring is active, keep shield visible even while active.
    if UIScreen.main.isCaptured {
      showPrivacyShield()
      return
    }

    let isForegroundActive = window?.windowScene?.activationState == .foregroundActive
    if isForegroundActive {
      hidePrivacyShield()
    } else {
      showPrivacyShield()
    }
  }

  private func showPrivacyShield() {
    guard let window = window else { return }

    if privacyShieldView == nil {
      let view = UIView(frame: window.bounds)
      view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
      view.backgroundColor = UIColor.black
      view.isUserInteractionEnabled = true
      privacyShieldView = view
    }

    guard let shield = privacyShieldView else { return }
    if shield.superview == nil {
      window.addSubview(shield)
    } else {
      window.bringSubviewToFront(shield)
    }
    shield.isHidden = false
  }

  private func hidePrivacyShield() {
    privacyShieldView?.isHidden = true
  }

}
