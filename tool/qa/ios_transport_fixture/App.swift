// Copyright 2026 Layergram. Licensed under the Apache License, Version 2.0.
import UIKit

/// Offline host for testing the real installed keyboard extension. No vault,
/// identity, network transport or application crypto is implemented here.
@main final class TransportApp: UIResponder, UIApplicationDelegate {
  func application(_ application: UIApplication,
                   configurationForConnecting session: UISceneSession,
                   options: UIScene.ConnectionOptions) -> UISceneConfiguration {
    let configuration = UISceneConfiguration(name: "Transport", sessionRole: session.role)
    configuration.delegateClass = TransportScene.self
    return configuration
  }
}

final class TransportScene: UIResponder, UIWindowSceneDelegate {
  var window: UIWindow?
  private var captureTimer: Timer?

  func scene(_ scene: UIScene, willConnectTo session: UISceneSession,
             options: UIScene.ConnectionOptions) {
    guard let scene = scene as? UIWindowScene else { return }
    let candidate = ProcessInfo.processInfo.environment["LAYERGRAM_QA_INCOMING_CARRIER"]
    let incoming = candidate.flatMap { text in
      text.utf16.count <= 4_000 && (text.hasPrefix("p1.") || text.hasPrefix("m3.") || text.hasPrefix("b3."))
        ? text : nil
    }
    let window = UIWindow(windowScene: scene)
#if targetEnvironment(simulator)
    if ProcessInfo.processInfo.environment["LAYERGRAM_QA_SIMULATOR_BIOMETRIC_PROBE"] == "YES" {
      window.rootViewController = SimulatorBiometricProbe()
      window.makeKeyAndVisible()
      self.window = window
      return
    }
#endif
    let controller = UIViewController()
    controller.view.backgroundColor = .systemBackground
    let input = UITextView()
    input.accessibilityIdentifier = "probe.transport.field"
    input.font = .systemFont(ofSize: 17)
    input.layer.borderWidth = 1
    let send = UIButton(type: .system)
    send.accessibilityIdentifier = "probe.transport.send"
    send.setTitle("Send in offline transport", for: .normal)
    send.addAction(UIAction { _ in input.text = "" }, for: .touchUpInside)
    let hide = UIButton(type: .system)
    hide.accessibilityIdentifier = "probe.transport.hideKeyboard"
    hide.setTitle("Hide keyboard", for: .normal)
    hide.addAction(UIAction { _ in input.resignFirstResponder() }, for: .touchUpInside)
    let show = UIButton(type: .system)
    show.accessibilityIdentifier = "probe.transport.showKeyboard"
    show.setTitle("Show keyboard", for: .normal)
    show.addAction(UIAction { _ in input.becomeFirstResponder() }, for: .touchUpInside)
    let focusControls = UIStackView(arrangedSubviews: [hide, show])
    focusControls.distribution = .fillEqually
    let copy = UIButton(type: .system)
    copy.accessibilityIdentifier = "probe.transport.copyIncoming"
    copy.setTitle("Copy incoming test carrier", for: .normal)
    copy.isEnabled = incoming != nil
    copy.addAction(UIAction { _ in
      // Copy only the supplied test ciphertext, after the keyboard has opened.
      // The containing app can legitimately clear the clipboard on handoff.
      if let incoming { UIPasteboard.general.string = incoming }
    }, for: .touchUpInside)
    let capture = UILabel()
    capture.accessibilityIdentifier = "probe.capture.state"
    let layout = UIStackView(arrangedSubviews: [input, send, focusControls, copy, capture])
    layout.axis = .vertical
    layout.spacing = 8
    layout.translatesAutoresizingMaskIntoConstraints = false
    controller.view.addSubview(layout)
    NSLayoutConstraint.activate([
      layout.topAnchor.constraint(equalTo: controller.view.safeAreaLayoutGuide.topAnchor, constant: 12),
      layout.leadingAnchor.constraint(equalTo: controller.view.leadingAnchor, constant: 12),
      layout.trailingAnchor.constraint(equalTo: controller.view.trailingAnchor, constant: -12),
      input.heightAnchor.constraint(equalToConstant: 180),
      send.heightAnchor.constraint(equalToConstant: 44),
      focusControls.heightAnchor.constraint(equalToConstant: 44),
      copy.heightAnchor.constraint(equalToConstant: 44),
    ])
    captureTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { _ in
      capture.text = scene.screen.isCaptured ? "captured" : "notCaptured"
    }
    window.rootViewController = controller
    window.makeKeyAndVisible()
    self.window = window
  }
}
