// Copyright 2026 Layergram. Licensed under the Apache License, Version 2.0.
#if targetEnvironment(simulator)
import LocalAuthentication
import UIKit

/// OS-sensor control test, separate from the actual Layergram keyboard gate.
/// No identity, custody, key material or Layergram session is accessible here.
final class SimulatorBiometricProbe: UIViewController {
  private let status = UILabel()
  private var context: LAContext?

  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = .systemBackground
    status.accessibilityIdentifier = "probe.biometric.state"
    status.text = "notStarted"
    let authenticate = UIButton(type: .system)
    authenticate.setTitle("Authenticate simulator sensor", for: .normal)
    authenticate.accessibilityIdentifier = "probe.biometric.authenticate"
    authenticate.addAction(UIAction { [weak self] _ in self?.authenticate() }, for: .touchUpInside)
    let layout = UIStackView(arrangedSubviews: [status, authenticate])
    layout.axis = .vertical; layout.spacing = 16
    layout.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(layout)
    NSLayoutConstraint.activate([
      layout.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
      layout.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
      layout.centerYAnchor.constraint(equalTo: view.centerYAnchor),
      authenticate.heightAnchor.constraint(equalToConstant: 44),
    ])
  }

  private func authenticate() {
    guard context == nil else { return }
    let candidate = LAContext()
    candidate.localizedFallbackTitle = ""
    var error: NSError?
    guard candidate.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
      status.text = "unavailable:\(error?.code ?? 0)"
      return
    }
    context = candidate
    status.text = "pending"
    candidate.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
      localizedReason: "QA simulator biometric sensor control") { [weak self] success, error in
      DispatchQueue.main.async {
        guard let self, self.context === candidate else { return }
        self.context = nil
        self.status.text = success ? "authenticated" : "rejected:\((error as NSError?)?.code ?? 0)"
      }
    }
  }
}
#endif
