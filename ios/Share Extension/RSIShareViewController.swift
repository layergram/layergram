import UIKit
import Social

#if canImport(UniformTypeIdentifiers)
import UniformTypeIdentifiers
#endif
import MobileCoreServices

public let kSchemePrefix = "ShareMedia"
public let kUserDefaultsKey = "ShareKey"
public let kUserDefaultsMessageKey = "ShareMessageKey"
public let kAppGroupIdKey = "AppGroupId"

@available(swift, introduced: 5.0)
open class RSIShareViewController: SLComposeServiceViewController {
  private var hostAppBundleIdentifier = ""
  private var appGroupId = ""
  private var sharedMedia: [SharedMediaFile] = []
  private var attachmentsReady = false
  private var redirectRequested = false
  private var hasSavedShare = false

  /// Override to prevent automatic redirect to the host app.
  open func shouldAutoRedirect() -> Bool {
    return true
  }

  open override func isContentValid() -> Bool {
    return true
  }

  open override func viewDidLoad() {
    super.viewDidLoad()
    loadIds()
  }

  open override func didSelectPost() {
    redirectRequested = true
    saveAndRedirectIfReady(message: contentText)
  }

  open override func viewDidAppear(_ animated: Bool) {
    super.viewDidAppear(animated)

    let extensionItems =
        extensionContext?.inputItems.compactMap { $0 as? NSExtensionItem } ?? []
    let attachments = extensionItems.flatMap { $0.attachments ?? [] }

    guard !attachments.isEmpty else {
      attachmentsReady = true
      if shouldAutoRedirect() {
        redirectRequested = true
      }
      saveAndRedirectIfReady(message: contentText)
      return
    }

    let group = DispatchGroup()

    for provider in attachments {
      group.enter()
      loadSupportedItem(from: provider) { [weak self] item in
        DispatchQueue.main.async {
          if let item {
            self?.sharedMedia.append(item)
          }
          group.leave()
        }
      }
    }

    group.notify(queue: .main) { [weak self] in
      guard let self else { return }
      self.attachmentsReady = true
      if self.shouldAutoRedirect() {
        self.redirectRequested = true
      }
      self.saveAndRedirectIfReady(message: self.contentText)
    }
  }

  open override func configurationItems() -> [Any]! {
    return []
  }

  private func loadSupportedItem(
    from provider: NSItemProvider,
    completion: @escaping (SharedMediaFile?) -> Void
  ) {
    if provider.hasItemConformingToTypeIdentifier(SharedMediaType.text.toUTTypeIdentifier) {
      provider.loadItem(
        forTypeIdentifier: SharedMediaType.text.toUTTypeIdentifier,
        options: nil
      ) { item, _ in
        if let text = item as? String {
          let normalized = text.trimmingCharacters(in: .whitespacesAndNewlines)
          if !normalized.isEmpty {
            completion(
              SharedMediaFile(
                path: normalized,
                mimeType: "text/plain",
                type: .text
              )
            )
            return
          }
        }
        completion(nil)
      }
      return
    }

    if provider.hasItemConformingToTypeIdentifier(SharedMediaType.url.toUTTypeIdentifier) {
      provider.loadItem(
        forTypeIdentifier: SharedMediaType.url.toUTTypeIdentifier,
        options: nil
      ) { item, _ in
        if let url = item as? URL {
          completion(
            SharedMediaFile(path: url.absoluteString, mimeType: nil, type: .url)
          )
          return
        }

        if let text = item as? String {
          let normalized = text.trimmingCharacters(in: .whitespacesAndNewlines)
          if !normalized.isEmpty {
            completion(
              SharedMediaFile(path: normalized, mimeType: nil, type: .url)
            )
            return
          }
        }

        completion(nil)
      }
      return
    }

    completion(nil)
  }

  private func saveAndRedirectIfReady(message: String? = nil) {
    guard attachmentsReady, redirectRequested, !hasSavedShare else {
      return
    }
    hasSavedShare = true
    saveAndRedirect(message: message)
  }

  private func loadIds() {
    guard let shareExtensionBundleId = Bundle.main.bundleIdentifier else {
      return
    }

    if let lastDot = shareExtensionBundleId.lastIndex(of: ".") {
      hostAppBundleIdentifier = String(shareExtensionBundleId[..<lastDot])
    } else {
      hostAppBundleIdentifier = shareExtensionBundleId
    }

    let defaultAppGroupId = "group.\(hostAppBundleIdentifier)"
    let customAppGroupId = Bundle.main.object(forInfoDictionaryKey: kAppGroupIdKey) as? String
    appGroupId = customAppGroupId ?? defaultAppGroupId
  }

  private func saveAndRedirect(message: String? = nil) {
    // Ensure IDs are loaded.
    loadIds()

    let userDefaults = UserDefaults(suiteName: appGroupId)
    if let data = try? JSONEncoder().encode(sharedMedia) {
      userDefaults?.set(data, forKey: kUserDefaultsKey)
    }
    userDefaults?.set(message, forKey: kUserDefaultsMessageKey)
    userDefaults?.synchronize()

    redirectToHostApp()
  }

  private func redirectToHostApp() {
    loadIds()

    guard let url = URL(string: "\(kSchemePrefix)-\(hostAppBundleIdentifier):share") else {
      extensionContext?.completeRequest(returningItems: [], completionHandler: nil)
      return
    }

    var responder: UIResponder? = self

    if #available(iOS 18.0, *) {
      while responder != nil {
        if let application = responder as? UIApplication {
          application.open(url, options: [:], completionHandler: nil)
        }
        responder = responder?.next
      }
    } else {
      let selectorOpenURL = sel_registerName("openURL:")

      while responder != nil {
        if responder?.responds(to: selectorOpenURL) == true {
          _ = responder?.perform(selectorOpenURL, with: url)
        }
        responder = responder?.next
      }
    }

    extensionContext?.completeRequest(returningItems: [], completionHandler: nil)
  }
}

public struct SharedMediaFile: Codable {
  public var path: String
  public var mimeType: String?
  public var thumbnail: String?
  public var duration: Double?
  public var type: SharedMediaType

  public init(
    path: String,
    mimeType: String? = nil,
    thumbnail: String? = nil,
    duration: Double? = nil,
    type: SharedMediaType
  ) {
    self.path = path
    self.mimeType = mimeType
    self.thumbnail = thumbnail
    self.duration = duration
    self.type = type
  }
}

public enum SharedMediaType: String, Codable, CaseIterable {
  case text
  case url

  public var toUTTypeIdentifier: String {
    if #available(iOS 14.0, *), let id = utTypeIdentifierIOS14 {
      return id
    }
    switch self {
    case .text:
      return kUTTypeText as String
    case .url:
      return kUTTypeURL as String
    }
  }

  @available(iOS 14.0, *)
  private var utTypeIdentifierIOS14: String? {
    #if canImport(UniformTypeIdentifiers)
    switch self {
    case .text:
      return UTType.text.identifier
    case .url:
      return UTType.url.identifier
    }
    #else
    return nil
    #endif
  }
}
