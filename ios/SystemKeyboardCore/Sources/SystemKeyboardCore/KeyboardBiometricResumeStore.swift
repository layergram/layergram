import Foundation
import LocalAuthentication
import Security

/// An opt-in, revocable recovery capability for an idle keyboard.
/// Keychain enforces the current biometric set and device-only, unlocked access.
/// The containing app revokes this item whenever it reclaims keyboard custody.
public enum KeyboardBiometricResumeStore {
    public enum LoadResult {
        case success(Data)
        case retryable
        case unavailable
    }
    private static let service = "app.layergram.keyboard.biometric-resume.v1"
    private static let hintService = "app.layergram.keyboard.biometric-resume-hint.v1"
    private static let account = "autonomous-custody"

    private static func query(group: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrAccessGroup as String: group]
    }

    private static func hintQuery(group: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: hintService,
         kSecAttrAccount as String: account,
         kSecAttrAccessGroup as String: group]
    }

    public static func remove(group: String) {
        SecItemDelete(query(group: group) as CFDictionary)
        SecItemDelete(hintQuery(group: group) as CFDictionary)
    }

    /// A failed write leaves no usable item. Never store this capability in
    /// ordinary preferences or an App Group file.
    @discardableResult public static func save(_ payload: Data, group: String) -> Bool {
        guard !payload.isEmpty, payload.count <= 65_536,
              let hint = KeyboardBiometricResumeHint.encode(ticketData: payload) else { return false }
        remove(group: group)
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet, &error) else { return false }
        var attributes = query(group: group)
        attributes[kSecValueData as String] = payload
        attributes[kSecAttrAccessControl as String] = control
        guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else { return false }
        var hintAttributes = hintQuery(group: group)
        hintAttributes[kSecValueData as String] = hint
        hintAttributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(hintAttributes as CFDictionary, nil) == errSecSuccess else {
            remove(group: group)
            return false
        }
        return true
    }

    /// Read only an opaque editor hash and deadline after a new extension
    /// process appears. The protected ticket itself is never loaded here.
    public static func resumeDeadline(group: String, document: String, now: Int64,
                                      allowBiometricEditorRebind: Bool = false) -> Int64? {
        var attributes = hintQuery(group: group)
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        switch KeyboardBiometricResumeHint.admission(data: data, document: document, now: now) {
        case .matched(let expires):
            return expires
        case .differentEditor(let expires):
            // A screenshot sheet can briefly replace the host document before
            // the original editor returns. A new editor may only *offer* Face
            // ID when explicitly requested; this hint carries no key and
            // cannot itself authorize a keyboard session.
            return allowBiometricEditorRebind ? expires : nil
        case .invalid:
            remove(group: group)
            return nil
        }
    }

    /// Call only after a deliberate tap. Keychain may present Face ID/Touch ID.
    /// Cancellation, changed enrollment, lockout, and missing entitlements fail
    /// closed; there is no device-passcode fallback for this shortcut.
    public static func load(group: String, reason: String) -> LoadResult {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                        error: nil) else { return .unavailable }
        var attributes = query(group: group)
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        attributes[kSecUseAuthenticationContext as String] = context
        attributes[kSecUseOperationPrompt as String] = reason
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        if status == errSecUserCanceled || status == errSecAuthFailed {
            return .retryable
        }
        guard status == errSecSuccess, let data = result as? Data else {
            return .unavailable
        }
        return .success(data)
    }
}
