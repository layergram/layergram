import CryptoKit
import Foundation
import Security

/// Independent, device-only copy of the *encrypted* custody state. The App
/// Group directory may be replaced during an iOS app update, so its file cannot
/// be the only durable copy while the keyboard owns the V3 ratchet.
public protocol KeyboardCustodyMirror {
    func load() throws -> Data?
    func save(_ sealedState: Data) throws
    func remove() throws
}

/// The app and keyboard already share this App Group as a Keychain access
/// group. The recovery key remains in the app's private encrypted journal;
/// this item contains only the AES-GCM sealed state and never grants a session.
public final class KeyboardKeychainCustodyMirror: KeyboardCustodyMirror {
    private static let service = "app.layergram.keyboard.custody-mirror.v1"
    private static let account = "v3-working-state"
    private let group: String
    private let epoch: Data
    private let accountName: String

    public init(group: String, epoch: Data, account: String = "v3-working-state") {
        self.group = group
        self.epoch = epoch
        self.accountName = account
    }

    /// Used only for admission when the app has not yet loaded an identity and
    /// therefore cannot know the epoch. No ciphertext or key is returned.
    public static func hasAny(group: String) throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: group,
            kSecAttrSynchronizable as String: false,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return false }
        guard status == errSecSuccess else { throw KeyboardCustodyStore.Failure.unavailable }
        return true
    }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: Self.service,
         kSecAttrAccount as String: accountName,
         kSecAttrAccessGroup as String: group,
         kSecAttrSynchronizable as String: false]
    }

    public func load() throws -> Data? {
        var attributes = query
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = value as? Data,
              data.count >= 53,
              data.count <= KeyboardCustodyStore.maxPlaintextBytes + 64,
              data[0] == 1, Data(data[1..<17]) == epoch else {
            throw KeyboardCustodyStore.Failure.unavailable
        }
        return data
    }

    public func save(_ sealedState: Data) throws {
        guard sealedState.count >= 53,
              sealedState.count <= KeyboardCustodyStore.maxPlaintextBytes + 64,
              sealedState[0] == 1,
              Data(sealedState[1..<17]) == epoch else {
            throw KeyboardCustodyStore.Failure.invalidInput
        }
        let previous = try load()
        let digest = Data(SHA256.hash(data: sealedState))
        let status: OSStatus
        if previous == nil {
            var attributes = query
            attributes[kSecValueData as String] = sealedState
            attributes[kSecAttrGeneric as String] = digest
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(attributes as CFDictionary, nil)
        } else {
            var expected = query
            expected[kSecAttrGeneric as String] = Data(SHA256.hash(data: previous!))
            status = SecItemUpdate(expected as CFDictionary,
                [kSecValueData as String: sealedState,
                 kSecAttrGeneric as String: digest] as CFDictionary)
        }
        guard status == errSecSuccess, try load() == sealedState else {
            throw KeyboardCustodyStore.Failure.unavailable
        }
    }

    public func remove() throws {
        guard let previous = try load() else { return }
        var expected = query
        expected[kSecAttrGeneric as String] = Data(SHA256.hash(data: previous))
        let status = SecItemDelete(expected as CFDictionary)
        guard (status == errSecSuccess || status == errSecItemNotFound),
              try load() == nil else {
            throw KeyboardCustodyStore.Failure.unavailable
        }
    }
}
