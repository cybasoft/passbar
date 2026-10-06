import Foundation
import Security

public enum SecretKey: String, CaseIterable, Sendable {
    case privateKey = "private-key"
    case passphrase = "passphrase"
}

/// Abstraction over secret persistence (macOS Keychain in production).
public protocol SecretStore: Sendable {
    func set(_ data: Data, for key: SecretKey) throws
    func get(_ key: SecretKey) throws -> Data?
    func deleteAll() throws
}

/// SECURITY CRITICAL: stores the user's private key and passphrase.
/// Items are generic passwords in the macOS Keychain, readable only while the
/// device is unlocked and never migrated to other devices or iCloud.
public struct KeychainSecretStore: SecretStore {
    private let service: String
    public init(service: String = "local.passbolt-menubar") { self.service = service }

    private func query(_ key: SecretKey) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: key.rawValue]
    }

    public func set(_ data: Data, for key: SecretKey) throws {
        var attrs = query(key)
        let update = [kSecValueData as String: data]
        var status = SecItemUpdate(attrs as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            attrs[kSecValueData as String] = data
            attrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(attrs as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw PassboltError.keychain(status) }
    }

    public func get(_ key: SecretKey) throws -> Data? {
        var q = query(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw PassboltError.keychain(status) }
        return out as? Data
    }

    public func deleteAll() throws {
        for key in SecretKey.allCases {
            let status = SecItemDelete(query(key) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw PassboltError.keychain(status) }
        }
    }
}

/// Non-persistent store for tests.
public final class InMemorySecretStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [SecretKey: Data] = [:]
    public init() {}
    public func set(_ data: Data, for key: SecretKey) throws { lock.lock(); items[key] = data; lock.unlock() }
    public func get(_ key: SecretKey) throws -> Data? { lock.lock(); defer { lock.unlock() }; return items[key] }
    public func deleteAll() throws { lock.lock(); items = [:]; lock.unlock() }
}
