import Foundation
import Security
class SecureStorageHandler {
    private let svc = "com.neelakandan.flutter_neo_shield"
    func write(key: String, value: String) -> Bool {
        guard let data = value.data(using: .utf8) else { return false }
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: svc, kSecAttrAccount as String: key] as CFDictionary)
        return SecItemAdd([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: svc, kSecAttrAccount as String: key, kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly] as CFDictionary, nil) == errSecSuccess
    }
    func read(key: String) -> String? {
        var result: AnyObject?
        guard SecItemCopyMatching([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: svc, kSecAttrAccount as String: key, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne] as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    func delete(key: String) -> Bool {
        let s = SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: svc, kSecAttrAccount as String: key] as CFDictionary)
        return s == errSecSuccess || s == errSecItemNotFound
    }
    func containsKey(key: String) -> Bool {
        return SecItemCopyMatching([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: svc, kSecAttrAccount as String: key, kSecReturnData as String: false] as CFDictionary, nil) == errSecSuccess
    }
    func wipeAll() -> Bool {
        let s = SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: svc] as CFDictionary)
        return s == errSecSuccess || s == errSecItemNotFound
    }
}
