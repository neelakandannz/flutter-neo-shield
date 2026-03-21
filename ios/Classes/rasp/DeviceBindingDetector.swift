import UIKit
import CommonCrypto
class DeviceBindingDetector {
    static func getDeviceFingerprint() -> String {
        var components = ""
        if let vid = UIDevice.current.identifierForVendor?.uuidString { components += vid }
        components += UIDevice.current.model + UIDevice.current.systemName
        var size = 0; sysctlbyname("hw.machine", nil, &size, nil, 0)
        var machine = [CChar](repeating: 0, count: size); sysctlbyname("hw.machine", &machine, &size, nil, 0)
        components += String(cString: machine)
        guard let data = components.data(using: .utf8) else { return "" }
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
