import Foundation
import IOKit
import CommonCrypto
class DeviceBindingDetector {
    static func getDeviceFingerprint() -> String {
        var components = ""
        let pe = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        if pe != 0 {
            if let uuid = IORegistryEntryCreateCFProperty(pe, "IOPlatformUUID" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String { components += uuid }
            IOObjectRelease(pe)
        }
        var size = 0; sysctlbyname("hw.model", nil, &size, nil, 0)
        var model = [CChar](repeating: 0, count: size); sysctlbyname("hw.model", &model, &size, nil, 0)
        components += String(cString: model)
        guard let data = components.data(using: .utf8) else { return "" }
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
