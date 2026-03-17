import Foundation
import Darwin
import SystemConfiguration

public class NetworkThreatDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    private static let vpnPrefixes: [String] = [
        d([59,39,61,34]), d([62,35,56]), d([39,35,59,41,39]), d([58,50,56]), d([58,38,38]),
    ]

    private static let proxyVars: [String] = [
        d([38,39,60,60,27,62,33,39,52,61]),
        d([38,39,60,60,55,17,35,58,35,60,55]),
        d([6,7,28,28,27,30,1,7,20,29]),
        d([6,7,28,28,23,17,3,26,3,28,23]),
        d([15,31,4,19,20,28,28,16,21]),
    ]

    public static func check() -> [String: Any] {
        let proxyDetected = checkProxy()
        let vpnDetected = checkVpn()

        return [
            "proxyDetected": proxyDetected,
            "vpnDetected": vpnDetected,
            "detected": proxyDetected || vpnDetected
        ]
    }

    public static func checkSimple() -> Bool {
        return checkProxy() || checkVpn()
    }

    private static func checkProxy() -> Bool {
        guard let proxySettings = SCDynamicStoreCopyProxies(nil) as? [String: Any] else {
            return false
        }

        if let httpEnabled = proxySettings[kSCPropNetProxiesHTTPEnable as String] as? Int,
           httpEnabled == 1 {
            if let httpProxy = proxySettings[kSCPropNetProxiesHTTPProxy as String] as? String,
               !httpProxy.isEmpty {
                return true
            }
        }

        if let httpsEnabled = proxySettings[kSCPropNetProxiesHTTPSEnable as String] as? Int,
           httpsEnabled == 1 {
            if let httpsProxy = proxySettings[kSCPropNetProxiesHTTPSProxy as String] as? String,
               !httpsProxy.isEmpty {
                return true
            }
        }

        if let socksEnabled = proxySettings[kSCPropNetProxiesSOCKSEnable as String] as? Int,
           socksEnabled == 1 {
            if let socksProxy = proxySettings[kSCPropNetProxiesSOCKSProxy as String] as? String,
               !socksProxy.isEmpty {
                return true
            }
        }

        let env = ProcessInfo.processInfo.environment
        for varName in proxyVars {
            if let value = env[varName], !value.isEmpty {
                return true
            }
        }

        return false
    }

    private static func checkVpn() -> Bool {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return false
        }
        defer { freeifaddrs(ifaddr) }

        var addr = firstAddr
        while true {
            let name = String(cString: addr.pointee.ifa_name)
            let flags = Int32(addr.pointee.ifa_flags)
            let isUp = (flags & IFF_UP) != 0

            if isUp {
                for prefix in vpnPrefixes {
                    if name.hasPrefix(prefix) {
                        return true
                    }
                }
            }

            guard let next = addr.pointee.ifa_next else { break }
            addr = next
        }

        return false
    }
}
