import Foundation
import Darwin

/// Detects network-level threats used during reverse engineering from desktop.
public class NetworkThreatDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    // VPN interface prefixes (encoded)
    private static let vpnPrefixes: [String] = [
        d([59,39,61,34]),    // utun
        d([62,35,56]),       // ppp
        d([39,35,59,41,39]), // ipsec
        d([58,50,56]),       // tap
        d([58,38,38]),       // tun
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
        guard let proxySettings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return false
        }

        if let httpProxy = proxySettings[kCFNetworkProxiesHTTPProxy as String] as? String,
           !httpProxy.isEmpty {
            if let httpEnabled = proxySettings[kCFNetworkProxiesHTTPEnable as String] as? Int,
               httpEnabled == 1 {
                return true
            }
        }

        if let httpsProxy = proxySettings[kCFNetworkProxiesHTTPSProxy as String] as? String,
           !httpsProxy.isEmpty {
            if let httpsEnabled = proxySettings[kCFNetworkProxiesHTTPSEnable as String] as? Int,
               httpsEnabled == 1 {
                return true
            }
        }

        if let socksProxy = proxySettings[kCFNetworkProxiesSOCKSProxy as String] as? String,
           !socksProxy.isEmpty {
            if let socksEnabled = proxySettings[kCFNetworkProxiesSOCKSEnable as String] as? Int,
               socksEnabled == 1 {
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
