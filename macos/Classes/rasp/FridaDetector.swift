import Foundation
import Darwin

public class FridaDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    private static let fridaPaths: [String] = [
        d([97,38,59,62,107,34,60,43,45,40,97,49,33,34,107,40,33,33,40,37,99,32,45,62,50,43,33]),
        d([97,38,59,62,107,34,60,43,45,40,97,49,33,34,107,40,33,33,40,37]),
        d([97,38,59,62,107,34,60,43,45,40,97,63,33,46,107,40,33,33,40,37]),
        d([97,38,59,62,107,44,58,38,99,34,60,58,44,45,105,61,54,58,58,33,60]),
        d([97,38,59,62,107,61,49,33,34,107,40,33,33,40,37,99,32,45,62,50,43,33]),
        d([97,60,56,56,107,38,60,37,41,38,60,54,63,99,38,39,61,103,42,54,39,55,41]),
        d([97,60,56,56,107,38,60,37,41,38,60,54,63,99,38,39,61,103,42,54,39,55,41,97,55,43,33,62,41,54]),
    ]

    private static let suspiciousNames: [String] = [
        d([40,33,33,40,37]),
        d([40,33,33,40,37,41,50,44,43,33,58]),
        d([40,33,33,40,37,99,50,47,41,42,58]),
        d([40,33,33,40,37,99,52,41,40,35,43,39]),
    ]

    public static func check() -> Bool {
        return checkPorts() || checkFiles() || checkLoadedLibraries()
    }

    private static func checkPorts() -> Bool {
        let fridaPorts: [in_port_t] = [27042, 27043, 4444]
        for port in fridaPorts {
            if isPortOpen(port) {
                return true
            }
        }
        return false
    }

    private static func checkFiles() -> Bool {
        for path in fridaPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }

    private static func checkLoadedLibraries() -> Bool {
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let imageName = _dyld_get_image_name(i) {
                let nameStr = String(cString: imageName).lowercased()
                for suspicious in suspiciousNames {
                    if nameStr.contains(suspicious) {
                        return true
                    }
                }
            }
        }
        return false
    }

    private static func isPortOpen(_ port: in_port_t) -> Bool {
        let sockfd = socket(AF_INET, SOCK_STREAM, 0)
        guard sockfd != -1 else { return false }
        defer { close(sockfd) }

        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let result = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(sockfd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        return result == 0
    }
}
