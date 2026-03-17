import Foundation
import MachO

public class HookDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    // Suspicious library names (encoded)
    private static let suspiciousLibraries: [String] = [
        d([61,38,42,63,48,60,50,60,41]),
        d([45,42,43,62,45,62,39]),
        d([40,33,33,40,37]),
        d([40,33,33,40,37,41,50,44,43,33,58]),
        d([61,32,36,39,45,34,63,59,59,45,58,48,32]),
        d([61,32,36,39,45,34,63,59,59,45,58,48,32,126]),
        d([35,60,42,37,40,43,32,61,46,55,58,33,41,56,33]),
        d([61,38,42,63,48,60,50,60,41,45,32,32,45,62,48,43,33]),
        d([61,38,42,63,48,60,50,60,41,40,33,50,44,41,54]),
        d([61,38,42,63,48,60,50,60,41,38,33,60,60,63,48,60,50,56]),
        d([34,58,42,47,61,45,33,33,60,48]),
        d([34,58,42,38,37,39,63,42,62,33,47,56]),
        d([61,38,42,63,48,39,39,61,56,33]),
        d([45,54,56,36,33,39]),
        d([60,60,43,39,33,58,49,39,35,48,61,39,58,45,52]),
        d([45,60,36,35,54,62,58,43,39,33,60]),
        d([61,61,39,35,40,39,54]),
        d([61,59,41,40,43,57]),
        d([34,58,42,41,54,58,42]),
        d([45,59,39,37,39,55]),
    ]

    public static func check() -> Bool {
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let imageName = _dyld_get_image_name(i) {
                let nameStr = String(cString: imageName).lowercased()
                for suspicious in suspiciousLibraries {
                    if nameStr.contains(suspicious) {
                        return true
                    }
                }
            }
        }

        return false
    }
}
