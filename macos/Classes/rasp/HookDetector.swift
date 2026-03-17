import Foundation
import MachO

public class HookDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    private static let sDyldInsertLibs = d([10,10,4,8,27,7,29,27,9,22,26,12,4,5,6,28,18,26,5,1,29])
    private static let sDyldLibPath = d([10,10,4,8,27,2,26,10,30,5,28,10,23,28,5,26,27])
    private static let sDyldFwPath = d([10,10,4,8,27,8,1,9,1,1,25,28,26,7,27,30,18,28,4])

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
        d([61,38,42,63,48,39,39,61,56,33]),
        d([61,59,41,40,43,57]),
        d([34,58,42,41,54,58,42]),
        d([39,61,34,41,39,58]),
        d([38,60,39,39]),
        d([39,61,60,41,54,62,60,59,41]),
        d([40,58,59,36,44,33,60,35]),
        d([35,58,60,33,52,60,60,48,53]),
        d([45,59,41,62,40,43,32,56,62,43,54,42]),
    ]

    public static func check() -> Bool {
        return checkDYLDEnvironment() || checkLoadedDylibs()
    }

    private static func checkDYLDEnvironment() -> Bool {
        let env = ProcessInfo.processInfo.environment

        if env[sDyldInsertLibs] != nil { return true }
        if env[sDyldLibPath] != nil { return true }
        if env[sDyldFwPath] != nil { return true }

        return false
    }

    private static func checkLoadedDylibs() -> Bool {
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
