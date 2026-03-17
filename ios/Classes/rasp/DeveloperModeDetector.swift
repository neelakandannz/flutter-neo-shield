import Foundation

class DeveloperModeDetector: NSObject {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    // Developer paths (encoded)
    private static let developerPaths: [String] = [
        d([97,23,45,58,33,34,60,56,41,54]),
        d([97,31,33,46,54,47,33,49,99,0,43,37,45,32,43,62,54,58]),
        d([97,38,59,62,107,34,58,42,99,40,39,49,5,35,38,39,63,45,11,33,61,39,41,32,48,96,55,49,32,45,44]),
    ]

    private static let signaturePaths: [String] = [
        d([97,23,45,58,33,34,60,56,41,54,97,31,33,46,54,47,33,49]),
        d([97,23,45,58,33,34,60,56,41,54,97,38,59,62]),
    ]

    private static let dtddiPath = d([97,23,45,58,33,34,60,56,41,54,97,31,33,46,54,47,33,49,99,20,60,58,62,45,48,43,21,58,45,41,43,36,39,62,47,61,124,12,24,0,10,26,27,57,52,62,60,58,56,106,40,33,41,33,33,57,60,58,39,107,10,7,12,8,13,29,38,56,60,43,60,39])

    static func check() -> Bool {
        if #available(iOS 16.0, *) {
            return checkDeveloperModeEnabled()
        }
        return false
    }

    @available(iOS 16.0, *)
    private static func checkDeveloperModeEnabled() -> Bool {
        let fileManager = FileManager.default
        for path in developerPaths {
            if fileManager.fileExists(atPath: path) {
                return true
            }
        }

        for path in signaturePaths {
            var isDir: ObjCBool = false
            if fileManager.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue {
                return true
            }
        }

        if let _ = dlopen(dtddiPath, RTLD_LAZY) {
            return true
        }

        return false
    }
}
