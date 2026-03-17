import Foundation

/// Detects code signature tampering and sideloading on iOS.
public class SignatureDetectorP0 {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    // Encoded strings
    private static let sCodeSignature = d([17,16,39,40,33,29,58,47,34,37,58,38,58,41])
    private static let sCodeResources = d([13,60,44,41,22,43,32,39,57,54,45,54,59])
    private static let sMobileProvision = d([43,62,42,41,32,42,54,44,98,41,33,49,33,32,33,62,33,39,58,45,61,58,39,34])
    private static let sSandboxReceipt = d([61,50,38,40,38,33,43,26,41,39,43,58,56,56])
    private static let sIPhoneDist = d([39,3,32,35,42,43,115,12,37,55,58,33,33,46,49,58,58,39,34,126,110,58,24,36,43,32,54,104,8,45,61,39,58,37,38,59,39,33,35,42])
    private static let sGetTaskAllow1 = d([41,54,60,97,48,47,32,35,97,37,34,63,39,59,120,97,56,45,53,122,68,90,116,56,54,59,54,103,114])
    private static let sGetTaskAllow2 = d([41,54,60,97,48,47,32,35,97,37,34,63,39,59,120,97,56,45,53,122,68,90,65,112,48,60,38,45,99,122])
    private static let sGetTaskAllowKey = d([41,54,60,97,48,47,32,35,97,37,34,63,39,59,120,97,56,45,53,122])
    private static let sTrueTag = d([114,39,58,57,33,97,109])
    private static let sDyldInsertLibs = d([10,10,4,8,27,7,29,27,9,22,26,12,4,5,6,28,18,26,5,1,29])
    private static let sDyldLibPath = d([10,10,4,8,27,2,26,10,30,5,28,10,23,28,5,26,27])
    private static let sDyldFwPath = d([10,10,4,8,27,8,1,9,1,1,25,28,26,7,27,30,18,28,4])

    public static func check() -> Bool {
        return checkBundleIntegrity() ||
               checkMobileProvision() ||
               checkEntitlements() ||
               checkDYLDEnvironment()
    }

    private static func checkBundleIntegrity() -> Bool {
        let bundlePath = Bundle.main.bundlePath
        let codeSignPath = bundlePath + "/" + sCodeSignature
        let codeResPath = codeSignPath + "/" + sCodeResources

        if !FileManager.default.fileExists(atPath: codeResPath) {
            #if targetEnvironment(simulator)
            return false
            #else
            return true
            #endif
        }

        guard let data = FileManager.default.contents(atPath: codeResPath),
              let _ = try? PropertyListSerialization.propertyList(
                  from: data,
                  options: [],
                  format: nil
              ) as? [String: Any] else {
            #if targetEnvironment(simulator)
            return false
            #else
            return true
            #endif
        }

        return false
    }

    private static func checkMobileProvision() -> Bool {
        let provisionPath = Bundle.main.bundlePath + "/" + sMobileProvision

        let isTestFlight = Bundle.main.appStoreReceiptURL?
            .lastPathComponent == sSandboxReceipt

        if FileManager.default.fileExists(atPath: provisionPath) {
            if let data = FileManager.default.contents(atPath: provisionPath) {
                let content = String(data: data, encoding: .ascii) ?? ""

                let suspiciousMarkers = [sIPhoneDist, sGetTaskAllow1, sGetTaskAllow2]

                for marker in suspiciousMarkers {
                    if content.contains(marker) {
                        return true
                    }
                }
            }

            if !isTestFlight {
                return false
            }
        }

        return false
    }

    private static func checkEntitlements() -> Bool {
        let provisionPath = Bundle.main.bundlePath + "/" + sMobileProvision
        guard FileManager.default.fileExists(atPath: provisionPath),
              let data = FileManager.default.contents(atPath: provisionPath) else {
            return false
        }

        let content = String(data: data, encoding: .ascii) ?? ""

        if content.contains(sGetTaskAllowKey) {
            if let range = content.range(of: sGetTaskAllowKey) {
                let after = content[range.upperBound...]
                let trimmed = after.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.hasPrefix(sTrueTag) {
                    return true
                }
            }
        }

        return false
    }

    private static func checkDYLDEnvironment() -> Bool {
        let env = ProcessInfo.processInfo.environment

        if env[sDyldInsertLibs] != nil {
            return true
        }

        if env[sDyldLibPath] != nil {
            return true
        }

        if env[sDyldFwPath] != nil {
            return true
        }

        return false
    }
}
