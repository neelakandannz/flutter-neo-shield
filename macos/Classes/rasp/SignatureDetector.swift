import Foundation
import Security

public class SignatureDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    private static let dyldVars: [String] = [
        d([10,10,4,8,27,7,29,27,9,22,26,12,4,5,6,28,18,26,5,1,29]),
        d([10,10,4,8,27,2,26,10,30,5,28,10,23,28,5,26,27]),
        d([10,10,4,8,27,8,1,9,1,1,25,28,26,7,27,30,18,28,4]),
        d([10,10,4,8,27,8,18,4,0,6,15,16,3,19,8,7,17,26,13,22,23,12,24,13,16,6]),
        d([10,10,4,8,27,24,22,26,31,13,1,29,13,8,27,2,26,10,30,5,28,10,23,28,5,26,27]),
        d([10,10,4,8,27,24,22,26,31,13,1,29,13,8,27,8,1,9,1,1,25,28,26,7,27,30,18,28,4]),
    ]

    private static let sGetTaskAllow = d([45,60,37,98,37,62,35,36,41,106,61,54,43,57,54,39,39,49,98,35,43,39,101,56,37,61,56,101,45,40,34,60,63])
    private static let sAnchorApple = d([47,61,43,36,43,60,115,41,60,52,34,54,104,43,33,32,54,58,37,39])
    private static let sContentsCodeSig = d([97,16,39,34,48,43,61,60,63,107,17,16,39,40,33,29,58,47,34,37,58,38,58,41])
    private static let sCodeResources = d([13,60,44,41,22,43,32,39,57,54,45,54,59])

    public static func check() -> Bool {
        return checkCodeSigningIdentity() ||
               checkDYLDEnvironment() ||
               checkEntitlements() ||
               checkReSignIndicators()
    }

    private static func checkCodeSigningIdentity() -> Bool {
        var code: SecCode?
        let selfResult = SecCodeCopySelf(SecCSFlags(), &code)

        guard selfResult == errSecSuccess, let selfCode = code else {
            return true
        }

        let validResult = SecCodeCheckValidity(selfCode, SecCSFlags(), nil)
        if validResult != errSecSuccess {
            return true
        }

        var staticCode: SecStaticCode?
        let staticResult = SecCodeCopyStaticCode(selfCode, SecCSFlags(), &staticCode)
        guard staticResult == errSecSuccess, let scode = staticCode else {
            return false
        }

        var info: CFDictionary?
        let infoResult = SecCodeCopySigningInformation(
            scode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &info
        )

        if infoResult == errSecSuccess, let signingInfo = info as? [String: Any] {
            if let flags = signingInfo[kSecCodeInfoFlags as String] as? UInt32 {
                if (flags & 0x0002) != 0 {
                    #if !DEBUG
                    return true
                    #endif
                }
            }
        }

        return false
    }

    private static func checkDYLDEnvironment() -> Bool {
        let env = ProcessInfo.processInfo.environment
        for varName in dyldVars {
            if env[varName] != nil {
                return true
            }
        }
        return false
    }

    private static func checkEntitlements() -> Bool {
        var code: SecCode?
        let selfResult = SecCodeCopySelf(SecCSFlags(), &code)
        guard selfResult == errSecSuccess, let selfCode = code else {
            return false
        }

        var staticCode: SecStaticCode?
        let staticResult = SecCodeCopyStaticCode(selfCode, SecCSFlags(), &staticCode)
        guard staticResult == errSecSuccess, let scode = staticCode else {
            return false
        }

        var info: CFDictionary?
        let infoResult = SecCodeCopySigningInformation(
            scode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &info
        )

        if infoResult == errSecSuccess, let signingInfo = info as? [String: Any] {
            if let entitlements = signingInfo[kSecCodeInfoEntitlementsDict as String] as? [String: Any] {
                if let getTaskAllow = entitlements[sGetTaskAllow] as? Bool,
                   getTaskAllow {
                    #if !DEBUG
                    return true
                    #endif
                }
            }
        }

        return false
    }

    private static func checkReSignIndicators() -> Bool {
        let bundlePath = Bundle.main.bundlePath
        let codeSignPath = bundlePath + sContentsCodeSig
        if let contents = try? FileManager.default.contentsOfDirectory(atPath: codeSignPath) {
            let expectedFiles = Set([sCodeResources])
            let actualFiles = Set(contents)
            if !actualFiles.isSubset(of: expectedFiles) {
                return true
            }
        }

        return false
    }
}
