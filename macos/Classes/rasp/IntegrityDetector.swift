import Foundation
import Security

public class IntegrityDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    private static let sAnchorApple = d([47,61,43,36,43,60,115,41,60,52,34,54,104,43,33,32,54,58,37,39])
    private static let sContentsCodeSig = d([97,16,39,34,48,43,61,60,63,107,17,16,39,40,33,29,58,47,34,37,58,38,58,41])
    private static let sCodeResources = d([13,60,44,41,22,43,32,39,57,54,45,54,59])

    public static func check() -> Bool {
        return checkCodeSignature() || checkBundleStructure()
    }

    private static func checkCodeSignature() -> Bool {
        guard let bundleURL = Bundle.main.executableURL else {
            return true
        }

        var staticCode: SecStaticCode?
        let createResult = SecStaticCodeCreateWithPath(
            bundleURL as CFURL,
            SecCSFlags(),
            &staticCode
        )

        guard createResult == errSecSuccess, let code = staticCode else {
            return true
        }

        let checkResult = SecStaticCodeCheckValidity(
            code,
            SecCSFlags(rawValue: kSecCSCheckAllArchitectures),
            nil
        )

        if checkResult != errSecSuccess {
            return true
        }

        var requirement: SecRequirement?
        let reqResult = SecRequirementCreateWithString(
            sAnchorApple as CFString,
            SecCSFlags(),
            &requirement
        )

        if reqResult == errSecSuccess, let req = requirement {
            let validResult = SecStaticCodeCheckValidity(code, SecCSFlags(), req)
            if validResult != errSecSuccess {
                return true
            }
        }

        return false
    }

    private static func checkBundleStructure() -> Bool {
        let bundlePath = Bundle.main.bundlePath
        let codeSignPath = bundlePath + sContentsCodeSig
        let codeResPath = codeSignPath + "/" + sCodeResources

        if !FileManager.default.fileExists(atPath: codeResPath) {
            #if DEBUG
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
            #if DEBUG
            return false
            #else
            return true
            #endif
        }

        return false
    }
}
