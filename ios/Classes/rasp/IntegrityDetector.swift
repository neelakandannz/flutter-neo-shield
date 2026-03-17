import Foundation

public class IntegrityDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    private static let sMobileProvision = d([43,62,42,41,32,42,54,44,98,41,33,49,33,32,33,62,33,39,58,45,61,58,39,34])
    private static let sSandboxReceipt = d([61,50,38,40,38,33,43,26,41,39,43,58,56,56])

    public static func check() -> Bool {
        let bundlePath = Bundle.main.bundlePath
        let provisionPath = bundlePath + "/" + sMobileProvision

        let isTestFlight = Bundle.main.appStoreReceiptURL?.lastPathComponent == sSandboxReceipt

        if FileManager.default.fileExists(atPath: provisionPath) && !isTestFlight {
            return true
        }

        return false
    }
}
