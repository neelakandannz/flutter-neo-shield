import Foundation

public class DeveloperModeDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    private static let sSecurity = d([97,38,59,62,107,44,58,38,99,55,43,48,61,62,45,58,42])
    private static let sAuthDb = d([47,38,60,36,43,60,58,50,45,48,39,60,38,40,38])
    private static let sRead = d([60,54,41,40])
    private static let sTaskport = d([61,42,59,56,33,35,125,56,62,45,56,58,36,41,35,43,125,60,45,55,37,35,39,62,48])
    private static let sAllow = d([47,63,36,35,51])
    private static let sDisabled = d([42,58,59,45,38,34,54,44])

    private static let developerPaths: [String] = [
        d([97,18,56,60,40,39,48,41,56,45,33,61,59,99,28,45,60,44,41,106,47,35,56]),
        d([97,31,33,46,54,47,33,49,99,0,43,37,45,32,43,62,54,58,99,7,33,62,37,45,42,42,31,33,34,33,26,60,39,32,55]),
        d([97,38,59,62,107,44,58,38,99,60,45,60,44,41,105,61,54,36,41,39,58]),
    ]

    private static let sXcodeSelect = d([97,38,59,62,107,44,58,38,99,60,45,60,44,41,105,61,54,36,41,39,58])
    private static let sDashP = d([99,35])
    private static let sSpctl = d([97,38,59,62,107,61,49,33,34,107,61,35,43,56,40])
    private static let sDashDashStatus = d([99,126,59,56,37,58,38,59])

    public static func check() -> Bool {
        return checkDevToolsSecurity() || checkXcodePresence() || checkGatekeeper()
    }

    private static func checkDevToolsSecurity() -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: sSecurity)
        process.arguments = [sAuthDb, sRead, sTaskport]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""

            if output.contains(sAllow) {
                return true
            }
        } catch {
            // Can't check
        }

        return false
    }

    private static func checkXcodePresence() -> Bool {
        for path in developerPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: sXcodeSelect)
        process.arguments = [sDashP]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()

            if process.terminationStatus == 0 {
                return true
            }
        } catch {
            // xcode-select not available
        }

        return false
    }

    private static func checkGatekeeper() -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: sSpctl)
        process.arguments = [sDashDashStatus]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""

            if output.lowercased().contains(sDisabled) {
                return true
            }
        } catch {
            // Can't check Gatekeeper status
        }

        return false
    }
}
