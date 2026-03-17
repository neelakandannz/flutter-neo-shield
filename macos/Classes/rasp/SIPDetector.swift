import Foundation

public class SIPDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    private static let sCsrutil = d([97,38,59,62,107,44,58,38,99,39,61,33,61,56,45,34])
    private static let sStatus = d([61,39,41,56,49,61])
    private static let sDisabled = d([42,58,59,45,38,34,54,44])
    private static let protectedPaths: [String] = [
        d([97,0,49,63,48,43,62,103,0,45,44,33,41,62,61]),
        d([97,38,59,62,107,34,58,42]),
        d([97,38,59,62,107,44,58,38]),
    ]
    private static let sSipTest = d([97,125,38,41,43,17,32,32,37,33,34,55,23,63,45,62,12,60,41,55,58])

    public static func check() -> Bool {
        return checkRootPrivileges() || checkSIPDisabled() || checkSuspiciousPaths()
    }

    private static func checkRootPrivileges() -> Bool {
        return getuid() == 0 || geteuid() == 0
    }

    private static func checkSIPDisabled() -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: sCsrutil)
        process.arguments = [sStatus]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""

            if output.lowercased().contains(sDisabled) {
                return true
            }
        } catch {
            return true
        }

        return false
    }

    private static func checkSuspiciousPaths() -> Bool {
        for base in protectedPaths {
            let path = base + sSipTest
            let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
            if fd != -1 {
                close(fd)
                unlink(path)
                return true
            }
        }

        return false
    }
}
