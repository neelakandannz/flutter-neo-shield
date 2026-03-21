import Foundation
import MachO
class CodeInjectionDetector {
    static func check() -> Bool { return checkDyldInjection() || checkSuspiciousDylibs() }
    private static func checkDyldInjection() -> Bool {
        for v in ["DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"] {
            if ProcessInfo.processInfo.environment[v] != nil { return true }
        }
        return false
    }
    private static func checkSuspiciousDylibs() -> Bool {
        let count = _dyld_image_count()
        let suspicious = ["inject", "payload", "exploit", "backdoor", "trojan", "keylog"]
        for i in 0..<count {
            guard let name = _dyld_get_image_name(i) else { continue }
            let n = String(cString: name).lowercased()
            for s in suspicious { if n.contains(s) { return true } }
        }
        return false
    }
    static func getSuspiciousModules() -> String {
        var modules: [String] = []
        let count = _dyld_image_count()
        let suspicious = ["inject", "payload", "exploit", "backdoor", "trojan", "keylog", "frida", "substrate"]
        for i in 0..<count {
            guard let name = _dyld_get_image_name(i) else { continue }
            let n = String(cString: name).lowercased()
            for s in suspicious { if n.contains(s) { modules.append(String(cString: name)); break } }
        }
        return modules.joined(separator: ",")
    }
}
