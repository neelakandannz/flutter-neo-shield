import Foundation

public class EmulatorDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    private static let sSimDeviceName = d([29,26,5,25,8,15,7,7,30,27,10,22,30,5,7,11,12,6,13,9,11])
    private static let sSimHostHome = d([29,26,5,25,8,15,7,7,30,27,6,28,27,24,27,6,28,5,9])
    private static let sI386 = d([39,96,112,122])
    private static let sX8664 = d([54,107,126,19,114,122])

    public static func check() -> Bool {
        #if targetEnvironment(simulator)
            return true
        #else
            if ProcessInfo.processInfo.environment[sSimDeviceName] != nil {
                return true
            }
            if ProcessInfo.processInfo.environment[sSimHostHome] != nil {
                return true
            }

            var name = [Int32](repeating: 0, count: 2)
            name[0] = CTL_HW
            name[1] = HW_MACHINE
            var size = Int()
            sysctl(UnsafeMutablePointer<Int32>(mutating: name), 2, nil, &size, nil, 0)
            var machine = [CChar](repeating: 0, count: size)
            sysctl(UnsafeMutablePointer<Int32>(mutating: name), 2, &machine, &size, nil, 0)
            let platform = String(cString: machine)

            if platform == sI386 || platform == sX8664 {
                return true
            }

            return false
        #endif
    }
}
