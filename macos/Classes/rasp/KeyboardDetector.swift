import Cocoa
import Carbon
class KeyboardDetector {
    static func isThirdPartyKeyboard() -> Bool { return false }
    static func getCurrentKeyboardPackage() -> String { return "" }
    static func checkKeylogger() -> Bool { return false }
}
