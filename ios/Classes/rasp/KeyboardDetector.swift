import UIKit
class KeyboardDetector {
    static func isThirdPartyKeyboard() -> Bool {
        let modes = UITextInputMode.activeInputModes
        for mode in modes {
            if let id = mode.value(forKey: "identifier") as? String {
                if !id.hasPrefix("com.apple.") && !id.isEmpty { return true }
            }
        }
        return false
    }
    static func getCurrentKeyboardPackage() -> String {
        for mode in UITextInputMode.activeInputModes {
            if let id = mode.value(forKey: "identifier") as? String { return id }
        }
        return ""
    }
    static func checkKeylogger() -> Bool { return isThirdPartyKeyboard() }
}
