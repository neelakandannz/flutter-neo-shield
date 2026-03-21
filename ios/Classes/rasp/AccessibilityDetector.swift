import UIKit
class AccessibilityDetector {
    static func check() -> Bool { return UIAccessibility.isVoiceOverRunning && UIAccessibility.isSwitchControlRunning }
    static func isScreenReaderActive() -> Bool { return UIAccessibility.isVoiceOverRunning }
    static func getEnabledServices() -> String {
        var s: [String] = []
        if UIAccessibility.isVoiceOverRunning { s.append("VoiceOver") }
        if UIAccessibility.isSwitchControlRunning { s.append("SwitchControl") }
        if UIAccessibility.isAssistiveTouchRunning { s.append("AssistiveTouch") }
        return s.joined(separator: ",")
    }
}
