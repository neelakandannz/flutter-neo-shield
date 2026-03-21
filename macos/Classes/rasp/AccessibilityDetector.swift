import Cocoa
class AccessibilityDetector {
    static func check() -> Bool { return AXIsProcessTrusted() }
    static func getEnabledServices() -> String { return AXIsProcessTrusted() ? "AccessibilityTrusted" : "" }
    static func isScreenReaderActive() -> Bool { return NSWorkspace.shared.isVoiceOverEnabled }
}
