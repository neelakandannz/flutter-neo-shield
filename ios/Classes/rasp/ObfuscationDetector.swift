import Foundation
class ObfuscationDetector {
    static func check() -> Bool { return NSStringFromClass(ObfuscationDetector.self).contains("ObfuscationDetector") }
}
