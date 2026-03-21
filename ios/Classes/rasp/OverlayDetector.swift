import UIKit
class OverlayDetector {
    static func check() -> Bool {
        guard let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first else { return false }
        return scene.windows.count > 3
    }
    static func checkClickjacking() -> Bool { return false }
}
