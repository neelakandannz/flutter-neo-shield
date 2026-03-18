import CoreLocation

/// Layer 1: Mock Provider Detection for macOS.
class MockProviderDetector {
    func check() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        if !CLLocationManager.locationServicesEnabled() {
            return false
        }
        // Check for developer tools that can simulate location
        if FileManager.default.fileExists(atPath: "/Applications/Xcode.app") {
            // Xcode installed doesn't mean simulating, but if combined
            // with other signals it's noteworthy
        }
        return false
        #endif
    }
}
