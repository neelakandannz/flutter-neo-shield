import CoreLocation

/// Layer 1: Mock Location Provider Detection for iOS.
class MockProviderDetector {

    /// Primary check combining all iOS mock detection methods.
    func check() -> Bool {
        return checkSimulatedEnvironment() ||
               checkSourceInformation() ||
               checkAccuracyAnomalies()
    }

    /// Check for Xcode simulated location / simulator.
    func checkSimulatedEnvironment() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        // Check for developer disk image (enables Xcode location simulation)
        if FileManager.default.fileExists(atPath: "/Developer") {
            return true
        }
        if ProcessInfo.processInfo.environment["__XPC_DYLD_FRAMEWORK_PATH"] != nil {
            return true
        }
        return false
        #endif
    }

    /// Check CLLocation.sourceInformation (iOS 15+).
    @available(iOS 15.0, *)
    func checkSourceInformationForLocation(_ location: CLLocation) -> Bool {
        guard let sourceInfo = location.sourceInformation else {
            return false
        }
        return sourceInfo.isSimulatedBySoftware
    }

    /// Quick check using CLLocationManager state.
    private func checkSourceInformation() -> Bool {
        if #available(iOS 15.0, *) {
            // Can't check without a location, but check services state
            if !CLLocationManager.locationServicesEnabled() {
                return false // No location = can't be mock
            }
        }
        return false
    }

    /// Check for suspicious accuracy values.
    private func checkAccuracyAnomalies() -> Bool {
        // This is checked when validateLocation is called with actual coordinates
        return false
    }

    /// Validate a specific CLLocation for mock indicators.
    func validateLocation(_ location: CLLocation) -> Double {
        var score: Double = 0.0

        // Perfect accuracy < 1m is unrealistic for consumer GPS
        if location.horizontalAccuracy > 0 && location.horizontalAccuracy < 1.0 {
            score += 0.4
        }

        // Negative accuracy = invalid
        if location.horizontalAccuracy < 0 {
            score += 0.6
        }

        // Exact zero altitude with valid horizontal fix
        if location.altitude == 0.0 && location.verticalAccuracy >= 0 {
            score += 0.2
        }

        if #available(iOS 15.0, *) {
            if let sourceInfo = location.sourceInformation {
                if sourceInfo.isSimulatedBySoftware {
                    score += 0.9
                }
            }
        }

        return min(score, 1.0)
    }
}
