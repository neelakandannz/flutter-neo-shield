import CoreLocation

/// Layer 4: GPS Signal Anomaly Detection for iOS.
///
/// iOS doesn't expose raw GNSS data, so we analyze CLLocation properties.
class GpsSignalAnalyzer {

    private var lastAnomalyScore: Double = 0.0

    func getLastAnomalyScore() -> Double { return lastAnomalyScore }

    /// Analyze a CLLocation for GPS signal anomalies.
    func analyzeLocation(_ location: CLLocation) -> Double {
        var score: Double = 0.0

        // Sub-meter accuracy without RTK is suspicious
        if location.horizontalAccuracy > 0 && location.horizontalAccuracy < 0.5 {
            score += 0.5
        }

        // Speed inconsistent with course
        if location.speed > 0 && location.course < 0 {
            score += 0.3
        }

        // Altitude without vertical accuracy
        if location.altitude != 0 && location.verticalAccuracy < 0 {
            score += 0.2
        }

        // Timestamp in future or far past
        let timeDiff = abs(location.timestamp.timeIntervalSinceNow)
        if timeDiff > 60 {
            score += 0.4
        }

        // Location services disabled but we got a location
        if !CLLocationManager.locationServicesEnabled() {
            score += 0.9
        }

        lastAnomalyScore = min(score, 1.0)
        return lastAnomalyScore
    }
}
