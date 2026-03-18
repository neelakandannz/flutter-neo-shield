import Foundation
import CoreLocation

/// Layer 6: Temporal Anomaly Detection for iOS.
/// Same algorithm as Android — detects impossible movement patterns.
class TemporalAnomalyDetector {

    struct LocationSnapshot {
        let latitude: Double
        let longitude: Double
        let altitude: Double
        let speed: Double
        let bearing: Double
        let accuracy: Double
        let timestamp: TimeInterval
        let systemTimestamp: TimeInterval
    }

    private var history: [LocationSnapshot] = []
    private var lastScore: Double = 0.0
    private let maxHistory = 100

    func getLastScore() -> Double { return lastScore }

    func addLocation(_ snapshot: LocationSnapshot) -> Double {
        let score: Double
        if !history.isEmpty {
            score = analyzeAgainstHistory(snapshot)
        } else {
            score = 0.0
        }
        history.append(snapshot)
        if history.count > maxHistory { history.removeFirst() }
        lastScore = score
        return score
    }

    func addCLLocation(_ location: CLLocation) -> Double {
        let snapshot = LocationSnapshot(
            latitude: location.coordinate.latitude,
            longitude: location.coordinate.longitude,
            altitude: location.altitude,
            speed: location.speed,
            bearing: location.course,
            accuracy: location.horizontalAccuracy,
            timestamp: location.timestamp.timeIntervalSince1970,
            systemTimestamp: ProcessInfo.processInfo.systemUptime
        )
        return addLocation(snapshot)
    }

    private func analyzeAgainstHistory(_ current: LocationSnapshot) -> Double {
        guard let prev = history.last else { return 0.0 }
        var score: Double = 0.0

        let timeDelta = current.timestamp - prev.timestamp
        guard timeDelta > 0 else { return 0.6 }

        // Check 1: Impossible speed
        let distance = haversineDistance(
            lat1: prev.latitude, lon1: prev.longitude,
            lat2: current.latitude, lon2: current.longitude
        )
        let calculatedSpeed = distance / timeDelta

        if calculatedSpeed > 340.0 {
            score += 0.9
        } else if calculatedSpeed > 100.0 && prev.speed < 5.0 {
            score += 0.7
        }

        // Check 2: Altitude impossibility
        let altRate = abs(current.altitude - prev.altitude) / timeDelta
        if altRate > 100.0 { score += 0.6 }

        // Check 3: Bearing reversal at speed
        var bearingDelta = abs(current.bearing - prev.bearing)
        if bearingDelta > 180 { bearingDelta = 360 - bearingDelta }
        if bearingDelta > 150 && current.speed > 20.0 && timeDelta < 2.0 {
            score += 0.5
        }

        // Check 4: System time drift
        let systemTimeDelta = current.systemTimestamp - prev.systemTimestamp
        if systemTimeDelta > 0 {
            let timeRatio = timeDelta / systemTimeDelta
            if abs(timeRatio - 1.0) > 0.5 { score += 0.4 }
        }

        // Check 5: Accuracy oscillation
        if abs(current.accuracy - prev.accuracy) > 50.0 && timeDelta < 5.0 {
            score += 0.3
        }

        // Check 6: Repeated coordinates
        let duplicates = history.filter {
            abs($0.latitude - current.latitude) < 0.000001 &&
            abs($0.longitude - current.longitude) < 0.000001
        }.count
        if duplicates > 3 { score += 0.5 }

        return min(score, 1.0)
    }

    private func haversineDistance(lat1: Double, lon1: Double, lat2: Double, lon2: Double) -> Double {
        let r = 6371000.0
        let dLat = (lat2 - lat1) * .pi / 180
        let dLon = (lon2 - lon1) * .pi / 180
        let a = sin(dLat / 2) * sin(dLat / 2) +
                cos(lat1 * .pi / 180) * cos(lat2 * .pi / 180) *
                sin(dLon / 2) * sin(dLon / 2)
        let c = 2 * atan2(sqrt(a), sqrt(1 - a))
        return r * c
    }
}
