import Foundation

/// Layer 7: Environment Integrity Check for iOS.
class LocationIntegrityChecker {

    private let weights: [String: Double] = [
        "mockProvider": 1.0,
        "spoofingApp": 0.9,
        "locationHook": 0.95,
        "gpsSignal": 0.7,
        "sensorFusion": 0.8,
        "temporalAnomaly": 0.85,
    ]

    func computeConfidence(scores: [String: Double]) -> Double {
        var totalScore: Double = 0.0
        var totalWeight: Double = 0.0

        for (key, weight) in weights {
            let score = scores[key] ?? 0.0
            totalScore += score * weight
            totalWeight += weight
        }

        guard totalWeight > 0 else { return 0.0 }

        let normalized = totalScore / totalWeight

        let triggeredLayers = scores.filter { $0.value > 0.3 }.count
        let amplifier: Double
        switch triggeredLayers {
        case 4...: amplifier = 1.5
        case 3: amplifier = 1.3
        case 2: amplifier = 1.1
        default: amplifier = 1.0
        }

        return min(normalized * amplifier, 1.0)
    }
}
