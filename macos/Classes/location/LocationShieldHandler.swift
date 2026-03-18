import Foundation
import FlutterMacOS
import CoreLocation

/// Handles Location Shield method calls on macOS.
class LocationShieldHandler: NSObject {

    private let mockProviderDetector = MockProviderDetector()
    private let locationHookDetector = LocationHookDetector()
    private let temporalAnomalyDetector = TemporalAnomalyDetector()
    private let locationIntegrityChecker = LocationIntegrityChecker()

    func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let method = call.method

        if method == ShieldCodec.mCheckFakeLocation {
            handleFullCheck(call, result: result)
        } else if method == ShieldCodec.mCheckMockProvider {
            result(mockProviderDetector.check())
        } else if method == ShieldCodec.mCheckSpoofingApps {
            result([
                "detected": false,
                "detectedApps": [] as [String],
                "defaultMockApp": nil as String?
            ] as [String: Any?])
        } else if method == ShieldCodec.mCheckLocationHooks {
            result(locationHookDetector.check())
        } else if method == ShieldCodec.mCheckGpsAnomaly {
            result(0.0 as Double)
        } else if method == ShieldCodec.mCheckSensorFusion {
            result(0.0 as Double)
        } else if method == ShieldCodec.mCheckTemporalAnomaly {
            result(temporalAnomalyDetector.getLastScore())
        } else {
            result(FlutterMethodNotImplemented)
        }
    }

    private func handleFullCheck(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        var scores: [String: Double] = [:]
        var detectedMethods: [String] = []

        // Layer 1: Mock Provider
        let mockDetected = mockProviderDetector.check()
        scores["mockProvider"] = mockDetected ? 1.0 : 0.0
        if mockDetected { detectedMethods.append("mockProvider") }

        // Layer 2: Spoofing Apps (limited on macOS)
        scores["spoofingApp"] = 0.0

        // Layer 3: Location Hooks
        let hooksDetected = locationHookDetector.check()
        scores["locationHook"] = hooksDetected ? 0.95 : 0.0
        if hooksDetected { detectedMethods.append("locationHook") }

        // Layer 4: GPS Signal (limited on macOS)
        scores["gpsSignal"] = 0.0

        // Layer 5: Sensor Fusion (limited on macOS)
        scores["sensorFusion"] = 0.0

        // Layer 6: Temporal Anomaly
        let temporalScore = temporalAnomalyDetector.getLastScore()
        scores["temporalAnomaly"] = temporalScore
        if temporalScore > 0.3 { detectedMethods.append("temporalAnomaly") }

        // Layer 7: Integrity
        let confidence = locationIntegrityChecker.computeConfidence(scores: scores)
        scores["integrity"] = confidence

        let isSpoofed = confidence >= 0.5

        result([
            "isSpoofed": isSpoofed,
            "confidence": confidence,
            "detectedMethods": detectedMethods,
            "layerScores": scores,
            "summary": isSpoofed
                ? "Fake location detected (confidence: \(String(format: "%.2f", confidence)))"
                : "Location appears authentic"
        ] as [String: Any])
    }
}
