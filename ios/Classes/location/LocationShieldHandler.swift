import Foundation
import Flutter
import CoreLocation

/// Handles all Location Shield method calls from Flutter.
class LocationShieldHandler: NSObject {

    private let mockProviderDetector = MockProviderDetector()
    private let spoofingAppDetector = SpoofingAppDetector()
    private let locationHookDetector = LocationHookDetector()
    private let gpsSignalAnalyzer = GpsSignalAnalyzer()
    private let sensorFusionValidator = SensorFusionValidator()
    private let temporalAnomalyDetector = TemporalAnomalyDetector()
    private let locationIntegrityChecker = LocationIntegrityChecker()

    func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let method = call.method

        if method == ShieldCodec.mCheckFakeLocation {
            handleFullCheck(call, result: result)
        } else if method == ShieldCodec.mCheckMockProvider {
            result(mockProviderDetector.check())
        } else if method == ShieldCodec.mCheckSpoofingApps {
            let tweaks = spoofingAppDetector.checkLocationTweakDylibs()
            let paths = spoofingAppDetector.checkSpoofingToolPaths()
            let detected = tweaks > 0.0 || paths > 0.0
            result([
                "detected": detected,
                "detectedApps": spoofingAppDetector.detectedTweakNames,
                "defaultMockApp": nil as String?
            ] as [String: Any?])
        } else if method == ShieldCodec.mCheckLocationHooks {
            result(locationHookDetector.check())
        } else if method == ShieldCodec.mCheckGpsAnomaly {
            result(gpsSignalAnalyzer.getLastAnomalyScore())
        } else if method == ShieldCodec.mCheckSensorFusion {
            result(sensorFusionValidator.getLastCorrelationScore())
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
        let mockScore: Double = mockDetected ? 1.0 : 0.0
        scores["mockProvider"] = mockScore
        if mockDetected { detectedMethods.append("mockProvider") }

        // Layer 2: Spoofing Apps/Tweaks
        let tweakScore = spoofingAppDetector.checkLocationTweakDylibs()
        let pathScore = spoofingAppDetector.checkSpoofingToolPaths()
        let spoofScore = max(tweakScore, pathScore)
        scores["spoofingApp"] = spoofScore
        if spoofScore > 0.3 { detectedMethods.append("spoofingApp") }

        // Layer 3: Location Hooks
        let hooksDetected = locationHookDetector.check()
        let hookScore: Double = hooksDetected ? 0.95 : 0.0
        scores["locationHook"] = hookScore
        if hooksDetected { detectedMethods.append("locationHook") }

        // Layer 4: GPS Signal Anomaly
        let gpsScore = gpsSignalAnalyzer.getLastAnomalyScore()
        scores["gpsSignal"] = gpsScore
        if gpsScore > 0.3 { detectedMethods.append("gpsSignal") }

        // Layer 5: Sensor Fusion
        let sensorScore = sensorFusionValidator.getLastCorrelationScore()
        scores["sensorFusion"] = sensorScore
        if sensorScore > 0.3 { detectedMethods.append("sensorFusion") }

        // Layer 6: Temporal Anomaly
        let temporalScore = temporalAnomalyDetector.getLastScore()
        scores["temporalAnomaly"] = temporalScore
        if temporalScore > 0.3 { detectedMethods.append("temporalAnomaly") }

        // Layer 7: Integrity aggregation
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
