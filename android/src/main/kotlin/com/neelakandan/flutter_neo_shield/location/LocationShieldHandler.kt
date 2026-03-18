package com.neelakandan.flutter_neo_shield.location

import android.content.Context
import android.hardware.SensorManager
import android.location.LocationManager
import com.neelakandan.flutter_neo_shield.ShieldCodec
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * Handles all Location Shield method calls from Flutter.
 * Dispatches to individual detection layers and aggregates results.
 */
class LocationShieldHandler(private val context: Context) {

    private val mockProviderDetector = MockProviderDetector(context)
    private val spoofingAppDetector = SpoofingAppDetector(context)
    private val locationHookDetector = LocationHookDetector()
    private val gpsSignalAnalyzer = GpsSignalAnalyzer(context)
    private val sensorFusionValidator = SensorFusionValidator(context)
    private val temporalAnomalyDetector = TemporalAnomalyDetector()
    private val locationIntegrityChecker = LocationIntegrityChecker()

    fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            ShieldCodec.decode(ShieldCodec.M_CHECK_FAKE_LOCATION) -> {
                handleFullCheck(call, result)
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_MOCK_PROVIDER) -> {
                result.success(mockProviderDetector.check())
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_SPOOFING_APPS) -> {
                val apps = spoofingAppDetector.checkInstalledSpoofingApps()
                val defaultMock = spoofingAppDetector.checkDefaultMockLocationApp()
                result.success(hashMapOf(
                    "detected" to apps.isNotEmpty(),
                    "detectedApps" to apps,
                    "defaultMockApp" to defaultMock
                ))
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_LOCATION_HOOKS) -> {
                result.success(locationHookDetector.check())
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_GPS_ANOMALY) -> {
                result.success(gpsSignalAnalyzer.getLastAnomalyScore())
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_SENSOR_FUSION) -> {
                result.success(sensorFusionValidator.getLastCorrelationScore())
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_TEMPORAL_ANOMALY) -> {
                result.success(temporalAnomalyDetector.getLastScore())
            }
            else -> result.notImplemented()
        }
    }

    private fun handleFullCheck(call: MethodCall, result: MethodChannel.Result) {
        try {
            val scores = HashMap<String, Double>()
            val detectedMethods = mutableListOf<String>()

            // Layer 1: Mock Provider Detection
            val mockDetected = mockProviderDetector.check()
            val mockScore = if (mockDetected) 1.0 else 0.0
            scores["mockProvider"] = mockScore
            if (mockDetected) detectedMethods.add("mockProvider")

            // Layer 2: Spoofing App Detection
            val spoofApps = spoofingAppDetector.checkInstalledSpoofingApps()
            val spoofRunning = spoofingAppDetector.checkRunningSpoofers()
            val spoofScore = when {
                spoofApps.isNotEmpty() && spoofRunning -> 1.0
                spoofApps.isNotEmpty() -> 0.8
                spoofRunning -> 0.7
                else -> 0.0
            }
            scores["spoofingApp"] = spoofScore
            if (spoofScore > 0.3) detectedMethods.add("spoofingApp")

            // Layer 3: Location Hook Detection
            val hooksDetected = locationHookDetector.check()
            val hookScore = if (hooksDetected) 0.95 else 0.0
            scores["locationHook"] = hookScore
            if (hooksDetected) detectedMethods.add("locationHook")

            // Layer 4: GPS Signal Anomaly
            val gpsScore = gpsSignalAnalyzer.getLastAnomalyScore()
            scores["gpsSignal"] = gpsScore
            if (gpsScore > 0.3) detectedMethods.add("gpsSignal")

            // Layer 5: Sensor Fusion
            val sensorScore = sensorFusionValidator.getLastCorrelationScore()
            scores["sensorFusion"] = sensorScore
            if (sensorScore > 0.3) detectedMethods.add("sensorFusion")

            // Layer 6: Temporal Anomaly
            val temporalScore = temporalAnomalyDetector.getLastScore()
            scores["temporalAnomaly"] = temporalScore
            if (temporalScore > 0.3) detectedMethods.add("temporalAnomaly")

            // Layer 7: Cross-reference integrity
            val confidence = locationIntegrityChecker.computeConfidence(scores)
            scores["integrity"] = confidence

            val isSpoofed = confidence >= 0.5

            result.success(hashMapOf(
                "isSpoofed" to isSpoofed,
                "confidence" to confidence,
                "detectedMethods" to detectedMethods,
                "layerScores" to scores,
                "summary" to if (isSpoofed) "Fake location detected (confidence: ${"%.2f".format(confidence)})" else "Location appears authentic"
            ))
        } catch (e: Exception) {
            // Fail-closed
            result.success(hashMapOf(
                "isSpoofed" to true,
                "confidence" to 1.0,
                "detectedMethods" to listOf("error"),
                "layerScores" to emptyMap<String, Double>(),
                "summary" to "Detection error — assuming spoofed (fail-closed): ${e.message}"
            ))
        }
    }
}
