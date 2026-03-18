package com.neelakandan.flutter_neo_shield.location

import android.content.Context
import android.location.GnssStatus
import android.location.LocationManager
import android.os.Build
import kotlin.math.abs
import kotlin.math.sqrt

/**
 * Layer 4: GPS Signal Anomaly Detection.
 *
 * Analyzes GNSS satellite data for spoofing indicators:
 * uniform SNR, impossible satellite counts, constellation anomalies.
 */
class GpsSignalAnalyzer(private val context: Context) {

    private var lastAnomalyScore = 0.0
    private var gnssCallback: GnssStatus.Callback? = null

    init {
        startGnssMonitoring()
    }

    fun getLastAnomalyScore(): Double = lastAnomalyScore

    private fun startGnssMonitoring() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return
        try {
            val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
                ?: return
            gnssCallback = object : GnssStatus.Callback() {
                override fun onSatelliteStatusChanged(status: GnssStatus) {
                    lastAnomalyScore = analyzeSatelliteSignals(status)
                }
            }
            try {
                lm.registerGnssStatusCallback(gnssCallback!!, null)
            } catch (_: SecurityException) {
                // No location permission — can't monitor GNSS
            }
        } catch (_: Exception) {}
    }

    /** Analyze satellite signal-to-noise ratios for spoofing patterns. */
    fun analyzeSatelliteSignals(status: GnssStatus): Double {
        val satelliteCount = status.satelliteCount
        if (satelliteCount == 0) return 0.3

        val snrValues = mutableListOf<Float>()
        val constellationTypes = mutableSetOf<Int>()

        for (i in 0 until satelliteCount) {
            if (status.usedInFix(i)) {
                snrValues.add(status.getCn0DbHz(i))
                constellationTypes.add(status.getConstellationType(i))
            }
        }

        if (snrValues.isEmpty()) return 0.2

        var score = 0.0

        // Anomaly 1: Uniform SNR (real GPS has 15-50 dB spread)
        val snrStdDev = calculateStdDev(snrValues)
        if (snrStdDev < 2.0f && snrValues.size > 3) {
            score += 0.4
        }

        // Anomaly 2: Impossibly high average SNR
        val avgSnr = snrValues.average()
        if (avgSnr > 45.0) {
            score += 0.3
        }

        // Anomaly 3: Only one constellation type for many satellites
        if (constellationTypes.size == 1 && satelliteCount > 8) {
            score += 0.2
        }

        // Anomaly 4: Too many perfect satellites
        if (satelliteCount > 20 && snrValues.all { it > 30.0f }) {
            score += 0.3
        }

        return score.coerceIn(0.0, 1.0)
    }

    private fun calculateStdDev(values: List<Float>): Float {
        if (values.isEmpty()) return 0f
        val mean = values.average().toFloat()
        val variance = values.map { (it - mean) * (it - mean) }.average().toFloat()
        return sqrt(variance)
    }
}
