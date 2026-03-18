package com.neelakandan.flutter_neo_shield.location

import kotlin.math.*

/**
 * Layer 6: Temporal Anomaly Detection.
 *
 * Detects impossible movement patterns: teleportation, impossible speed,
 * altitude jumps, bearing reversal at speed, timestamp manipulation,
 * coordinate repetition, and grid patterns.
 */
class TemporalAnomalyDetector {

    data class LocationSnapshot(
        val latitude: Double,
        val longitude: Double,
        val altitude: Double,
        val speed: Float,
        val bearing: Float,
        val accuracy: Float,
        val timestamp: Long,
        val systemTimestamp: Long = System.nanoTime()
    )

    private val history = ArrayDeque<LocationSnapshot>(100)
    private var lastScore = 0.0

    fun getLastScore(): Double = lastScore

    /** Add a new location and analyze against history. Returns spoof score 0.0-1.0. */
    fun addLocation(snapshot: LocationSnapshot): Double {
        val score = if (history.isNotEmpty()) {
            analyzeAgainstHistory(snapshot)
        } else {
            0.0
        }
        history.addLast(snapshot)
        if (history.size > 100) history.removeFirst()
        lastScore = score
        return score
    }

    private fun analyzeAgainstHistory(current: LocationSnapshot): Double {
        val prev = history.last()
        var score = 0.0

        val timeDelta = (current.timestamp - prev.timestamp) / 1000.0
        if (timeDelta <= 0) {
            return 0.6 // Time went backwards
        }

        // Check 1: Impossible speed
        val distance = haversineDistance(
            prev.latitude, prev.longitude,
            current.latitude, current.longitude
        )
        val calculatedSpeed = distance / timeDelta

        if (calculatedSpeed > 340.0) {
            score += 0.9 // Faster than speed of sound
        } else if (calculatedSpeed > 100.0 && prev.speed < 5.0f) {
            score += 0.7
        }

        // Check 2: Altitude impossibility
        val altDelta = abs(current.altitude - prev.altitude)
        val altRate = altDelta / timeDelta
        if (altRate > 100.0) {
            score += 0.6
        }

        // Check 3: Bearing reversal with maintained speed
        val bearingDelta = abs(current.bearing - prev.bearing)
        val normalizedBearingDelta = if (bearingDelta > 180) 360 - bearingDelta else bearingDelta
        if (normalizedBearingDelta > 150 && current.speed > 20.0f && timeDelta < 2.0) {
            score += 0.5
        }

        // Check 4: GPS time vs system time drift
        val systemTimeDelta = (current.systemTimestamp - prev.systemTimestamp) / 1_000_000_000.0
        val timeRatio = if (systemTimeDelta > 0) timeDelta / systemTimeDelta else 0.0
        if (abs(timeRatio - 1.0) > 0.5) {
            score += 0.4
        }

        // Check 5: Accuracy oscillation
        val accuracyDelta = abs(current.accuracy - prev.accuracy)
        if (accuracyDelta > 50.0f && timeDelta < 5.0) {
            score += 0.3
        }

        // Check 6: Repeated exact coordinates (replay attack)
        val recentDuplicates = history.count {
            abs(it.latitude - current.latitude) < 0.000001 &&
            abs(it.longitude - current.longitude) < 0.000001
        }
        if (recentDuplicates > 3) {
            score += 0.5
        }

        // Check 7: Grid pattern detection
        if (history.size >= 10) {
            if (detectGridPattern()) {
                score += 0.6
            }
        }

        return score.coerceIn(0.0, 1.0)
    }

    private fun detectGridPattern(): Boolean {
        val recent = history.toList().takeLast(10)
        val latDeltas = recent.zipWithNext().map { (a, b) -> b.latitude - a.latitude }
        val lonDeltas = recent.zipWithNext().map { (a, b) -> b.longitude - a.longitude }

        if (latDeltas.isEmpty()) return false

        val latStdDev = calculateStdDev(latDeltas)
        val lonStdDev = calculateStdDev(lonDeltas)

        return latStdDev < 0.00001 && lonStdDev < 0.00001 &&
               latDeltas.any { abs(it) > 0.0 }
    }

    private fun haversineDistance(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val r = 6371000.0
        val dLat = Math.toRadians(lat2 - lat1)
        val dLon = Math.toRadians(lon2 - lon1)
        val a = sin(dLat / 2) * sin(dLat / 2) +
                cos(Math.toRadians(lat1)) * cos(Math.toRadians(lat2)) *
                sin(dLon / 2) * sin(dLon / 2)
        val c = 2 * atan2(sqrt(a), sqrt(1 - a))
        return r * c
    }

    private fun calculateStdDev(values: List<Double>): Double {
        if (values.isEmpty()) return 0.0
        val mean = values.average()
        val variance = values.map { (it - mean) * (it - mean) }.average()
        return sqrt(variance)
    }
}
