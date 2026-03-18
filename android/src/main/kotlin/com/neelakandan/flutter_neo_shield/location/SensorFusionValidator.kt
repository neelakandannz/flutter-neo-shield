package com.neelakandan.flutter_neo_shield.location

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import kotlin.math.abs
import kotlin.math.sqrt

/**
 * Layer 5: Sensor Fusion Validation.
 *
 * Cross-correlates GPS movement with accelerometer/gyroscope data.
 * If GPS says moving but sensors show stationary → spoofed.
 */
class SensorFusionValidator(private val context: Context) : SensorEventListener {

    private val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
    private var lastAccelEnergy = 0.0f
    private var lastCorrelationScore = 0.0
    private var accelSamples = mutableListOf<FloatArray>()

    init {
        startSensorMonitoring()
    }

    fun getLastCorrelationScore(): Double = lastCorrelationScore

    private fun startSensorMonitoring() {
        try {
            val accel = sensorManager?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
            if (accel != null) {
                sensorManager?.registerListener(this, accel, SensorManager.SENSOR_DELAY_NORMAL)
            }
        } catch (_: Exception) {}
    }

    override fun onSensorChanged(event: SensorEvent) {
        if (event.sensor.type == Sensor.TYPE_ACCELEROMETER) {
            accelSamples.add(event.values.copyOf())
            if (accelSamples.size > 50) {
                accelSamples.removeAt(0)
            }
            lastAccelEnergy = calculateAccelEnergy(accelSamples)
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}

    /** Check if sensor availability is suspicious (emulator/spoofed env). */
    fun checkSensorAvailability(): Double {
        var score = 0.0
        if (sensorManager?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) == null) score += 0.2
        if (sensorManager?.getDefaultSensor(Sensor.TYPE_GYROSCOPE) == null) score += 0.2
        if (sensorManager?.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD) == null) score += 0.1
        if (sensorManager?.getDefaultSensor(Sensor.TYPE_PRESSURE) == null) score += 0.1
        return score.coerceIn(0.0, 1.0)
    }

    /** Correlate GPS speed with accelerometer energy.
     * Call this with the GPS-reported speed to update correlation score. */
    fun updateWithGpsSpeed(gpsSpeedMs: Float) {
        var score = 0.0

        // GPS shows fast movement but no accelerometer activity
        if (gpsSpeedMs > 5.0f && lastAccelEnergy < 0.2f) {
            score += 0.7
        }

        // GPS stationary but significant accelerometer activity
        if (gpsSpeedMs < 0.5f && lastAccelEnergy > 3.0f) {
            score += 0.3
        }

        // Sensor unavailability adds suspicion
        score += checkSensorAvailability() * 0.3

        lastCorrelationScore = score.coerceIn(0.0, 1.0)
    }

    private fun calculateAccelEnergy(samples: List<FloatArray>): Float {
        if (samples.isEmpty()) return 0.0f
        var sumSq = 0.0f
        for (sample in samples) {
            val magnitude = sqrt(
                sample[0] * sample[0] + sample[1] * sample[1] + sample[2] * sample[2]
            )
            val deviation = magnitude - 9.81f
            sumSq += deviation * deviation
        }
        return sqrt(sumSq / samples.size)
    }

    fun dispose() {
        try {
            sensorManager?.unregisterListener(this)
        } catch (_: Exception) {}
    }
}
