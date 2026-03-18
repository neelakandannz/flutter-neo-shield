import CoreMotion
import CoreLocation

/// Layer 5: Sensor Fusion Validation for iOS.
class SensorFusionValidator {

    private let motionManager = CMMotionManager()
    private let activityManager = CMMotionActivityManager()
    private var lastCorrelationScore: Double = 0.0
    private var lastActivity: CMMotionActivity?
    private var isMonitoring = false

    init() {
        startMonitoring()
    }

    func getLastCorrelationScore() -> Double { return lastCorrelationScore }

    private func startMonitoring() {
        guard !isMonitoring else { return }
        isMonitoring = true

        if CMMotionActivityManager.isActivityAvailable() {
            activityManager.startActivityUpdates(to: .main) { [weak self] activity in
                self?.lastActivity = activity
            }
        }

        if motionManager.isAccelerometerAvailable {
            motionManager.accelerometerUpdateInterval = 0.1
            motionManager.startAccelerometerUpdates()
        }
    }

    /// Correlate GPS data with motion sensors.
    func correlateWithGPS(gpsSpeed: Double) -> Double {
        var score: Double = 0.0

        // Check activity vs GPS speed
        if let activity = lastActivity {
            // GPS says fast but activity says stationary
            if gpsSpeed > 5.0 && activity.stationary {
                score += 0.6
            }
            // GPS says automotive but activity says walking
            if gpsSpeed > 20.0 && activity.walking && !activity.automotive {
                score += 0.4
            }
        }

        // Check accelerometer energy vs GPS speed
        if let accelData = motionManager.accelerometerData {
            let accel = accelData.acceleration
            let magnitude = sqrt(accel.x * accel.x + accel.y * accel.y + accel.z * accel.z)
            let deviation = abs(magnitude - 1.0) // gravity = 1.0g

            // GPS fast but no acceleration
            if gpsSpeed > 5.0 && deviation < 0.02 {
                score += 0.5
            }
        }

        // Sensor availability check
        score += checkSensorAvailability() * 0.3

        lastCorrelationScore = min(score, 1.0)
        return lastCorrelationScore
    }

    func checkSensorAvailability() -> Double {
        var score: Double = 0.0
        if !motionManager.isAccelerometerAvailable { score += 0.2 }
        if !motionManager.isGyroAvailable { score += 0.2 }
        if !motionManager.isMagnetometerAvailable { score += 0.1 }
        if !CMAltimeter.isRelativeAltitudeAvailable() { score += 0.1 }
        if !CMMotionActivityManager.isActivityAvailable() { score += 0.1 }
        if !CMPedometer.isStepCountingAvailable() { score += 0.1 }
        return min(score, 1.0)
    }

    func dispose() {
        motionManager.stopAccelerometerUpdates()
        activityManager.stopActivityUpdates()
        isMonitoring = false
    }
}
