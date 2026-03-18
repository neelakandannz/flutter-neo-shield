import 'dart:async';
import 'dart:developer' as developer;

import '../platform/location_channel.dart';
import '../rasp/rasp_shield.dart';
import '../rasp/security_mode.dart';
import '../rasp/security_result.dart';
import 'location_result.dart';

/// Native-level fake location detection shield.
///
/// Provides 7-layer defense-in-depth detection of GPS spoofing,
/// mock locations, and location manipulation across all platforms.
///
/// Detection layers:
/// 1. Mock Provider Detection — platform settings & API flags
/// 2. Spoofing App Detection — known package/process scanning
/// 3. Location Hook Detection — symbol table & inline hook checks
/// 4. GPS Signal Anomaly Detection — NMEA validation, satellite analysis
/// 5. Sensor Fusion Correlation — accelerometer/gyro/baro vs GPS
/// 6. Temporal Anomaly Detection — impossible movement, timestamp gaps
/// 7. Environment Integrity Check — cross-reference with RASP detectors
class LocationShield {
  LocationShield._();

  /// Singleton instance.
  static final LocationShield instance = LocationShield._();

  StreamSubscription<dynamic>? _monitorSubscription;

  /// One-shot location authenticity check (all 7 layers).
  ///
  /// Returns [LocationVerdict] with confidence score and detected methods.
  /// Requires the app to have location permission already granted.
  Future<LocationVerdict> checkLocationAuthenticity({
    LocationShieldConfig config = const LocationShieldConfig(),
  }) {
    return LocationChannel.checkFakeLocation(config.toMap());
  }

  /// Start continuous location monitoring.
  ///
  /// Emits [LocationVerdict] on every location update.
  /// Temporal anomaly detection improves over time as history builds.
  Stream<LocationVerdict> monitorLocation({
    LocationShieldConfig config = const LocationShieldConfig(),
  }) {
    return LocationChannel.events.map((event) {
      if (event is Map) {
        return LocationVerdict.fromMap(event);
      }
      return LocationVerdict.failClosed('invalidEvent');
    });
  }

  /// Stop continuous monitoring.
  void stopMonitoring() {
    _monitorSubscription?.cancel();
    _monitorSubscription = null;
  }

  /// Check if any known spoofing apps are installed.
  /// Does NOT require location permission.
  Future<SpoofingAppResult> checkSpoofingApps() {
    return LocationChannel.checkSpoofingApps();
  }

  /// Check if mock location provider is enabled in developer settings.
  /// Does NOT require location permission.
  Future<bool> isMockLocationEnabled() {
    return LocationChannel.checkMockProvider();
  }

  /// Validate an externally-obtained location against all detection layers.
  ///
  /// Pass a location from geolocator/location package for validation.
  Future<LocationVerdict> validateLocation({
    required double latitude,
    required double longitude,
    required double altitude,
    required double accuracy,
    required double speed,
    required double bearing,
    required DateTime timestamp,
  }) {
    return LocationChannel.checkFakeLocation({
      'latitude': latitude,
      'longitude': longitude,
      'altitude': altitude,
      'accuracy': accuracy,
      'speed': speed,
      'bearing': bearing,
      'timestamp': timestamp.millisecondsSinceEpoch,
    });
  }

  /// Full security scan combining LocationShield + RaspShield.
  ///
  /// Provides highest confidence by cross-referencing all detectors.
  /// RASP results amplify location spoof scores (e.g., root + location
  /// anomaly = very likely spoofed).
  Future<LocationVerdict> fullLocationSecurityScan({
    LocationShieldConfig config = const LocationShieldConfig(),
    SecurityMode mode = SecurityMode.silent,
    void Function(LocationVerdict verdict)? onThreat,
  }) async {
    // Run RASP and location checks in parallel
    final results = await Future.wait([
      checkLocationAuthenticity(config: config),
      RaspShield.fullSecurityScan(mode: SecurityMode.silent),
    ]);

    final locationVerdict = results[0] as LocationVerdict;
    final raspReport = results[1] as SecurityReport;

    // Build RASP context
    final raspContext = <String, bool>{
      'root': raspReport.rootDetected,
      'frida': raspReport.fridaDetected,
      'hook': raspReport.hookDetected,
      'emulator': raspReport.emulatorDetected,
      'debugger': raspReport.debuggerDetected,
    };

    // Amplify confidence if RASP detectors also triggered
    var amplifier = 1.0;
    if (raspReport.rootDetected) amplifier += 0.3;
    if (raspReport.fridaDetected) amplifier += 0.4;
    if (raspReport.hookDetected) amplifier += 0.3;
    if (raspReport.emulatorDetected) amplifier += 0.2;
    if (raspReport.debuggerDetected) amplifier += 0.2;
    amplifier = amplifier.clamp(1.0, 2.0);

    final amplifiedConfidence =
        (locationVerdict.confidence * amplifier).clamp(0.0, 1.0);

    final verdict = LocationVerdict(
      isSpoofed: amplifiedConfidence >= config.spoofThreshold,
      confidence: amplifiedConfidence,
      riskLevel: LocationVerdict.riskFromConfidence(amplifiedConfidence),
      detectedMethods: locationVerdict.detectedMethods,
      layerScores: locationVerdict.layerScores,
      raspContext: raspContext,
      summary: locationVerdict.summary,
    );

    if (verdict.isSpoofed) {
      switch (mode) {
        case SecurityMode.strict:
          throw SecurityException(
            'Fake location detected: $verdict',
          );
        case SecurityMode.warn:
          developer.log(
            'LOCATION WARNING: $verdict',
            name: 'LocationShield',
          );
        case SecurityMode.custom:
          onThreat?.call(verdict);
        case SecurityMode.silent:
          break;
      }
    }

    return verdict;
  }
}
