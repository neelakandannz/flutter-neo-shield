/// Risk classification levels for location spoofing.
enum RiskLevel {
  /// No spoofing risk detected.
  none,

  /// Low spoofing risk.
  low,

  /// Medium spoofing risk.
  medium,

  /// High spoofing risk.
  high,

  /// Critical — location is almost certainly spoofed.
  critical,
}

/// Result of location authenticity analysis.
class LocationVerdict {
  /// Constructs a [LocationVerdict] with the given detection results.
  const LocationVerdict({
    required this.isSpoofed,
    required this.confidence,
    required this.riskLevel,
    this.detectedMethods = const [],
    this.layerScores = const {},
    this.raspContext = const {},
    this.summary = '',
  });

  /// Create a fail-closed verdict when platform is unavailable.
  factory LocationVerdict.failClosed(String reason) => LocationVerdict(
        isSpoofed: true,
        confidence: 1.0,
        riskLevel: RiskLevel.critical,
        detectedMethods: [reason],
        summary: 'Platform check failed — assuming spoofed (fail-closed)',
      );

  /// Create from a native platform result map.
  factory LocationVerdict.fromMap(Map<dynamic, dynamic> map) {
    final scores = <String, double>{};
    if (map['layerScores'] is Map) {
      (map['layerScores'] as Map).forEach((k, v) {
        scores[k.toString()] = (v as num).toDouble();
      });
    }
    final rasp = <String, bool>{};
    if (map['raspContext'] is Map) {
      (map['raspContext'] as Map).forEach((k, v) {
        rasp[k.toString()] = v as bool;
      });
    }
    final methods = <String>[];
    if (map['detectedMethods'] is List) {
      for (final m in map['detectedMethods'] as List) {
        methods.add(m.toString());
      }
    }
    final conf = (map['confidence'] as num?)?.toDouble() ?? 0.0;
    return LocationVerdict(
      isSpoofed: map['isSpoofed'] as bool? ?? conf >= 0.5,
      confidence: conf,
      riskLevel: riskFromConfidence(conf),
      detectedMethods: methods,
      layerScores: scores,
      raspContext: rasp,
      summary: map['summary'] as String? ?? '',
    );
  }

  /// Whether the location is determined to be spoofed.
  final bool isSpoofed;

  /// Confidence score: 0.0 = definitely real, 1.0 = definitely spoofed.
  final double confidence;

  /// Risk level classification.
  final RiskLevel riskLevel;

  /// Which detection methods triggered.
  final List<String> detectedMethods;

  /// Raw scores from each detection layer (0.0-1.0).
  final Map<String, double> layerScores;

  /// RASP context that influenced the verdict.
  final Map<String, bool> raspContext;

  /// Human-readable summary of the detection.
  final String summary;

  /// Maps a confidence score to a [RiskLevel].
  static RiskLevel riskFromConfidence(double c) {
    if (c >= 0.8) return RiskLevel.critical;
    if (c >= 0.6) return RiskLevel.high;
    if (c >= 0.4) return RiskLevel.medium;
    if (c >= 0.2) return RiskLevel.low;
    return RiskLevel.none;
  }

  @override
  String toString() =>
      'LocationVerdict(spoofed: $isSpoofed, confidence: ${confidence.toStringAsFixed(2)}, risk: $riskLevel, methods: $detectedMethods)';
}

/// Result of spoofing app scan.
class SpoofingAppResult {
  /// Constructs a [SpoofingAppResult].
  const SpoofingAppResult({
    this.detected = false,
    this.detectedApps = const [],
    this.defaultMockApp,
  });

  /// Create from a native platform result map.
  factory SpoofingAppResult.fromMap(Map<dynamic, dynamic> map) {
    final apps = <String>[];
    if (map['detectedApps'] is List) {
      for (final a in map['detectedApps'] as List) {
        apps.add(a.toString());
      }
    }
    return SpoofingAppResult(
      detected: map['detected'] as bool? ?? apps.isNotEmpty,
      detectedApps: apps,
      defaultMockApp: map['defaultMockApp'] as String?,
    );
  }

  /// Whether any spoofing apps were detected.
  final bool detected;

  /// List of detected spoofing app package names/bundle IDs.
  final List<String> detectedApps;

  /// Whether mock location app is set as default provider.
  final String? defaultMockApp;

  @override
  String toString() =>
      'SpoofingAppResult(detected: $detected, apps: $detectedApps)';
}

/// Configuration for LocationShield behavior.
class LocationShieldConfig {
  /// Constructs a [LocationShieldConfig] with configurable thresholds.
  const LocationShieldConfig({
    this.spoofThreshold = 0.5,
    this.enableSensorFusion = true,
    this.enableGnssAnalysis = true,
    this.enableTemporalAnalysis = true,
    this.customWeights,
  });

  /// Minimum confidence to flag as spoofed (default: 0.5).
  final double spoofThreshold;

  /// Enable sensor fusion correlation (requires sensor permissions).
  final bool enableSensorFusion;

  /// Enable continuous GNSS monitoring (Android only, battery impact).
  final bool enableGnssAnalysis;

  /// Enable temporal anomaly detection (requires location history).
  final bool enableTemporalAnalysis;

  /// Custom weights for each detection layer.
  final Map<String, double>? customWeights;

  /// Serializes the config to a map for platform channel transport.
  Map<String, dynamic> toMap() => {
        'spoofThreshold': spoofThreshold,
        'enableSensorFusion': enableSensorFusion,
        'enableGnssAnalysis': enableGnssAnalysis,
        'enableTemporalAnalysis': enableTemporalAnalysis,
        if (customWeights != null) 'customWeights': customWeights,
      };
}

/// Sensor fusion diagnostic state.
class SensorFusionState {
  /// Constructs a [SensorFusionState] with sensor availability flags.
  const SensorFusionState({
    this.accelerometerAvailable = false,
    this.gyroscopeAvailable = false,
    this.magnetometerAvailable = false,
    this.barometerAvailable = false,
    this.pedometerAvailable = false,
    this.lastAccelEnergy,
    this.lastBaroAltitude,
    this.stepCount,
    this.headingDegrees,
  });

  /// Create from a native platform result map.
  factory SensorFusionState.fromMap(Map<dynamic, dynamic> map) =>
      SensorFusionState(
        accelerometerAvailable:
            map['accelerometerAvailable'] as bool? ?? false,
        gyroscopeAvailable: map['gyroscopeAvailable'] as bool? ?? false,
        magnetometerAvailable:
            map['magnetometerAvailable'] as bool? ?? false,
        barometerAvailable: map['barometerAvailable'] as bool? ?? false,
        pedometerAvailable: map['pedometerAvailable'] as bool? ?? false,
        lastAccelEnergy: (map['lastAccelEnergy'] as num?)?.toDouble(),
        lastBaroAltitude: (map['lastBaroAltitude'] as num?)?.toDouble(),
        stepCount: map['stepCount'] as int?,
        headingDegrees: (map['headingDegrees'] as num?)?.toDouble(),
      );

  /// Whether the accelerometer sensor is available.
  final bool accelerometerAvailable;

  /// Whether the gyroscope sensor is available.
  final bool gyroscopeAvailable;

  /// Whether the magnetometer sensor is available.
  final bool magnetometerAvailable;

  /// Whether the barometer sensor is available.
  final bool barometerAvailable;

  /// Whether the pedometer is available.
  final bool pedometerAvailable;

  /// Last measured accelerometer energy (RMS deviation from gravity).
  final double? lastAccelEnergy;

  /// Last barometric altitude estimate in meters.
  final double? lastBaroAltitude;

  /// Pedometer step count since monitoring started.
  final int? stepCount;

  /// Last magnetometer heading in degrees.
  final double? headingDegrees;

  @override
  String toString() =>
      'SensorFusionState(accel: $accelerometerAvailable, gyro: $gyroscopeAvailable, mag: $magnetometerAvailable, baro: $barometerAvailable)';
}
