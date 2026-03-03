/// Global configuration for flutter_neo_shield.
library;

import 'pii_pattern.dart';
import 'pii_type.dart';

/// Global configuration for the flutter_neo_shield PII detection engine.
///
/// Controls which PII types are enabled, custom replacement text,
/// additional patterns, and reporting behavior.
///
/// ```dart
/// final config = ShieldConfig(
///   enabledTypes: {PIIType.email, PIIType.phone, PIIType.ssn},
///   customReplacements: {PIIType.email: '[REMOVED]'},
///   enableReporting: true,
/// );
/// FlutterNeoShield.init(config: config);
/// ```
class ShieldConfig {
  /// Creates a [ShieldConfig] with the specified options.
  ///
  /// All parameters have sensible defaults. Call with no arguments
  /// for a configuration that detects all PII types.
  const ShieldConfig({
    this.enabledTypes = const {},
    this.customReplacements = const {},
    this.customPatterns = const [],
    this.sensitiveNames = const {},
    this.silentInRelease = true,
    this.enableReporting = false,
  });

  /// The set of PII types to detect.
  ///
  /// An empty set means all types are enabled.
  final Set<PIIType> enabledTypes;

  /// Custom replacement text per PII type.
  ///
  /// Overrides the default replacement text for matched patterns.
  final Map<PIIType, String> customReplacements;

  /// Additional custom [PIIPattern] definitions.
  final List<PIIPattern> customPatterns;

  /// Initial set of person names to register for name detection.
  final Set<String> sensitiveNames;

  /// If true, suppress all log output in release mode.
  final bool silentInRelease;

  /// If true, track detection counts in [ShieldReport].
  final bool enableReporting;

  /// Returns whether all PII types are enabled.
  ///
  /// An empty [enabledTypes] set means all types are active.
  bool get allTypesEnabled => enabledTypes.isEmpty;

  /// Returns whether a specific [PIIType] is enabled.
  ///
  /// ```dart
  /// config.isTypeEnabled(PIIType.email); // true if email detection is on
  /// ```
  bool isTypeEnabled(PIIType type) =>
      enabledTypes.isEmpty || enabledTypes.contains(type);

  /// Creates a copy of this config with the given fields replaced.
  ///
  /// ```dart
  /// final updated = config.copyWith(enableReporting: true);
  /// ```
  ShieldConfig copyWith({
    Set<PIIType>? enabledTypes,
    Map<PIIType, String>? customReplacements,
    List<PIIPattern>? customPatterns,
    Set<String>? sensitiveNames,
    bool? silentInRelease,
    bool? enableReporting,
  }) {
    return ShieldConfig(
      enabledTypes: enabledTypes ?? this.enabledTypes,
      customReplacements: customReplacements ?? this.customReplacements,
      customPatterns: customPatterns ?? this.customPatterns,
      sensitiveNames: sensitiveNames ?? this.sensitiveNames,
      silentInRelease: silentInRelease ?? this.silentInRelease,
      enableReporting: enableReporting ?? this.enableReporting,
    );
  }
}
