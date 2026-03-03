/// Result model for clipboard copy operations.
library;

import '../core/pii_type.dart';

/// Represents the result of a secure clipboard copy operation.
///
/// Contains information about whether PII was detected, the type of PII,
/// and when the clipboard will be auto-cleared.
///
/// ```dart
/// final result = await ClipboardShield().copy('john@test.com');
/// if (result.piiDetected) {
///   print('PII type: ${result.piiType}');
///   print('Clears in: ${result.expiresIn}');
/// }
/// ```
class ClipboardCopyResult {
  /// Creates a [ClipboardCopyResult] with the given details.
  const ClipboardCopyResult({
    required this.success,
    required this.piiDetected,
    this.piiType,
    this.expiresAt,
    this.expiresIn,
  });

  /// Whether the copy operation was successful.
  final bool success;

  /// Whether PII was detected in the copied text.
  final bool piiDetected;

  /// The primary type of PII detected, if any.
  final PIIType? piiType;

  /// The timestamp when the clipboard will be auto-cleared.
  final DateTime? expiresAt;

  /// Duration until the clipboard auto-clears.
  final Duration? expiresIn;

  @override
  String toString() =>
      'ClipboardCopyResult(success: $success, piiDetected: $piiDetected, '
      'piiType: $piiType, expiresIn: $expiresIn)';
}
