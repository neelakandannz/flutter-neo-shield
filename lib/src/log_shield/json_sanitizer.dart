/// JSON/Map PII sanitization utilities.
library;

import '../core/pii_detector.dart';

/// Utility class for sanitizing PII from JSON maps and lists.
///
/// Replaces values of sensitive keys with `[REDACTED]` and runs PII
/// detection on remaining string values to catch unexpected PII.
///
/// ```dart
/// final sanitized = JsonSanitizer.sanitize({
///   'name': 'John Doe',
///   'id': 123,
///   'note': 'Call 555-123-4567',
/// });
/// // {'name': '[REDACTED]', 'id': 123, 'note': 'Call [PHONE HIDDEN]'}
/// ```
class JsonSanitizer {
  /// Private constructor — all methods are static.
  JsonSanitizer._();

  /// Sanitizes a JSON map by replacing sensitive key values with
  /// `[REDACTED]` and running PII detection on other string values.
  ///
  /// The [sensitiveKeys] parameter overrides the default list of keys
  /// to treat as sensitive.
  ///
  /// ```dart
  /// final clean = JsonSanitizer.sanitize({'email': 'a@b.com'});
  /// // {'email': '[REDACTED]'}
  /// ```
  static Map<String, dynamic> sanitize(
    Map<String, dynamic> json, {
    List<String>? sensitiveKeys,
  }) {
    final keys = sensitiveKeys ?? PIIDetector.defaultSensitiveKeys;
    final keysLower = keys.map((k) => k.toLowerCase()).toSet();
    return _sanitizeMap(json, keysLower);
  }

  /// Sanitizes each item in a list, processing maps and strings.
  ///
  /// ```dart
  /// final clean = JsonSanitizer.sanitizeList([
  ///   {'name': 'John'},
  ///   'Call 555-123-4567',
  /// ]);
  /// ```
  static List<dynamic> sanitizeList(
    List<dynamic> list, {
    List<String>? sensitiveKeys,
  }) {
    final keys = sensitiveKeys ?? PIIDetector.defaultSensitiveKeys;
    final keysLower = keys.map((k) => k.toLowerCase()).toSet();
    return _sanitizeListInternal(list, keysLower);
  }

  static Map<String, dynamic> _sanitizeMap(
    Map<String, dynamic> json,
    Set<String> sensitiveKeysLower,
  ) {
    final result = <String, dynamic>{};

    for (final entry in json.entries) {
      if (sensitiveKeysLower.contains(entry.key.toLowerCase())) {
        result[entry.key] = '[REDACTED]';
      } else if (entry.value is Map<String, dynamic>) {
        result[entry.key] = _sanitizeMap(
          entry.value as Map<String, dynamic>,
          sensitiveKeysLower,
        );
      } else if (entry.value is List) {
        result[entry.key] = _sanitizeListInternal(
          entry.value as List<dynamic>,
          sensitiveKeysLower,
        );
      } else if (entry.value is String) {
        result[entry.key] = PIIDetector().sanitize(entry.value as String);
      } else {
        result[entry.key] = entry.value;
      }
    }

    return result;
  }

  static List<dynamic> _sanitizeListInternal(
    List<dynamic> list,
    Set<String> sensitiveKeysLower,
  ) {
    return list.map((item) {
      if (item is Map<String, dynamic>) {
        return _sanitizeMap(item, sensitiveKeysLower);
      } else if (item is List) {
        return _sanitizeListInternal(item, sensitiveKeysLower);
      } else if (item is String) {
        return PIIDetector().sanitize(item);
      }
      return item;
    }).toList();
  }
}
