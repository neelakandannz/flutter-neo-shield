import '../core/pii_detector.dart';

/// Data Leak Prevention Shield — Prevents sensitive data from
/// leaking through intents, deep links, share sheets, and other channels.
class DlpShield {
  DlpShield._();
  /// Singleton instance of [DlpShield].
  static final DlpShield instance = DlpShield._();

  /// Sanitizes PII from deep link query parameters in the given [url].
  ///
  /// Returns the URL with sensitive values redacted.
  String sanitizeDeepLink(String url) {
    final uri = Uri.tryParse(url);
    if (uri == null) return url;
    final sanitizedParams = <String, String>{};
    for (final entry in uri.queryParameters.entries) {
      sanitizedParams[entry.key] = PIIDetector().sanitize(entry.value);
    }
    return uri.replace(queryParameters: sanitizedParams).toString();
  }

  /// Sanitizes PII from intent/share [extras] map values.
  Map<String, dynamic> sanitizeExtras(Map<String, dynamic> extras) {
    return extras.map((key, value) {
      if (value is String) return MapEntry(key, PIIDetector().sanitize(value));
      return MapEntry(key, value);
    });
  }

  /// Detects PII types present in [data] and returns their names.
  List<String> detectLeaks(String data) =>
      PIIDetector().detect(data).map((m) => m.type.name).toList();

  /// Validates [data] for PII before sharing. Returns `null` if clean,
  /// or a list of detected PII type names.
  List<String>? validateShareData(String data) {
    final leaks = detectLeaks(data);
    return leaks.isEmpty ? null : leaks;
  }
}
