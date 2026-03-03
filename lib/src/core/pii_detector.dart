/// Main PII detection engine for flutter_neo_shield.
library;

import 'package:meta/meta.dart';

import 'pii_pattern.dart';
import 'pii_type.dart';
import 'shield_config.dart';
import 'shield_report.dart';

/// The core PII detection and sanitization engine.
///
/// Singleton class that detects and replaces Personally Identifiable
/// Information in strings using regex patterns and optional validators.
///
/// ```dart
/// final detector = PIIDetector();
/// final clean = detector.sanitize('Email: john@test.com');
/// print(clean); // 'Email: [EMAIL HIDDEN]'
/// ```
class PIIDetector {
  /// Returns the singleton [PIIDetector] instance.
  factory PIIDetector() => _instance;

  PIIDetector._internal() {
    _initBuiltInPatterns();
  }

  static final PIIDetector _instance = PIIDetector._internal();

  ShieldConfig _config = const ShieldConfig();
  ShieldReport? _report;
  final List<PIIPattern> _patterns = [];
  final Set<String> _sensitiveNames = {};

  /// The default sensitive keys used for JSON sanitization.
  static const List<String> defaultSensitiveKeys = [
    'name',
    'email',
    'phone',
    'ssn',
    'password',
    'token',
    'address',
    'birthDate',
    'telecom',
    'identifier',
    'creditCard',
    'cardNumber',
    'cvv',
    'secret',
    'access_token',
    'refresh_token',
    'api_key',
    'authorization',
  ];

  /// Configures the detector with the given [config].
  ///
  /// Can be called multiple times to update configuration.
  ///
  /// ```dart
  /// PIIDetector().configure(ShieldConfig(
  ///   enabledTypes: {PIIType.email, PIIType.phone},
  ///   enableReporting: true,
  /// ));
  /// ```
  void configure(ShieldConfig config) {
    _config = config;
    if (config.enableReporting) {
      _report ??= ShieldReport();
    }

    // Register initial sensitive names.
    for (final name in config.sensitiveNames) {
      _sensitiveNames.add(name);
    }

    // Add custom patterns.
    for (final pattern in config.customPatterns) {
      if (!_patterns.any(
        (p) =>
            p.type == pattern.type && p.regex.pattern == pattern.regex.pattern,
      )) {
        _patterns.add(pattern);
      }
    }
  }

  /// The current configuration.
  ShieldConfig get config => _config;

  /// The detection report, or null if reporting is disabled.
  ShieldReport? get report => _report;

  /// Registers a single sensitive [name] for name detection.
  ///
  /// Names must be at least 2 characters to avoid false positives.
  ///
  /// ```dart
  /// PIIDetector().registerName('John');
  /// ```
  void registerName(String name) {
    if (name.length >= 2) {
      _sensitiveNames.add(name);
    }
  }

  /// Registers multiple sensitive [names] at once.
  ///
  /// ```dart
  /// PIIDetector().registerNames(['John', 'Doe', 'Maria']);
  /// ```
  void registerNames(List<String> names) {
    for (final name in names) {
      registerName(name);
    }
  }

  /// Removes a previously registered [name].
  ///
  /// ```dart
  /// PIIDetector().unregisterName('John');
  /// ```
  void unregisterName(String name) {
    _sensitiveNames.remove(name);
  }

  /// Clears all registered sensitive names.
  ///
  /// Useful to call on user logout.
  ///
  /// ```dart
  /// PIIDetector().clearNames();
  /// ```
  void clearNames() {
    _sensitiveNames.clear();
  }

  /// Returns the set of currently registered sensitive names.
  @visibleForTesting
  Set<String> get sensitiveNames => Set.unmodifiable(_sensitiveNames);

  /// Adds a custom [PIIPattern] at runtime.
  ///
  /// ```dart
  /// PIIDetector().addPattern(PIIPattern(
  ///   type: PIIType.custom,
  ///   regex: RegExp(r'ACCT-\d{10}'),
  ///   replacement: '[ACCOUNT HIDDEN]',
  /// ));
  /// ```
  void addPattern(PIIPattern pattern) {
    _patterns.add(pattern);
  }

  /// Removes all patterns of the given [type].
  ///
  /// ```dart
  /// PIIDetector().removePattern(PIIType.email);
  /// ```
  void removePattern(PIIType type) {
    _patterns.removeWhere((p) => p.type == type);
  }

  /// The main sanitization method. Replaces all detected PII in [input]
  /// with configured replacement text.
  ///
  /// ```dart
  /// final clean = PIIDetector().sanitize('Call 555-123-4567');
  /// print(clean); // 'Call [PHONE HIDDEN]'
  /// ```
  String sanitize(String input) {
    if (input.isEmpty) return input;

    final matches = detect(input);
    if (matches.isEmpty) return input;

    // Sort matches by start position descending so replacements don't
    // shift indices for earlier matches.
    final sorted = List<PIIMatch>.from(matches)
      ..sort((a, b) => b.start.compareTo(a.start));

    var result = input;
    for (final match in sorted) {
      result = result.replaceRange(match.start, match.end, match.replacement);
    }

    return result;
  }

  /// Detects all PII in [input] and returns a list of [PIIMatch] objects.
  ///
  /// Does not modify the input string.
  ///
  /// ```dart
  /// final matches = PIIDetector().detect('Email: john@test.com');
  /// print(matches.length); // 1
  /// print(matches.first.type); // PIIType.email
  /// ```
  List<PIIMatch> detect(String input) {
    if (input.isEmpty) return [];

    final allMatches = <_PrioritizedMatch>[];

    for (var priority = 0; priority < _patterns.length; priority++) {
      final pattern = _patterns[priority];
      if (!_config.isTypeEnabled(pattern.type)) continue;

      final regexMatches = pattern.regex.allMatches(input);
      for (final regexMatch in regexMatches) {
        final matched = regexMatch.group(0)!;

        // Run optional validator.
        if (pattern.validator != null && !pattern.validator!(matched)) {
          continue;
        }

        final replacement =
            _config.customReplacements[pattern.type] ?? pattern.replacement;

        // For password fields, preserve the key name.
        String finalReplacement;
        if (pattern.type == PIIType.passwordField) {
          final keyMatch = RegExp(
            r'(password|passwd|pwd|secret|token|api_key|apikey|api-key|access_token|refresh_token)',
            caseSensitive: false,
          ).firstMatch(matched);
          if (keyMatch != null) {
            final key = keyMatch.group(0)!;
            final separator = matched.substring(
              keyMatch.end,
              matched.indexOf(RegExp(r'[=:]'), keyMatch.end) + 1,
            );
            finalReplacement = '$key$separator[HIDDEN]';
          } else {
            finalReplacement = replacement;
          }
        } else {
          finalReplacement = replacement;
        }

        allMatches.add(_PrioritizedMatch(
          priority: priority,
          match: PIIMatch(
            type: pattern.type,
            original: matched,
            start: regexMatch.start,
            end: regexMatch.end,
            replacement: finalReplacement,
          ),
        ));

        if (_config.enableReporting) {
          _report?.recordDetection(pattern.type);
        }
      }
    }

    // Handle registered names (PIIType.name).
    if (_config.isTypeEnabled(PIIType.name) && _sensitiveNames.isNotEmpty) {
      final namePriority = _patterns.length; // Lowest priority.
      for (final name in _sensitiveNames) {
        if (name.length < 2) continue;

        final nameRegex = RegExp(
          '\\b${RegExp.escape(name)}\\b',
          caseSensitive: false,
        );
        final nameMatches = nameRegex.allMatches(input);
        for (final match in nameMatches) {
          final replacement =
              _config.customReplacements[PIIType.name] ?? '[NAME HIDDEN]';

          // Check for overlap with existing matches.
          final overlaps = allMatches.any(
            (m) => match.start < m.match.end && match.end > m.match.start,
          );
          if (!overlaps) {
            allMatches.add(_PrioritizedMatch(
              priority: namePriority,
              match: PIIMatch(
                type: PIIType.name,
                original: match.group(0)!,
                start: match.start,
                end: match.end,
                replacement: replacement,
              ),
            ));

            if (_config.enableReporting) {
              _report?.recordDetection(PIIType.name);
            }
          }
        }
      }
    }

    // Remove overlapping matches — when overlaps occur, keep the higher
    // priority (lower number) pattern. Sort by priority first to process
    // more important patterns first.
    allMatches.sort((a, b) => a.priority.compareTo(b.priority));

    final deduped = <PIIMatch>[];
    for (final pm in allMatches) {
      // Check if this match overlaps with any already-selected match.
      final overlaps = deduped.any(
        (m) => pm.match.start < m.end && pm.match.end > m.start,
      );
      if (!overlaps) {
        deduped.add(pm.match);
      }
    }

    // Sort final results by position for correct replacement order.
    deduped.sort((a, b) => a.start.compareTo(b.start));

    return deduped;
  }

  /// Returns true if [input] contains any detectable PII.
  ///
  /// ```dart
  /// PIIDetector().containsPII('john@test.com'); // true
  /// PIIDetector().containsPII('Hello world'); // false
  /// ```
  bool containsPII(String input) => detect(input).isNotEmpty;

  /// Returns the [PIIType] of the first PII found in [input], or null.
  ///
  /// ```dart
  /// PIIDetector().getPIIType('john@test.com'); // PIIType.email
  /// ```
  PIIType? getPIIType(String input) {
    final matches = detect(input);
    return matches.isEmpty ? null : matches.first.type;
  }

  /// Sanitizes a JSON map by replacing values of sensitive keys with
  /// `[REDACTED]` and running PII detection on remaining string values.
  ///
  /// Recursively processes nested maps and lists.
  ///
  /// ```dart
  /// final clean = PIIDetector().sanitizeJson({
  ///   'name': 'John',
  ///   'id': 123,
  ///   'note': 'Call 555-123-4567',
  /// });
  /// // {'name': '[REDACTED]', 'id': 123, 'note': 'Call [PHONE HIDDEN]'}
  /// ```
  Map<String, dynamic> sanitizeJson(
    Map<String, dynamic> json, {
    List<String>? sensitiveKeys,
  }) {
    final keys = sensitiveKeys ?? defaultSensitiveKeys;
    final keysLower = keys.map((k) => k.toLowerCase()).toSet();

    return _sanitizeMap(json, keysLower);
  }

  Map<String, dynamic> _sanitizeMap(
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
        result[entry.key] = _sanitizeList(
          entry.value as List<dynamic>,
          sensitiveKeysLower,
        );
      } else if (entry.value is String) {
        result[entry.key] = sanitize(entry.value as String);
      } else {
        result[entry.key] = entry.value;
      }
    }

    return result;
  }

  List<dynamic> _sanitizeList(
    List<dynamic> list,
    Set<String> sensitiveKeysLower,
  ) {
    return list.map((item) {
      if (item is Map<String, dynamic>) {
        return _sanitizeMap(item, sensitiveKeysLower);
      } else if (item is List) {
        return _sanitizeList(item, sensitiveKeysLower);
      } else if (item is String) {
        return sanitize(item);
      }
      return item;
    }).toList();
  }

  /// Resets the detector to its default state.
  ///
  /// Clears all custom patterns, registered names, and report data.
  /// Useful in tests.
  ///
  /// ```dart
  /// PIIDetector().reset();
  /// ```
  void reset() {
    _config = const ShieldConfig();
    _report?.reset();
    _report = null;
    _sensitiveNames.clear();
    _patterns.clear();
    _initBuiltInPatterns();
  }

  /// Initializes the built-in PII detection patterns.
  ///
  /// Order matters: SSN before phone, JWT before generic API key,
  /// password fields before generic strings.
  void _initBuiltInPatterns() {
    _patterns.addAll([
      // 1. SSN — process BEFORE phone to avoid conflicts.
      PIIPattern(
        type: PIIType.ssn,
        regex: RegExp(r'\b\d{3}-\d{2}-\d{4}\b'),
        replacement: '[SSN HIDDEN]',
        description: 'US Social Security Numbers with dashes',
      ),
      PIIPattern(
        type: PIIType.ssn,
        regex: RegExp(r'\b(?<!\d)\d{9}(?!\d)\b'),
        replacement: '[SSN HIDDEN]',
        description:
            'US Social Security Numbers without dashes (9 consecutive digits)',
      ),

      // 2. Credit Card — Luhn-validated.
      PIIPattern(
        type: PIIType.creditCard,
        regex: RegExp(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b'),
        replacement: '[CARD HIDDEN]',
        description: 'Credit/debit card numbers (13-19 digits)',
        validator: _luhnValidate,
      ),

      // 3. JWT Token.
      PIIPattern(
        type: PIIType.jwtToken,
        regex: RegExp(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        replacement: '[JWT HIDDEN]',
        description: 'JSON Web Tokens',
      ),

      // 4. Bearer Token.
      PIIPattern(
        type: PIIType.bearerToken,
        regex: RegExp(r'Bearer\s+\S+', caseSensitive: false),
        replacement: 'Bearer [TOKEN HIDDEN]',
        description: 'Authorization bearer tokens',
      ),

      // 5. Password fields — key-value pairs with sensitive keys.
      PIIPattern(
        type: PIIType.passwordField,
        regex: RegExp(
          r'(password|passwd|pwd|secret|token|api_key|apikey|api-key|access_token|refresh_token)\s*[=:]\s*\S+',
          caseSensitive: false,
        ),
        replacement: '[PASSWORD HIDDEN]',
        description: 'Password and secret key-value pairs',
      ),

      // 6. API Key — common prefixed formats.
      PIIPattern(
        type: PIIType.apiKey,
        regex: RegExp(r'\b(?:sk|pk|api|key|token)-[A-Za-z0-9]{20,}\b'),
        replacement: '[API_KEY HIDDEN]',
        description: 'Common API key formats',
      ),

      // 7. Email addresses.
      PIIPattern(
        type: PIIType.email,
        regex: RegExp(
          r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        ),
        replacement: '[EMAIL HIDDEN]',
        description: 'Email addresses',
      ),

      // 8. Date of Birth — process BEFORE phone to avoid conflicts.
      PIIPattern(
        type: PIIType.dateOfBirth,
        regex: RegExp(
          r'\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b',
        ),
        replacement: '[DOB HIDDEN]',
        description: 'Dates in YYYY-MM-DD format',
      ),
      PIIPattern(
        type: PIIType.dateOfBirth,
        regex: RegExp(
          r'\b(?:0[1-9]|1[0-2])[/](?:0[1-9]|[12]\d|3[01])[/](?:19|20)\d{2}\b',
        ),
        replacement: '[DOB HIDDEN]',
        description: 'Dates in MM/DD/YYYY format',
      ),

      // 9. IP Address (IPv4) — process BEFORE phone to avoid conflicts.
      PIIPattern(
        type: PIIType.ipAddress,
        regex: RegExp(
          r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        ),
        replacement: '[IP HIDDEN]',
        description: 'IPv4 addresses',
      ),

      // 10. Phone numbers (international) — after IP to avoid matching IPs.
      PIIPattern(
        type: PIIType.phone,
        regex: RegExp(
          r'(?:\+\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?(?:\d[\s-]?){6,14}\d\b',
        ),
        replacement: '[PHONE HIDDEN]',
        description: 'Phone numbers in various international formats',
      ),
    ]);
  }

  /// Validates a credit card number using the Luhn algorithm.
  static bool _luhnValidate(String match) {
    final digits = match.replaceAll(RegExp(r'[\s-]'), '');
    if (digits.length < 13 || digits.length > 19) return false;
    if (!RegExp(r'^\d+$').hasMatch(digits)) return false;

    var sum = 0;
    var alternate = false;

    for (var i = digits.length - 1; i >= 0; i--) {
      var n = int.parse(digits[i]);
      if (alternate) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alternate = !alternate;
    }

    return sum % 10 == 0;
  }
}

/// Internal helper to track pattern priority during detection.
class _PrioritizedMatch {
  const _PrioritizedMatch({required this.priority, required this.match});

  final int priority;
  final PIIMatch match;
}
