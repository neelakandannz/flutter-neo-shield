/// Pattern definition model for PII detection.
library;

import 'pii_type.dart';

/// Defines a PII detection pattern with its regex, type, and replacement text.
///
/// Used by [PIIDetector] to match and replace PII in strings.
/// Developers can create custom patterns and register them at runtime.
///
/// ```dart
/// final pattern = PIIPattern(
///   type: PIIType.custom,
///   regex: RegExp(r'ACCT-\d{10}'),
///   replacement: '[ACCOUNT HIDDEN]',
///   description: 'Internal account numbers',
/// );
/// PIIDetector().addPattern(pattern);
/// ```
class PIIPattern {
  /// Creates a [PIIPattern] with the required fields.
  const PIIPattern({
    required this.type,
    required this.regex,
    required this.replacement,
    this.description = '',
    this.validator,
  });

  /// The PII type this pattern detects.
  final PIIType type;

  /// The regular expression used to match PII.
  final RegExp regex;

  /// The text that replaces matched PII.
  final String replacement;

  /// An optional human-readable description of what this pattern matches.
  final String description;

  /// An optional validation function that receives the matched text and
  /// returns true if it is a valid match.
  ///
  /// Used for additional validation beyond regex, such as Luhn algorithm
  /// for credit card numbers.
  final bool Function(String match)? validator;

  @override
  String toString() =>
      'PIIPattern(type: $type, replacement: $replacement, description: $description)';
}
