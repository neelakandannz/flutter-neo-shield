/// Top-level global functions for safe, PII-sanitized logging.
///
/// These functions are direct replacements for `print()` and can be
/// used anywhere in the application.
library;

import 'log_shield.dart';

/// Sanitizes PII from [message] and logs it with a level and optional tag.
///
/// Drop-in replacement for structured logging.
///
/// ```dart
/// shieldLog('User email: john@test.com');
/// // Output: [INFO] User email: [EMAIL HIDDEN]
///
/// shieldLog('Auth failed', level: 'ERROR', tag: 'auth');
/// // Output: [ERROR] [auth] Auth failed
/// ```
void shieldLog(String message, {String level = 'INFO', String? tag}) {
  LogShield().log(message, level: level, tag: tag);
}

/// Sanitizes PII from a JSON map and logs it.
///
/// ```dart
/// shieldLogJson('API Response', {'name': 'John', 'email': 'a@b.com'});
/// // Output: [INFO] API Response: {"name": "[REDACTED]", "email": "[REDACTED]"}
/// ```
void shieldLogJson(String label, Map<String, dynamic> json) {
  LogShield().logJson(label, json);
}

/// Sanitizes PII from error messages and logs them.
///
/// ```dart
/// shieldLogError('Login failed for john@test.com', error: e);
/// // Output: [ERROR] Login failed for [EMAIL HIDDEN]
/// ```
void shieldLogError(String message, {Object? error, StackTrace? stackTrace}) {
  LogShield().logError(message, error: error, stackTrace: stackTrace);
}
