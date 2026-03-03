/// Log Shield module — PII-sanitized logging for Flutter.
///
/// Provides structured, PII-sanitized logging that automatically
/// redacts sensitive data.
///
/// ```dart
/// import 'package:flutter_neo_shield/log_shield.dart';
///
/// shieldLog('User email: john@test.com');
/// // Output: [INFO] User email: [EMAIL HIDDEN]
/// ```
library log_shield;

// Core (shared PII engine)
export 'src/core/pii_detector.dart';
export 'src/core/pii_pattern.dart';
export 'src/core/pii_type.dart';
export 'src/core/shield_config.dart';
export 'src/core/shield_report.dart';

// Log Shield
export 'src/log_shield/json_sanitizer.dart';
export 'src/log_shield/log_shield.dart';
export 'src/log_shield/log_shield_config.dart';
export 'src/log_shield/safe_log.dart';
