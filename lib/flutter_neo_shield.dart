/// Client-side PII protection toolkit for Flutter.
///
/// Auto-scrubs sensitive data from logs, secures clipboard with timed
/// auto-clear, and protects sensitive strings in memory.
///
/// ```dart
/// import 'package:flutter_neo_shield/flutter_neo_shield.dart';
///
/// void main() {
///   WidgetsFlutterBinding.ensureInitialized();
///   FlutterNeoShield.init();
///   runApp(MyApp());
/// }
/// ```
library flutter_neo_shield;

// Core
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

// Clipboard Shield
export 'src/clipboard_shield/clipboard_copy_result.dart';
export 'src/clipboard_shield/clipboard_shield.dart';
export 'src/clipboard_shield/clipboard_shield_config.dart';
export 'src/clipboard_shield/secure_copy.dart';
export 'src/clipboard_shield/secure_copy_button.dart';
export 'src/clipboard_shield/secure_paste_field.dart';

// Memory Shield
export 'src/memory_shield/memory_shield.dart';
export 'src/memory_shield/memory_shield_config.dart';
export 'src/memory_shield/secure_bytes.dart';
export 'src/memory_shield/secure_string.dart';
export 'src/memory_shield/secure_value.dart';

// String Shield
export 'src/string_shield/annotations.dart';
export 'src/string_shield/deobfuscator.dart';
export 'src/string_shield/obfuscation_strategy.dart';
export 'src/string_shield/string_shield.dart';
export 'src/string_shield/string_shield_config.dart';

// RASP Shield
export 'src/rasp/rasp_shield.dart';
export 'src/rasp/security_mode.dart';
export 'src/rasp/security_result.dart';

// Main
export 'src/flutter_neo_shield.dart';

// Desktop plugin stubs (required for dart_plugin_registrant)
export 'flutter_neo_shield_stub.dart';
