/// Memory Shield module — secure memory wipe for Flutter.
///
/// Provides secure containers for sensitive strings and byte arrays
/// that overwrite their content with zeros on dispose.
///
/// ```dart
/// import 'package:flutter_neo_shield/memory_shield.dart';
///
/// final secret = SecureString('my-api-key');
/// print(secret.value); // 'my-api-key'
/// secret.dispose();
/// ```
library memory_shield;

// Core (shared PII engine)
export 'src/core/pii_detector.dart';
export 'src/core/pii_pattern.dart';
export 'src/core/pii_type.dart';
export 'src/core/shield_config.dart';
export 'src/core/shield_report.dart';

// Memory Shield
export 'src/memory_shield/memory_shield.dart';
export 'src/memory_shield/memory_shield_config.dart';
export 'src/memory_shield/secure_bytes.dart';
export 'src/memory_shield/secure_string.dart';
export 'src/memory_shield/secure_value.dart';
