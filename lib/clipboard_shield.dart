/// Clipboard Shield module — secure clipboard management for Flutter.
///
/// Auto-clears clipboard after a configurable timeout and detects
/// PII in copied text.
///
/// ```dart
/// import 'package:flutter_neo_shield/clipboard_shield.dart';
///
/// final result = await ClipboardShield().copy('secret', expireAfter: Duration(seconds: 15));
/// ```
library clipboard_shield;

// Core (shared PII engine)
export 'src/core/pii_detector.dart';
export 'src/core/pii_pattern.dart';
export 'src/core/pii_type.dart';
export 'src/core/shield_config.dart';
export 'src/core/shield_report.dart';

// Clipboard Shield
export 'src/clipboard_shield/clipboard_copy_result.dart';
export 'src/clipboard_shield/clipboard_shield.dart';
export 'src/clipboard_shield/clipboard_shield_config.dart';
export 'src/clipboard_shield/secure_copy.dart';
export 'src/clipboard_shield/secure_copy_button.dart';
export 'src/clipboard_shield/secure_paste_field.dart';
