/// Core secureCopy function for clipboard protection.
library;

import 'clipboard_copy_result.dart';
import 'clipboard_shield.dart';

/// Convenience function to securely copy [text] to the clipboard.
///
/// Delegates to [ClipboardShield.copy] with optional [expireAfter].
///
/// ```dart
/// final result = await secureCopy('myP@ssw0rd');
/// print(result.piiDetected); // true
/// ```
Future<ClipboardCopyResult> secureCopy(
  String text, {
  Duration? expireAfter,
}) {
  return ClipboardShield().copy(text, expireAfter: expireAfter);
}
