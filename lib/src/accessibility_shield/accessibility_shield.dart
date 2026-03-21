import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';

/// Accessibility Service Abuse Detection Shield.
///
/// Detects suspicious accessibility services that can read screen content,
/// capture keystrokes, and perform actions on behalf of the user.
class AccessibilityShield {
  AccessibilityShield._();
  /// Singleton instance of [AccessibilityShield].
  static final AccessibilityShield instance = AccessibilityShield._();

  /// Check if any non-system accessibility services are active.
  static Future<bool> checkAccessibilityAbuse() {
    return RaspChannel.invokeDetection(
      ShieldCodec.d(ShieldCodec.mCheckAccessibility),
    );
  }

  /// Get list of enabled accessibility service package names.
  static Future<List<String>> getEnabledServices() async {
    final result = await RaspChannel.invokeStringMethod(
      ShieldCodec.d(ShieldCodec.mGetAccessibilityServices),
    );
    if (result == null || result.isEmpty) return [];
    return result.split(',');
  }

  /// Check if screen reader is active (legitimate accessibility use).
  static Future<bool> isScreenReaderActive() {
    return RaspChannel.invokeDetection(
      ShieldCodec.d(ShieldCodec.mCheckScreenReader),
    );
  }
}
