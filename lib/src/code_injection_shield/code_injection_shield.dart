import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';

/// Code Injection Detection Shield — Detects dynamic code loading.
class CodeInjectionShield {
  CodeInjectionShield._();
  /// Singleton instance of [CodeInjectionShield].
  static final CodeInjectionShield instance = CodeInjectionShield._();

  /// Checks whether dynamic code loading or injection is detected.
  ///
  /// Returns `true` if suspicious code injection activity is found.
  static Future<bool> checkCodeInjection() =>
      RaspChannel.invokeDetection(ShieldCodec.d(ShieldCodec.mCheckCodeInjection));

  /// Returns a list of suspicious native module names detected at runtime.
  ///
  /// Returns an empty list if none are found.
  static Future<List<String>> getSuspiciousModules() async {
    final result = await RaspChannel.invokeStringMethod(ShieldCodec.d(ShieldCodec.mGetSuspiciousModules));
    if (result == null || result.isEmpty) return [];
    return result.split(',');
  }
}
