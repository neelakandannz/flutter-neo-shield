import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';

/// Obfuscation Health Check Shield — Verifies that app code is properly obfuscated.
class ObfuscationShield {
  ObfuscationShield._();
  /// Singleton instance of [ObfuscationShield].
  static final ObfuscationShield instance = ObfuscationShield._();

  /// Checks whether the native binary appears to be obfuscated.
  ///
  /// Returns `true` if obfuscation indicators are present.
  static Future<bool> isObfuscated() =>
      RaspChannel.invokeDetection(ShieldCodec.d(ShieldCodec.mCheckObfuscation));

  /// Checks if Dart symbol names are still readable (not obfuscated).
  ///
  /// Returns `true` if the class name matches the unobfuscated original,
  /// indicating that `--obfuscate` was **not** applied during build.
  bool checkDartSymbols() {
    final name = runtimeType.toString();
    return name == 'ObfuscationShield';
  }
}
