import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';
import 'security_result.dart';

/// Detects the presence of Frida instrumentation frameworks.
class FridaDetector {
  static final String _m = ShieldCodec.d(ShieldCodec.mCheckFrida);

  /// Executes the detection check on the native platform.
  static Future<SecurityResult> check() async {
    final isDetected = await RaspChannel.invokeDetection(_m);
    return SecurityResult(
      isDetected: isDetected,
      message: isDetected ? 'Instrumentation framework detected' : null,
    );
  }
}
