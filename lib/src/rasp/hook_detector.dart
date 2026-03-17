import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';
import 'security_result.dart';

/// Detects the presence of hooking frameworks (e.g., Xposed, Substrate, Cycript).
class HookDetector {
  static final String _m = ShieldCodec.d(ShieldCodec.mCheckHooks);

  /// Executes the detection check on the native platform.
  static Future<SecurityResult> check() async {
    final isDetected = await RaspChannel.invokeDetection(_m);
    return SecurityResult(
      isDetected: isDetected,
      message: isDetected ? 'Code hooking framework detected' : null,
    );
  }
}
