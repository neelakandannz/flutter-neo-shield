import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';
import 'security_result.dart';

/// Detects if a debugger is currently attached to the application process.
class DebuggerDetector {
  static final String _m = ShieldCodec.d(ShieldCodec.mCheckDebugger);

  /// Executes the detection check on the native platform.
  static Future<SecurityResult> check() async {
    final isDetected = await RaspChannel.invokeDetection(_m);
    return SecurityResult(
      isDetected: isDetected,
      message:
          isDetected ? 'Debugger attached' : null,
    );
  }
}
