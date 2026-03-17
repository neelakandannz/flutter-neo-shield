import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';
import 'security_result.dart';

/// Detects if the application is running on an emulator or simulator.
class EmulatorDetector {
  static final String _m = ShieldCodec.d(ShieldCodec.mCheckEmulator);

  /// Executes the detection check on the native platform.
  static Future<SecurityResult> check() async {
    final isDetected = await RaspChannel.invokeDetection(_m);
    return SecurityResult(
      isDetected: isDetected,
      message: isDetected ? 'Emulator/simulator detected' : null,
    );
  }
}
