import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';
import 'security_result.dart';

/// Detects if the device is rooted (Android) or jailbroken (iOS).
class RootDetector {
  static final String _m = ShieldCodec.d(ShieldCodec.mCheckRoot);

  /// Executes the detection check on the native platform.
  static Future<SecurityResult> check() async {
    final isDetected = await RaspChannel.invokeDetection(_m);
    return SecurityResult(
      isDetected: isDetected,
      message: isDetected ? 'Device root/jailbreak detected' : null,
    );
  }
}
