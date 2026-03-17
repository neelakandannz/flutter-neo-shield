import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';
import 'security_result.dart';

/// Detects issues with app binary integrity and suspicious installation sources.
class IntegrityDetector {
  static final String _m = ShieldCodec.d(ShieldCodec.mCheckIntegrity);

  /// Executes the detection check on the native platform.
  static Future<SecurityResult> check() async {
    final isDetected = await RaspChannel.invokeDetection(_m);
    return SecurityResult(
      isDetected: isDetected,
      message: isDetected ? 'Application integrity compromised' : null,
    );
  }
}
