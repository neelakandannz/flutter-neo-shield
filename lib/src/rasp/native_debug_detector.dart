import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';
import 'security_result.dart';

/// Detects native-level debuggers (GDB, LLDB, strace) attached from desktop.
///
/// The existing [DebuggerDetector] only checks Java-level debugging
/// (`Debug.isDebuggerConnected` on Android, `P_TRACED` on iOS).
///
/// This detector adds deeper native checks:
///
/// **Android:**
/// - `/proc/self/status` TracerPid — catches ptrace-attached debuggers
/// - `/proc/self/wchan` — detects ptrace_stop state
/// - Timing anomaly — single-stepping causes measurable delays
///
/// **iOS:**
/// - Mach exception port check — debuggers register exception ports
/// - Timing anomaly — single-stepping detection
/// - PT_DENY_ATTACH support — prevents debugger attachment entirely
class NativeDebugDetector {
  static final String _m = ShieldCodec.d(ShieldCodec.mCheckNativeDebug);

  /// Executes native-level debug detection on the platform.
  static Future<SecurityResult> check() async {
    final isDetected = await RaspChannel.invokeDetection(_m);
    return SecurityResult(
      isDetected: isDetected,
      message: isDetected ? 'Native debugger detected' : null,
    );
  }
}
