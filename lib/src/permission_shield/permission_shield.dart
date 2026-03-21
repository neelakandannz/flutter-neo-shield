import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';

/// Permission Shield — Runtime permission monitoring.
class PermissionShield {
  PermissionShield._();
  /// Singleton instance of [PermissionShield].
  static final PermissionShield instance = PermissionShield._();

  final Set<String> _expectedPermissions = {};

  /// Registers a set of [permissions] the app expects to use at runtime.
  void registerExpectedPermissions(Set<String> permissions) => _expectedPermissions.addAll(permissions);

  /// Checks whether the device camera is currently in use by another app.
  static Future<bool> isCameraInUse() =>
      RaspChannel.invokeDetection(ShieldCodec.d(ShieldCodec.mCheckCameraInUse));

  /// Checks whether the device microphone is currently in use by another app.
  static Future<bool> isMicrophoneInUse() =>
      RaspChannel.invokeDetection(ShieldCodec.d(ShieldCodec.mCheckMicInUse));

  /// Checks whether location is being accessed in the background.
  static Future<bool> isLocationAccessedInBackground() =>
      RaspChannel.invokeDetection(ShieldCodec.d(ShieldCodec.mCheckBgLocation));

  /// Clears all registered expected permissions.
  void reset() => _expectedPermissions.clear();
}
