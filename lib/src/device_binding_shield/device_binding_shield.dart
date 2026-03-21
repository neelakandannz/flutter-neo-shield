import '../platform/shield_codec.dart';
import 'package:flutter/services.dart';

/// Device Binding Shield — Binds tokens/sessions to a specific device.
class DeviceBindingShield {
  DeviceBindingShield._();
  /// Singleton instance of [DeviceBindingShield].
  static final DeviceBindingShield instance = DeviceBindingShield._();

  static final MethodChannel _channel = MethodChannel(
    ShieldCodec.d(ShieldCodec.chDeviceBinding),
  );

  String? _cachedFingerprint;

  /// Returns a unique hardware-derived fingerprint for this device.
  ///
  /// The result is cached after the first call. Returns `null` if
  /// the platform does not support device binding.
  Future<String?> getDeviceFingerprint() async {
    if (_cachedFingerprint != null) return _cachedFingerprint;
    try {
      _cachedFingerprint = await _channel.invokeMethod<String>('getDeviceFingerprint');
      return _cachedFingerprint;
    } on MissingPluginException { return null; }
    on PlatformException { return null; }
  }

  /// Validates that the current device fingerprint matches [expectedFingerprint].
  ///
  /// Returns `false` if the fingerprints differ or the platform is unavailable.
  Future<bool> validateBinding(String expectedFingerprint) async {
    final current = await getDeviceFingerprint();
    if (current == null) return false;
    return current == expectedFingerprint;
  }

  /// Clears the cached fingerprint so the next call fetches a fresh value.
  void clearCache() => _cachedFingerprint = null;
}
