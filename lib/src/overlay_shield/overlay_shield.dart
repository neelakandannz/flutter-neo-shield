import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';

/// Overlay/Tapjacking Shield — detects malicious overlays that steal taps.
///
/// On Android, detects TYPE_APPLICATION_OVERLAY windows drawn over your app.
/// On iOS, not applicable (OS prevents overlay attacks by design).
/// On Web, detects iframe embedding (clickjacking).
class OverlayShield {
  OverlayShield._();
  /// Singleton instance of [OverlayShield].
  static final OverlayShield instance = OverlayShield._();

  bool _filterTouchesEnabled = false;

  /// Whether touch filtering is currently enabled.
  bool get isFilteringTouches => _filterTouchesEnabled;

  /// Enable touch filtering — rejects touches when app window is obscured.
  Future<bool> enableTouchFiltering() async {
    final result = await RaspChannel.invokeDetection(
      ShieldCodec.d(ShieldCodec.mEnableOverlayProtection),
    );
    _filterTouchesEnabled = !result;
    return _filterTouchesEnabled;
  }

  /// Disable touch filtering.
  Future<void> disableTouchFiltering() async {
    await RaspChannel.invokeDetection(
      ShieldCodec.d(ShieldCodec.mDisableOverlayProtection),
    );
    _filterTouchesEnabled = false;
  }

  /// Check if any overlay windows are currently visible over the app.
  static Future<bool> checkOverlayAttack() async {
    return RaspChannel.invokeDetection(
      ShieldCodec.d(ShieldCodec.mCheckOverlay),
    );
  }

  /// Check if the app is embedded in an iframe (clickjacking).
  static Future<bool> checkClickjacking() async {
    return RaspChannel.invokeDetection(
      ShieldCodec.d(ShieldCodec.mCheckClickjacking),
    );
  }
}
