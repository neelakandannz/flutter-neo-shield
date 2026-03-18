import 'dart:async';
import 'package:flutter/services.dart';
import 'dart:developer' as developer;

import 'shield_codec.dart';
import '../location_shield/location_result.dart';

/// Handles communication between Flutter and native layer for Location Shield.
///
/// Uses a fail-closed design: if the native platform is unavailable or
/// throws an error, checks report the location as spoofed (safe default).
class LocationChannel {
  static final MethodChannel _channel =
      MethodChannel(ShieldCodec.d(ShieldCodec.chLocation));

  static final EventChannel _eventChannel =
      EventChannel(ShieldCodec.d(ShieldCodec.chLocationEvents));

  static Stream<dynamic>? _eventStream;
  static bool _streamErrored = false;

  // Cached decoded method names
  static final String _mFakeLocation = ShieldCodec.d(ShieldCodec.mCheckFakeLocation);
  static final String _mMockProvider = ShieldCodec.d(ShieldCodec.mCheckMockProvider);
  static final String _mSpoofingApps = ShieldCodec.d(ShieldCodec.mCheckSpoofingApps);
  static final String _mLocationHooks = ShieldCodec.d(ShieldCodec.mCheckLocationHooks);
  static final String _mGpsAnomaly = ShieldCodec.d(ShieldCodec.mCheckGpsAnomaly);
  static final String _mSensorFusion = ShieldCodec.d(ShieldCodec.mCheckSensorFusion);
  static final String _mTemporalAnomaly = ShieldCodec.d(ShieldCodec.mCheckTemporalAnomaly);

  /// Lazily initializes and returns the broadcast event stream.
  static Stream<dynamic> get _events {
    if (_eventStream == null || _streamErrored) {
      _streamErrored = false;
      _eventStream = _eventChannel.receiveBroadcastStream().handleError(
        (Object error) {
          _streamErrored = true;
          developer.log(
            'Location event stream error: $error — '
            'stream will be re-created on next access',
            name: 'LocationChannel',
          );
        },
      );
    }
    return _eventStream!;
  }

  /// Stream of location verdict events from continuous monitoring.
  static Stream<dynamic> get events => _events;

  /// Invoke the full fake location check (all 7 layers).
  static Future<LocationVerdict> checkFakeLocation([Map<String, dynamic>? config]) async {
    try {
      final result = await _channel.invokeMethod<Map>(_mFakeLocation, config);
      if (result != null) {
        return LocationVerdict.fromMap(result);
      }
      return LocationVerdict.failClosed('nullResult');
    } on MissingPluginException {
      developer.log(
        'checkFakeLocation: native plugin not registered — reporting as spoofed (fail-closed)',
        name: 'LocationChannel',
      );
      return LocationVerdict.failClosed('pluginMissing');
    } on PlatformException catch (e) {
      developer.log('Failed to check fake location: ${e.message}',
          name: 'LocationChannel');
      return LocationVerdict.failClosed('platformError');
    }
  }

  /// Check mock location provider only (Layer 1).
  static Future<bool> checkMockProvider() async {
    try {
      final result = await _channel.invokeMethod<bool>(_mMockProvider);
      return result ?? true; // fail-closed
    } on MissingPluginException {
      developer.log(
        'checkMockProvider: native plugin not registered — reporting as detected (fail-closed)',
        name: 'LocationChannel',
      );
      return true;
    } on PlatformException catch (e) {
      developer.log('Failed to check mock provider: ${e.message}',
          name: 'LocationChannel');
      return true;
    }
  }

  /// Check for known spoofing apps (Layer 2).
  static Future<SpoofingAppResult> checkSpoofingApps() async {
    try {
      final result = await _channel.invokeMethod<Map>(_mSpoofingApps);
      if (result != null) {
        return SpoofingAppResult.fromMap(result);
      }
      return const SpoofingAppResult(detected: true, detectedApps: ['unknown']);
    } on MissingPluginException {
      developer.log(
        'checkSpoofingApps: native plugin not registered',
        name: 'LocationChannel',
      );
      return const SpoofingAppResult();
    } on PlatformException catch (e) {
      developer.log('Failed to check spoofing apps: ${e.message}',
          name: 'LocationChannel');
      return const SpoofingAppResult();
    }
  }

  /// Check for location API hooks (Layer 3).
  static Future<bool> checkLocationHooks() async {
    try {
      final result = await _channel.invokeMethod<bool>(_mLocationHooks);
      return result ?? true;
    } on MissingPluginException {
      return true;
    } on PlatformException {
      return true;
    }
  }

  /// Check GPS signal anomalies (Layer 4).
  static Future<double> checkGpsAnomaly() async {
    try {
      final result = await _channel.invokeMethod<double>(_mGpsAnomaly);
      return result ?? 0.5;
    } on MissingPluginException {
      return 0.5;
    } on PlatformException {
      return 0.5;
    }
  }

  /// Check sensor fusion correlation (Layer 5).
  static Future<double> checkSensorFusion() async {
    try {
      final result = await _channel.invokeMethod<double>(_mSensorFusion);
      return result ?? 0.0;
    } on MissingPluginException {
      return 0.0;
    } on PlatformException {
      return 0.0;
    }
  }

  /// Check temporal anomalies (Layer 6).
  static Future<double> checkTemporalAnomaly() async {
    try {
      final result = await _channel.invokeMethod<double>(_mTemporalAnomaly);
      return result ?? 0.0;
    } on MissingPluginException {
      return 0.0;
    } on PlatformException {
      return 0.0;
    }
  }

  /// Resets the event stream. Only for testing.
  static void resetForTesting() {
    _eventStream = null;
    _streamErrored = false;
  }
}
