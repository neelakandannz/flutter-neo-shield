import 'dart:async';
import 'package:flutter/services.dart';
import 'dart:developer' as developer;

import 'shield_codec.dart';

/// Handles communication between Flutter and native layer for Screen Shield.
///
/// Provides methods to enable/disable screen protection and streams for
/// screenshot and recording detection events.
class ScreenChannel {
  static final MethodChannel _channel =
      MethodChannel(ShieldCodec.d(ShieldCodec.chScreen));

  static final EventChannel _eventChannel =
      EventChannel(ShieldCodec.d(ShieldCodec.chScreenEvents));

  static Stream<dynamic>? _eventStream;
  static bool _streamErrored = false;

  /// Lazily initializes and returns the broadcast event stream.
  ///
  /// If the previous stream ended due to an error, a new stream is
  /// created on the next access so that event detection can recover.
  static Stream<dynamic> get _events {
    if (_eventStream == null || _streamErrored) {
      _streamErrored = false;
      _eventStream = _eventChannel.receiveBroadcastStream().handleError(
        (Object error) {
          _streamErrored = true;
          developer.log(
            'Screen event stream error: $error — '
            'stream will be re-created on next access',
            name: 'ScreenChannel',
          );
        },
      );
    }
    return _eventStream!;
  }

  // Cached decoded method names (decoded once, reused).
  static final String _mEnable = ShieldCodec.d(ShieldCodec.mEnableScreenProtection);
  static final String _mDisable = ShieldCodec.d(ShieldCodec.mDisableScreenProtection);
  static final String _mIsActive = ShieldCodec.d(ShieldCodec.mIsScreenProtectionActive);
  static final String _mEnableGuard = ShieldCodec.d(ShieldCodec.mEnableAppSwitcherGuard);
  static final String _mDisableGuard = ShieldCodec.d(ShieldCodec.mDisableAppSwitcherGuard);
  static final String _mIsRecorded = ShieldCodec.d(ShieldCodec.mIsScreenBeingRecorded);

  /// Enable screen protection (screenshots + recording).
  static Future<bool> enableProtection() async {
    try {
      final result =
          await _channel.invokeMethod<bool>(_mEnable);
      return result ?? false;
    } on MissingPluginException {
      developer.log(
        'screen protection: native plugin not registered — '
        'unavailable on this platform',
        name: 'ScreenChannel',
      );
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to enable screen protection: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Disable screen protection.
  static Future<bool> disableProtection() async {
    try {
      final result =
          await _channel.invokeMethod<bool>(_mDisable);
      return result ?? false;
    } on MissingPluginException {
      developer.log(
        'screen protection disable: native plugin not registered',
        name: 'ScreenChannel',
      );
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to disable screen protection: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Query whether screen protection is currently active.
  static Future<bool> isProtectionActive() async {
    try {
      final result =
          await _channel.invokeMethod<bool>(_mIsActive);
      return result ?? false;
    } on MissingPluginException {
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to query screen protection state: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Enable app switcher guard (blur/hide content in recent apps).
  static Future<bool> enableAppSwitcherGuard() async {
    try {
      final result =
          await _channel.invokeMethod<bool>(_mEnableGuard);
      return result ?? false;
    } on MissingPluginException {
      developer.log(
        'app switcher guard: native plugin not registered',
        name: 'ScreenChannel',
      );
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to enable app switcher guard: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Disable app switcher guard.
  static Future<bool> disableAppSwitcherGuard() async {
    try {
      final result =
          await _channel.invokeMethod<bool>(_mDisableGuard);
      return result ?? false;
    } on MissingPluginException {
      developer.log(
        'app switcher guard disable: native plugin not registered',
        name: 'ScreenChannel',
      );
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to disable app switcher guard: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Query whether the screen is currently being recorded.
  static Future<bool> isScreenBeingRecorded() async {
    try {
      final result =
          await _channel.invokeMethod<bool>(_mIsRecorded);
      return result ?? false;
    } on MissingPluginException {
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to query recording state: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Stream of events from native side.
  ///
  /// Events are maps with a "type" key:
  /// - `{"type": "screenshot"}` — screenshot was taken (iOS)
  /// - `{"type": "recording", "isRecording": bool}` — recording state changed
  static Stream<dynamic> get events => _events;

  /// Resets the event stream. Only for testing.
  static void resetForTesting() {
    _eventStream = null;
    _streamErrored = false;
  }
}
