import 'package:flutter/material.dart';
import '../platform/rasp_channel.dart';
import '../platform/shield_codec.dart';

/// Secure Input Shield — Anti-Keylogger protection.
class SecureInputShield {
  SecureInputShield._();
  /// Singleton instance of [SecureInputShield].
  static final SecureInputShield instance = SecureInputShield._();

  /// Check if a third-party (non-system) keyboard is active.
  static Future<bool> isThirdPartyKeyboardActive() {
    return RaspChannel.invokeDetection(
      ShieldCodec.d(ShieldCodec.mCheckKeyboard),
    );
  }

  /// Get the current input method package name (Android only).
  static Future<String?> getCurrentKeyboardPackage() {
    return RaspChannel.invokeStringMethod(
      ShieldCodec.d(ShieldCodec.mGetKeyboardPackage),
    );
  }

  /// Check if any keylogger-like accessibility service is monitoring input.
  static Future<bool> isKeyloggerDetected() {
    return RaspChannel.invokeDetection(
      ShieldCodec.d(ShieldCodec.mCheckKeylogger),
    );
  }
}

/// A secure text field that forces system keyboard and blocks
/// accessibility event leaks on sensitive input.
class SecureTextField extends StatelessWidget {
  /// Creates a [SecureTextField] with the given options.
  const SecureTextField({
    super.key,
    this.controller,
    this.decoration,
    this.obscureText = false,
    this.onChanged,
    this.onSubmitted,
    this.keyboardType,
    this.autofillHints,
    this.maxLength,
  });

  /// Controller for the underlying [TextField].
  final TextEditingController? controller;

  /// Decoration for the underlying [TextField].
  final InputDecoration? decoration;

  /// Whether to obscure the entered text (e.g. for passwords).
  final bool obscureText;

  /// Called when the text changes.
  final ValueChanged<String>? onChanged;

  /// Called when the user submits the text (e.g. presses done).
  final ValueChanged<String>? onSubmitted;

  /// The type of keyboard to display.
  final TextInputType? keyboardType;

  /// Autofill hints for the platform's autofill service.
  final Iterable<String>? autofillHints;

  /// Maximum number of characters allowed.
  final int? maxLength;

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: controller,
      decoration: decoration,
      obscureText: obscureText,
      onChanged: onChanged,
      onSubmitted: onSubmitted,
      keyboardType: keyboardType,
      autofillHints: autofillHints,
      maxLength: maxLength,
      enableIMEPersonalizedLearning: false,
      enableSuggestions: false,
      autocorrect: false,
    );
  }
}
