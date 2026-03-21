import '../platform/shield_codec.dart';
import 'package:flutter/services.dart';

/// Secure Storage Shield — Persistent encrypted key-value storage.
///
/// Uses platform Keystore/Keychain for key management:
/// - Android: AES-256-GCM encrypted SharedPreferences
/// - iOS/macOS: Keychain Services
/// - Windows: DPAPI
/// - Linux: Encrypted file storage
/// - Web: In-memory fallback
class SecureStorageShield {
  SecureStorageShield._();
  /// Singleton instance of [SecureStorageShield].
  static final SecureStorageShield instance = SecureStorageShield._();

  static final MethodChannel _channel = MethodChannel(
    ShieldCodec.d(ShieldCodec.chSecureStorage),
  );

  /// Writes a [value] to encrypted storage under the given [key].
  ///
  /// Returns `true` on success, `false` if the platform is unavailable.
  Future<bool> write({required String key, required String value}) async {
    try {
      final result = await _channel.invokeMethod<bool>('writeSecure', {'key': key, 'value': value});
      return result ?? false;
    } on MissingPluginException { return false; }
    on PlatformException { return false; }
  }

  /// Reads the decrypted value for [key] from encrypted storage.
  ///
  /// Returns `null` if the key does not exist or the platform is unavailable.
  Future<String?> read({required String key}) async {
    try {
      return await _channel.invokeMethod<String>('readSecure', {'key': key});
    } on MissingPluginException { return null; }
    on PlatformException { return null; }
  }

  /// Deletes the entry for [key] from encrypted storage.
  ///
  /// Returns `true` on success, `false` if the platform is unavailable.
  Future<bool> delete({required String key}) async {
    try {
      final result = await _channel.invokeMethod<bool>('deleteSecure', {'key': key});
      return result ?? false;
    } on MissingPluginException { return false; }
    on PlatformException { return false; }
  }

  /// Checks whether [key] exists in encrypted storage.
  ///
  /// Returns `true` if present, `false` otherwise or if the platform is unavailable.
  Future<bool> containsKey({required String key}) async {
    try {
      final result = await _channel.invokeMethod<bool>('containsKeySecure', {'key': key});
      return result ?? false;
    } on MissingPluginException { return false; }
    on PlatformException { return false; }
  }

  /// Deletes all entries from encrypted storage.
  ///
  /// Returns `true` on success, `false` if the platform is unavailable.
  Future<bool> wipeAll() async {
    try {
      final result = await _channel.invokeMethod<bool>('wipeAllSecure');
      return result ?? false;
    } on MissingPluginException { return false; }
    on PlatformException { return false; }
  }
}
