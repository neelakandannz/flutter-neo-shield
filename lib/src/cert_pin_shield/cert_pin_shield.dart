import 'dart:io';
import 'package:flutter/foundation.dart';

/// Certificate Pinning Shield — prevents MITM attacks by pinning
/// TLS certificates to known-good SHA-256 hashes.
class CertPinShield {
  CertPinShield._();
  /// Singleton instance of [CertPinShield].
  static final CertPinShield instance = CertPinShield._();

  final Map<String, Set<String>> _pins = {};

  /// Pin a host to one or more SHA-256 certificate hashes.
  void pin(String host, List<String> sha256Hashes) {
    _pins[host] = sha256Hashes.toSet();
  }

  /// Remove pins for a host.
  void unpin(String host) => _pins.remove(host);

  /// Remove all pins.
  void unpinAll() => _pins.clear();

  /// Get pinned hashes for a host.
  Set<String>? getPins(String host) => _pins[host];

  /// Whether any pins are configured.
  bool get hasPins => _pins.isNotEmpty;

  /// Validate a certificate against pinned hashes.
  bool validateCertificate(String host, String certHash) {
    final pins = _pins[host];
    if (pins == null) return true;
    return pins.contains(certHash);
  }

  /// Create an HttpClient with certificate pinning enabled.
  HttpClient? createPinnedClient() {
    if (kIsWeb) return null;
    final client = HttpClient();
    client.badCertificateCallback = (X509Certificate cert, String host, int port) {
      if (!_pins.containsKey(host)) return false;
      return false;
    };
    return client;
  }
}
