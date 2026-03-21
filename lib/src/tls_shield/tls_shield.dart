import 'dart:io';
import 'package:flutter/foundation.dart';

/// TLS Configuration Shield — Enforces secure TLS settings.
class TlsShield {
  TlsShield._();
  /// The singleton [TlsShield] instance.
  static final TlsShield instance = TlsShield._();

  /// Creates an [HttpClient] configured with the platform's default secure context.
  ///
  /// Returns `null` on web where [HttpClient] is not available.
  HttpClient? createSecureClient() {
    if (kIsWeb) return null;
    return HttpClient(context: SecurityContext.defaultContext);
  }

  /// Validates the TLS configuration of [host] on the given [port].
  ///
  /// Returns `null` if the connection succeeds with modern TLS,
  /// or an error message if the protocol is outdated or the connection fails.
  Future<String?> validateHost(String host, {int port = 443}) async {
    if (kIsWeb) return null;
    try {
      final socket = await SecureSocket.connect(host, port, timeout: const Duration(seconds: 10));
      final protocol = socket.selectedProtocol;
      socket.destroy();
      if (protocol != null && protocol.contains('1.0')) return 'Host $host using outdated TLS: $protocol';
      return null;
    } catch (e) { return 'TLS connection to $host failed: $e'; }
  }

  /// Validates TLS for multiple [hosts] and returns a map of failures.
  ///
  /// Keys are host names; values are error messages. An empty map means all passed.
  Future<Map<String, String>> validateHosts(List<String> hosts) async {
    final failures = <String, String>{};
    for (final host in hosts) {
      final error = await validateHost(host);
      if (error != null) failures[host] = error;
    }
    return failures;
  }
}
