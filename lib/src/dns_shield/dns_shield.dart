import 'dart:io';
import 'package:flutter/foundation.dart';

/// DNS Shield — DNS spoofing and manipulation detection.
class DnsShield {
  DnsShield._();
  /// Singleton instance of [DnsShield].
  static final DnsShield instance = DnsShield._();

  final Map<String, Set<String>> _expectedIPs = {};

  /// Pins a [domain] to a set of [expectedIPs] for DNS validation.
  void pinDomain(String domain, Set<String> expectedIPs) => _expectedIPs[domain] = expectedIPs;

  /// Removes the DNS pin for [domain].
  void unpinDomain(String domain) => _expectedIPs.remove(domain);

  /// Validates DNS resolution of [domain] against its pinned IPs.
  ///
  /// Returns `null` if valid, or an error message describing the mismatch.
  /// Always returns `null` on web (DNS checks not available).
  Future<String?> validateDns(String domain) async {
    if (kIsWeb) return null;
    final expected = _expectedIPs[domain];
    if (expected == null) return null;
    try {
      final addresses = await InternetAddress.lookup(domain);
      final resolved = addresses.map((a) => a.address).toSet();
      if (resolved.intersection(expected).isEmpty) {
        return 'DNS resolution for $domain returned unexpected IPs: $resolved';
      }
      return null;
    } catch (e) { return 'DNS lookup failed for $domain: $e'; }
  }

  /// Validates all pinned domains and returns a map of failures.
  ///
  /// Keys are domain names; values are error messages. An empty map means all passed.
  Future<Map<String, String>> validateAll() async {
    final failures = <String, String>{};
    for (final domain in _expectedIPs.keys) {
      final error = await validateDns(domain);
      if (error != null) failures[domain] = error;
    }
    return failures;
  }

  /// Removes all pinned domains.
  void reset() => _expectedIPs.clear();
}
