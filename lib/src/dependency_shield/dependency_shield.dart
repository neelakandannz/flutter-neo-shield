import 'dart:io';
import 'package:flutter/foundation.dart';

/// Dependency Integrity Shield — Verifies package checksums.
class DependencyShield {
  DependencyShield._();
  /// Singleton instance of [DependencyShield].
  static final DependencyShield instance = DependencyShield._();

  final Map<String, String> _expectedHashes = {};

  /// Registers expected [hashes] for dependency files (e.g. `pubspec.lock`).
  void registerHashes(Map<String, String> hashes) => _expectedHashes.addAll(hashes);

  /// Verifies the lockfile at [lockfilePath] against registered hashes.
  ///
  /// Returns a map of failures (file name to error message). An empty map means
  /// the lockfile matches expectations.
  Future<Map<String, String>> verifyLockfile(String lockfilePath) async {
    if (kIsWeb) return {};
    final failures = <String, String>{};
    try {
      final content = await File(lockfilePath).readAsString();
      final hash = content.hashCode.toRadixString(16);
      if (_expectedHashes.containsKey('pubspec.lock') && _expectedHashes['pubspec.lock'] != hash) {
        failures['pubspec.lock'] = 'Hash mismatch: expected ${_expectedHashes['pubspec.lock']}, got $hash';
      }
    } catch (e) { failures['pubspec.lock'] = 'Failed to read: $e'; }
    return failures;
  }

  /// Clears all registered expected hashes.
  void reset() => _expectedHashes.clear();
}
