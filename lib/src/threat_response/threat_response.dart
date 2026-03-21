import 'dart:io' show exit;
import 'package:flutter/foundation.dart';
import '../memory_shield/memory_shield.dart';
import '../rasp/security_result.dart';
import '../secure_storage_shield/secure_storage_shield.dart';

/// Automated threat response engine.
class ThreatResponse {
  ThreatResponse._();
  /// The singleton [ThreatResponse] instance.
  static final ThreatResponse instance = ThreatResponse._();

  final List<void Function(SecurityReport)> _listeners = [];

  /// Registers a [listener] invoked whenever [respond] processes a threat.
  void addListener(void Function(SecurityReport) listener) => _listeners.add(listener);

  /// Removes a previously registered threat [listener].
  void removeListener(void Function(SecurityReport) listener) => _listeners.remove(listener);

  /// Wipes all in-memory secrets held by [MemoryShield].
  void wipeSecrets() => MemoryShield().disposeAll();

  /// Wipes all data in [SecureStorageShield].
  Future<void> wipeStorage() async => await SecureStorageShield.instance.wipeAll();

  /// Wipes both in-memory secrets and persistent secure storage.
  Future<void> wipeAll() async { wipeSecrets(); await wipeStorage(); }

  /// Executes the configured threat response for the given [report].
  ///
  /// Notifies all listeners, optionally wipes secrets/storage, calls
  /// [ThreatResponseConfig.onThreatDetected], and kills the app if critical.
  Future<void> respond(SecurityReport report, ThreatResponseConfig config) async {
    if (report.isSafe) return;
    for (final listener in _listeners) { listener(report); }
    if (config.wipeSecretsOnThreat) wipeSecrets();
    if (config.wipeStorageOnThreat) await wipeStorage();
    config.onThreatDetected?.call(report);
    if (config.killAppOnCritical && _isCritical(report) && !kIsWeb) exit(0);
  }

  bool _isCritical(SecurityReport report) {
    var count = 0;
    if (report.debuggerDetected) count++;
    if (report.rootDetected) count++;
    if (report.fridaDetected) count++;
    if (report.hookDetected) count++;
    if (report.integrityTampered) count++;
    if (report.signatureTampered) count++;
    if (report.nativeDebugDetected) count++;
    return count >= 3;
  }
}

/// Configuration for automated threat response behavior.
class ThreatResponseConfig {
  /// Creates a [ThreatResponseConfig] with the given response actions.
  const ThreatResponseConfig({
    this.wipeSecretsOnThreat = false,
    this.wipeStorageOnThreat = false,
    this.killAppOnCritical = false,
    this.onThreatDetected,
  });

  /// Whether to wipe in-memory secrets when any threat is detected.
  final bool wipeSecretsOnThreat;

  /// Whether to wipe secure storage when any threat is detected.
  final bool wipeStorageOnThreat;

  /// Whether to force-kill the app when 3+ critical threats are found.
  final bool killAppOnCritical;

  /// Optional callback invoked with the [SecurityReport] on threat detection.
  final void Function(SecurityReport report)? onThreatDetected;
}
