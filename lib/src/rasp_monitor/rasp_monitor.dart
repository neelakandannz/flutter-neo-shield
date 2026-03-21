import 'dart:async';
import 'dart:developer' as developer;
import '../rasp/rasp_shield.dart';
import '../rasp/security_mode.dart';
import '../rasp/security_result.dart';

/// Continuous RASP Monitor — Background watchdog for security threats.
class RaspMonitor {
  RaspMonitor._();
  /// Singleton instance of [RaspMonitor].
  static final RaspMonitor instance = RaspMonitor._();

  Timer? _timer;
  bool _isRunning = false;
  int _threatCount = 0;
  SecurityReport? _lastReport;

  /// Whether the monitor is actively running periodic scans.
  bool get isRunning => _isRunning;

  /// Total number of threat reports detected since monitoring started.
  int get threatCount => _threatCount;

  /// The most recent [SecurityReport] from the last scan cycle.
  SecurityReport? get lastReport => _lastReport;

  final _controller = StreamController<SecurityReport>.broadcast();

  /// A broadcast stream of [SecurityReport]s emitted after each scan.
  Stream<SecurityReport> get reports => _controller.stream;

  /// Starts periodic background security scans at the given [interval].
  ///
  /// [mode] controls the response behavior (see [SecurityMode]).
  /// [onThreat] is invoked when [SecurityMode.custom] is used and a threat is found.
  void startMonitoring({
    Duration interval = const Duration(seconds: 30),
    SecurityMode mode = SecurityMode.silent,
    void Function(SecurityReport report)? onThreat,
  }) {
    if (_isRunning) return;
    _isRunning = true;
    _threatCount = 0;
    _runScan(mode, onThreat);
    _timer = Timer.periodic(interval, (_) => _runScan(mode, onThreat));
  }

  /// Stops the periodic scanning timer.
  void stopMonitoring() {
    _timer?.cancel();
    _timer = null;
    _isRunning = false;
  }

  Future<void> _runScan(SecurityMode mode, void Function(SecurityReport)? onThreat) async {
    try {
      final report = await RaspShield.fullSecurityScan(mode: SecurityMode.silent);
      _lastReport = report;
      if (!report.isSafe) {
        _threatCount++;
        switch (mode) {
          case SecurityMode.strict: throw SecurityException('Continuous RASP: $report');
          case SecurityMode.warn: developer.log('RASP MONITOR: $report', name: 'RaspMonitor');
          case SecurityMode.custom: onThreat?.call(report);
          case SecurityMode.silent: break;
        }
      }
      if (!_controller.isClosed) _controller.add(report);
    } catch (e) {
      if (e is SecurityException) rethrow;
      developer.log('RASP monitor scan failed: $e', name: 'RaspMonitor');
    }
  }

  /// Stops monitoring and resets the threat counter and last report.
  void reset() { stopMonitoring(); _threatCount = 0; _lastReport = null; }

  /// Stops monitoring and closes the [reports] stream permanently.
  void dispose() { stopMonitoring(); _controller.close(); }
}
