import 'package:flutter/material.dart';
import '../rasp/rasp_shield.dart';
import '../rasp/security_result.dart';

/// Security Score Dashboard Widget — Visual overview of security posture.
class SecurityDashboard extends StatefulWidget {
  /// Creates a [SecurityDashboard] widget.
  const SecurityDashboard({super.key});

  @override
  State<SecurityDashboard> createState() => _SecurityDashboardState();
}

class _SecurityDashboardState extends State<SecurityDashboard> {
  SecurityReport? _report;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _runScan();
  }

  Future<void> _runScan() async {
    setState(() => _loading = true);
    try {
      final report = await RaspShield.fullSecurityScan();
      if (mounted) setState(() { _report = report; _loading = false; });
    } catch (e) {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Card(child: Padding(padding: EdgeInsets.all(16), child: Center(child: CircularProgressIndicator())));
    }
    final report = _report;
    if (report == null) {
      return const Card(child: Padding(padding: EdgeInsets.all(16), child: Text('Security scan failed')));
    }
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(children: [
              Icon(report.isSafe ? Icons.shield : Icons.warning, color: report.isSafe ? Colors.green : Colors.red, size: 28),
              const SizedBox(width: 8),
              Text(report.isSafe ? 'SECURE' : 'THREATS DETECTED',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: report.isSafe ? Colors.green : Colors.red)),
              const Spacer(),
              IconButton(icon: const Icon(Icons.refresh), onPressed: _runScan),
            ]),
            const Divider(),
            _row('Debugger', report.debuggerDetected),
            _row('Root/Jailbreak', report.rootDetected),
            _row('Emulator', report.emulatorDetected),
            _row('Frida', report.fridaDetected),
            _row('Hooks', report.hookDetected),
            _row('Integrity', report.integrityTampered),
            _row('Developer Mode', report.developerModeDetected),
            _row('Signature', report.signatureTampered),
            _row('Native Debug', report.nativeDebugDetected),
            _row('Network Threat', report.networkThreatDetected),
          ],
        ),
      ),
    );
  }

  Widget _row(String label, bool detected) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(children: [
        Icon(detected ? Icons.error : Icons.check_circle, color: detected ? Colors.red : Colors.green, size: 18),
        const SizedBox(width: 8),
        Expanded(child: Text(label)),
        Text(detected ? 'DETECTED' : 'SAFE',
          style: TextStyle(color: detected ? Colors.red : Colors.green, fontWeight: FontWeight.w500, fontSize: 12)),
      ]),
    );
  }
}
