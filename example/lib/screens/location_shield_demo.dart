import 'package:flutter/material.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';

/// Demo screen for the Location Shield module.
class LocationShieldDemo extends StatefulWidget {
  const LocationShieldDemo({super.key});

  @override
  State<LocationShieldDemo> createState() => _LocationShieldDemoState();
}

class _LocationShieldDemoState extends State<LocationShieldDemo> {
  LocationVerdict? _verdict;
  SpoofingAppResult? _spoofResult;
  bool? _mockEnabled;
  bool _loading = false;
  String _status = 'Tap a button to run detection';

  Future<void> _runFullCheck() async {
    setState(() {
      _loading = true;
      _status = 'Running 7-layer detection...';
    });
    try {
      final verdict = await LocationShield.instance.checkLocationAuthenticity();
      setState(() {
        _verdict = verdict;
        _status = verdict.isSpoofed
            ? 'FAKE LOCATION DETECTED!'
            : 'Location appears authentic';
      });
    } catch (e) {
      setState(() => _status = 'Error: $e');
    } finally {
      setState(() => _loading = false);
    }
  }

  Future<void> _checkSpoofingApps() async {
    setState(() {
      _loading = true;
      _status = 'Scanning for spoofing apps...';
    });
    try {
      final result = await LocationShield.instance.checkSpoofingApps();
      setState(() {
        _spoofResult = result;
        _status = result.detected
            ? 'Spoofing apps found: ${result.detectedApps.length}'
            : 'No spoofing apps detected';
      });
    } catch (e) {
      setState(() => _status = 'Error: $e');
    } finally {
      setState(() => _loading = false);
    }
  }

  Future<void> _checkMockLocation() async {
    setState(() {
      _loading = true;
      _status = 'Checking mock location setting...';
    });
    try {
      final enabled = await LocationShield.instance.isMockLocationEnabled();
      setState(() {
        _mockEnabled = enabled;
        _status = enabled
            ? 'Mock location is ENABLED'
            : 'Mock location is disabled';
      });
    } catch (e) {
      setState(() => _status = 'Error: $e');
    } finally {
      setState(() => _loading = false);
    }
  }

  Future<void> _runFullScan() async {
    setState(() {
      _loading = true;
      _status = 'Running RASP + Location scan...';
    });
    try {
      final verdict = await LocationShield.instance.fullLocationSecurityScan();
      setState(() {
        _verdict = verdict;
        _status = verdict.isSpoofed
            ? 'THREAT: Fake location + RASP context detected!'
            : 'All clear — location and device are authentic';
      });
    } catch (e) {
      setState(() => _status = 'Error: $e');
    } finally {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Status card
        Card(
          color: _verdict?.isSpoofed == true
              ? Colors.red.shade50
              : _verdict?.isSpoofed == false
                  ? Colors.green.shade50
                  : null,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                if (_loading) const CircularProgressIndicator(),
                if (!_loading)
                  Icon(
                    _verdict?.isSpoofed == true
                        ? Icons.warning_amber_rounded
                        : _verdict?.isSpoofed == false
                            ? Icons.check_circle_outline
                            : Icons.location_on_outlined,
                    size: 48,
                    color: _verdict?.isSpoofed == true
                        ? Colors.red
                        : _verdict?.isSpoofed == false
                            ? Colors.green
                            : theme.colorScheme.primary,
                  ),
                const SizedBox(height: 8),
                Text(_status, style: theme.textTheme.titleMedium,
                    textAlign: TextAlign.center),
              ],
            ),
          ),
        ),

        const SizedBox(height: 16),

        // Action buttons
        FilledButton.icon(
          onPressed: _loading ? null : _runFullCheck,
          icon: const Icon(Icons.gps_fixed),
          label: const Text('7-Layer Location Check'),
        ),
        const SizedBox(height: 8),
        OutlinedButton.icon(
          onPressed: _loading ? null : _checkSpoofingApps,
          icon: const Icon(Icons.app_blocking),
          label: const Text('Check Spoofing Apps'),
        ),
        const SizedBox(height: 8),
        OutlinedButton.icon(
          onPressed: _loading ? null : _checkMockLocation,
          icon: const Icon(Icons.developer_mode),
          label: const Text('Check Mock Location Setting'),
        ),
        const SizedBox(height: 8),
        FilledButton.tonalIcon(
          onPressed: _loading ? null : _runFullScan,
          icon: const Icon(Icons.security),
          label: const Text('Full RASP + Location Scan'),
        ),

        const SizedBox(height: 24),

        // Results
        if (_verdict != null) ...[
          Text('Detection Results', style: theme.textTheme.titleLarge),
          const SizedBox(height: 8),
          _resultRow('Spoofed', '${_verdict!.isSpoofed}'),
          _resultRow('Confidence', _verdict!.confidence.toStringAsFixed(3)),
          _resultRow('Risk Level', _verdict!.riskLevel.name.toUpperCase()),
          _resultRow('Methods', _verdict!.detectedMethods.join(', ')),
          const SizedBox(height: 8),
          Text('Layer Scores', style: theme.textTheme.titleSmall),
          ..._verdict!.layerScores.entries.map(
            (e) => _resultRow(e.key, e.value.toStringAsFixed(3)),
          ),
          if (_verdict!.raspContext.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text('RASP Context', style: theme.textTheme.titleSmall),
            ..._verdict!.raspContext.entries.map(
              (e) => _resultRow(e.key, e.value ? 'DETECTED' : 'clean'),
            ),
          ],
        ],

        if (_spoofResult != null) ...[
          const SizedBox(height: 16),
          Text('Spoofing App Scan', style: theme.textTheme.titleLarge),
          const SizedBox(height: 8),
          _resultRow('Detected', '${_spoofResult!.detected}'),
          _resultRow('Apps', _spoofResult!.detectedApps.join(', ')),
          if (_spoofResult!.defaultMockApp != null)
            _resultRow('Default Mock App', _spoofResult!.defaultMockApp!),
        ],

        if (_mockEnabled != null) ...[
          const SizedBox(height: 16),
          _resultRow('Mock Location Enabled', '$_mockEnabled'),
        ],
      ],
    );
  }

  Widget _resultRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 140,
            child: Text(label,
                style: const TextStyle(fontWeight: FontWeight.w600)),
          ),
          Expanded(child: Text(value)),
        ],
      ),
    );
  }
}
