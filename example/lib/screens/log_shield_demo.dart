import 'package:flutter/material.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';

import '../widgets/demo_card.dart';

/// Demo screen showcasing Log Shield functionality.
class LogShieldDemo extends StatefulWidget {
  /// Creates a [LogShieldDemo].
  const LogShieldDemo({super.key});

  @override
  State<LogShieldDemo> createState() => _LogShieldDemoState();
}

class _LogShieldDemoState extends State<LogShieldDemo> {
  final _inputController = TextEditingController();
  final _nameController = TextEditingController();
  final _customPatternController = TextEditingController(
    text: r'ACCT-\d{10}',
  );
  final _outputLines = <String>[];
  bool _customPatternAdded = false;

  final _examples = [
    'User email is john@example.com',
    'Token: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123',
    'SSN: 123-45-6789',
    'Call +1 (555) 123-4567',
    'Card: 4532 0151 1283 0366',
    'password=MyS3cret!',
    'IP: 192.168.1.1',
    'DOB: 1985-03-15',
    'API Key: sk-abcdefghijklmnopqrstuvwxyz',
  ];

  @override
  void initState() {
    super.initState();
    _inputController.text = _examples.first;

    // Set up LogShield to capture output.
    LogShield().init(LogShieldConfig(
      outputHandler: (message, level) {
        setState(() {
          _outputLines.add(message);
        });
      },
    ));
  }

  @override
  void dispose() {
    _inputController.dispose();
    _nameController.dispose();
    _customPatternController.dispose();
    super.dispose();
  }

  void _logInput() {
    shieldLog(_inputController.text);
  }

  void _registerName() {
    final name = _nameController.text.trim();
    if (name.isNotEmpty) {
      PIIDetector().registerName(name);
      setState(() {
        _outputLines.add('--- Registered name: $name ---');
      });
      _nameController.clear();
    }
  }

  void _logJsonExample() {
    shieldLogJson('API Response', {
      'name': 'John Doe',
      'id': 12345,
      'email': 'john@example.com',
      'address': '123 Main St',
      'note': 'Call 555-123-4567 for details',
    });
  }

  void _logErrorExample() {
    try {
      // Simulate an error that contains PII.
      throw const FormatException(
        'Invalid input for user john@example.com with card 4532015112830366',
      );
    } catch (e, stackTrace) {
      shieldLogError(
        'Login failed for john@example.com',
        error: e,
        stackTrace: stackTrace,
      );
    }
  }

  void _addCustomPattern() {
    final pattern = _customPatternController.text.trim();
    if (pattern.isEmpty) return;

    try {
      PIIDetector().addPattern(PIIPattern(
        type: PIIType.custom,
        regex: RegExp(pattern),
        replacement: '[CUSTOM HIDDEN]',
        description: 'Custom pattern from demo',
      ));
      setState(() {
        _customPatternAdded = true;
        _outputLines.add('--- Added custom pattern: $pattern ---');
      });
    } catch (e) {
      setState(() {
        _outputLines.add('--- Invalid regex: $e ---');
      });
    }
  }

  void _removeCustomPattern() {
    PIIDetector().removePattern(PIIType.custom);
    setState(() {
      _customPatternAdded = false;
      _outputLines.add('--- Removed all custom patterns ---');
    });
  }

  void _showShieldReport() {
    final report = PIIDetector().report;
    if (report == null) {
      setState(() {
        _outputLines.add('--- Reporting is disabled. Enable with '
            'ShieldConfig(enableReporting: true) ---');
      });
      return;
    }
    final stats = report.getStats();
    setState(() {
      _outputLines.add('--- Shield Report ---');
      _outputLines.add('Total detections: ${stats['totalDetections']}');
      final counts = stats['countsByType'] as Map<String, dynamic>;
      for (final entry in counts.entries) {
        _outputLines.add('  ${entry.key}: ${entry.value}');
      }
      _outputLines.add(
        'Last detection: ${stats['lastDetectionTimestamp'] ?? 'N/A'}',
      );
      _outputLines.add(
        'Recent events: ${stats['recentEventsCount']}',
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.only(bottom: 32),
      children: [
        DemoCard(
          title: 'Log Sanitization',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _inputController,
                decoration: const InputDecoration(
                  labelText: 'Enter text to log',
                  border: OutlineInputBorder(),
                ),
                maxLines: 2,
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  ElevatedButton(
                    onPressed: _logInput,
                    child: const Text('Log it'),
                  ),
                  const SizedBox(width: 8),
                  TextButton(
                    onPressed: () {
                      setState(() => _outputLines.clear());
                    },
                    child: const Text('Clear output'),
                  ),
                ],
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'Quick Examples',
          child: Wrap(
            spacing: 8,
            runSpacing: 4,
            children: _examples.map((example) {
              return ActionChip(
                label: Text(
                  example.length > 30
                      ? '${example.substring(0, 30)}...'
                      : example,
                  style: const TextStyle(fontSize: 12),
                ),
                onPressed: () {
                  _inputController.text = example;
                  _logInput();
                },
              );
            }).toList(),
          ),
        ),
        DemoCard(
          title: 'Error Logging (shieldLogError)',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Logs errors with sanitized PII, error objects, and stack traces.',
                style: TextStyle(fontSize: 12),
              ),
              const SizedBox(height: 8),
              ElevatedButton.icon(
                onPressed: _logErrorExample,
                icon: const Icon(Icons.error_outline),
                label: const Text('Trigger Error Log'),
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'Name Registration',
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _nameController,
                  decoration: const InputDecoration(
                    labelText: 'Register a name',
                    border: OutlineInputBorder(),
                    hintText: 'e.g., John',
                  ),
                ),
              ),
              const SizedBox(width: 8),
              ElevatedButton(
                onPressed: _registerName,
                child: const Text('Register'),
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'Custom PII Pattern',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Add a custom regex pattern to detect your own PII types. '
                'Try logging "Account ACCT-1234567890" after adding.',
                style: TextStyle(fontSize: 12),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _customPatternController,
                decoration: const InputDecoration(
                  labelText: 'Regex pattern',
                  border: OutlineInputBorder(),
                  hintText: r'e.g., ACCT-\d{10}',
                ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  ElevatedButton.icon(
                    onPressed: _customPatternAdded ? null : _addCustomPattern,
                    icon: const Icon(Icons.add),
                    label: const Text('Add Pattern'),
                  ),
                  const SizedBox(width: 8),
                  TextButton.icon(
                    onPressed:
                        _customPatternAdded ? _removeCustomPattern : null,
                    icon: const Icon(Icons.remove),
                    label: const Text('Remove'),
                  ),
                ],
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'JSON Sanitization',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Raw JSON:',
                style: Theme.of(context).textTheme.bodySmall,
              ),
              Container(
                padding: const EdgeInsets.all(8),
                color: Colors.grey.shade100,
                child: const Text(
                  '{"name": "John Doe", "id": 12345, "email": "john@example.com"}',
                  style: TextStyle(fontFamily: 'monospace', fontSize: 12),
                ),
              ),
              const SizedBox(height: 8),
              ElevatedButton(
                onPressed: _logJsonExample,
                child: const Text('Sanitize & Log JSON'),
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'Shield Report (Detection Statistics)',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'View PII detection statistics tracked by ShieldReport. '
                'Enabled via ShieldConfig(enableReporting: true) in main.dart.',
                style: TextStyle(fontSize: 12),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  ElevatedButton.icon(
                    onPressed: _showShieldReport,
                    icon: const Icon(Icons.analytics),
                    label: const Text('Show Report'),
                  ),
                  const SizedBox(width: 8),
                  TextButton(
                    onPressed: () {
                      PIIDetector().report?.reset();
                      setState(() {
                        _outputLines.add('--- Report reset ---');
                      });
                    },
                    child: const Text('Reset'),
                  ),
                ],
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'Dio Interceptor (DioShieldInterceptor)',
          child: Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.grey.shade900,
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Text(
              '// Add to your Dio instance:\n'
              'final dio = Dio();\n'
              'dio.interceptors.add(\n'
              '  DioShieldInterceptor(\n'
              '    sanitizeRequestBody: true,\n'
              '    sanitizeResponseBody: true,\n'
              '    sensitiveHeaders: [\n'
              "      'authorization',\n"
              "      'cookie',\n"
              "      'x-api-key',\n"
              '    ],\n'
              '  ),\n'
              ');\n\n'
              '// All HTTP traffic logs will have\n'
              '// PII automatically sanitized.',
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: 13,
                color: Colors.greenAccent,
              ),
            ),
          ),
        ),
        DemoCard(
          title: 'Console Output',
          child: Container(
            constraints: const BoxConstraints(maxHeight: 300),
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Colors.black87,
              borderRadius: BorderRadius.circular(8),
            ),
            child: ListView.builder(
              shrinkWrap: true,
              itemCount: _outputLines.length,
              itemBuilder: (context, index) {
                return Text(
                  _outputLines[index],
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: Colors.greenAccent,
                  ),
                );
              },
            ),
          ),
        ),
      ],
    );
  }
}
