import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';

import '../widgets/demo_card.dart';

/// Demo screen showcasing Clipboard Shield functionality.
class ClipboardShieldDemo extends StatefulWidget {
  /// Creates a [ClipboardShieldDemo].
  const ClipboardShieldDemo({super.key});

  @override
  State<ClipboardShieldDemo> createState() => _ClipboardShieldDemoState();
}

class _ClipboardShieldDemoState extends State<ClipboardShieldDemo> {
  final _textController = TextEditingController(
    text: '4532 0151 1283 0366',
  );
  final _pasteController = TextEditingController();
  String _status = 'Idle';
  String _piiInfo = 'None';
  Timer? _countdownTimer;
  int _remainingSeconds = 0;
  StreamSubscription<void>? _clearSub;

  @override
  void initState() {
    super.initState();
    ClipboardShield().init(const ClipboardShieldConfig(
      defaultExpiry: Duration(seconds: 15),
      detectPIIOnCopy: true,
    ));

    _clearSub = ClipboardShield().onCleared.listen((_) {
      if (mounted) {
        setState(() {
          _status = 'Cleared';
          _remainingSeconds = 0;
        });
        _countdownTimer?.cancel();
      }
    });
  }

  @override
  void dispose() {
    _textController.dispose();
    _pasteController.dispose();
    _countdownTimer?.cancel();
    _clearSub?.cancel();
    super.dispose();
  }

  Future<void> _secureCopy() async {
    final result = await ClipboardShield().copy(
      _textController.text,
      expireAfter: const Duration(seconds: 15),
    );

    setState(() {
      _status = result.success ? 'Active' : 'Failed';
      _piiInfo = result.piiDetected
          ? result.piiType?.displayName ?? 'Unknown'
          : 'None';
      _remainingSeconds = 15;
    });

    _countdownTimer?.cancel();
    _countdownTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (mounted) {
        setState(() {
          _remainingSeconds--;
          if (_remainingSeconds <= 0) {
            timer.cancel();
          }
        });
      } else {
        timer.cancel();
      }
    });
  }

  Future<void> _clearNow() async {
    await ClipboardShield().clearNow();
    _countdownTimer?.cancel();
    setState(() {
      _status = 'Cleared';
      _remainingSeconds = 0;
    });
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.only(bottom: 32),
      children: [
        DemoCard(
          title: 'Secure Copy',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _textController,
                decoration: const InputDecoration(
                  labelText: 'Sensitive text to copy',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: SecureCopyButton(
                      text: _textController.text,
                      expireAfter: const Duration(seconds: 15),
                      onCopied: () => _secureCopy(),
                      showSnackBar: false,
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 16,
                          vertical: 12,
                        ),
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.primary,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: const Text(
                          'Secure Copy (Widget)',
                          textAlign: TextAlign.center,
                          style: TextStyle(color: Colors.white),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  ElevatedButton(
                    onPressed: _secureCopy,
                    child: const Text('Copy (API)'),
                  ),
                ],
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'Status',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildStatusRow('Clipboard', _status),
              _buildStatusRow('PII Detected', _piiInfo),
              _buildStatusRow(
                'Auto-clear in',
                _remainingSeconds > 0 ? '${_remainingSeconds}s' : '-',
              ),
              const SizedBox(height: 8),
              ElevatedButton.icon(
                onPressed: _clearNow,
                icon: const Icon(Icons.clear),
                label: const Text('Clear Now'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.red.shade400,
                  foregroundColor: Colors.white,
                ),
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'Secure Paste Field',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Paste here — clipboard auto-clears after paste:',
                style: TextStyle(fontSize: 12),
              ),
              const SizedBox(height: 8),
              SecurePasteField(
                controller: _pasteController,
                decoration: const InputDecoration(
                  labelText: 'Paste here',
                  border: OutlineInputBorder(),
                ),
                onPasted: (text) {
                  setState(() {
                    _status = 'Cleared (after paste)';
                  });
                },
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'Sample Data',
          child: Wrap(
            spacing: 8,
            runSpacing: 4,
            children: [
              _buildSampleChip('Credit Card', '4532 0151 1283 0366'),
              _buildSampleChip('Email', 'john@example.com'),
              _buildSampleChip('Password', 'MyS3cretP@ss!'),
              _buildSampleChip('SSN', '123-45-6789'),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildStatusRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          SizedBox(
            width: 120,
            child: Text(
              '$label:',
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
          ),
          Text(value),
        ],
      ),
    );
  }

  Widget _buildSampleChip(String label, String value) {
    return ActionChip(
      label: Text(label, style: const TextStyle(fontSize: 12)),
      onPressed: () {
        _textController.text = value;
      },
    );
  }
}
