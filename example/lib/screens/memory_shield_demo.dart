import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';

import '../widgets/demo_card.dart';

/// Demo screen showcasing Memory Shield functionality.
class MemoryShieldDemo extends StatefulWidget {
  /// Creates a [MemoryShieldDemo].
  const MemoryShieldDemo({super.key});

  @override
  State<MemoryShieldDemo> createState() => _MemoryShieldDemoState();
}

class _MemoryShieldDemoState extends State<MemoryShieldDemo> {
  final _secrets = <String, SecureString>{};
  final _log = <String>[];
  int _counter = 0;
  bool _lifecycleBound = false;
  final _matchController = TextEditingController();

  void _addLog(String message) {
    setState(() {
      _log.insert(0, message);
      if (_log.length > 50) _log.removeLast();
    });
  }

  @override
  void dispose() {
    _matchController.dispose();
    super.dispose();
  }

  // --- SecureString ---

  void _createSecret() {
    _counter++;
    final key = 'secret_$_counter';
    final secret = SecureString(
      'api-key-${DateTime.now().millisecondsSinceEpoch}',
    );
    _secrets[key] = secret;
    _addLog('Created $key (active: ${MemoryShield().activeCount})');
    setState(() {});
  }

  void _createWithMaxAge() {
    _counter++;
    final key = 'timed_$_counter';
    final secret = SecureString(
      'temp-secret-${DateTime.now().millisecondsSinceEpoch}',
      maxAge: const Duration(seconds: 5),
    );
    _secrets[key] = secret;
    _addLog(
        'Created $key with 5s maxAge (active: ${MemoryShield().activeCount})');

    // Check after 5 seconds.
    Future.delayed(const Duration(seconds: 6), () {
      if (mounted) {
        _addLog(
          '$key auto-disposed: ${secret.isDisposed} (active: ${MemoryShield().activeCount})',
        );
      }
    });

    setState(() {});
  }

  void _readSecret(String key) {
    final secret = _secrets[key];
    if (secret == null) {
      _addLog('$key: not found');
      return;
    }
    try {
      final value = secret.value;
      _addLog('$key value: $value');
    } on StateError catch (e) {
      _addLog('$key ERROR: $e');
    }
  }

  void _disposeSecret(String key) {
    final secret = _secrets[key];
    if (secret == null) {
      _addLog('$key: not found');
      return;
    }
    secret.dispose();
    _addLog('Disposed $key (active: ${MemoryShield().activeCount})');
    setState(() {});
  }

  void _disposeAll() {
    MemoryShield().disposeAll();
    _addLog('Disposed ALL (active: ${MemoryShield().activeCount})');
    setState(() {});
  }

  void _useOnceDemo() {
    _counter++;
    final result = SecureString('one-time-secret-$_counter').useOnce(
      (val) => 'Hash of "$val" = ${val.hashCode}',
    );
    _addLog('useOnce result: $result');
    _addLog('Active after useOnce: ${MemoryShield().activeCount}');
    setState(() {});
  }

  // --- Constant-time comparison ---

  void _matchesDemo() {
    _counter++;
    const password = 'MyS3cretP@ss!';
    final secret = SecureString(password);
    final testInput = _matchController.text;

    final isMatch = secret.matches(testInput);
    _addLog('--- matches() demo ---');
    _addLog(
      'Comparing stored password with "$testInput": $isMatch',
    );
    _addLog('(Uses constant-time comparison to prevent timing attacks)');
    secret.dispose();
    setState(() {});
  }

  // --- SecureBytes ---

  void _createSecureBytes() {
    _counter++;
    final key = 'bytes_$_counter';
    final data = Uint8List.fromList([0x48, 0x65, 0x6C, 0x6C, 0x6F]); // Hello
    final secureBytes = SecureBytes(data);

    _addLog('--- SecureBytes demo ---');
    _addLog('Created $key with ${secureBytes.length} bytes');
    _addLog('Bytes: ${secureBytes.bytes}');
    _addLog('Base64: ${secureBytes.toBase64()}');

    secureBytes.dispose();
    _addLog('Disposed $key, isDisposed: ${secureBytes.isDisposed}');
    _addLog('Active: ${MemoryShield().activeCount}');
    setState(() {});
  }

  void _secureBytesFromBase64() {
    _counter++;
    final key = 'b64_$_counter';
    final secureBytes = SecureBytes.fromBase64('SGVsbG8gV29ybGQ=');

    _addLog('--- SecureBytes.fromBase64 demo ---');
    _addLog('Created $key from base64 "SGVsbG8gV29ybGQ="');
    _addLog('Length: ${secureBytes.length} bytes');

    final text = secureBytes.useOnce(
      (bytes) => String.fromCharCodes(bytes),
    );
    _addLog('useOnce decoded text: "$text"');
    _addLog('Auto-disposed after useOnce: ${secureBytes.isDisposed}');
    _addLog('Active: ${MemoryShield().activeCount}');
    setState(() {});
  }

  // --- SecureValue<T> ---

  void _createSecureValue() {
    _counter++;
    final key = 'value_$_counter';

    final credentials = SecureValue<Map<String, String>>(
      {'username': 'admin', 'token': 'abc-xyz-123'},
      wiper: (map) {
        _addLog('Custom wiper called — clearing map');
        map.clear();
      },
    );

    _addLog('--- SecureValue<Map> demo ---');
    _addLog('Created $key with credentials map');
    _addLog('Value: ${credentials.value}');

    credentials.dispose();
    _addLog('Disposed $key (wiper executed)');
    _addLog('isDisposed: ${credentials.isDisposed}');
    _addLog('Active: ${MemoryShield().activeCount}');
    setState(() {});
  }

  void _secureValueUseOnce() {
    _counter++;

    final token = SecureValue<String>(
      'refresh-token-${DateTime.now().millisecondsSinceEpoch}',
      maxAge: const Duration(seconds: 10),
    );

    final result = token.useOnce(
      (val) => 'Token hash: ${val.hashCode}',
    );
    _addLog('--- SecureValue useOnce demo ---');
    _addLog('Result: $result');
    _addLog('Auto-disposed: ${token.isDisposed}');
    _addLog('Active: ${MemoryShield().activeCount}');
    setState(() {});
  }

  // --- Lifecycle binding ---

  void _toggleLifecycleBinding() {
    if (_lifecycleBound) {
      MemoryShield().unbindFromLifecycle();
      _addLog('Unbound from lifecycle');
    } else {
      MemoryShield().bindToLifecycle();
      _addLog('Bound to lifecycle — secrets auto-dispose on app background');
    }
    setState(() {
      _lifecycleBound = !_lifecycleBound;
    });
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.only(bottom: 32),
      children: [
        DemoCard(
          title: 'SecureString',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Active containers: ${MemoryShield().activeCount}',
                style: Theme.of(context).textTheme.headlineSmall,
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  ElevatedButton.icon(
                    onPressed: _createSecret,
                    icon: const Icon(Icons.add),
                    label: const Text('Create SecureString'),
                  ),
                  ElevatedButton.icon(
                    onPressed: _createWithMaxAge,
                    icon: const Icon(Icons.timer),
                    label: const Text('Create with 5s maxAge'),
                  ),
                  ElevatedButton.icon(
                    onPressed: _useOnceDemo,
                    icon: const Icon(Icons.flash_on),
                    label: const Text('Use Once'),
                  ),
                  ElevatedButton.icon(
                    onPressed: _disposeAll,
                    icon: const Icon(Icons.delete_sweep),
                    label: const Text('Dispose All'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.red.shade400,
                      foregroundColor: Colors.white,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'Constant-Time Comparison (matches)',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'SecureString.matches() uses constant-time comparison to '
                'prevent timing attacks. The stored password is "MyS3cretP@ss!".',
                style: TextStyle(fontSize: 12),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _matchController,
                      decoration: const InputDecoration(
                        labelText: 'Test password',
                        border: OutlineInputBorder(),
                        hintText: 'Try: MyS3cretP@ss!',
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  ElevatedButton.icon(
                    onPressed: _matchesDemo,
                    icon: const Icon(Icons.compare_arrows),
                    label: const Text('Compare'),
                  ),
                ],
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'SecureBytes',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Secure container for binary data (encryption keys, etc.) '
                'with byte-level overwriting on dispose.',
                style: TextStyle(fontSize: 12),
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  ElevatedButton.icon(
                    onPressed: _createSecureBytes,
                    icon: const Icon(Icons.memory),
                    label: const Text('Create & Dispose'),
                  ),
                  ElevatedButton.icon(
                    onPressed: _secureBytesFromBase64,
                    icon: const Icon(Icons.transform),
                    label: const Text('From Base64'),
                  ),
                ],
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'SecureValue<T> (Generic Container)',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Hold any Dart object securely with an optional custom wiper '
                'function for type-specific cleanup.',
                style: TextStyle(fontSize: 12),
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  ElevatedButton.icon(
                    onPressed: _createSecureValue,
                    icon: const Icon(Icons.data_object),
                    label: const Text('Map with Wiper'),
                  ),
                  ElevatedButton.icon(
                    onPressed: _secureValueUseOnce,
                    icon: const Icon(Icons.flash_on),
                    label: const Text('Value useOnce'),
                  ),
                ],
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'Lifecycle Binding',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Bind MemoryShield to the app lifecycle so all secrets are '
                'auto-disposed when the app goes to the background.',
                style: TextStyle(fontSize: 12),
              ),
              const SizedBox(height: 8),
              ElevatedButton.icon(
                onPressed: _toggleLifecycleBinding,
                icon: Icon(
                  _lifecycleBound ? Icons.link_off : Icons.link,
                ),
                label: Text(
                  _lifecycleBound
                      ? 'Unbind from Lifecycle'
                      : 'Bind to Lifecycle',
                ),
                style: _lifecycleBound
                    ? ElevatedButton.styleFrom(
                        backgroundColor: Colors.orange.shade400,
                        foregroundColor: Colors.white,
                      )
                    : null,
              ),
              if (_lifecycleBound)
                const Padding(
                  padding: EdgeInsets.only(top: 8),
                  child: Text(
                    'Lifecycle bound — minimize the app to auto-dispose all '
                    'active containers.',
                    style: TextStyle(
                      fontSize: 12,
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ),
            ],
          ),
        ),
        if (_secrets.isNotEmpty)
          DemoCard(
            title: 'Active Secrets',
            child: Column(
              children: _secrets.entries.map((entry) {
                final disposed = entry.value.isDisposed;
                return ListTile(
                  dense: true,
                  leading: Icon(
                    disposed ? Icons.lock_open : Icons.lock,
                    color: disposed ? Colors.grey : Colors.green,
                  ),
                  title: Text(entry.key),
                  subtitle: Text(disposed ? 'DISPOSED' : 'Active'),
                  trailing: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      IconButton(
                        icon: const Icon(Icons.visibility),
                        tooltip: 'Read value',
                        onPressed: () => _readSecret(entry.key),
                      ),
                      IconButton(
                        icon: const Icon(Icons.delete),
                        tooltip: 'Dispose',
                        onPressed: () => _disposeSecret(entry.key),
                      ),
                    ],
                  ),
                );
              }).toList(),
            ),
          ),
        DemoCard(
          title: 'Activity Log',
          child: Container(
            constraints: const BoxConstraints(maxHeight: 250),
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Colors.black87,
              borderRadius: BorderRadius.circular(8),
            ),
            child: ListView.builder(
              shrinkWrap: true,
              itemCount: _log.length,
              itemBuilder: (context, index) {
                return Text(
                  _log[index],
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
