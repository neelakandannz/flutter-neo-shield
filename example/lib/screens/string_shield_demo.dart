import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';

import '../widgets/demo_card.dart';

/// Demo screen showcasing String Shield functionality.
///
/// Since code generation requires build_runner, this demo simulates
/// the obfuscation/deobfuscation process to show how it works.
class StringShieldDemo extends StatefulWidget {
  /// Creates a [StringShieldDemo].
  const StringShieldDemo({super.key});

  @override
  State<StringShieldDemo> createState() => _StringShieldDemoState();
}

class _StringShieldDemoState extends State<StringShieldDemo> {
  final _inputController = TextEditingController(
    text: 'https://api.myapp.com/v2',
  );
  final _log = <String>[];
  ObfuscationStrategy _selectedStrategy = ObfuscationStrategy.xor;

  @override
  void initState() {
    super.initState();
    StringShield().init(const StringShieldConfig(
      enableCache: true,
      enableStats: true,
    ));
  }

  @override
  void dispose() {
    _inputController.dispose();
    super.dispose();
  }

  void _addLog(String message) {
    setState(() {
      _log.insert(0, message);
      if (_log.length > 50) _log.removeLast();
    });
  }

  void _demonstrateXor(String input) {
    final random = Random.secure();
    final bytes = Uint8List.fromList(utf8.encode(input));
    final key = Uint8List.fromList(
      List.generate(bytes.length, (_) => random.nextInt(256)),
    );

    // Encrypt (what the generator does at build time).
    final encrypted = Uint8List(bytes.length);
    for (var i = 0; i < bytes.length; i++) {
      encrypted[i] = bytes[i] ^ key[i % key.length];
    }

    _addLog('--- XOR Strategy ---');
    _addLog('Original: $input');
    _addLog(
      'Encrypted bytes: [${encrypted.take(8).join(", ")}${encrypted.length > 8 ? ", ..." : ""}]',
    );

    // Decrypt (what happens at runtime).
    final decrypted = Deobfuscator.xor(encrypted, key);
    _addLog('Decrypted: $decrypted');
    _addLog('Match: ${decrypted == input}');
  }

  void _demonstrateEnhancedXor(String input) {
    final random = Random.secure();
    final bytes = Uint8List.fromList(utf8.encode(input));
    final key = Uint8List.fromList(
      List.generate(bytes.length, (_) => random.nextInt(256)),
    );

    // Step 1: XOR.
    final xored = List<int>.generate(
      bytes.length,
      (i) => bytes[i] ^ key[i],
    );
    // Step 2: Reverse.
    final reversed = xored.reversed.toList();
    // Step 3: Insert junk bytes.
    final junkCount = bytes.length ~/ 4;
    final totalLength = reversed.length + junkCount;
    final junkPositions = <int>{};
    while (junkPositions.length < junkCount) {
      junkPositions.add(random.nextInt(totalLength));
    }
    final sortedJunk = junkPositions.toList()..sort();

    final withJunk = <int>[];
    var realIndex = 0;
    for (var i = 0; i < totalLength; i++) {
      if (sortedJunk.contains(i)) {
        withJunk.add(random.nextInt(256));
      } else {
        withJunk.add(reversed[realIndex]);
        realIndex++;
      }
    }

    _addLog('--- Enhanced XOR Strategy ---');
    _addLog('Original: $input');
    _addLog('With junk (${withJunk.length} bytes, $junkCount junk): '
        '[${withJunk.take(8).join(", ")}${withJunk.length > 8 ? ", ..." : ""}]');

    final decrypted = Deobfuscator.enhancedXor(
      Uint8List.fromList(withJunk),
      key,
      sortedJunk,
    );
    _addLog('Decrypted: $decrypted');
    _addLog('Match: ${decrypted == input}');
  }

  void _demonstrateSplit(String input) {
    final random = Random.secure();
    final bytes = Uint8List.fromList(utf8.encode(input));
    const chunkCount = 3;
    final chunkSize = (bytes.length / chunkCount).ceil();

    final chunks = <Uint8List>[];
    for (var i = 0; i < bytes.length; i += chunkSize) {
      final end = (i + chunkSize > bytes.length) ? bytes.length : i + chunkSize;
      chunks.add(Uint8List.fromList(bytes.sublist(i, end)));
    }

    // Shuffle.
    final indices = List<int>.generate(chunks.length, (i) => i);
    final shuffled = List<int>.from(indices)..shuffle(random);
    final shuffledChunks =
        List<Uint8List>.filled(chunks.length, Uint8List(0));
    final order = List<int>.filled(chunks.length, 0);
    for (var i = 0; i < chunks.length; i++) {
      shuffledChunks[shuffled[i]] = chunks[i];
      order[i] = shuffled[i];
    }

    _addLog('--- Split Strategy ---');
    _addLog('Original: $input');
    _addLog('Split into ${chunks.length} chunks, shuffled order: $order');

    final decrypted = Deobfuscator.split(shuffledChunks, order);
    _addLog('Decrypted: $decrypted');
    _addLog('Match: ${decrypted == input}');
  }

  void _runDemo() {
    final input = _inputController.text.trim();
    if (input.isEmpty) return;

    switch (_selectedStrategy) {
      case ObfuscationStrategy.xor:
        _demonstrateXor(input);
      case ObfuscationStrategy.enhancedXor:
        _demonstrateEnhancedXor(input);
      case ObfuscationStrategy.split:
        _demonstrateSplit(input);
    }

    StringShield().recordAccess('Demo.input');
    _addLog(
      'Stats: ${StringShield().deobfuscationCount} total deobfuscations',
    );
  }

  void _clearCache() {
    StringShield().clearCache();
    _addLog('Cache cleared (size: ${StringShield().cacheSize})');
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.only(bottom: 32),
      children: [
        DemoCard(
          title: 'String Obfuscation Demo',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Enter a string to see how it gets obfuscated and '
                'deobfuscated at runtime. In a real app, the generator '
                'does the encryption at build time automatically.',
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _inputController,
                decoration: const InputDecoration(
                  labelText: 'String to obfuscate',
                  hintText: 'e.g. https://api.myapp.com/v2',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              SegmentedButton<ObfuscationStrategy>(
                segments: const [
                  ButtonSegment(
                    value: ObfuscationStrategy.xor,
                    label: Text('XOR'),
                  ),
                  ButtonSegment(
                    value: ObfuscationStrategy.enhancedXor,
                    label: Text('Enhanced'),
                  ),
                  ButtonSegment(
                    value: ObfuscationStrategy.split,
                    label: Text('Split'),
                  ),
                ],
                selected: {_selectedStrategy},
                onSelectionChanged: (selected) {
                  setState(() => _selectedStrategy = selected.first);
                },
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  ElevatedButton.icon(
                    onPressed: _runDemo,
                    icon: const Icon(Icons.lock),
                    label: const Text('Obfuscate & Decrypt'),
                  ),
                  ElevatedButton.icon(
                    onPressed: _clearCache,
                    icon: const Icon(Icons.cached),
                    label: const Text('Clear Cache'),
                  ),
                ],
              ),
            ],
          ),
        ),
        DemoCard(
          title: 'How It Works in Real Code',
          child: Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.grey.shade900,
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Text(
              '@ObfuscateClass()\n'
              'abstract class AppSecrets {\n'
              '  @Obfuscate()\n'
              "  static const String apiUrl = 'https://...';\n"
              '}\n\n'
              '// Usage:\n'
              r'final url = $AppSecrets.apiUrl;',
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: 13,
                color: Colors.greenAccent,
              ),
            ),
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
            child: _log.isEmpty
                ? const Center(
                    child: Text(
                      'Tap "Obfuscate & Decrypt" to see it in action',
                      style: TextStyle(color: Colors.grey),
                    ),
                  )
                : ListView.builder(
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
