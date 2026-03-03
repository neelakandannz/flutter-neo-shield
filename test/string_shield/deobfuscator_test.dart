import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('Deobfuscator', () {
    group('xor', () {
      test('round-trips a simple ASCII string', () {
        const original = 'Hello, World!';
        final bytes = Uint8List.fromList(utf8.encode(original));
        final key = Uint8List.fromList(
          List.generate(bytes.length, (i) => 42 + i),
        );

        final encrypted = Uint8List(bytes.length);
        for (var i = 0; i < bytes.length; i++) {
          encrypted[i] = bytes[i] ^ key[i % key.length];
        }

        final result = Deobfuscator.xor(encrypted, key);
        expect(result, equals(original));
      });

      test('round-trips a UTF-8 string with multi-byte characters', () {
        const original = 'Caf\u00e9 \u2615';
        final bytes = Uint8List.fromList(utf8.encode(original));
        final random = Random(42);
        final key = Uint8List.fromList(
          List.generate(bytes.length, (_) => random.nextInt(256)),
        );

        final encrypted = Uint8List(bytes.length);
        for (var i = 0; i < bytes.length; i++) {
          encrypted[i] = bytes[i] ^ key[i % key.length];
        }

        final result = Deobfuscator.xor(encrypted, key);
        expect(result, equals(original));
      });

      test('handles empty string', () {
        final result =
            Deobfuscator.xor(Uint8List(0), Uint8List.fromList([1]));
        expect(result, equals(''));
      });

      test('works with key shorter than data', () {
        const original = 'abcdefgh';
        final bytes = Uint8List.fromList(utf8.encode(original));
        final key = Uint8List.fromList([0xAA, 0xBB]);

        final encrypted = Uint8List(bytes.length);
        for (var i = 0; i < bytes.length; i++) {
          encrypted[i] = bytes[i] ^ key[i % key.length];
        }

        final result = Deobfuscator.xor(encrypted, key);
        expect(result, equals(original));
      });

      test('round-trips a URL string', () {
        const original = 'https://api.myapp.com/v2/users?token=abc123';
        final bytes = Uint8List.fromList(utf8.encode(original));
        final random = Random.secure();
        final key = Uint8List.fromList(
          List.generate(bytes.length, (_) => random.nextInt(256)),
        );

        final encrypted = Uint8List(bytes.length);
        for (var i = 0; i < bytes.length; i++) {
          encrypted[i] = bytes[i] ^ key[i % key.length];
        }

        final result = Deobfuscator.xor(encrypted, key);
        expect(result, equals(original));
      });
    });

    group('enhancedXor', () {
      test('round-trips a string through enhanced XOR process', () {
        const original = 'SecretAPIKey123';
        final bytes = Uint8List.fromList(utf8.encode(original));
        final random = Random(99);
        final key = Uint8List.fromList(
          List.generate(bytes.length, (_) => random.nextInt(256)),
        );

        // Simulate compile-time encryption:
        // Step 1: XOR.
        final xored = List<int>.generate(
          bytes.length,
          (i) => bytes[i] ^ key[i],
        );
        // Step 2: Reverse.
        final reversed = xored.reversed.toList();
        // Step 3: Insert junk bytes.
        final junkPositions = <int>[2, 5, 8];
        final withJunk = <int>[];
        var realIndex = 0;
        for (var i = 0;
            realIndex < reversed.length || junkPositions.contains(i);
            i++) {
          if (junkPositions.contains(i)) {
            withJunk.add(random.nextInt(256));
          } else {
            if (realIndex < reversed.length) {
              withJunk.add(reversed[realIndex]);
              realIndex++;
            }
          }
        }

        final result = Deobfuscator.enhancedXor(
          Uint8List.fromList(withJunk),
          Uint8List.fromList(key),
          junkPositions,
        );
        expect(result, equals(original));
      });

      test('handles no junk positions', () {
        const original = 'NoJunk';
        final bytes = Uint8List.fromList(utf8.encode(original));
        final key = Uint8List.fromList(
          List.generate(bytes.length, (i) => i + 1),
        );

        final xored = List<int>.generate(
          bytes.length,
          (i) => bytes[i] ^ key[i],
        );
        final reversed = Uint8List.fromList(xored.reversed.toList());

        final result = Deobfuscator.enhancedXor(
          reversed,
          Uint8List.fromList(key),
          [],
        );
        expect(result, equals(original));
      });

      test('handles single junk position at start', () {
        const original = 'AB';
        final bytes = Uint8List.fromList(utf8.encode(original));
        final key = Uint8List.fromList([10, 20]);

        final xored = [bytes[0] ^ key[0], bytes[1] ^ key[1]];
        final reversed = xored.reversed.toList();
        // Insert junk at position 0.
        final withJunk = [0xFF, ...reversed];

        final result = Deobfuscator.enhancedXor(
          Uint8List.fromList(withJunk),
          Uint8List.fromList(key),
          [0],
        );
        expect(result, equals(original));
      });
    });

    group('split', () {
      test('reassembles chunks in correct order', () {
        const original = 'HelloWorld';
        final chunk0 = Uint8List.fromList(utf8.encode('Hello'));
        final chunk1 = Uint8List.fromList(utf8.encode('World'));

        // Stored out of order: [World, Hello]
        // Order: [1, 0] means read chunks[1] first, then chunks[0].
        final result = Deobfuscator.split(
          [chunk1, chunk0],
          [1, 0],
        );
        expect(result, equals(original));
      });

      test('handles single chunk', () {
        const original = 'single';
        final chunk = Uint8List.fromList(utf8.encode(original));

        final result = Deobfuscator.split([chunk], [0]);
        expect(result, equals(original));
      });

      test('handles three-way split', () {
        // "ABCDEF" split as "AB", "CD", "EF"
        // Stored shuffled as [EF, AB, CD] with order [1, 2, 0].
        final chunks = [
          Uint8List.fromList(utf8.encode('EF')),
          Uint8List.fromList(utf8.encode('AB')),
          Uint8List.fromList(utf8.encode('CD')),
        ];

        final result = Deobfuscator.split(chunks, [1, 2, 0]);
        expect(result, equals('ABCDEF'));
      });

      test('handles unequal chunk sizes', () {
        // "Hello!" split as "Hel", "lo", "!"
        // Stored shuffled as [lo, !, Hel] with order [2, 0, 1].
        final chunks = [
          Uint8List.fromList(utf8.encode('lo')),
          Uint8List.fromList(utf8.encode('!')),
          Uint8List.fromList(utf8.encode('Hel')),
        ];

        final result = Deobfuscator.split(chunks, [2, 0, 1]);
        expect(result, equals('Hello!'));
      });
    });
  });
}
