import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    MemoryShield().reset();
    MemoryShield().init(const MemoryShieldConfig(enablePlatformWipe: false));
  });

  group('SecureBytes', () {
    test('bytes returns original data', () {
      final original = Uint8List.fromList([1, 2, 3, 4, 5]);
      final secure = SecureBytes(original);

      expect(secure.bytes, equals(Uint8List.fromList([1, 2, 3, 4, 5])));
      secure.dispose();
    });

    test('bytes returns a copy, not the internal reference', () {
      final original = Uint8List.fromList([10, 20, 30]);
      final secure = SecureBytes(original);

      final retrieved = secure.bytes;
      retrieved[0] = 99;

      // Modifying the returned copy should not affect the internal data.
      expect(secure.bytes[0], equals(10));
      secure.dispose();
    });

    test('fromBase64 constructor works', () {
      // Base64 for [1, 2, 3, 4]
      final base64String = base64Encode([1, 2, 3, 4]);
      final secure = SecureBytes.fromBase64(base64String);

      expect(secure.bytes, equals(Uint8List.fromList([1, 2, 3, 4])));
      secure.dispose();
    });

    test('toBase64 returns correct encoding', () {
      final secure = SecureBytes(Uint8List.fromList([1, 2, 3, 4]));
      final expected = base64Encode([1, 2, 3, 4]);

      expect(secure.toBase64(), equals(expected));
      secure.dispose();
    });

    test('toBase64 throws StateError after dispose', () {
      final secure = SecureBytes(Uint8List.fromList([5, 6, 7]));
      secure.dispose();

      expect(() => secure.toBase64(), throwsStateError);
    });

    test('dispose makes bytes throw StateError', () {
      final secure = SecureBytes(Uint8List.fromList([1, 2, 3]));
      secure.dispose();

      expect(() => secure.bytes, throwsStateError);
    });

    test('useOnce works and disposes after', () {
      final secure = SecureBytes(Uint8List.fromList([10, 20, 30]));
      final result = secure.useOnce((bytes) => bytes.reduce((a, b) => a + b));

      expect(result, equals(60));
      expect(secure.isDisposed, isTrue);
    });

    test('useOnce disposes even if action throws', () {
      final secure = SecureBytes(Uint8List.fromList([1]));

      expect(
        () => secure.useOnce((bytes) => throw Exception('error')),
        throwsException,
      );

      expect(secure.isDisposed, isTrue);
    });

    test('isDisposed is correct before and after dispose', () {
      final secure = SecureBytes(Uint8List.fromList([1, 2]));

      expect(secure.isDisposed, isFalse);

      secure.dispose();

      expect(secure.isDisposed, isTrue);
    });

    test('double-dispose is safe (idempotent)', () {
      final secure = SecureBytes(Uint8List.fromList([1, 2, 3]));
      secure.dispose();

      expect(() => secure.dispose(), returnsNormally);
      expect(secure.isDisposed, isTrue);
    });

    test('length returns correct value', () {
      final secure = SecureBytes(Uint8List.fromList([1, 2, 3, 4, 5]));
      expect(secure.length, equals(5));
      secure.dispose();
    });

    test('length returns zero for empty bytes', () {
      final secure = SecureBytes(Uint8List(0));
      expect(secure.length, equals(0));
      secure.dispose();
    });

    test('constructor copies the input so modifying original has no effect',
        () {
      final original = Uint8List.fromList([1, 2, 3]);
      final secure = SecureBytes(original);

      // Modify the original.
      original[0] = 99;

      // The secure container should still have the original values.
      expect(secure.bytes[0], equals(1));
      secure.dispose();
    });

    test('createdAt is set on construction', () {
      final before = DateTime.now();
      final secure = SecureBytes(Uint8List.fromList([1]));
      final after = DateTime.now();

      expect(secure.createdAt.isAfter(before) || secure.createdAt == before,
          isTrue);
      expect(secure.createdAt.isBefore(after) || secure.createdAt == after,
          isTrue);
      secure.dispose();
    });

    test('fromBase64 round-trips correctly', () {
      final original = Uint8List.fromList([72, 101, 108, 108, 111]); // "Hello"
      final b64 = base64Encode(original);
      final secure = SecureBytes.fromBase64(b64);

      expect(secure.toBase64(), equals(b64));
      expect(secure.bytes, equals(original));
      secure.dispose();
    });
  });
}
