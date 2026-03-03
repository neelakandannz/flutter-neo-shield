import 'dart:typed_data';

import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    MemoryShield().reset();
    MemoryShield().init(const MemoryShieldConfig(enablePlatformWipe: false));
  });

  group('MemoryShield manager', () {
    test('is a singleton', () {
      final a = MemoryShield();
      final b = MemoryShield();
      expect(identical(a, b), isTrue);
    });

    test(
        'register/unregister tracking: create SecureString, activeCount = 1, dispose, activeCount = 0',
        () {
      expect(MemoryShield().activeCount, equals(0));

      final secure = SecureString('tracked');
      expect(MemoryShield().activeCount, equals(1));

      secure.dispose();
      expect(MemoryShield().activeCount, equals(0));
    });

    test('activeCount correct with multiple containers', () {
      expect(MemoryShield().activeCount, equals(0));

      final s1 = SecureString('one');
      expect(MemoryShield().activeCount, equals(1));

      final s2 = SecureString('two');
      expect(MemoryShield().activeCount, equals(2));

      final s3 = SecureBytes(Uint8List.fromList([1, 2, 3]));
      expect(MemoryShield().activeCount, equals(3));

      s1.dispose();
      expect(MemoryShield().activeCount, equals(2));

      s2.dispose();
      expect(MemoryShield().activeCount, equals(1));

      s3.dispose();
      expect(MemoryShield().activeCount, equals(0));
    });

    test('disposeAll() wipes everything, activeCount = 0', () {
      final s1 = SecureString('first');
      final s2 = SecureString('second');
      final b1 = SecureBytes(Uint8List.fromList([10, 20]));

      expect(MemoryShield().activeCount, equals(3));

      MemoryShield().disposeAll();

      expect(MemoryShield().activeCount, equals(0));
      expect(s1.isDisposed, isTrue);
      expect(s2.isDisposed, isTrue);
      expect(b1.isDisposed, isTrue);
    });

    test(
        'after disposeAll, all containers are disposed (accessing value throws)',
        () {
      final s1 = SecureString('secret1');
      final s2 = SecureString('secret2');
      final b1 = SecureBytes(Uint8List.fromList([5, 6, 7]));

      MemoryShield().disposeAll();

      expect(() => s1.value, throwsStateError);
      expect(() => s2.value, throwsStateError);
      expect(() => b1.bytes, throwsStateError);
    });

    test('disposeAll can be called when no containers exist', () {
      expect(MemoryShield().activeCount, equals(0));
      expect(() => MemoryShield().disposeAll(), returnsNormally);
      expect(MemoryShield().activeCount, equals(0));
    });

    test('containers re-register after disposeAll', () {
      final s1 = SecureString('before');
      MemoryShield().disposeAll();
      expect(MemoryShield().activeCount, equals(0));
      expect(s1.isDisposed, isTrue);

      final s2 = SecureString('after');
      expect(MemoryShield().activeCount, equals(1));
      expect(s2.value, equals('after'));

      s2.dispose();
      expect(MemoryShield().activeCount, equals(0));
    });

    test('reset() disposes all and resets config', () {
      MemoryShield().init(const MemoryShieldConfig(
        enablePlatformWipe: false,
        autoDisposeOnBackground: true,
      ));

      final s1 = SecureString('reset test');
      expect(MemoryShield().activeCount, equals(1));

      MemoryShield().reset();

      expect(MemoryShield().activeCount, equals(0));
      expect(s1.isDisposed, isTrue);
      // Config should be back to default.
      expect(MemoryShield().config.autoDisposeOnBackground, isFalse);
    });

    test('activeCount tracks SecureValue as well', () {
      expect(MemoryShield().activeCount, equals(0));

      final sv = SecureValue<String>('generic value');
      expect(MemoryShield().activeCount, equals(1));

      sv.dispose();
      expect(MemoryShield().activeCount, equals(0));
    });

    test('mixed container types tracked correctly', () {
      final ss = SecureString('string');
      final sb = SecureBytes(Uint8List.fromList([1]));
      final sv = SecureValue<int>(42);

      expect(MemoryShield().activeCount, equals(3));

      MemoryShield().disposeAll();

      expect(MemoryShield().activeCount, equals(0));
      expect(ss.isDisposed, isTrue);
      expect(sb.isDisposed, isTrue);
      expect(sv.isDisposed, isTrue);
    });
  });
}
