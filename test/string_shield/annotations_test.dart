import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('ObfuscateClass', () {
    test('has default xor strategy', () {
      const annotation = ObfuscateClass();
      expect(annotation.defaultStrategy, equals(ObfuscationStrategy.xor));
    });

    test('accepts custom default strategy', () {
      const annotation = ObfuscateClass(
        defaultStrategy: ObfuscationStrategy.enhancedXor,
      );
      expect(
        annotation.defaultStrategy,
        equals(ObfuscationStrategy.enhancedXor),
      );
    });

    test('accepts split strategy', () {
      const annotation = ObfuscateClass(
        defaultStrategy: ObfuscationStrategy.split,
      );
      expect(
        annotation.defaultStrategy,
        equals(ObfuscationStrategy.split),
      );
    });
  });

  group('Obfuscate', () {
    test('has null strategy by default', () {
      const annotation = Obfuscate();
      expect(annotation.strategy, isNull);
    });

    test('accepts explicit strategy', () {
      const annotation = Obfuscate(strategy: ObfuscationStrategy.split);
      expect(annotation.strategy, equals(ObfuscationStrategy.split));
    });

    test('accepts xor strategy', () {
      const annotation = Obfuscate(strategy: ObfuscationStrategy.xor);
      expect(annotation.strategy, equals(ObfuscationStrategy.xor));
    });

    test('accepts enhancedXor strategy', () {
      const annotation =
          Obfuscate(strategy: ObfuscationStrategy.enhancedXor);
      expect(annotation.strategy, equals(ObfuscationStrategy.enhancedXor));
    });
  });

  group('ObfuscationStrategy', () {
    test('has three values', () {
      expect(ObfuscationStrategy.values.length, equals(3));
    });

    test('values are xor, enhancedXor, split', () {
      expect(ObfuscationStrategy.values, contains(ObfuscationStrategy.xor));
      expect(
        ObfuscationStrategy.values,
        contains(ObfuscationStrategy.enhancedXor),
      );
      expect(
        ObfuscationStrategy.values,
        contains(ObfuscationStrategy.split),
      );
    });

    test('indices are sequential', () {
      expect(ObfuscationStrategy.xor.index, equals(0));
      expect(ObfuscationStrategy.enhancedXor.index, equals(1));
      expect(ObfuscationStrategy.split.index, equals(2));
    });
  });
}
