import 'package:fake_async/fake_async.dart';
import 'package:flutter/services.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  String? clipboardContent;

  setUp(() {
    ClipboardShield().reset();
    PIIDetector().reset();
    clipboardContent = null;

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform,
            (MethodCall methodCall) async {
      if (methodCall.method == 'Clipboard.setData') {
        clipboardContent = (methodCall.arguments as Map)['text'] as String?;
        return null;
      }
      if (methodCall.method == 'Clipboard.getData') {
        return <String, dynamic>{'text': clipboardContent};
      }
      return null;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null);
  });

  group('ClipboardShield', () {
    test('is a singleton', () {
      final a = ClipboardShield();
      final b = ClipboardShield();
      expect(identical(a, b), isTrue);
    });

    test('copy() stores text on clipboard', () async {
      await ClipboardShield().copy('hello world');
      expect(clipboardContent, equals('hello world'));
    });

    test('copy() returns ClipboardCopyResult with correct piiType for email',
        () async {
      final result = await ClipboardShield().copy('john@example.com');

      expect(result.success, isTrue);
      expect(result.piiDetected, isTrue);
      expect(result.piiType, equals(PIIType.email));
    });

    test('copy() returns ClipboardCopyResult with correct piiType for phone',
        () async {
      final result = await ClipboardShield().copy('555-123-4567');

      expect(result.success, isTrue);
      expect(result.piiDetected, isTrue);
      expect(result.piiType, equals(PIIType.phone));
    });

    test('copy() returns ClipboardCopyResult with correct piiType for SSN',
        () async {
      final result = await ClipboardShield().copy('123-45-6789');

      expect(result.success, isTrue);
      expect(result.piiDetected, isTrue);
      expect(result.piiType, equals(PIIType.ssn));
    });

    test('auto-clear fires after duration using fakeAsync', () {
      fakeAsync((async) {
        ClipboardShield().copy(
          'secret text',
          expireAfter: const Duration(seconds: 5),
        );

        // Allow the copy future to complete.
        async.flushMicrotasks();

        expect(clipboardContent, equals('secret text'));
        expect(ClipboardShield().isActive, isTrue);

        // Advance time by 5 seconds to trigger the auto-clear timer.
        async.elapse(const Duration(seconds: 5));

        // The auto-clear should have fired and cleared the clipboard.
        expect(clipboardContent, equals(''));
        expect(ClipboardShield().isActive, isFalse);
      });
    });

    test('clearNow() immediately clears clipboard', () async {
      await ClipboardShield().copy('sensitive data');
      expect(clipboardContent, equals('sensitive data'));

      await ClipboardShield().clearNow();
      expect(clipboardContent, equals(''));
      expect(ClipboardShield().isActive, isFalse);
    });

    test('cancelAutoClear() stops timer', () {
      fakeAsync((async) {
        ClipboardShield().copy(
          'timer test',
          expireAfter: const Duration(seconds: 10),
        );
        async.flushMicrotasks();

        expect(ClipboardShield().isActive, isTrue);

        ClipboardShield().cancelAutoClear();
        expect(ClipboardShield().isActive, isFalse);

        // Advance past the original timer duration.
        async.elapse(const Duration(seconds: 15));

        // Clipboard should NOT have been cleared because we cancelled.
        expect(clipboardContent, equals('timer test'));
      });
    });

    test('multiple rapid copies: only latest timer active', () {
      fakeAsync((async) {
        ClipboardShield().copy(
          'first',
          expireAfter: const Duration(seconds: 10),
        );
        async.flushMicrotasks();

        ClipboardShield().copy(
          'second',
          expireAfter: const Duration(seconds: 10),
        );
        async.flushMicrotasks();

        ClipboardShield().copy(
          'third',
          expireAfter: const Duration(seconds: 10),
        );
        async.flushMicrotasks();

        expect(clipboardContent, equals('third'));
        expect(ClipboardShield().isActive, isTrue);

        // Advance time to trigger the timer.
        async.elapse(const Duration(seconds: 10));

        // The clipboard should be cleared by the latest timer.
        expect(clipboardContent, equals(''));
        expect(ClipboardShield().isActive, isFalse);
      });
    });

    test('Duration.zero for defaultExpiry disables auto-clear', () {
      fakeAsync((async) {
        ClipboardShield().init(const ClipboardShieldConfig(
          defaultExpiry: Duration.zero,
        ));

        ClipboardShield().copy('no expire');
        async.flushMicrotasks();

        expect(clipboardContent, equals('no expire'));
        expect(ClipboardShield().isActive, isFalse);

        // Advance significant time.
        async.elapse(const Duration(minutes: 5));

        // Clipboard should still contain the text.
        expect(clipboardContent, equals('no expire'));
      });
    });

    test('isActive returns correct state', () async {
      // Before any copy, isActive should be false.
      expect(ClipboardShield().isActive, isFalse);

      await ClipboardShield().copy(
        'active test',
        expireAfter: const Duration(seconds: 30),
      );

      // After copy with expiry, isActive should be true.
      expect(ClipboardShield().isActive, isTrue);

      ClipboardShield().cancelAutoClear();

      // After cancel, isActive should be false.
      expect(ClipboardShield().isActive, isFalse);
    });

    test('copy() with no PII returns piiDetected false', () async {
      final result = await ClipboardShield().copy('just plain text');

      expect(result.success, isTrue);
      expect(result.piiDetected, isFalse);
      expect(result.piiType, isNull);
    });

    test('copy() result includes expiresAt and expiresIn when expiry set',
        () async {
      final result = await ClipboardShield().copy(
        'timed text',
        expireAfter: const Duration(seconds: 15),
      );

      expect(result.success, isTrue);
      expect(result.expiresAt, isNotNull);
      expect(result.expiresIn, equals(const Duration(seconds: 15)));
    });

    test('copy() result has null expiresAt when no expiry', () async {
      ClipboardShield().init(const ClipboardShieldConfig(
        defaultExpiry: Duration.zero,
      ));

      final result = await ClipboardShield().copy('no timer text');

      expect(result.success, isTrue);
      expect(result.expiresAt, isNull);
      expect(result.expiresIn, isNull);
    });

    test('reset() cancels timer and restores default config', () async {
      ClipboardShield().init(const ClipboardShieldConfig(
        defaultExpiry: Duration(seconds: 60),
        clearAfterPaste: false,
      ));

      await ClipboardShield().copy('reset test');
      expect(ClipboardShield().isActive, isTrue);

      ClipboardShield().reset();

      expect(ClipboardShield().isActive, isFalse);
      // Config should be back to default.
      expect(
        ClipboardShield().config.defaultExpiry,
        equals(const Duration(seconds: 30)),
      );
      expect(ClipboardShield().config.clearAfterPaste, isTrue);
    });
  });
}
