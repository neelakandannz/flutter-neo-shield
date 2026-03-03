import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  String? clipboardContent;

  setUp(() {
    ClipboardShield().reset();
    PIIDetector().reset();
    // Disable auto-clear for widget tests to avoid pending timer issues.
    ClipboardShield().init(const ClipboardShieldConfig(
      defaultExpiry: Duration.zero,
    ));
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
    ClipboardShield().cancelAutoClear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null);
  });

  group('SecureCopyButton', () {
    testWidgets('renders child correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: SecureCopyButton(
              text: 'test text',
              showSnackBar: false,
              child: Text('Copy Me'),
            ),
          ),
        ),
      );

      expect(find.text('Copy Me'), findsOneWidget);
    });

    testWidgets('tap triggers copy and text is on clipboard',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: SecureCopyButton(
              text: 'secret-value-123',
              showSnackBar: false,
              child: Text('Copy'),
            ),
          ),
        ),
      );

      await tester.tap(find.text('Copy'));
      await tester.pumpAndSettle();

      expect(clipboardContent, equals('secret-value-123'));
    });

    testWidgets('onCopied callback fires on tap', (WidgetTester tester) async {
      bool callbackFired = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SecureCopyButton(
              text: 'callback test',
              showSnackBar: false,
              onCopied: () {
                callbackFired = true;
              },
              child: const Text('Copy'),
            ),
          ),
        ),
      );

      expect(callbackFired, isFalse);

      await tester.tap(find.text('Copy'));
      await tester.pumpAndSettle();

      expect(callbackFired, isTrue);
    });

    testWidgets('shows snackbar after copy when showSnackBar is true',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: SecureCopyButton(
              text: 'snack text',
              showSnackBar: true,
              child: Text('Copy'),
            ),
          ),
        ),
      );

      await tester.tap(find.text('Copy'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 100));

      // With Duration.zero expiry, the message shows "0s".
      expect(find.textContaining('Copied!'), findsOneWidget);
    });

    testWidgets('renders as GestureDetector wrapping child',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: SecureCopyButton(
              text: 'icon test',
              showSnackBar: false,
              child: Icon(Icons.copy),
            ),
          ),
        ),
      );

      expect(find.byIcon(Icons.copy), findsOneWidget);
      expect(find.byType(GestureDetector), findsWidgets);
    });

    testWidgets('multiple taps copy latest text to clipboard',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: Column(
              children: [
                SecureCopyButton(
                  text: 'first-text',
                  showSnackBar: false,
                  child: Text('Copy First'),
                ),
                SecureCopyButton(
                  text: 'second-text',
                  showSnackBar: false,
                  child: Text('Copy Second'),
                ),
              ],
            ),
          ),
        ),
      );

      await tester.tap(find.text('Copy First'));
      await tester.pumpAndSettle();
      expect(clipboardContent, equals('first-text'));

      await tester.tap(find.text('Copy Second'));
      await tester.pumpAndSettle();
      expect(clipboardContent, equals('second-text'));
    });
  });
}
