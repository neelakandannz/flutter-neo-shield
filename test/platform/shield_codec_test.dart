import 'package:flutter_neo_shield/src/platform/shield_codec.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('ShieldCodec', () {
    group('encode/decode roundtrip', () {
      test('encodes and decodes back to original string', () {
        const original = 'hello world';
        final encoded = ShieldCodec.e(original);
        final decoded = ShieldCodec.d(encoded);
        expect(decoded, equals(original));
      });

      test('works with empty string', () {
        final encoded = ShieldCodec.e('');
        final decoded = ShieldCodec.d(encoded);
        expect(decoded, equals(''));
      });

      test('works with single character', () {
        final encoded = ShieldCodec.e('a');
        final decoded = ShieldCodec.d(encoded);
        expect(decoded, equals('a'));
      });

      test('works with special characters', () {
        const original = 'com.neelakandan/test_method:result';
        final encoded = ShieldCodec.e(original);
        final decoded = ShieldCodec.d(encoded);
        expect(decoded, equals(original));
      });

      test('encoded bytes differ from original codeUnits', () {
        const original = 'checkDebugger';
        final encoded = ShieldCodec.e(original);
        expect(encoded, isNot(equals(original.codeUnits)));
      });
    });

    group('channel name constants', () {
      test('chRasp decodes to RASP channel name', () {
        expect(
          ShieldCodec.d(ShieldCodec.chRasp),
          equals('com.neelakandan.flutter_neo_shield/rasp'),
        );
      });

      test('chScreen decodes to Screen channel name', () {
        expect(
          ShieldCodec.d(ShieldCodec.chScreen),
          equals('com.neelakandan.flutter_neo_shield/screen'),
        );
      });

      test('chMemory decodes to Memory channel name', () {
        expect(
          ShieldCodec.d(ShieldCodec.chMemory),
          equals('com.neelakandan.flutter_neo_shield/memory'),
        );
      });

      test('chScreenEvents decodes to Screen events channel name', () {
        expect(
          ShieldCodec.d(ShieldCodec.chScreenEvents),
          equals('com.neelakandan.flutter_neo_shield/screen_events'),
        );
      });
    });

    group('RASP method name constants', () {
      test('mCheckDebugger decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mCheckDebugger), equals('checkDebugger'));
      });

      test('mCheckRoot decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mCheckRoot), equals('checkRoot'));
      });

      test('mCheckEmulator decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mCheckEmulator), equals('checkEmulator'));
      });

      test('mCheckFrida decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mCheckFrida), equals('checkFrida'));
      });

      test('mCheckHooks decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mCheckHooks), equals('checkHooks'));
      });

      test('mCheckIntegrity decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mCheckIntegrity), equals('checkIntegrity'));
      });

      test('mCheckDeveloperMode decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mCheckDeveloperMode), equals('checkDeveloperMode'));
      });

      test('mCheckSignature decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mCheckSignature), equals('checkSignature'));
      });

      test('mGetSignatureHash decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mGetSignatureHash), equals('getSignatureHash'));
      });

      test('mCheckNativeDebug decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mCheckNativeDebug), equals('checkNativeDebug'));
      });

      test('mCheckNetworkThreats decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mCheckNetworkThreats), equals('checkNetworkThreats'));
      });
    });

    group('Screen method name constants', () {
      test('mEnableScreenProtection decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mEnableScreenProtection), equals('enableScreenProtection'));
      });

      test('mDisableScreenProtection decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mDisableScreenProtection), equals('disableScreenProtection'));
      });

      test('mIsScreenProtectionActive decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mIsScreenProtectionActive), equals('isScreenProtectionActive'));
      });

      test('mEnableAppSwitcherGuard decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mEnableAppSwitcherGuard), equals('enableAppSwitcherGuard'));
      });

      test('mDisableAppSwitcherGuard decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mDisableAppSwitcherGuard), equals('disableAppSwitcherGuard'));
      });

      test('mIsScreenBeingRecorded decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mIsScreenBeingRecorded), equals('isScreenBeingRecorded'));
      });
    });

    group('Memory method name constants', () {
      test('mAllocateSecure decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mAllocateSecure), equals('allocateSecure'));
      });

      test('mReadSecure decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mReadSecure), equals('readSecure'));
      });

      test('mWipeSecure decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mWipeSecure), equals('wipeSecure'));
      });

      test('mWipeAll decodes correctly', () {
        expect(ShieldCodec.d(ShieldCodec.mWipeAll), equals('wipeAll'));
      });
    });

    group('consistency checks', () {
      test('re-encoding decoded values produces original encoded bytes', () {
        final decoded = ShieldCodec.d(ShieldCodec.chRasp);
        final reEncoded = ShieldCodec.e(decoded);
        expect(reEncoded, equals(ShieldCodec.chRasp));
      });

      test('all RASP method constants produce unique decoded values', () {
        final methods = [
          ShieldCodec.d(ShieldCodec.mCheckDebugger),
          ShieldCodec.d(ShieldCodec.mCheckRoot),
          ShieldCodec.d(ShieldCodec.mCheckEmulator),
          ShieldCodec.d(ShieldCodec.mCheckFrida),
          ShieldCodec.d(ShieldCodec.mCheckHooks),
          ShieldCodec.d(ShieldCodec.mCheckIntegrity),
          ShieldCodec.d(ShieldCodec.mCheckDeveloperMode),
          ShieldCodec.d(ShieldCodec.mCheckSignature),
          ShieldCodec.d(ShieldCodec.mGetSignatureHash),
          ShieldCodec.d(ShieldCodec.mCheckNativeDebug),
          ShieldCodec.d(ShieldCodec.mCheckNetworkThreats),
        ];
        expect(methods.toSet().length, equals(methods.length));
      });

      test('all channel constants produce unique decoded values', () {
        final channels = [
          ShieldCodec.d(ShieldCodec.chRasp),
          ShieldCodec.d(ShieldCodec.chScreen),
          ShieldCodec.d(ShieldCodec.chMemory),
          ShieldCodec.d(ShieldCodec.chScreenEvents),
        ];
        expect(channels.toSet().length, equals(channels.length));
      });
    });
  });
}
