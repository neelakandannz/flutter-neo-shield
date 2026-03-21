/// Anti-reverse-engineering codec for method channel communication.
///
/// Encodes channel names, method names, and detection messages so they
/// do not appear as searchable plaintext strings in compiled binaries.
///
/// Uses XOR encoding with a derived key. The key is constructed from
/// arithmetic operations to avoid appearing as a literal constant.
class ShieldCodec {
  ShieldCodec._();

  // Key derived from arithmetic — does not appear as a literal string.
  // ignore: prefer_final_fields
  static final List<int> _k = [
    0x32 + 0x1C, // 78
    0x41 + 0x12, // 83
    0x24 + 0x24, // 72
    0x3E + 0x0E, // 76
    0x22 + 0x22, // 68
  ];

  /// Decodes an XOR-encoded byte list back to a [String].
  static String d(List<int> encoded) {
    return String.fromCharCodes(
      List<int>.generate(
          encoded.length, (i) => encoded[i] ^ _k[i % _k.length]),
    );
  }

  /// Encodes a plaintext [String] to an XOR-encoded byte list.
  ///
  /// Used only for generating constants and in tests.
  static List<int> e(String plain) {
    final bytes = plain.codeUnits;
    return List<int>.generate(
        bytes.length, (i) => bytes[i] ^ _k[i % _k.length]);
  }

  // ---------------------------------------------------------------------------
  // Pre-encoded channel names
  // ---------------------------------------------------------------------------

  /// `com.neelakandan.flutter_neo_shield/rasp`
  static const chRasp = [45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 60, 50, 59, 60];

  /// `com.neelakandan.flutter_neo_shield/screen`
  static const chScreen = [45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 61, 48, 58, 41, 33, 32];

  /// `com.neelakandan.flutter_neo_shield/memory`
  static const chMemory = [45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 35, 54, 37, 35, 54, 55];

  /// `com.neelakandan.flutter_neo_shield/screen_events`
  static const chScreenEvents = [45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 61, 48, 58, 41, 33, 32, 12, 45, 58, 33, 32, 39, 59];

  // ---------------------------------------------------------------------------
  // Pre-encoded RASP method names
  // ---------------------------------------------------------------------------

  /// `checkDebugger`
  static const mCheckDebugger = [45, 59, 45, 47, 47, 10, 54, 42, 57, 35, 41, 54, 58];

  /// `checkRoot`
  static const mCheckRoot = [45, 59, 45, 47, 47, 28, 60, 39, 56];

  /// `checkEmulator`
  static const mCheckEmulator = [45, 59, 45, 47, 47, 11, 62, 61, 32, 37, 58, 60, 58];

  /// `checkFrida`
  static const mCheckFrida = [45, 59, 45, 47, 47, 8, 33, 33, 40, 37];

  /// `checkHooks`
  static const mCheckHooks = [45, 59, 45, 47, 47, 6, 60, 39, 39, 55];

  /// `checkIntegrity`
  static const mCheckIntegrity = [45, 59, 45, 47, 47, 7, 61, 60, 41, 35, 60, 58, 60, 53];

  /// `checkDeveloperMode`
  static const mCheckDeveloperMode = [45, 59, 45, 47, 47, 10, 54, 62, 41, 40, 33, 35, 45, 62, 9, 33, 55, 45];

  /// `checkSignature`
  static const mCheckSignature = [45, 59, 45, 47, 47, 29, 58, 47, 34, 37, 58, 38, 58, 41];

  /// `getSignatureHash`
  static const mGetSignatureHash = [41, 54, 60, 31, 45, 41, 61, 41, 56, 49, 60, 54, 0, 45, 55, 38];

  /// `checkNativeDebug`
  static const mCheckNativeDebug = [45, 59, 45, 47, 47, 0, 50, 60, 37, 50, 43, 23, 45, 46, 49, 41];

  /// `checkNetworkThreats`
  static const mCheckNetworkThreats = [45, 59, 45, 47, 47, 0, 54, 60, 59, 43, 60, 56, 28, 36, 54, 43, 50, 60, 63];

  // ---------------------------------------------------------------------------
  // Pre-encoded Screen method names
  // ---------------------------------------------------------------------------

  /// `enableScreenProtection`
  static const mEnableScreenProtection = [43, 61, 41, 46, 40, 43, 0, 43, 62, 33, 43, 61, 24, 62, 43, 58, 54, 43, 56, 45, 33, 61];

  /// `disableScreenProtection`
  static const mDisableScreenProtection = [42, 58, 59, 45, 38, 34, 54, 27, 47, 54, 43, 54, 38, 28, 54, 33, 39, 45, 47, 48, 39, 60, 38];

  /// `isScreenProtectionActive`
  static const mIsScreenProtectionActive = [39, 32, 27, 47, 54, 43, 54, 38, 28, 54, 33, 39, 45, 47, 48, 39, 60, 38, 13, 39, 58, 58, 62, 41];

  /// `enableAppSwitcherGuard`
  static const mEnableAppSwitcherGuard = [43, 61, 41, 46, 40, 43, 18, 56, 60, 23, 57, 58, 60, 47, 44, 43, 33, 15, 57, 37, 60, 55];

  /// `disableAppSwitcherGuard`
  static const mDisableAppSwitcherGuard = [42, 58, 59, 45, 38, 34, 54, 9, 60, 52, 29, 36, 33, 56, 39, 38, 54, 58, 11, 49, 47, 33, 44];

  /// `isScreenBeingRecorded`
  static const mIsScreenBeingRecorded = [39, 32, 27, 47, 54, 43, 54, 38, 14, 33, 39, 61, 47, 30, 33, 45, 60, 58, 40, 33, 42];

  // ---------------------------------------------------------------------------
  // Pre-encoded Memory method names
  // ---------------------------------------------------------------------------

  /// `allocateSecure`
  static const mAllocateSecure = [47, 63, 36, 35, 39, 47, 39, 45, 31, 33, 45, 38, 58, 41];

  /// `readSecure`
  static const mReadSecure = [60, 54, 41, 40, 23, 43, 48, 61, 62, 33];

  /// `wipeSecure`
  static const mWipeSecure = [57, 58, 56, 41, 23, 43, 48, 61, 62, 33];

  /// `wipeAll`
  static const mWipeAll = [57, 58, 56, 41, 5, 34, 63];

  // ---------------------------------------------------------------------------
  // Pre-encoded Location method names
  // ---------------------------------------------------------------------------

  /// `com.neelakandan.flutter_neo_shield/location`
  static const chLocation = [45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 34, 60, 43, 45, 48, 39, 60, 38];

  /// `com.neelakandan.flutter_neo_shield/location_events`
  static const chLocationEvents = [45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 34, 60, 43, 45, 48, 39, 60, 38, 19, 33, 56, 54, 38, 56, 55];

  /// `checkFakeLocation`
  static const mCheckFakeLocation = [45, 59, 45, 47, 47, 8, 50, 35, 41, 8, 33, 48, 41, 56, 45, 33, 61];

  /// `checkMockProvider`
  static const mCheckMockProvider = [45, 59, 45, 47, 47, 3, 60, 43, 39, 20, 60, 60, 62, 45, 32, 43, 33];

  /// `checkSpoofingApps`
  static const mCheckSpoofingApps = [45, 59, 45, 47, 47, 29, 35, 39, 35, 34, 39, 61, 47, 13, 52, 62, 32];

  /// `checkLocationHooks`
  static const mCheckLocationHooks = [45, 59, 45, 47, 47, 2, 60, 43, 45, 48, 39, 60, 38, 4, 43, 33, 56, 59];

  /// `checkGpsAnomaly`
  static const mCheckGpsAnomaly = [45, 59, 45, 47, 47, 9, 35, 59, 13, 42, 33, 62, 41, 32, 61];

  /// `checkSensorFusion`
  static const mCheckSensorFusion = [45, 59, 45, 47, 47, 29, 54, 38, 63, 43, 60, 21, 61, 63, 45, 33, 61];

  /// `checkTemporalAnomaly`
  static const mCheckTemporalAnomaly = [45, 59, 45, 47, 47, 26, 54, 37, 60, 43, 60, 50, 36, 13, 42, 33, 62, 41, 32, 61];

  // ---------------------------------------------------------------------------
  // Pre-encoded new channel names (v2.0.0)
  // ---------------------------------------------------------------------------

  /// `com.neelakandan.flutter_neo_shield/secure_storage`
  static const chSecureStorage = [45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 61, 54, 43, 57, 54, 43, 12, 59, 56, 43, 60, 50, 47, 41];

  /// `com.neelakandan.flutter_neo_shield/biometric`
  static const chBiometric = [45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 44, 58, 39, 33, 33, 58, 33, 33, 47];

  /// `com.neelakandan.flutter_neo_shield/device_binding`
  static const chDeviceBinding = [45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 42, 54, 62, 37, 39, 43, 12, 42, 37, 42, 42, 58, 38, 43];

  // ---------------------------------------------------------------------------
  // Pre-encoded new RASP method names (v2.0.0)
  // ---------------------------------------------------------------------------

  /// `enableOverlayProtection`
  static const mEnableOverlayProtection = [43, 61, 41, 46, 40, 43, 28, 62, 41, 54, 34, 50, 49, 28, 54, 33, 39, 45, 47, 48, 39, 60, 38];

  /// `disableOverlayProtection`
  static const mDisableOverlayProtection = [42, 58, 59, 45, 38, 34, 54, 7, 58, 33, 60, 63, 41, 53, 20, 60, 60, 60, 41, 39, 58, 58, 39, 34];

  /// `checkOverlay`
  static const mCheckOverlay = [45, 59, 45, 47, 47, 1, 37, 45, 62, 40, 47, 42];

  /// `checkClickjacking`
  static const mCheckClickjacking = [45, 59, 45, 47, 47, 13, 63, 33, 47, 47, 36, 50, 43, 39, 45, 32, 52];

  /// `checkAccessibility`
  static const mCheckAccessibility = [45, 59, 45, 47, 47, 15, 48, 43, 41, 55, 61, 58, 42, 37, 40, 39, 39, 49];

  /// `getAccessibilityServices`
  static const mGetAccessibilityServices = [41, 54, 60, 13, 39, 45, 54, 59, 63, 45, 44, 58, 36, 37, 48, 55, 0, 45, 62, 50, 39, 48, 45, 63];

  /// `checkScreenReader`
  static const mCheckScreenReader = [45, 59, 45, 47, 47, 29, 48, 58, 41, 33, 32, 1, 45, 45, 32, 43, 33];

  /// `checkKeyboard`
  static const mCheckKeyboard = [45, 59, 45, 47, 47, 5, 54, 49, 46, 43, 47, 33, 44];

  /// `getKeyboardPackage`
  static const mGetKeyboardPackage = [41, 54, 60, 7, 33, 55, 49, 39, 45, 54, 42, 3, 41, 47, 47, 47, 52, 45];

  /// `checkKeylogger`
  static const mCheckKeylogger = [45, 59, 45, 47, 47, 5, 54, 49, 32, 43, 41, 52, 45, 62];

  /// `checkCodeInjection`
  static const mCheckCodeInjection = [45, 59, 45, 47, 47, 13, 60, 44, 41, 13, 32, 57, 45, 47, 48, 39, 60, 38];

  /// `getSuspiciousModules`
  static const mGetSuspiciousModules = [41, 54, 60, 31, 49, 61, 35, 33, 47, 45, 33, 38, 59, 1, 43, 42, 38, 36, 41, 55];

  /// `checkObfuscation`
  static const mCheckObfuscation = [45, 59, 45, 47, 47, 1, 49, 46, 57, 55, 45, 50, 60, 37, 43, 32];

  /// `checkCameraInUse`
  static const mCheckCameraInUse = [45, 59, 45, 47, 47, 13, 50, 37, 41, 54, 47, 26, 38, 25, 55, 43];

  /// `checkMicInUse`
  static const mCheckMicInUse = [45, 59, 45, 47, 47, 3, 58, 43, 5, 42, 27, 32, 45];

  /// `checkBgLocation`
  static const mCheckBgLocation = [45, 59, 45, 47, 47, 12, 52, 4, 35, 39, 47, 39, 33, 35, 42];
}
