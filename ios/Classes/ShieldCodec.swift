import Foundation

/// Anti-reverse-engineering codec for method channel communication.
///
/// Encodes channel names, method names, and detection messages so they
/// do not appear as searchable plaintext strings in compiled binaries.
///
/// Uses XOR encoding with a derived key.
struct ShieldCodec {
    private init() {}

    // Key derived from arithmetic — does not appear as a literal constant.
    private static let _k: [Int] = [
        0x32 + 0x1C, // 78
        0x41 + 0x12, // 83
        0x24 + 0x24, // 72
        0x3E + 0x0E, // 76
        0x22 + 0x22, // 68
    ]

    /// Decodes an XOR-encoded int array back to a `String`.
    static func decode(_ encoded: [Int]) -> String {
        let chars = encoded.enumerated().map { i, v in
            Character(UnicodeScalar(v ^ _k[i % _k.length])!)
        }
        return String(chars)
    }

    // -------------------------------------------------------------------------
    // Pre-decoded channel names (cached as static let)
    // -------------------------------------------------------------------------

    /// `com.neelakandan.flutter_neo_shield/rasp`
    static let chRasp = decode([45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 60, 50, 59, 60])

    /// `com.neelakandan.flutter_neo_shield/screen`
    static let chScreen = decode([45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 61, 48, 58, 41, 33, 32])

    /// `com.neelakandan.flutter_neo_shield/memory`
    static let chMemory = decode([45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 35, 54, 37, 35, 54, 55])

    /// `com.neelakandan.flutter_neo_shield/screen_events`
    static let chScreenEvents = decode([45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 61, 48, 58, 41, 33, 32, 12, 45, 58, 33, 32, 39, 59])

    // -------------------------------------------------------------------------
    // Pre-decoded RASP method names
    // -------------------------------------------------------------------------

    /// `checkDebugger`
    static let mCheckDebugger = decode([45, 59, 45, 47, 47, 10, 54, 42, 57, 35, 41, 54, 58])

    /// `checkRoot`
    static let mCheckRoot = decode([45, 59, 45, 47, 47, 28, 60, 39, 56])

    /// `checkEmulator`
    static let mCheckEmulator = decode([45, 59, 45, 47, 47, 11, 62, 61, 32, 37, 58, 60, 58])

    /// `checkFrida`
    static let mCheckFrida = decode([45, 59, 45, 47, 47, 8, 33, 33, 40, 37])

    /// `checkHooks`
    static let mCheckHooks = decode([45, 59, 45, 47, 47, 6, 60, 39, 39, 55])

    /// `checkIntegrity`
    static let mCheckIntegrity = decode([45, 59, 45, 47, 47, 7, 61, 60, 41, 35, 60, 58, 60, 53])

    /// `checkDeveloperMode`
    static let mCheckDeveloperMode = decode([45, 59, 45, 47, 47, 10, 54, 62, 41, 40, 33, 35, 45, 62, 9, 33, 55, 45])

    /// `checkSignature`
    static let mCheckSignature = decode([45, 59, 45, 47, 47, 29, 58, 47, 34, 37, 58, 38, 58, 41])

    /// `getSignatureHash`
    static let mGetSignatureHash = decode([41, 54, 60, 31, 45, 41, 61, 41, 56, 49, 60, 54, 0, 45, 55, 38])

    /// `checkNativeDebug`
    static let mCheckNativeDebug = decode([45, 59, 45, 47, 47, 0, 50, 60, 37, 50, 43, 23, 45, 46, 49, 41])

    /// `checkNetworkThreats`
    static let mCheckNetworkThreats = decode([45, 59, 45, 47, 47, 0, 54, 60, 59, 43, 60, 56, 28, 36, 54, 43, 50, 60, 63])

    // -------------------------------------------------------------------------
    // Pre-decoded Screen method names
    // -------------------------------------------------------------------------

    /// `enableScreenProtection`
    static let mEnableScreenProtection = decode([43, 61, 41, 46, 40, 43, 0, 43, 62, 33, 43, 61, 24, 62, 43, 58, 54, 43, 56, 45, 33, 61])

    /// `disableScreenProtection`
    static let mDisableScreenProtection = decode([42, 58, 59, 45, 38, 34, 54, 27, 47, 54, 43, 54, 38, 28, 54, 33, 39, 45, 47, 48, 39, 60, 38])

    /// `isScreenProtectionActive`
    static let mIsScreenProtectionActive = decode([39, 32, 27, 47, 54, 43, 54, 38, 28, 54, 33, 39, 45, 47, 48, 39, 60, 38, 13, 39, 58, 58, 62, 41])

    /// `enableAppSwitcherGuard`
    static let mEnableAppSwitcherGuard = decode([43, 61, 41, 46, 40, 43, 18, 56, 60, 23, 57, 58, 60, 47, 44, 43, 33, 15, 57, 37, 60, 55])

    /// `disableAppSwitcherGuard`
    static let mDisableAppSwitcherGuard = decode([42, 58, 59, 45, 38, 34, 54, 9, 60, 52, 29, 36, 33, 56, 39, 38, 54, 58, 11, 49, 47, 33, 44])

    /// `isScreenBeingRecorded`
    static let mIsScreenBeingRecorded = decode([39, 32, 27, 47, 54, 43, 54, 38, 14, 33, 39, 61, 47, 30, 33, 45, 60, 58, 40, 33, 42])

    // -------------------------------------------------------------------------
    // Pre-decoded Memory method names
    // -------------------------------------------------------------------------

    /// `allocateSecure`
    static let mAllocateSecure = decode([47, 63, 36, 35, 39, 47, 39, 45, 31, 33, 45, 38, 58, 41])

    /// `readSecure`
    static let mReadSecure = decode([60, 54, 41, 40, 23, 43, 48, 61, 62, 33])

    /// `wipeSecure`
    static let mWipeSecure = decode([57, 58, 56, 41, 23, 43, 48, 61, 62, 33])

    /// `wipeAll`
    static let mWipeAll = decode([57, 58, 56, 41, 5, 34, 63])

    // -------------------------------------------------------------------------
    // Pre-decoded Location method names
    // -------------------------------------------------------------------------

    /// `com.neelakandan.flutter_neo_shield/location`
    static let chLocation = decode([45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 34, 60, 43, 45, 48, 39, 60, 38])

    /// `com.neelakandan.flutter_neo_shield/location_events`
    static let chLocationEvents = decode([45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 34, 60, 43, 45, 48, 39, 60, 38, 19, 33, 56, 54, 38, 56, 55])

    /// `checkFakeLocation`
    static let mCheckFakeLocation = decode([45, 59, 45, 47, 47, 8, 50, 35, 41, 8, 33, 48, 41, 56, 45, 33, 61])

    /// `checkMockProvider`
    static let mCheckMockProvider = decode([45, 59, 45, 47, 47, 3, 60, 43, 39, 20, 60, 60, 62, 45, 32, 43, 33])

    /// `checkSpoofingApps`
    static let mCheckSpoofingApps = decode([45, 59, 45, 47, 47, 29, 35, 39, 35, 34, 39, 61, 47, 13, 52, 62, 32])

    /// `checkLocationHooks`
    static let mCheckLocationHooks = decode([45, 59, 45, 47, 47, 2, 60, 43, 45, 48, 39, 60, 38, 4, 43, 33, 56, 59])

    /// `checkGpsAnomaly`
    static let mCheckGpsAnomaly = decode([45, 59, 45, 47, 47, 9, 35, 59, 13, 42, 33, 62, 41, 32, 61])

    /// `checkSensorFusion`
    static let mCheckSensorFusion = decode([45, 59, 45, 47, 47, 29, 54, 38, 63, 43, 60, 21, 61, 63, 45, 33, 61])

    /// `checkTemporalAnomaly`
    static let mCheckTemporalAnomaly = decode([45, 59, 45, 47, 47, 26, 54, 37, 60, 43, 60, 50, 36, 13, 42, 33, 62, 41, 32, 61])
}

// Swift Array doesn't have .length — provide it via extension for parity with Dart.
private extension Array {
    var length: Int { count }
}
