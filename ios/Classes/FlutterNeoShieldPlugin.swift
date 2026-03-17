import Flutter
import UIKit

/// FlutterNeoShieldPlugin — iOS platform implementation.
///
/// Provides native memory allocation, secure wipe operations,
/// RASP checks, and screen protection.
public class FlutterNeoShieldPlugin: NSObject, FlutterPlugin {
    private var secureStorage: [String: Data] = [:]

    // Screen Shield
    private let screenProtector = ScreenProtector()
    private let screenshotDetector = ScreenshotDetector()
    private let recordingDetector = ScreenRecordingDetector()
    private let appSwitcherGuard = AppSwitcherGuard()
    private var screenEventSink: FlutterEventSink?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let memoryChannel = FlutterMethodChannel(
            name: ShieldCodec.chMemory,
            binaryMessenger: registrar.messenger()
        )
        let raspChannel = FlutterMethodChannel(
            name: ShieldCodec.chRasp,
            binaryMessenger: registrar.messenger()
        )
        let screenChannel = FlutterMethodChannel(
            name: ShieldCodec.chScreen,
            binaryMessenger: registrar.messenger()
        )
        let screenEventChannel = FlutterEventChannel(
            name: ShieldCodec.chScreenEvents,
            binaryMessenger: registrar.messenger()
        )

        let instance = FlutterNeoShieldPlugin()
        registrar.addMethodCallDelegate(instance, channel: memoryChannel)
        registrar.addMethodCallDelegate(instance, channel: raspChannel)
        registrar.addMethodCallDelegate(instance, channel: screenChannel)
        screenEventChannel.setStreamHandler(instance)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        // Allow methods that don't require arguments
        let args = call.arguments as? [String: Any]
        let method = call.method

        // Memory Shield
        if method == ShieldCodec.mAllocateSecure {
            guard let args = args,
                  let id = args["id"] as? String,
                  let data = args["data"] as? FlutterStandardTypedData else {
                result(FlutterError(code: "INVALID_ARGS", message: "id and data required", details: nil))
                return
            }
            secureStorage[id] = Data(data.data)
            result(nil)
        } else if method == ShieldCodec.mReadSecure {
            guard let args = args,
                  let id = args["id"] as? String,
                  let data = secureStorage[id] else {
                result(FlutterError(code: "NOT_FOUND", message: "No secure data found", details: nil))
                return
            }
            result(FlutterStandardTypedData(bytes: data))
        } else if method == ShieldCodec.mWipeSecure {
            let id = args?["id"] as? String
            if let id = id, let count = secureStorage[id]?.count, count > 0 {
                secureStorage[id]?.resetBytes(in: 0..<count)
                secureStorage.removeValue(forKey: id)
            }
            result(nil)
        } else if method == ShieldCodec.mWipeAll {
            wipeAll()
            result(nil)

        // RASP Shield — all boolean results wrapped through validateResult()
        // for self-integrity and cross-detector validation.
        } else if method == ShieldCodec.mCheckDebugger {
            result(validateResult(DebuggerDetector.check()))
        } else if method == ShieldCodec.mCheckRoot {
            result(validateRootResult(JailbreakDetector.check()))
        } else if method == ShieldCodec.mCheckEmulator {
            result(validateResult(EmulatorDetector.check()))
        } else if method == ShieldCodec.mCheckHooks {
            result(validateResult(HookDetector.check()))
        } else if method == ShieldCodec.mCheckFrida {
            result(validateResult(FridaDetector.check()))
        } else if method == ShieldCodec.mCheckIntegrity {
            result(validateResult(IntegrityDetector.check()))
        } else if method == ShieldCodec.mCheckDeveloperMode {
            result(validateResult(DeveloperModeDetector.check()))
        } else if method == ShieldCodec.mCheckSignature {
            result(validateResult(SignatureDetectorP0.check()))
        } else if method == ShieldCodec.mGetSignatureHash {
            // iOS doesn't expose signing certificate hash the same way Android does.
            // Return nil — the developer should use Android for hash retrieval.
            result(nil)
        } else if method == ShieldCodec.mCheckNativeDebug {
            result(validateResult(NativeDebugDetector.check()))
        } else if method == ShieldCodec.mCheckNetworkThreats {
            result(validateResult(NetworkThreatDetector.checkSimple()))

        // Screen Shield
        } else if method == ShieldCodec.mEnableScreenProtection {
            result(screenProtector.enable(in: getKeyWindow()))
        } else if method == ShieldCodec.mDisableScreenProtection {
            result(screenProtector.disable())
        } else if method == ShieldCodec.mIsScreenProtectionActive {
            result(screenProtector.isActive)
        } else if method == ShieldCodec.mEnableAppSwitcherGuard {
            appSwitcherGuard.enable(in: getKeyWindow())
            result(true)
        } else if method == ShieldCodec.mDisableAppSwitcherGuard {
            appSwitcherGuard.disable()
            result(true)
        } else if method == ShieldCodec.mIsScreenBeingRecorded {
            result(recordingDetector.isRecording)
        } else {
            result(FlutterMethodNotImplemented)
        }
    }

    /// Cross-validates a RASP detection result with the self-integrity checker.
    ///
    /// If the detector returned false (not detected) but our own code has been
    /// hooked, we override to true (detected) — because the "false" result
    /// cannot be trusted if the detection code itself is compromised.
    private func validateResult(_ detected: Bool) -> Bool {
        if detected { return true }
        if SelfIntegrityChecker.isHooked() { return true }
        return false
    }

    /// Cross-detector validation for jailbreak: if root returns false but
    /// hooks are detected, flag root as suspicious (hook frameworks hide jailbreak).
    private func validateRootResult(_ rootDetected: Bool) -> Bool {
        if rootDetected { return true }
        if HookDetector.check() { return true }
        return validateResult(rootDetected)
    }

    /// Returns the key window, using the modern UIWindowScene API on iOS 15+
    /// and falling back to the deprecated UIApplication.shared.windows otherwise.
    private func getKeyWindow() -> UIWindow? {
        if #available(iOS 15.0, *) {
            return UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap { $0.windows }
                .first { $0.isKeyWindow }
        } else {
            return UIApplication.shared.windows.first { $0.isKeyWindow }
                ?? UIApplication.shared.windows.first
        }
    }

    private func wipeAll() {
        for key in secureStorage.keys {
            if let count = secureStorage[key]?.count, count > 0 {
                secureStorage[key]?.resetBytes(in: 0..<count)
            }
        }
        secureStorage.removeAll()
    }

    /// Set up screenshot and recording detection, sending events to the Dart side.
    private func startDetection() {
        screenshotDetector.startDetecting { [weak self] in
            self?.screenEventSink?(["type": "screenshot"])
        }
        recordingDetector.startDetecting { [weak self] isCaptured in
            self?.screenEventSink?(["type": "recording", "isRecording": isCaptured])
        }
    }

    private func stopDetection() {
        screenshotDetector.stopDetecting()
        recordingDetector.stopDetecting()
    }
}

// MARK: - FlutterStreamHandler for Screen Events
extension FlutterNeoShieldPlugin: FlutterStreamHandler {
    public func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        screenEventSink = events
        startDetection()
        return nil
    }

    public func onCancel(withArguments arguments: Any?) -> FlutterError? {
        screenEventSink = nil
        stopDetection()
        return nil
    }
}
