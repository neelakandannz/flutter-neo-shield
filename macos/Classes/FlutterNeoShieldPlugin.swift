import Cocoa
import FlutterMacOS

/// FlutterNeoShieldPlugin — macOS platform implementation.
///
/// Provides native memory allocation, secure wipe operations,
/// RASP checks, and screen protection for macOS.
public class FlutterNeoShieldPlugin: NSObject, FlutterPlugin {
    private var secureStorage: [String: Data] = [:]

    // Screen Shield
    private let screenProtector = ScreenProtector()
    private let screenRecordingDetector = ScreenRecordingDetector()
    private var screenEventSink: FlutterEventSink?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let memoryChannel = FlutterMethodChannel(
            name: ShieldCodec.chMemory,
            binaryMessenger: registrar.messenger
        )
        let raspChannel = FlutterMethodChannel(
            name: ShieldCodec.chRasp,
            binaryMessenger: registrar.messenger
        )
        let screenChannel = FlutterMethodChannel(
            name: ShieldCodec.chScreen,
            binaryMessenger: registrar.messenger
        )
        let screenEventChannel = FlutterEventChannel(
            name: ShieldCodec.chScreenEvents,
            binaryMessenger: registrar.messenger
        )

        let instance = FlutterNeoShieldPlugin()
        registrar.addMethodCallDelegate(instance, channel: memoryChannel)
        registrar.addMethodCallDelegate(instance, channel: raspChannel)
        registrar.addMethodCallDelegate(instance, channel: screenChannel)
        screenEventChannel.setStreamHandler(instance)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = call.arguments as? [String: Any]

        switch call.method {
        // Memory Shield
        case ShieldCodec.mAllocateSecure:
            guard let args = args,
                  let id = args["id"] as? String,
                  let data = args["data"] as? FlutterStandardTypedData else {
                result(FlutterError(code: "INVALID_ARGS", message: "id and data required", details: nil))
                return
            }
            secureStorage[id] = Data(data.data)
            result(nil)

        case ShieldCodec.mReadSecure:
            guard let args = args,
                  let id = args["id"] as? String,
                  let data = secureStorage[id] else {
                result(FlutterError(code: "NOT_FOUND", message: "No secure data found", details: nil))
                return
            }
            result(FlutterStandardTypedData(bytes: data))

        case ShieldCodec.mWipeSecure:
            let id = args?["id"] as? String
            if let id = id, let count = secureStorage[id]?.count, count > 0 {
                secureStorage[id]?.resetBytes(in: 0..<count)
                secureStorage.removeValue(forKey: id)
            }
            result(nil)

        case ShieldCodec.mWipeAll:
            wipeAll()
            result(nil)

        // RASP Shield
        case ShieldCodec.mCheckDebugger:
            result(DebuggerDetector.check())

        case ShieldCodec.mCheckRoot:
            result(SIPDetector.check())

        case ShieldCodec.mCheckEmulator:
            result(VMDetector.check())

        case ShieldCodec.mCheckHooks:
            result(HookDetector.check())

        case ShieldCodec.mCheckFrida:
            result(FridaDetector.check())

        case ShieldCodec.mCheckIntegrity:
            result(IntegrityDetector.check())

        case ShieldCodec.mCheckDeveloperMode:
            result(DeveloperModeDetector.check())

        case ShieldCodec.mCheckSignature:
            result(SignatureDetector.check())

        case ShieldCodec.mGetSignatureHash:
            result(nil)

        case ShieldCodec.mCheckNativeDebug:
            result(NativeDebugDetector.check())

        case ShieldCodec.mCheckNetworkThreats:
            result(NetworkThreatDetector.checkSimple())

        // Screen Shield
        case ShieldCodec.mEnableScreenProtection:
            result(screenProtector.enable())

        case ShieldCodec.mDisableScreenProtection:
            result(screenProtector.disable())

        case ShieldCodec.mIsScreenProtectionActive:
            result(screenProtector.isActive)

        case ShieldCodec.mEnableAppSwitcherGuard:
            // macOS doesn't have an app switcher like iOS
            // but we can hide window content on deactivation
            result(false)

        case ShieldCodec.mDisableAppSwitcherGuard:
            result(false)

        case ShieldCodec.mIsScreenBeingRecorded:
            result(screenRecordingDetector.isRecording)

        default:
            result(FlutterMethodNotImplemented)
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

    private func startDetection() {
        screenRecordingDetector.startDetecting { [weak self] isRecording in
            self?.screenEventSink?(["type": "recording", "isRecording": isRecording])
        }
    }

    private func stopDetection() {
        screenRecordingDetector.stopDetecting()
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
