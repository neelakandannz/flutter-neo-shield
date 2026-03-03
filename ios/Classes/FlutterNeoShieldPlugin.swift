import Flutter
import UIKit

/// FlutterNeoShieldPlugin — iOS platform implementation.
///
/// Provides native memory allocation and secure wipe operations
/// for the Memory Shield module.
public class FlutterNeoShieldPlugin: NSObject, FlutterPlugin {
    private var secureStorage: [String: Data] = [:]

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "com.neelakandan.flutter_neo_shield/memory",
            binaryMessenger: registrar.messenger()
        )
        let instance = FlutterNeoShieldPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any] else {
            if call.method == "wipeAll" {
                wipeAll()
                result(nil)
                return
            }
            result(FlutterError(code: "INVALID_ARGS", message: "Arguments required", details: nil))
            return
        }

        switch call.method {
        case "allocateSecure":
            guard let id = args["id"] as? String,
                  let data = args["data"] as? FlutterStandardTypedData else {
                result(FlutterError(code: "INVALID_ARGS", message: "id and data required", details: nil))
                return
            }
            secureStorage[id] = Data(data.data)
            result(nil)

        case "readSecure":
            guard let id = args["id"] as? String,
                  let data = secureStorage[id] else {
                result(FlutterError(code: "NOT_FOUND", message: "No secure data found", details: nil))
                return
            }
            result(FlutterStandardTypedData(bytes: data))

        case "wipeSecure":
            guard let id = args["id"] as? String else {
                result(nil)
                return
            }
            if var data = secureStorage[id] {
                data.resetBytes(in: 0..<data.count)
                secureStorage.removeValue(forKey: id)
            }
            result(nil)

        case "wipeAll":
            wipeAll()
            result(nil)

        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func wipeAll() {
        for key in secureStorage.keys {
            if var data = secureStorage[key] {
                data.resetBytes(in: 0..<data.count)
            }
        }
        secureStorage.removeAll()
    }
}
