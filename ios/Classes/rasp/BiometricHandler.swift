import LocalAuthentication
class BiometricHandler {
    static func checkAvailability() -> [String: Any] {
        let ctx = LAContext(); var error: NSError?
        let can = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        var types: [String] = []
        if #available(iOS 11.0, *) {
            switch ctx.biometryType {
            case .faceID: types.append("faceID")
            case .touchID: types.append("touchID")
            case .opticID: types.append("opticID")
            default: break
            }
        }
        return ["available": can, "types": types, "canAuth": can]
    }
    static func authenticate(reason: String, allowDeviceCredential: Bool, completion: @escaping ([String: Any]) -> Void) {
        let ctx = LAContext()
        let policy: LAPolicy = allowDeviceCredential ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics
        ctx.evaluatePolicy(policy, localizedReason: reason) { success, error in
            DispatchQueue.main.async {
                completion(success ? ["success": true] : ["success": false, "error": error?.localizedDescription ?? "Failed"])
            }
        }
    }
}
