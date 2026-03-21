import AVFoundation
import CoreLocation
class PermissionDetector {
    static func isCameraInUse() -> Bool { return AVCaptureDevice.authorizationStatus(for: .video) == .authorized }
    static func isMicrophoneInUse() -> Bool { return AVCaptureDevice.authorizationStatus(for: .audio) == .authorized }
    static func isLocationAccessedInBackground() -> Bool { return CLLocationManager.authorizationStatus() == .authorizedAlways }
}
