import AVFoundation
class PermissionDetector {
    static func isCameraInUse() -> Bool { return AVCaptureDevice.authorizationStatus(for: .video) == .authorized }
    static func isMicrophoneInUse() -> Bool { return AVCaptureDevice.authorizationStatus(for: .audio) == .authorized }
    static func isLocationAccessedInBackground() -> Bool { return false }
}
