import Foundation
import MachO

/// Layer 2: Spoofing App/Tweak Detection for iOS.
class SpoofingAppDetector {

    var detectedTweakNames: [String] = []

    /// Check for jailbreak location tweak dylibs loaded in process.
    func checkLocationTweakDylibs() -> Double {
        var score: Double = 0.0
        detectedTweakNames = []

        let suspiciousDylibs = [
            "LocationFaker",
            "akLocationX",
            "Relocate",
            "LocationHandle",
            "GPSCheat",
            "LocationSimulator",
            "FakeLocation",
            "LibSandy",
            "LocationFixer",
            "NTSpeed",
        ]

        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                for tweak in suspiciousDylibs {
                    if name.localizedCaseInsensitiveContains(tweak) {
                        score += 0.9
                        detectedTweakNames.append(tweak)
                    }
                }
            }
        }

        return min(score, 1.0)
    }

    /// Check filesystem for known spoofing tool artifacts.
    func checkSpoofingToolPaths() -> Double {
        var score: Double = 0.0

        let suspiciousPaths = [
            "/Library/MobileSubstrate/DynamicLibraries/LocationFaker.dylib",
            "/Library/MobileSubstrate/DynamicLibraries/akLocationX.dylib",
            "/usr/lib/Relocate.dylib",
            "/Library/PreferenceBundles/LocationFakerPrefs.bundle",
            "/var/mobile/Library/Preferences/com.xdadevelopers.locationfaker.plist",
            "/Library/MobileSubstrate/DynamicLibraries/GPSCheat.dylib",
            "/Library/MobileSubstrate/DynamicLibraries/LocationHandle.dylib",
        ]

        for path in suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) {
                score += 0.9
                detectedTweakNames.append(path.components(separatedBy: "/").last ?? path)
            }
        }

        return min(score, 1.0)
    }

    /// Check for location-related URL schemes.
    func checkSpoofingURLSchemes() -> Double {
        // On iOS, can't check for arbitrary URL schemes without declaring them
        return 0.0
    }
}
