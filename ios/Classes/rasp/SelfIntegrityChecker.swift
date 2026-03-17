import Foundation
import ObjectiveC

/// Self-integrity checker for iOS that detects if our plugin
/// has been tampered with via method swizzling, DYLD injection,
/// or suspicious framework loading.
public class SelfIntegrityChecker {

    /// Returns true if tampering is detected.
    public static func isHooked() -> Bool {
        return checkPluginSwizzling() ||
               checkDYLDInjection() ||
               checkSuspiciousClasses()
    }

    /// Check 1: Verify that the FlutterNeoShieldPlugin class (which IS
    /// an NSObject subclass via FlutterPlugin) hasn't been swizzled.
    private static func checkPluginSwizzling() -> Bool {
        guard let ownImageRange = getOwnImageRange() else {
            return true // fail-closed
        }

        // FlutterNeoShieldPlugin is an NSObject subclass (via FlutterPlugin)
        // so it has ObjC method dispatch that can be swizzled.
        guard let pluginClass = NSClassFromString("FlutterNeoShieldPlugin") else {
            return true // fail-closed: our own class not found
        }

        // Check a known instance method selector
        let sel = NSSelectorFromString("handleMethodCall:result:")
        guard let method = class_getInstanceMethod(pluginClass, sel) else {
            return false // method not found is OK (may use different selector)
        }

        let imp = method_getImplementation(method)
        let impAddr = unsafeBitCast(imp, to: UInt.self)

        if impAddr < ownImageRange.lowerBound || impAddr > ownImageRange.upperBound {
            return true
        }

        return false
    }

    /// Check 2: Verify no DYLD injection environment variables are set.
    private static func checkDYLDInjection() -> Bool {
        let env = ProcessInfo.processInfo.environment
        let dangerousVars = [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH"
        ]

        for varName in dangerousVars {
            if env[varName] != nil {
                return true
            }
        }

        return false
    }

    /// Check 3: Look for suspicious Objective-C classes that indicate
    /// hook frameworks are loaded.
    private static func checkSuspiciousClasses() -> Bool {
        let suspiciousClassNames = [
            "SubstrateHook",
            "CydiaSubstrate",
            "MSHookFunction",
            "FridaAgent",
            "FridaGadget",
            "SubstituteHook",
        ]

        for name in suspiciousClassNames {
            if objc_getClass(name) != nil {
                return true
            }
        }

        return false
    }

    /// Returns the address range of our own loaded image (Mach-O binary).
    private static func getOwnImageRange() -> ClosedRange<UInt>? {
        let selfAddr = unsafeBitCast(
            getOwnImageRange as () -> ClosedRange<UInt>?,
            to: UInt.self
        )

        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            guard let header = _dyld_get_image_header(i) else { continue }
            _ = _dyld_get_image_vmaddr_slide(i)

            let headerAddr = UInt(bitPattern: header)
            let upperBound = headerAddr + 256 * 1024 * 1024

            if selfAddr >= headerAddr && selfAddr <= upperBound {
                return headerAddr...upperBound
            }
        }

        return nil
    }
}
