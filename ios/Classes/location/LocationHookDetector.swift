import Foundation
import CoreLocation
import ObjectiveC

/// Layer 3: Location API Hook Detection for iOS.
class LocationHookDetector {

    func check() -> Bool {
        return checkCLLocationPropertyHooks() ||
               checkCLLocationManagerHooks() ||
               checkInlineHooks()
    }

    /// Check if CLLocation property getters have been swizzled.
    func checkCLLocationPropertyHooks() -> Bool {
        guard let locationClass = NSClassFromString("CLLocation") else {
            return true // fail-closed
        }

        let criticalProperties = [
            "coordinate",
            "altitude",
            "horizontalAccuracy",
            "verticalAccuracy",
            "speed",
            "course",
            "timestamp",
        ]

        for property in criticalProperties {
            let getter = NSSelectorFromString(property)
            guard let method = class_getInstanceMethod(locationClass, getter) else {
                continue
            }

            let imp = method_getImplementation(method)
            var info = Dl_info()

            if dladdr(unsafeBitCast(imp, to: UnsafeRawPointer.self), &info) != 0 {
                if let fname = info.dli_fname {
                    let path = String(cString: fname)
                    if !path.contains("CoreLocation") && !path.contains("LocationSupport") {
                        return true // IMP not in CoreLocation = swizzled
                    }
                }
            }
        }

        return false
    }

    /// Check if CLLocationManager methods have been swizzled.
    func checkCLLocationManagerHooks() -> Bool {
        guard let managerClass = NSClassFromString("CLLocationManager") else {
            return true
        }

        let criticalMethods: [Selector] = [
            #selector(CLLocationManager.startUpdatingLocation),
            #selector(CLLocationManager.requestLocation),
        ]

        for selector in criticalMethods {
            guard let method = class_getInstanceMethod(managerClass, selector) else {
                continue
            }

            let imp = method_getImplementation(method)
            var info = Dl_info()

            if dladdr(unsafeBitCast(imp, to: UnsafeRawPointer.self), &info) != 0 {
                if let fname = info.dli_fname {
                    let path = String(cString: fname)
                    if !path.contains("CoreLocation") {
                        return true
                    }
                }
            }
        }

        return false
    }

    /// Check for inline hooks (ARM64 trampoline) at CLLocation.coordinate.
    func checkInlineHooks() -> Bool {
        guard let locationClass = NSClassFromString("CLLocation") else {
            return true
        }

        let selector = NSSelectorFromString("coordinate")
        guard let method = class_getInstanceMethod(locationClass, selector) else {
            return false
        }

        let imp = method_getImplementation(method)
        let funcPtr = unsafeBitCast(imp, to: UnsafePointer<UInt32>.self)

        // ARM64 trampoline: LDR X16, #8 = 0x58000050
        let firstInstr = funcPtr.pointee
        if firstInstr == 0x58000050 {
            let secondInstr = funcPtr.advanced(by: 1).pointee
            if secondInstr == 0xD61F0200 { // BR X16
                return true
            }
        }

        // Unconditional branch at entry = hook
        if (firstInstr & 0xFC000000) == 0x14000000 {
            return true
        }

        return false
    }
}
