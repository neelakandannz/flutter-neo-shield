import Foundation
import CoreLocation
import ObjectiveC

/// Layer 3: Location Hook Detection for macOS.
class LocationHookDetector {
    func check() -> Bool {
        return checkCLLocationPropertyHooks() || checkCLLocationManagerHooks()
    }

    private func checkCLLocationPropertyHooks() -> Bool {
        guard let locationClass = NSClassFromString("CLLocation") else {
            return true
        }

        let properties = ["coordinate", "altitude", "horizontalAccuracy", "speed", "course"]

        for property in properties {
            let getter = NSSelectorFromString(property)
            guard let method = class_getInstanceMethod(locationClass, getter) else { continue }

            let imp = method_getImplementation(method)
            var info = Dl_info()

            if dladdr(unsafeBitCast(imp, to: UnsafeRawPointer.self), &info) != 0 {
                if let fname = info.dli_fname {
                    let path = String(cString: fname)
                    if !path.contains("CoreLocation") && !path.contains("LocationSupport") {
                        return true
                    }
                }
            }
        }
        return false
    }

    private func checkCLLocationManagerHooks() -> Bool {
        guard let managerClass = NSClassFromString("CLLocationManager") else {
            return true
        }

        let selectors: [Selector] = [
            #selector(CLLocationManager.startUpdatingLocation),
        ]

        for selector in selectors {
            guard let method = class_getInstanceMethod(managerClass, selector) else { continue }
            let imp = method_getImplementation(method)
            var info = Dl_info()

            if dladdr(unsafeBitCast(imp, to: UnsafeRawPointer.self), &info) != 0 {
                if let fname = info.dli_fname {
                    let path = String(cString: fname)
                    if !path.contains("CoreLocation") { return true }
                }
            }
        }
        return false
    }
}
