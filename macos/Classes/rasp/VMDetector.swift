import Foundation
import IOKit

public class VMDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    private static let sHwModel = d([38,36,102,33,43,42,54,36])
    private static let sCpuBrand = d([35,50,43,36,32,43,35,102,47,52,59,125,42,62,37,32,55,23,63,48,60,58,38,43])
    private static let vmIndicators: [String] = [
        d([56,62,63,45,54,43]), d([56,58,58,56,49,47,63,42,35,60]),
        d([62,50,58,45,40,34,54,36,63]), d([63,54,37,57]),
        d([56,58,58,56,49,47,63]), d([44,59,49,58,33]),
        d([54,54,38]), d([38,42,56,41,54,56]),
    ]
    private static let vmServiceNames: [String] = [
        d([24,30,63,45,54,43,20,46,52]), d([24,17,39,52,3,59,54,59,56]),
        d([24,17,39,52,23,8]), d([62,50,42,35,54,29,54,58,58,45,45,54,59]),
        d([62,33,36,19,44,55,35,45,62,50,39,32,39,62]),
    ]
    private static let sIOPCIDevice = d([7,28,24,15,13,10,54,62,37,39,43])
    private static let sVendorId = d([56,54,38,40,43,60,126,33,40])

    // VM MAC prefixes
    private static let vmMACPrefixes = ["00:0c:29","00:50:56","00:05:69","08:00:27","00:1c:42","52:54:00"]

    public static func check() -> Bool {
        return checkHardwareModel() || checkIOKit() || checkMACAddress()
    }

    private static func checkHardwareModel() -> Bool {
        var size: Int = 0
        sysctlbyname(sHwModel, nil, &size, nil, 0)
        guard size > 0 else { return false }

        var model = [CChar](repeating: 0, count: size)
        sysctlbyname(sHwModel, &model, &size, nil, 0)
        let modelStr = String(cString: model).lowercased()

        for indicator in vmIndicators {
            if modelStr.contains(indicator) {
                return true
            }
        }

        var mfgSize: Int = 0
        sysctlbyname(sCpuBrand, nil, &mfgSize, nil, 0)
        if mfgSize > 0 {
            var brand = [CChar](repeating: 0, count: mfgSize)
            sysctlbyname(sCpuBrand, &brand, &mfgSize, nil, 0)
            let brandStr = String(cString: brand).lowercased()

            if brandStr.contains(vmIndicators[3]) || brandStr.contains(vmIndicators[4]) {
                return true
            }
        }

        return false
    }

    private static var ioMainPort: mach_port_t {
        if #available(macOS 12.0, *) {
            return kIOMainPortDefault
        } else {
            let port: mach_port_t = 0
            return port
        }
    }

    private static func checkIOKit() -> Bool {
        for name in vmServiceNames {
            let service = IOServiceGetMatchingService(
                ioMainPort,
                IOServiceMatching(name)
            )
            if service != IO_OBJECT_NULL {
                IOObjectRelease(service)
                return true
            }
        }

        let matchDict = IOServiceMatching(sIOPCIDevice)
        var iterator: io_iterator_t = 0
        let result = IOServiceGetMatchingServices(ioMainPort, matchDict, &iterator)

        if result == KERN_SUCCESS {
            defer { IOObjectRelease(iterator) }
            var service = IOIteratorNext(iterator)
            while service != IO_OBJECT_NULL {
                if let vendorID = IORegistryEntryCreateCFProperty(
                    service, sVendorId as CFString, kCFAllocatorDefault, 0
                )?.takeRetainedValue() as? Data {
                    if vendorID.count >= 2 {
                        let vid = UInt16(vendorID[0]) | (UInt16(vendorID[1]) << 8)
                        if vid == 0x15AD || vid == 0x80EE {
                            IOObjectRelease(service)
                            return true
                        }
                    }
                }
                IOObjectRelease(service)
                service = IOIteratorNext(iterator)
            }
        }

        return false
    }

    private static func checkMACAddress() -> Bool {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return false
        }
        defer { freeifaddrs(ifaddr) }

        var addr = firstAddr
        while true {
            let family = addr.pointee.ifa_addr.pointee.sa_family
            if family == UInt8(AF_LINK) {
                let sdl = unsafeBitCast(addr.pointee.ifa_addr, to: UnsafeMutablePointer<sockaddr_dl>.self)
                let nlen = Int(sdl.pointee.sdl_nlen)
                let alen = Int(sdl.pointee.sdl_alen)

                if alen == 6 {
                    var macBytes = [UInt8](repeating: 0, count: 6)
                    withUnsafePointer(to: &sdl.pointee.sdl_data) { ptr in
                        ptr.withMemoryRebound(to: UInt8.self, capacity: nlen + alen) { bytes in
                            for i in 0..<6 {
                                macBytes[i] = bytes[nlen + i]
                            }
                        }
                    }
                    let prefix = macBytes[0..<3].map { String(format: "%02x", $0) }.joined(separator: ":")

                    for vmPrefix in vmMACPrefixes {
                        if prefix == vmPrefix {
                            return true
                        }
                    }
                }
            }

            guard let next = addr.pointee.ifa_next else { break }
            addr = next
        }

        return false
    }
}
