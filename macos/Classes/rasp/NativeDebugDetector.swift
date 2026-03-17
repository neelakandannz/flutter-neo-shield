import Foundation
import Darwin
import MachO

@_silgen_name("ptrace")
private func swift_ptrace(_ request: CInt, _ pid: pid_t, _ addr: UnsafeMutableRawPointer?, _ data: CInt) -> CInt

public class NativeDebugDetector {

    private static let _k: [Int] = [0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22]
    private static func d(_ e: [Int]) -> String {
        String(e.enumerated().map { i, v in Character(UnicodeScalar(v ^ _k[i % _k.count])!) })
    }

    // Debugger parent process names (encoded)
    private static let debuggerNames: [String] = [
        d([34,63,44,46]),
        d([41,55,42]),
        d([42,54,42,57,35,61,54,58,58,33,60]),
        d([42,39,58,45,39,43]),
        d([42,39,58,57,55,61]),
        d([61,39,58,45,39,43]),
        d([34,39,58,45,39,43]),
        d([62,33,39,47,33,61,32,45,52,52]),
    ]

    public static func check() -> Bool {
        return checkSysctl() ||
               checkExceptionPorts() ||
               checkParentProcess() ||
               checkTimingAnomaly()
    }

    public static func denyDebuggerAttachment() -> Bool {
        let PT_DENY_ATTACH: CInt = 31
        let result = swift_ptrace(PT_DENY_ATTACH, 0, nil, 0)
        return result == 0
    }

    private static func checkSysctl() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if result != 0 {
            return true
        }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    private static func checkExceptionPorts() -> Bool {
        var count: mach_msg_type_number_t = 0
        let excTypesCount = Int(EXC_TYPES_COUNT)
        var masks = [exception_mask_t](repeating: 0, count: excTypesCount)
        var ports = [mach_port_t](repeating: 0, count: excTypesCount)
        var behaviors = [exception_behavior_t](repeating: 0, count: excTypesCount)
        var flavors = [thread_state_flavor_t](repeating: 0, count: excTypesCount)

        let excMaskAll: exception_mask_t = exception_mask_t(
            EXC_MASK_BAD_ACCESS |
            EXC_MASK_BAD_INSTRUCTION |
            EXC_MASK_ARITHMETIC |
            EXC_MASK_EMULATION |
            EXC_MASK_SOFTWARE |
            EXC_MASK_BREAKPOINT |
            EXC_MASK_SYSCALL |
            EXC_MASK_MACH_SYSCALL |
            EXC_MASK_RPC_ALERT |
            EXC_MASK_MACHINE
        )

        let result = withUnsafeMutablePointer(to: &count) { countPtr in
            task_get_exception_ports(
                mach_task_self_,
                excMaskAll,
                &masks,
                countPtr,
                &ports,
                &behaviors,
                &flavors
            )
        }

        if result != KERN_SUCCESS {
            return false
        }

        for i in 0..<Int(count) {
            if ports[i] != 0 && ports[i] != mach_port_t(MACH_PORT_NULL) {
                return true
            }
        }

        return false
    }

    private static func checkParentProcess() -> Bool {
        let ppid = getppid()

        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, ppid]
        var size = MemoryLayout<kinfo_proc>.stride
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if result != 0 {
            return false
        }

        let parentName = withUnsafePointer(to: &info.kp_proc.p_comm) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN)) { cStr in
                String(cString: cStr)
            }
        }.lowercased()

        for name in debuggerNames {
            if parentName.contains(name) {
                return true
            }
        }

        return false
    }

    private static func checkTimingAnomaly() -> Bool {
        let start = CFAbsoluteTimeGetCurrent()
        var sum: Int64 = 0
        for i in 0..<10000 {
            sum += Int64(i)
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start
        _ = sum

        return elapsed > 0.5
    }
}
