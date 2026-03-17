package com.neelakandan.flutter_neo_shield.rasp

import java.io.File

/**
 * Native-level debugger detection that catches GDB, LLDB, and other
 * native debuggers attached from desktop via ADB.
 *
 * The existing DebuggerDetector only checks Java-level debugging
 * (Debug.isDebuggerConnected). This detector checks:
 *
 * 1. /proc/self/status TracerPid — non-zero means a native debugger
 *    (GDB, LLDB, strace) is ptrace-attached to this process.
 * 2. /proc/self/wchan — if the process is stopped in ptrace_stop.
 * 3. Timing-based detection — single-stepping causes measurable delays.
 */
class NativeDebugDetector {

    companion object {
        private val _k = intArrayOf(0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22)
        private fun d(vararg e: Int): String = String(CharArray(e.size) { i -> (e[i] xor _k[i % _k.size]).toChar() })

        private val procStatusPath = d(97,35,58,35,39,97,32,45,32,34,97,32,60,45,48,59,32)
        private val tracerPidStr = d(26,33,41,47,33,60,3,33,40,126)
        private val procWchanPath = d(97,35,58,35,39,97,32,45,32,34,97,36,43,36,37,32)
        private val ptraceStopStr = d(62,39,58,45,39,43,12,59,56,43,62)
        private val traceStr = d(58,33,41,47,33)
    }

    fun check(): Boolean {
        return checkTracerPid() || checkWchan() || checkTimingAnomaly()
    }

    /**
     * Reads /proc/self/status and checks TracerPid.
     * TracerPid != 0 means a process is ptrace-attached (native debugger).
     */
    private fun checkTracerPid(): Boolean {
        try {
            val statusFile = File(procStatusPath)
            if (!statusFile.exists()) return false

            val lines = statusFile.readLines()
            for (line in lines) {
                if (line.startsWith(tracerPidStr)) {
                    val pid = line.substringAfter(tracerPidStr).trim()
                    if (pid != "0") {
                        return true // A process is tracing us
                    }
                }
            }
        } catch (e: Exception) {
            // Fail-closed: if we can't read /proc/self/status, assume traced
            return true
        }
        return false
    }

    /**
     * Checks /proc/self/wchan for ptrace_stop.
     * When a debugger halts execution, the wait channel shows ptrace_stop.
     */
    private fun checkWchan(): Boolean {
        try {
            val wchanFile = File(procWchanPath)
            if (!wchanFile.exists()) return false

            val wchan = wchanFile.readText().trim()
            if (wchan.contains(ptraceStopStr) || wchan.contains(traceStr)) {
                return true
            }
        } catch (e: Exception) {
            // Fail-closed: if we can't read wchan, assume debug trace
            return true
        }
        return false
    }

    /**
     * Timing-based detection: when single-stepping through code with a
     * debugger, even simple operations take much longer than normal.
     *
     * We measure the time for a tight loop. Under normal execution this
     * takes < 5ms. Under a debugger with breakpoints or single-stepping,
     * it takes significantly longer.
     *
     * Threshold is set conservatively to avoid false positives on slow devices.
     */
    private fun checkTimingAnomaly(): Boolean {
        try {
            val start = System.nanoTime()
            // Simple computation that should be very fast
            @Suppress("UNUSED_VARIABLE")
            var sum = 0L
            for (i in 0 until 10000) {
                sum += i
            }
            val elapsed = System.nanoTime() - start

            // 500ms threshold — normal execution is < 5ms even on slow devices.
            // A debugger single-stepping would take seconds.
            if (elapsed > 500_000_000L) {
                return true
            }
        } catch (e: Exception) {
            // Fail-closed: timing check failure is suspicious
            return true
        }
        return false
    }
}
