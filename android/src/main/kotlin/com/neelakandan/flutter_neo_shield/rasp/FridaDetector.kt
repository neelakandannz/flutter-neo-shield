package com.neelakandan.flutter_neo_shield.rasp

import java.io.File
import java.net.Socket
import java.util.Scanner

class FridaDetector {

    companion object {
        private val _k = intArrayOf(0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22)
        private fun d(vararg e: Int): String = String(CharArray(e.size) { i -> (e[i] xor _k[i % _k.size]).toChar() })

        private val fridaAgentStr = d(40,33,33,40,37,99,50,47,41,42,58)
        private val fridaGadgetStr = d(40,33,33,40,37,99,52,41,40,35,43,39)
        private val fridaServerStr = d(40,33,33,40,37,99,32,45,62,50,43,33)
        private val linjectorStr = d(34,58,38,38,33,45,39,39,62)
        private val procPrefix = d(97,35,58,35,39,97)
        private val mapsFile = d(97,62,41,60,55)
    }

    fun check(): Boolean {
        // 1. Check for Frida on common ports
        val fridaPorts = intArrayOf(27042, 27043, 4444)
        for (port in fridaPorts) {
            try {
                Socket("127.0.0.1", port).use {
                    return true
                }
            } catch (e: Exception) {
                // port not open
            }
        }

        // 2. Scan memory maps for frida agent
        try {
            val pid = android.os.Process.myPid()
            val file = File(procPrefix + pid + mapsFile)
            if (file.exists()) {
                Scanner(file).use { scanner ->
                    while (scanner.hasNextLine()) {
                        val line = scanner.nextLine()
                        if (line.contains(fridaAgentStr) ||
                            line.contains(fridaGadgetStr) ||
                            line.contains(fridaServerStr) ||
                            line.contains(linjectorStr)) {
                            return true
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // Fail-closed: if we can't read /proc maps, assume Frida is present
            return true
        }

        return false
    }
}
