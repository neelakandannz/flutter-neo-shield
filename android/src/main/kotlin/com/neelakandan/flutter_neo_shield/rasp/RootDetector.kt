package com.neelakandan.flutter_neo_shield.rasp

import java.io.File

class RootDetector {

    companion object {
        // XOR key derived from arithmetic — never appears as a literal
        private val _k = intArrayOf(0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22)
        private fun d(vararg e: Int): String = String(CharArray(e.size) { i -> (e[i] xor _k[i % _k.size]).toChar() })

        // su binary paths (encoded)
        private val suPaths = arrayOf(
            d(97,32,49,63,48,43,62,103,45,52,62,124,27,57,52,43,33,61,63,33,60,125,41,60,47),
            d(97,32,42,37,42,97,32,61),
            d(97,32,49,63,48,43,62,103,46,45,32,124,59,57),
            d(97,32,49,63,48,43,62,103,52,38,39,61,103,63,49),
            d(97,55,41,56,37,97,63,39,47,37,34,124,48,46,45,32,124,59,57),
            d(97,55,41,56,37,97,63,39,47,37,34,124,42,37,42,97,32,61),
            d(97,32,49,63,48,43,62,103,63,32,97,43,42,37,42,97,32,61),
            d(97,32,49,63,48,43,62,103,46,45,32,124,46,45,45,34,32,41,42,33,97,32,61),
            d(97,55,41,56,37,97,63,39,47,37,34,124,59,57),
            d(97,32,61,99,38,39,61,103,63,49)
        )

        // Magisk paths (encoded)
        private val magiskPaths = arrayOf(
            d(97,32,42,37,42,97,125,37,45,35,39,32,35),
            d(97,48,41,47,44,43,124,102,40,45,61,50,42,32,33,17,62,41,43,45,61,56),
            d(97,55,45,58,107,96,62,41,43,45,61,56,102,57,42,44,63,39,47,47),
            d(97,55,41,56,37,97,50,44,46,107,35,50,47,37,55,37),
            d(97,55,41,56,37,97,50,44,46,107,35,50,47,37,55,37,125,44,46)
        )

        private val testKeysStr = d(58,54,59,56,105,37,54,49,63)
        private val whichCmd = d(57,59,33,47,44)
        private val suCmd = d(61,38)
    }

    fun check(): Boolean {
        // Basic Root detection by checking for su binaries
        for (path in suPaths) {
            if (File(path).exists()) {
                return true
            }
        }

        // Check for test-keys build
        val buildTags = android.os.Build.TAGS
        if (buildTags != null && buildTags.contains(testKeysStr)) {
            return true
        }

        // Check for Magisk Manager (various package names)
        try {
            for (path in magiskPaths) {
                if (File(path).exists()) {
                    return true
                }
            }
        } catch (e: Exception) {
            // Fail-closed: permission errors reading Magisk paths are suspicious
            return true
        }

        // Check if su is accessible via runtime exec
        try {
            val process = Runtime.getRuntime().exec(arrayOf(whichCmd, suCmd))
            val exitCode = process.waitFor()
            if (exitCode == 0) return true
        } catch (e: Exception) {
            // Fail-closed: inability to exec 'which su' is suspicious
            return true
        }

        return false
    }
}
