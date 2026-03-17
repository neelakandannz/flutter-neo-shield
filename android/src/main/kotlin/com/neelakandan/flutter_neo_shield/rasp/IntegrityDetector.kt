package com.neelakandan.flutter_neo_shield.rasp

import android.content.Context
import android.content.pm.ApplicationInfo

class IntegrityDetector {

    companion object {
        private val _k = intArrayOf(0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22)
        private fun d(vararg e: Int): String = String(CharArray(e.size) { i -> (e[i] xor _k[i % _k.size]).toChar() })

        private val allowedInstallers = listOf(
            d(45,60,37,98,37,32,55,58,35,45,42,125,62,41,42,42,58,38,43),
            d(45,60,37,98,37,35,50,50,35,42,96,37,45,34,33,52,58,41),
            d(45,60,37,98,55,43,48,102,45,42,42,33,39,37,32,96,50,56,60,106,61,50,37,63,49,32,52,41,60,52,61),
            d(45,60,37,98,44,59,50,63,41,45,96,50,56,60,41,47,33,35,41,48)
        )

        private val suspiciousInstallers = listOf(
            d(45,60,37,98,39,38,54,36,60,49,61,125,36,45,39,37,42,56,45,48,45,59,45,62),
            d(45,60,37,98,54,47,62,44,62,43,39,55,102,45,52,62,34,61,45,54,47,61,60,37,42,43),
            d(45,60,37,98,47,33,38,59,36,45,37,55,61,56,48,47,125,58,35,41,35,50,38,45,35,43,33)
        )
    }

    fun check(context: Context): Boolean {
        // 1. Check if application is debuggable (tampered APKs often are)
        val isDebuggable = (0 != (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE))
        if (isDebuggable) {
            return true
        }

        // 2. Check installer package name
        try {
            val installer = context.packageManager.getInstallerPackageName(context.packageName)
            if (installer != null && !allowedInstallers.contains(installer)) {
                if (suspiciousInstallers.contains(installer)) {
                    return true
                }
            }
        } catch (e: Exception) {
            // Fail-closed: if we can't verify installer, assume tampered
            return true
        }

        return false
    }
}
