package com.neelakandan.flutter_neo_shield.rasp

import android.content.Context
import android.content.pm.PackageManager
import java.lang.reflect.Modifier

class HookDetector {

    companion object {
        private val _k = intArrayOf(0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22)
        private fun d(vararg e: Int): String = String(CharArray(e.size) { i -> (e[i] xor _k[i % _k.size]).toChar() })

        // Hook framework package names (encoded)
        private val hookPackages = arrayOf(
            d(42,54,102,62,43,44,37,102,45,42,42,33,39,37,32,96,43,56,35,55,43,55,102,37,42,61,39,41,32,40,43,33),  // de.robv.android.xposed.installer
            d(45,60,37,98,55,47,38,58,37,47,96,32,61,46,55,58,33,41,56,33),                                          // com.saurik.substrate
            d(33,33,47,98,40,61,35,39,63,33,42,125,36,63,52,33,32,45,40),                                            // org.lsposed.lsposed
            d(58,60,56,98,46,33,59,38,59,49,96,62,41,43,45,61,56),                                                   // top.johnwu.magisk
            d(33,33,47,98,40,61,35,39,63,33,42,125,37,45,42,47,52,45,62),                                            // org.lsposed.manager
            d(39,60,102,43,45,58,59,61,46,106,34,32,56,35,55,43,55,102,33,37,32,50,47,41,54),                        // io.github.lsposed.manager
            d(45,60,37,98,48,33,35,34,35,44,32,36,61,98,41,47,52,33,63,47),                                          // com.topjohnwu.magisk
            d(35,54,102,59,33,39,32,32,57,106,43,43,56),                                                             // me.weishu.exp
            d(45,60,37,98,34,33,33,37,53,44,35,125,32,37,32,43,33,39,35,48),                                         // com.formyhm.hideroot
            d(45,60,37,98,37,35,35,32,35,54,47,32,102,36,45,42,54,37,53,54,33,60,60)                                 // com.amphoras.hidemyroot
        )

        // Xposed class name (encoded)
        private val xposedBridgeClass = d(42,54,102,62,43,44,37,102,45,42,42,33,39,37,32,96,43,56,35,55,43,55,102,20,52,33,32,45,40,6,60,58,44,43,33)  // de.robv.android.xposed.XposedBridge

        // Stack trace markers (encoded)
        private val xposedStr = d(54,35,39,63,33,42)                           // xposed
        private val saurikSubstrate = d(45,60,37,98,55,47,38,58,37,47,96,32,61,46,55,58,33,41,56,33) // com.saurik.substrate
        private val lsposedStr = d(2,0,24,35,55,43,55)                         // LSPosed
    }

    fun check(context: Context): Boolean {
        // 1. Check for installed hook packages
        val pm = context.packageManager
        for (pkg in hookPackages) {
            try {
                pm.getPackageInfo(pkg, PackageManager.GET_META_DATA)
                return true
            } catch (e: PackageManager.NameNotFoundException) {
                // not installed
            }
        }

        // 2. Check for Xposed classes loaded in memory
        try {
            val hasXposed = Class.forName(xposedBridgeClass) != null
            if (hasXposed) return true
        } catch (e: ClassNotFoundException) {
            // expected
        }

        // 3. Inspect stack traces for hooking frameworks
        try {
            throw Exception()
        } catch (e: Exception) {
            for (element in e.stackTrace) {
                if (element.className.contains(xposedStr) ||
                    element.className.contains(saurikSubstrate) ||
                    element.className.contains(lsposedStr)
                ) {
                    return true
                }
            }
        }

        return false
    }
}
