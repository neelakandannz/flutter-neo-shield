package com.neelakandan.flutter_neo_shield.location

import android.location.LocationManager
import java.io.File
import java.lang.reflect.Modifier

/**
 * Layer 3: Location API Hook Detection.
 *
 * Detects Xposed/Frida hooks on LocationManager methods,
 * checks for suspicious native libraries loaded near location code,
 * and verifies Java reflection integrity of location classes.
 */
class LocationHookDetector {

    fun check(): Boolean {
        return checkLocationManagerIntegrity() ||
               checkNativeLocationHooks() ||
               checkReflectionHooks()
    }

    /** Verify LocationManager methods haven't been hooked via Xposed. */
    private fun checkLocationManagerIntegrity(): Boolean {
        try {
            val method = LocationManager::class.java.getDeclaredMethod(
                "getLastKnownLocation", String::class.java
            )
            // Xposed hooks change method modifiers to native
            if (Modifier.isNative(method.modifiers)) {
                return true
            }
            // Method should be declared by LocationManager
            if (method.declaringClass.name != "android.location.LocationManager") {
                return true
            }
        } catch (_: NoSuchMethodException) {
            return true // method removed = suspicious
        } catch (_: Exception) {}
        return false
    }

    /** Check /proc/self/maps for suspicious libraries near location code. */
    private fun checkNativeLocationHooks(): Boolean {
        try {
            val maps = File("/proc/self/maps").readText()
            val suspiciousLibs = listOf(
                "frida", "xposed", "substrate", "cydia",
                "libgadget", "liblief", "fakegps", "mockloc"
            )
            for (lib in suspiciousLibs) {
                if (maps.contains(lib, ignoreCase = true)) {
                    return true
                }
            }
            // Check TracerPid
            val status = File("/proc/self/status").readText()
            val tracerPid = Regex("TracerPid:\\s+(\\d+)").find(status)?.groupValues?.get(1)
            if (tracerPid != null && tracerPid != "0") {
                return true
            }
        } catch (_: Exception) {
            return true // fail-closed
        }
        return false
    }

    /** Check for reflection-based hooks on location classes. */
    private fun checkReflectionHooks(): Boolean {
        try {
            val locationClass = Class.forName("android.location.LocationManager")
            val methods = locationClass.declaredMethods
            for (method in methods) {
                if (method.name.contains("getLastKnown") ||
                    method.name.contains("requestLocation")) {
                    val modifiers = method.modifiers
                    if (Modifier.isAbstract(modifiers) || method.isSynthetic) {
                        return true
                    }
                }
            }
        } catch (_: Exception) {
            return true // fail-closed
        }
        return false
    }
}
