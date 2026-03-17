package com.neelakandan.flutter_neo_shield.rasp

import android.os.Build
import java.io.File

class EmulatorDetector {

    companion object {
        private val _k = intArrayOf(0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22)
        private fun d(vararg e: Int): String = String(CharArray(e.size) { i -> (e[i] xor _k[i % _k.size]).toChar() })

        private val sGeneric = d(41,54,38,41,54,39,48)
        private val sUnknown = d(59,61,35,34,43,57,61)
        private val sGoogleSdk = d(41,60,39,43,40,43,12,59,40,47)
        private val sEmulator = d(11,62,61,32,37,58,60,58)
        private val sSdkX86 = d(15,61,44,62,43,39,55,104,31,0,5,115,42,57,45,34,39,104,42,43,60,115,48,116,114)
        private val sQcRefPhone = d(31,16,23,30,33,40,54,58,41,42,45,54,23,28,44,33,61,45)
        private val sGenymotion = d(9,54,38,53,41,33,39,33,35,42)
        private val sBuild = d(12,38,33,32,32)
        private val sSdk = d(61,55,35)
        private val sAndy = d(15,61,44,53)
        private val sTtVmHdragon = d(58,39,30,1,27,6,55,58,45,35,33,61)
        private val sDroid4X = d(10,33,39,37,32,122,11)
        private val sNox = d(32,60,48)
        private val sSdkX86Str = d(61,55,35,19,60,118,101)
        private val sSdkGoogle = d(61,55,35,19,35,33,60,47,32,33)
        private val sVbox86p = d(56,49,39,52,124,120,35)
        private val sEmultor = d(43,62,61,32,48,33,33)
        private val sMIT = d(3,26,28)
        private val sTiantianVM = d(26,58,41,34,48,39,50,38,26,9)
        private val sGenericX86 = d(41,54,38,41,54,39,48,23,52,124,120)
        private val sGenericX8664 = d(41,54,38,41,54,39,48,23,52,124,120,12,126,120)
        private val sGoldfish = d(41,60,36,40,34,39,32,32)
        private val sVbox86 = d(56,49,39,52,124,120)
        private val sTtVmX86 = d(58,39,30,1,27,54,107,126)
        private val sSdkX8664 = d(15,61,44,62,43,39,55,104,31,0,5,115,42,57,45,34,39,104,42,43,60,115,48,116,114,17,101,124)
        private val sQemud = d(97,55,45,58,107,61,60,43,39,33,58,124,57,41,41,59,55)
        private val sQemuPipe = d(97,55,45,58,107,63,54,37,57,27,62,58,56,41)
        private val sGetprop = d(41,54,60,60,54,33,35)
        private val sChipname = d(60,60,102,36,37,60,55,63,45,54,43,125,43,36,45,62,61,41,33,33)
        private val sRanchu = d(60,50,38,47,44,59)
    }

    fun check(): Boolean {
        val buildDetails = (Build.FINGERPRINT.startsWith(sGeneric)
                || Build.FINGERPRINT.startsWith(sUnknown)
                || Build.MODEL.contains(sGoogleSdk)
                || Build.MODEL.contains(sEmulator)
                || Build.MODEL.contains(sSdkX86)
                || Build.BOARD == sQcRefPhone
                || Build.MANUFACTURER.contains(sGenymotion)
                || Build.HOST.startsWith(sBuild)
                || (Build.BRAND.startsWith(sGeneric) && Build.DEVICE.startsWith(sGeneric))
                || sGoogleSdk.equals(Build.PRODUCT))

        if (buildDetails) return true

        var rating = 0
        if (Build.PRODUCT.contains(sSdk) ||
            Build.PRODUCT.contains(sAndy) ||
            Build.PRODUCT.contains(sTtVmHdragon) ||
            Build.PRODUCT.contains(sGoogleSdk) ||
            Build.PRODUCT.contains(sDroid4X) ||
            Build.PRODUCT.contains(sNox) ||
            Build.PRODUCT.contains(sSdkX86Str) ||
            Build.PRODUCT.contains(sSdkGoogle) ||
            Build.PRODUCT.contains(sVbox86p) ||
            Build.PRODUCT.contains(sEmultor)) {
            rating++
        }

        if (Build.MANUFACTURER.equals(sUnknown) ||
            Build.MANUFACTURER.equals(sGenymotion) ||
            Build.MANUFACTURER.contains(sAndy) ||
            Build.MANUFACTURER.contains(sMIT) ||
            Build.MANUFACTURER.contains(sNox) ||
            Build.MANUFACTURER.contains(sTiantianVM)){
            rating++
        }

        if (Build.BRAND.equals(sGeneric) ||
            Build.BRAND.equals(sGenericX86) ||
            Build.BRAND.equals(sTiantianVM) ||
            Build.BRAND.contains(sAndy)) {
            rating++
        }

        if (Build.DEVICE.contains(sGeneric) ||
            Build.DEVICE.contains(sGenericX86) ||
            Build.DEVICE.contains(sAndy) ||
            Build.DEVICE.contains(sTtVmHdragon) ||
            Build.DEVICE.contains(sDroid4X) ||
            Build.DEVICE.contains(sNox) ||
            Build.DEVICE.contains(sGenericX8664) ||
            Build.DEVICE.contains(sVbox86p)) {
            rating++
        }

        if (Build.MODEL.equals(sSdk) ||
            Build.MODEL.contains(sEmulator) ||
            Build.MODEL.equals(sGoogleSdk) ||
            Build.MODEL.contains(sDroid4X) ||
            Build.MODEL.contains(sTiantianVM) ||
            Build.MODEL.contains(sAndy) ||
            Build.MODEL.equals(sSdkX8664) ||
            Build.MODEL.equals(sSdkX86)) {
            rating++
        }

        if (Build.HARDWARE.equals(sGoldfish) ||
            Build.HARDWARE.equals(sVbox86) ||
            Build.HARDWARE.contains(sNox) ||
            Build.HARDWARE.contains(sTtVmX86)) {
            rating++
        }

        if (rating > 3) return true

        // Also check if goldfish properties file exists
        if (File(sQemud).exists() || File(sQemuPipe).exists()) {
            return true
        }

        // Check for QEMU-specific system properties
        try {
            val process = Runtime.getRuntime().exec(arrayOf(sGetprop, sChipname))
            val output = process.inputStream.bufferedReader().readText().trim()
            if (output.contains(sRanchu) || output.contains(sGoldfish)) {
                return true
            }
        } catch (e: Exception) {
            // Fail-closed: if we can't check emulator properties, assume detected
            return true
        }

        return false
    }
}
