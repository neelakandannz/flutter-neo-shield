package com.neelakandan.flutter_neo_shield

/**
 * XOR-based string codec to prevent plaintext channel/method name
 * strings from appearing in the compiled binary.
 */
internal object ShieldCodec {

    // Key constructed from arithmetic to avoid literal bytes in the binary.
    private val key = intArrayOf(0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22)

    /** Decode an XOR-encoded IntArray back to its original String. */
    fun decode(encoded: IntArray): String {
        val chars = CharArray(encoded.size) { i ->
            (encoded[i] xor key[i % key.size]).toChar()
        }
        return String(chars)
    }

    // ── Channel names ────────────────────────────────────────────────
    val CH_RASP = intArrayOf(45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 60, 50, 59, 60)
    val CH_SCREEN = intArrayOf(45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 61, 48, 58, 41, 33, 32)
    val CH_MEMORY = intArrayOf(45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 35, 54, 37, 35, 54, 55)
    val CH_SCREEN_EVENTS = intArrayOf(45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 61, 48, 58, 41, 33, 32, 12, 45, 58, 33, 32, 39, 59)

    // ── Method names ─────────────────────────────────────────────────
    val M_CHECK_DEBUGGER = intArrayOf(45, 59, 45, 47, 47, 10, 54, 42, 57, 35, 41, 54, 58)
    val M_CHECK_ROOT = intArrayOf(45, 59, 45, 47, 47, 28, 60, 39, 56)
    val M_CHECK_EMULATOR = intArrayOf(45, 59, 45, 47, 47, 11, 62, 61, 32, 37, 58, 60, 58)
    val M_CHECK_FRIDA = intArrayOf(45, 59, 45, 47, 47, 8, 33, 33, 40, 37)
    val M_CHECK_HOOKS = intArrayOf(45, 59, 45, 47, 47, 6, 60, 39, 39, 55)
    val M_CHECK_INTEGRITY = intArrayOf(45, 59, 45, 47, 47, 7, 61, 60, 41, 35, 60, 58, 60, 53)
    val M_CHECK_DEVELOPER_MODE = intArrayOf(45, 59, 45, 47, 47, 10, 54, 62, 41, 40, 33, 35, 45, 62, 9, 33, 55, 45)
    val M_CHECK_SIGNATURE = intArrayOf(45, 59, 45, 47, 47, 29, 58, 47, 34, 37, 58, 38, 58, 41)
    val M_GET_SIGNATURE_HASH = intArrayOf(41, 54, 60, 31, 45, 41, 61, 41, 56, 49, 60, 54, 0, 45, 55, 38)
    val M_CHECK_NATIVE_DEBUG = intArrayOf(45, 59, 45, 47, 47, 0, 50, 60, 37, 50, 43, 23, 45, 46, 49, 41)
    val M_CHECK_NETWORK_THREATS = intArrayOf(45, 59, 45, 47, 47, 0, 54, 60, 59, 43, 60, 56, 28, 36, 54, 43, 50, 60, 63)
    val M_ENABLE_SCREEN_PROTECTION = intArrayOf(43, 61, 41, 46, 40, 43, 0, 43, 62, 33, 43, 61, 24, 62, 43, 58, 54, 43, 56, 45, 33, 61)
    val M_DISABLE_SCREEN_PROTECTION = intArrayOf(42, 58, 59, 45, 38, 34, 54, 27, 47, 54, 43, 54, 38, 28, 54, 33, 39, 45, 47, 48, 39, 60, 38)
    val M_IS_SCREEN_PROTECTION_ACTIVE = intArrayOf(39, 32, 27, 47, 54, 43, 54, 38, 28, 54, 33, 39, 45, 47, 48, 39, 60, 38, 13, 39, 58, 58, 62, 41)
    val M_ENABLE_APP_SWITCHER_GUARD = intArrayOf(43, 61, 41, 46, 40, 43, 18, 56, 60, 23, 57, 58, 60, 47, 44, 43, 33, 15, 57, 37, 60, 55)
    val M_DISABLE_APP_SWITCHER_GUARD = intArrayOf(42, 58, 59, 45, 38, 34, 54, 9, 60, 52, 29, 36, 33, 56, 39, 38, 54, 58, 11, 49, 47, 33, 44)
    val M_IS_SCREEN_BEING_RECORDED = intArrayOf(39, 32, 27, 47, 54, 43, 54, 38, 14, 33, 39, 61, 47, 30, 33, 45, 60, 58, 40, 33, 42)
    val M_ALLOCATE_SECURE = intArrayOf(47, 63, 36, 35, 39, 47, 39, 45, 31, 33, 45, 38, 58, 41)
    val M_READ_SECURE = intArrayOf(60, 54, 41, 40, 23, 43, 48, 61, 62, 33)
    val M_WIPE_SECURE = intArrayOf(57, 58, 56, 41, 23, 43, 48, 61, 62, 33)
    val M_WIPE_ALL = intArrayOf(57, 58, 56, 41, 5, 34, 63)

    // ── Location method names ──────────────────────────────────────────
    val CH_LOCATION = intArrayOf(45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 34, 60, 43, 45, 48, 39, 60, 38)
    val CH_LOCATION_EVENTS = intArrayOf(45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 34, 60, 43, 45, 48, 39, 60, 38, 19, 33, 56, 54, 38, 56, 55)
    val M_CHECK_FAKE_LOCATION = intArrayOf(45, 59, 45, 47, 47, 8, 50, 35, 41, 8, 33, 48, 41, 56, 45, 33, 61)
    val M_CHECK_MOCK_PROVIDER = intArrayOf(45, 59, 45, 47, 47, 3, 60, 43, 39, 20, 60, 60, 62, 45, 32, 43, 33)
    val M_CHECK_SPOOFING_APPS = intArrayOf(45, 59, 45, 47, 47, 29, 35, 39, 35, 34, 39, 61, 47, 13, 52, 62, 32)
    val M_CHECK_LOCATION_HOOKS = intArrayOf(45, 59, 45, 47, 47, 2, 60, 43, 45, 48, 39, 60, 38, 4, 43, 33, 56, 59)
    val M_CHECK_GPS_ANOMALY = intArrayOf(45, 59, 45, 47, 47, 9, 35, 59, 13, 42, 33, 62, 41, 32, 61)
    val M_CHECK_SENSOR_FUSION = intArrayOf(45, 59, 45, 47, 47, 29, 54, 38, 63, 43, 60, 21, 61, 63, 45, 33, 61)
    val M_CHECK_TEMPORAL_ANOMALY = intArrayOf(45, 59, 45, 47, 47, 26, 54, 37, 60, 43, 60, 50, 36, 13, 42, 33, 62, 41, 32, 61)

    // ── New v2.0.0 channel names ───────────────────────────────────────
    val CH_SECURE_STORAGE = intArrayOf(45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 61, 54, 43, 57, 54, 43, 12, 59, 56, 43, 60, 50, 47, 41)
    val CH_BIOMETRIC = intArrayOf(45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 44, 58, 39, 33, 33, 58, 33, 33, 47)
    val CH_DEVICE_BINDING = intArrayOf(45, 60, 37, 98, 42, 43, 54, 36, 45, 47, 47, 61, 44, 45, 42, 96, 53, 36, 57, 48, 58, 54, 58, 19, 42, 43, 60, 23, 63, 44, 39, 54, 36, 40, 107, 42, 54, 62, 37, 39, 43, 12, 42, 37, 42, 42, 58, 38, 43)

    // ── New v2.0.0 method names ────────────────────────────────────────
    val M_ENABLE_OVERLAY_PROTECTION = intArrayOf(43, 61, 41, 46, 40, 43, 28, 62, 41, 54, 34, 50, 49, 28, 54, 33, 39, 45, 47, 48, 39, 60, 38)
    val M_DISABLE_OVERLAY_PROTECTION = intArrayOf(42, 58, 59, 45, 38, 34, 54, 7, 58, 33, 60, 63, 41, 53, 20, 60, 60, 60, 41, 39, 58, 58, 39, 34)
    val M_CHECK_OVERLAY = intArrayOf(45, 59, 45, 47, 47, 1, 37, 45, 62, 40, 47, 42)
    val M_CHECK_CLICKJACKING = intArrayOf(45, 59, 45, 47, 47, 13, 63, 33, 47, 47, 36, 50, 43, 39, 45, 32, 52)
    val M_CHECK_ACCESSIBILITY = intArrayOf(45, 59, 45, 47, 47, 15, 48, 43, 41, 55, 61, 58, 42, 37, 40, 39, 39, 49)
    val M_GET_ACCESSIBILITY_SERVICES = intArrayOf(41, 54, 60, 13, 39, 45, 54, 59, 63, 45, 44, 58, 36, 37, 48, 55, 0, 45, 62, 50, 39, 48, 45, 63)
    val M_CHECK_SCREEN_READER = intArrayOf(45, 59, 45, 47, 47, 29, 48, 58, 41, 33, 32, 1, 45, 45, 32, 43, 33)
    val M_CHECK_KEYBOARD = intArrayOf(45, 59, 45, 47, 47, 5, 54, 49, 46, 43, 47, 33, 44)
    val M_GET_KEYBOARD_PACKAGE = intArrayOf(41, 54, 60, 7, 33, 55, 49, 39, 45, 54, 42, 3, 41, 47, 47, 47, 52, 45)
    val M_CHECK_KEYLOGGER = intArrayOf(45, 59, 45, 47, 47, 5, 54, 49, 32, 43, 41, 52, 45, 62)
    val M_CHECK_CODE_INJECTION = intArrayOf(45, 59, 45, 47, 47, 13, 60, 44, 41, 13, 32, 57, 45, 47, 48, 39, 60, 38)
    val M_GET_SUSPICIOUS_MODULES = intArrayOf(41, 54, 60, 31, 49, 61, 35, 33, 47, 45, 33, 38, 59, 1, 43, 42, 38, 36, 41, 55)
    val M_CHECK_OBFUSCATION = intArrayOf(45, 59, 45, 47, 47, 1, 49, 46, 57, 55, 45, 50, 60, 37, 43, 32)
    val M_CHECK_CAMERA_IN_USE = intArrayOf(45, 59, 45, 47, 47, 13, 50, 37, 41, 54, 47, 26, 38, 25, 55, 43)
    val M_CHECK_MIC_IN_USE = intArrayOf(45, 59, 45, 47, 47, 3, 58, 43, 5, 42, 27, 32, 45)
    val M_CHECK_BG_LOCATION = intArrayOf(45, 59, 45, 47, 47, 12, 52, 4, 35, 39, 47, 39, 33, 35, 42)
}
