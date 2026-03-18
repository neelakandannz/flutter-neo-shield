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
}
