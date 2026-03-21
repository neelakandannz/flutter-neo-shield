package com.neelakandan.flutter_neo_shield.rasp
import android.content.Context
import android.os.Build
import android.provider.Settings
import java.security.MessageDigest
class DeviceBindingDetector {
    fun getDeviceFingerprint(context: Context): String {
        return try {
            val sb = StringBuilder()
            sb.append(Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: "")
            sb.append(Build.FINGERPRINT).append(Build.BOARD).append(Build.BRAND)
            sb.append(Build.DEVICE).append(Build.HARDWARE).append(Build.MANUFACTURER)
            sb.append(Build.MODEL).append(Build.PRODUCT)
            val digest = MessageDigest.getInstance("SHA-256")
            digest.digest(sb.toString().toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
        } catch (e: Exception) { "" }
    }
}
