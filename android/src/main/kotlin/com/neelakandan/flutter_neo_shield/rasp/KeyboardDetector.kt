package com.neelakandan.flutter_neo_shield.rasp
import android.content.Context
import android.provider.Settings
class KeyboardDetector {
    fun isThirdPartyKeyboard(context: Context): Boolean {
        return try {
            val currentIme = Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD) ?: return true
            val isSystem = currentIme.startsWith("com.android.") || currentIme.startsWith("com.google.") || currentIme.startsWith("com.samsung.") || currentIme.startsWith("com.sec.") || currentIme.startsWith("com.huawei.") || currentIme.startsWith("com.miui.") || currentIme.startsWith("com.oppo.") || currentIme.startsWith("com.oneplus.") || currentIme.startsWith("com.lge.")
            !isSystem
        } catch (e: Exception) { true }
    }
    fun getCurrentKeyboardPackage(context: Context): String {
        return try { Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD) ?: "" } catch (e: Exception) { "" }
    }
    fun checkKeylogger(context: Context): Boolean {
        return try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? android.view.accessibility.AccessibilityManager ?: return true
            val services = am.getEnabledAccessibilityServiceList(android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            for (service in services) {
                val caps = service.capabilities
                if (caps and android.accessibilityservice.AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT != 0) {
                    val pkg = service.resolveInfo?.serviceInfo?.packageName ?: continue
                    try {
                        val appInfo = context.packageManager.getApplicationInfo(pkg, 0)
                        if (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM == 0) return true
                    } catch (e: Exception) { return true }
                }
            }
            false
        } catch (e: Exception) { true }
    }
}
