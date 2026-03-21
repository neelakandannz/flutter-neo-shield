package com.neelakandan.flutter_neo_shield.rasp
import android.content.Context
import android.view.accessibility.AccessibilityManager
class AccessibilityDetector {
    fun check(context: Context): Boolean {
        return try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager ?: return true
            val services = am.getEnabledAccessibilityServiceList(android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            for (service in services) {
                val pkg = service.resolveInfo?.serviceInfo?.packageName ?: continue
                try {
                    val appInfo = context.packageManager.getApplicationInfo(pkg, 0)
                    if (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM == 0) return true
                } catch (e: Exception) { return true }
            }
            false
        } catch (e: Exception) { true }
    }
    fun getEnabledServices(context: Context): String {
        return try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager ?: return ""
            val services = am.getEnabledAccessibilityServiceList(android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            services.mapNotNull { it.resolveInfo?.serviceInfo?.packageName }.joinToString(",")
        } catch (e: Exception) { "" }
    }
    fun isScreenReaderActive(context: Context): Boolean {
        return try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager ?: return false
            am.isEnabled && am.isTouchExplorationEnabled
        } catch (e: Exception) { false }
    }
}
