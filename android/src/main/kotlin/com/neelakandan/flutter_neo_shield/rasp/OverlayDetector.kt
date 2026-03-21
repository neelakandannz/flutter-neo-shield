package com.neelakandan.flutter_neo_shield.rasp
import android.content.Context
import android.os.Build
import android.provider.Settings
class OverlayDetector {
    fun check(context: Context): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Settings.canDrawOverlays(context)
            } else false
        } catch (e: Exception) { true }
    }
}
