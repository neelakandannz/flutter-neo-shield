package com.neelakandan.flutter_neo_shield.rasp
import android.content.Context
class PermissionDetector {
    fun isCameraInUse(context: Context): Boolean = false
    fun isMicrophoneInUse(context: Context): Boolean = false
    fun isLocationAccessedInBackground(context: Context): Boolean {
        return try {
            val lm = context.getSystemService(Context.LOCATION_SERVICE) as? android.location.LocationManager ?: return false
            lm.isProviderEnabled(android.location.LocationManager.GPS_PROVIDER) || lm.isProviderEnabled(android.location.LocationManager.NETWORK_PROVIDER)
        } catch (e: Exception) { false }
    }
}
