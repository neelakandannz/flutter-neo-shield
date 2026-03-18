package com.neelakandan.flutter_neo_shield.location

import android.app.AppOpsManager
import android.content.Context
import android.location.LocationManager
import android.os.Build
import android.provider.Settings

/**
 * Layer 1: Mock Location Provider Detection.
 *
 * Checks Android developer settings, mock location app ops,
 * test providers, and location extras for spoofing indicators.
 */
class MockProviderDetector(private val context: Context) {

    /** Primary check: is mock location enabled or a mock provider active? */
    fun check(): Boolean {
        return checkMockLocationSetting() ||
               checkTestProviders() ||
               checkDefaultMockLocationApp() != null
    }

    /** Check developer setting for mock location. */
    fun checkMockLocationSetting(): Boolean {
        try {
            // Pre-Android 6.0
            @Suppress("DEPRECATION")
            val mockSetting = Settings.Secure.getString(
                context.contentResolver,
                "mock_location"
            )
            if (mockSetting == "1") return true
        } catch (_: Exception) {}

        return false
    }

    /** Check if any test providers are registered with LocationManager. */
    fun checkTestProviders(): Boolean {
        return try {
            val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
                ?: return true // fail-closed
            val providers = lm.allProviders
            providers.any { provider ->
                try {
                    val lp = lm.getProvider(provider)
                    // Test providers have specific characteristics
                    lp == null && provider != LocationManager.PASSIVE_PROVIDER
                } catch (_: Exception) {
                    false
                }
            }
        } catch (_: SecurityException) {
            true // fail-closed
        }
    }

    /** Check which app (if any) has MOCK_LOCATION app ops permission. */
    fun checkDefaultMockLocationApp(): String? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
                    ?: return null
                val packages = context.packageManager.getInstalledPackages(0)
                for (pkg in packages) {
                    try {
                        val ai = pkg.applicationInfo ?: continue
                        @Suppress("DEPRECATION")
                        val mode = appOps.checkOpNoThrow(
                            AppOpsManager.OPSTR_MOCK_LOCATION,
                            ai.uid,
                            pkg.packageName
                        )
                        if (mode == AppOpsManager.MODE_ALLOWED) {
                            return pkg.packageName
                        }
                    } catch (_: Exception) {
                        continue
                    }
                }
            } catch (_: Exception) {}
        }
        return null
    }
}
