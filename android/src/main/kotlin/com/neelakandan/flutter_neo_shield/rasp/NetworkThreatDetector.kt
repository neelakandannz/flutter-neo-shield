package com.neelakandan.flutter_neo_shield.rasp

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import java.net.NetworkInterface

/**
 * Detects network-level threats used during APK reverse engineering from desktop:
 *
 * 1. HTTP Proxy — Burp Suite, mitmproxy, Charles Proxy running on desktop
 * 2. VPN — VPN tunnels routing traffic through desktop interceptors
 *
 * These are the primary tools attackers use to intercept HTTPS traffic
 * after decompiling and repackaging an APK.
 */
class NetworkThreatDetector {

    companion object {
        private val _k = intArrayOf(0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22)
        private fun d(vararg e: Int): String = String(CharArray(e.size) { i -> (e[i] xor _k[i % _k.size]).toChar() })

        private val sHttpProxy = d(38,39,60,60,106,62,33,39,52,61,6,60,59,56)
        private val sHttpsProxy = d(38,39,60,60,55,96,35,58,35,60,55,27,39,63,48)
        private val sColonZero = d(116,99)
        private val sTun = d(58,38,38)
        private val sPpp = d(62,35,56)
        private val sTap = d(58,50,56)
        private val sUtun = d(59,39,61,34)
        private val sIpsec = d(39,35,59,41,39)
    }

    /**
     * Returns a map with:
     *   "proxyDetected" -> Boolean
     *   "vpnDetected"   -> Boolean
     *   "detected"      -> Boolean (true if ANY threat found)
     */
    fun check(context: Context): Map<String, Any> {
        val proxyDetected = checkProxy(context)
        val vpnDetected = checkVpn(context)

        return mapOf(
            "proxyDetected" to proxyDetected,
            "vpnDetected" to vpnDetected,
            "detected" to (proxyDetected || vpnDetected)
        )
    }

    /**
     * Simple boolean: returns true if proxy or VPN detected.
     */
    fun checkSimple(context: Context): Boolean {
        return checkProxy(context) || checkVpn(context)
    }

    /**
     * Detects HTTP/HTTPS proxy configuration.
     */
    private fun checkProxy(context: Context): Boolean {
        // Method 1: System property check
        try {
            val httpProxy = System.getProperty(sHttpProxy)
            if (!httpProxy.isNullOrEmpty()) {
                return true
            }

            val httpsProxy = System.getProperty(sHttpsProxy)
            if (!httpsProxy.isNullOrEmpty()) {
                return true
            }
        } catch (e: Exception) {
            // Fail-closed: if we can't read proxy settings, assume proxy present
            return true
        }

        // Method 2: ConnectivityManager proxy info (API 23+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                val network = cm?.activeNetwork
                val linkProperties = cm?.getLinkProperties(network)
                val proxyInfo = linkProperties?.httpProxy
                if (proxyInfo != null && proxyInfo.host != null) {
                    return true
                }
            } catch (e: Exception) {
                // Fail-closed: if ConnectivityManager check fails, assume proxy
                return true
            }
        }

        // Method 3: Global proxy setting
        try {
            val globalProxy = android.provider.Settings.Global.getString(
                context.contentResolver,
                android.provider.Settings.Global.HTTP_PROXY
            )
            if (!globalProxy.isNullOrEmpty() && globalProxy != sColonZero) {
                return true
            }
        } catch (e: Exception) {
            // Fail-closed: if we can't read global proxy, assume proxy present
            return true
        }

        return false
    }

    /**
     * Detects active VPN connections.
     */
    private fun checkVpn(context: Context): Boolean {
        // Method 1: ConnectivityManager network capabilities (API 23+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                val activeNetwork = cm?.activeNetwork
                if (activeNetwork != null) {
                    val caps = cm.getNetworkCapabilities(activeNetwork)
                    if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        return true
                    }
                }
            } catch (e: Exception) {
                // Fail-closed: if VPN capability check fails, assume VPN present
                return true
            }
        }

        // Method 2: Check for tun/ppp/tap network interfaces
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (!iface.isUp) continue
                val name = iface.name.lowercase()
                if (name.startsWith(sTun) ||
                    name.startsWith(sPpp) ||
                    name.startsWith(sTap) ||
                    name.startsWith(sUtun) ||
                    name.startsWith(sIpsec)) {
                    return true
                }
            }
        } catch (e: Exception) {
            // Fail-closed: if network interface check fails, assume VPN present
            return true
        }

        return false
    }
}
