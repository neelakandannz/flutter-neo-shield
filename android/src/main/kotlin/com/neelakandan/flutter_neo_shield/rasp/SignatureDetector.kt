package com.neelakandan.flutter_neo_shield.rasp

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Detects APK repackaging by verifying the signing certificate hash
 * and checking classes.dex integrity.
 */
class SignatureDetector {

    companion object {
        private val _k = intArrayOf(0x32 + 0x1C, 0x41 + 0x12, 0x24 + 0x24, 0x3E + 0x0E, 0x22 + 0x22)
        private fun d(vararg e: Int): String = String(CharArray(e.size) { i -> (e[i] xor _k[i % _k.size]).toChar() })

        private val sCnDebug = d(13,29,117,13,42,42,33,39,37,32,110,23,45,46,49,41)
        private val sCUsDebug = d(13,110,29,31,104,1,110,9,34,32,60,60,33,40,104,13,29,117,13,42,42,33,39,37,32,110,23,45,46,49,41)
        private val sX509 = d(22,125,125,124,125)
        private val sSha256 = d(29,27,9,97,118,123,101)
        private val sClassesDex = d(45,63,41,63,55,43,32,102,40,33,54)
    }

    fun check(
        context: Context,
        expectedSignatureHash: String? = null,
        expectedDexHashes: List<String>? = null
    ): Map<String, Any> {
        val result = mutableMapOf<String, Any>(
            "signatureTampered" to false,
            "dexTampered" to false,
            "detected" to false
        )

        try {
            val signatureTampered = checkSignature(context, expectedSignatureHash)
            result["signatureTampered"] = signatureTampered

            val dexTampered = if (expectedDexHashes != null) {
                checkDexIntegrity(context, expectedDexHashes)
            } else {
                false
            }
            result["dexTampered"] = dexTampered

            result["detected"] = signatureTampered || dexTampered
        } catch (e: Exception) {
            // Fail closed: if we can't verify, assume tampered
            result["signatureTampered"] = true
            result["detected"] = true
        }

        return result
    }

    fun checkSimple(context: Context): Boolean {
        return try {
            checkSignature(context, null)
        } catch (e: Exception) {
            true // fail closed
        }
    }

    @Suppress("DEPRECATION")
    private fun checkSignature(context: Context, expectedHash: String?): Boolean {
        val pm = context.packageManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val packageInfo = pm.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
            )
            val signingInfo = packageInfo.signingInfo ?: return true

            val signers = if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            }

            if (signers == null || signers.isEmpty()) {
                return true
            }

            if (signingInfo.hasMultipleSigners() && signers.size > 1) {
                return true
            }

            if (expectedHash != null) {
                val currentHash = sha256Hex(signers[0].toByteArray())
                if (!currentHash.equals(expectedHash, ignoreCase = true)) {
                    return true
                }
            }

            val certBytes = signers[0].toByteArray()
            if (isDebugCertificate(certBytes)) {
                return true
            }

        } else {
            val packageInfo = pm.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )
            val signatures = packageInfo.signatures

            if (signatures == null || signatures.isEmpty()) {
                return true
            }

            if (signatures.size > 1) {
                return true
            }

            if (expectedHash != null) {
                val currentHash = sha256Hex(signatures[0].toByteArray())
                if (!currentHash.equals(expectedHash, ignoreCase = true)) {
                    return true
                }
            }

            if (isDebugCertificate(signatures[0].toByteArray())) {
                return true
            }
        }

        return false
    }

    private fun checkDexIntegrity(context: Context, expectedHashes: List<String>): Boolean {
        try {
            val apkPath = context.applicationInfo.sourceDir
            ZipFile(apkPath).use { zipFile ->
                for (i in expectedHashes.indices) {
                    val dexName = if (i == 0) sClassesDex else sClassesDex.replaceFirst(".", "${i + 1}.")
                    val entry = zipFile.getEntry(dexName) ?: return true

                    zipFile.getInputStream(entry).use { inputStream ->
                        val md = MessageDigest.getInstance(sSha256)
                        val buffer = ByteArray(8192)
                        var bytesRead: Int
                        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                            md.update(buffer, 0, bytesRead)
                        }

                        val currentHash = md.digest().joinToString("") { "%02x".format(it) }
                        if (!currentHash.equals(expectedHashes[i], ignoreCase = true)) {
                            return true
                        }
                    }
                }
            }
        } catch (e: Exception) {
            return true // fail closed
        }
        return false
    }

    /**
     * Heuristic: debug certificates typically use CN=Android Debug.
     */
    private fun isDebugCertificate(certBytes: ByteArray): Boolean {
        try {
            val certFactory = java.security.cert.CertificateFactory.getInstance(sX509)
            val cert = certFactory.generateCertificate(certBytes.inputStream()) as java.security.cert.X509Certificate
            val issuer = cert.issuerDN.name
            if (issuer.contains(sCnDebug, ignoreCase = true) ||
                issuer.contains(sCUsDebug, ignoreCase = true)) {
                return true
            }
        } catch (e: Exception) {
            // If we can't parse the cert, don't flag this specific check
        }
        return false
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance(sSha256)
        val digest = md.digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    @Suppress("DEPRECATION")
    fun getCurrentSignatureHash(context: Context): String? {
        return try {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val packageInfo = pm.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                val signers = if (packageInfo.signingInfo.hasMultipleSigners()) {
                    packageInfo.signingInfo.apkContentsSigners
                } else {
                    packageInfo.signingInfo.signingCertificateHistory
                }
                if (signers != null && signers.isNotEmpty()) {
                    sha256Hex(signers[0].toByteArray())
                } else null
            } else {
                val packageInfo = pm.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
                if (packageInfo.signatures != null && packageInfo.signatures.isNotEmpty()) {
                    sha256Hex(packageInfo.signatures[0].toByteArray())
                } else null
            }
        } catch (e: Exception) {
            null
        }
    }
}
