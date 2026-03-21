package com.neelakandan.flutter_neo_shield.secure
import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
class SecureStorageHandler(private val context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("flutter_neo_shield_secure", Context.MODE_PRIVATE)
    private val secretKey: SecretKey by lazy { getOrCreateKey() }
    fun write(key: String, value: String): Boolean {
        return try { prefs.edit().putString(key, encrypt(value)).apply(); true } catch (e: Exception) { false }
    }
    fun read(key: String): String? {
        return try { val enc = prefs.getString(key, null) ?: return null; decrypt(enc) } catch (e: Exception) { null }
    }
    fun delete(key: String): Boolean {
        return try { prefs.edit().remove(key).apply(); true } catch (e: Exception) { false }
    }
    fun containsKey(key: String): Boolean = prefs.contains(key)
    fun wipeAll(): Boolean {
        return try { prefs.edit().clear().apply(); true } catch (e: Exception) { false }
    }
    private fun encrypt(plaintext: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encrypted = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }
    private fun decrypt(ciphertext: String): String {
        val combined = Base64.decode(ciphertext, Base64.NO_WRAP)
        val iv = combined.copyOfRange(0, 12)
        val encrypted = combined.copyOfRange(12, combined.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        return String(cipher.doFinal(encrypted), Charsets.UTF_8)
    }
    private fun getOrCreateKey(): SecretKey {
        val kp = context.getSharedPreferences("flutter_neo_shield_key", Context.MODE_PRIVATE)
        val existing = kp.getString("aes_key", null)
        if (existing != null) return SecretKeySpec(Base64.decode(existing, Base64.NO_WRAP), "AES")
        val kg = KeyGenerator.getInstance("AES"); kg.init(256, SecureRandom())
        val key = kg.generateKey()
        kp.edit().putString("aes_key", Base64.encodeToString(key.encoded, Base64.NO_WRAP)).apply()
        return key
    }
}
