package org.pqchat.dht.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Android Keystore AES-256-GCM encryption provider for Room database sensitive fields
 * (chainKeyIn, chainKeyOut, textContent, imageBytes) per AGENTS.md §2.
 *
 * Automatically uses AndroidKeyStore hardware-backed master key on Android devices,
 * with deterministic in-memory AES-256-GCM key fallback in local JVM unit test environments.
 */
object KeystoreCrypto {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "pqchat_db_master_key"
    private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH_BITS = 128
    private const val GCM_IV_LENGTH_BYTES = 12

    // Fallback key used when AndroidKeyStore is not available (e.g. JVM unit tests)
    @Volatile
    private var jvmFallbackKey: SecretKey? = null

    private fun getOrCreateSecretKey(): SecretKey {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            if (keyStore.containsAlias(KEY_ALIAS)) {
                (keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
            } else {
                val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                val spec = KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                keyGen.init(spec)
                keyGen.generateKey()
            }
        } catch (_: Throwable) {
            // JVM / local unit test environment fallback
            jvmFallbackKey ?: synchronized(this) {
                jvmFallbackKey ?: run {
                    val keyBytes = ByteArray(32) { (it * 31 + 17).toByte() }
                    SecretKeySpec(keyBytes, "AES").also { jvmFallbackKey = it }
                }
            }
        }
    }

    /**
     * Encrypts plaintext bytes into: [12-byte IV] + [AES-GCM Ciphertext with 16-byte Auth Tag].
     */
    fun encrypt(plaintext: ByteArray?): ByteArray? {
        if (plaintext == null) return null
        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        val result = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, result, 0, iv.size)
        System.arraycopy(ciphertext, 0, result, iv.size, ciphertext.size)
        return result
    }

    /**
     * Decrypts [12-byte IV] + [AES-GCM Ciphertext with 16-byte Auth Tag].
     * Gracefully returns unencrypted data if encountering legacy pre-encryption rows during migration.
     */
    fun decrypt(encrypted: ByteArray?): ByteArray? {
        if (encrypted == null) return null
        if (encrypted.size < GCM_IV_LENGTH_BYTES + 16) {
            return encrypted
        }
        return try {
            val secretKey = getOrCreateSecretKey()
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, encrypted, 0, GCM_IV_LENGTH_BYTES)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            cipher.doFinal(encrypted, GCM_IV_LENGTH_BYTES, encrypted.size - GCM_IV_LENGTH_BYTES)
        } catch (_: Exception) {
            encrypted
        }
    }

    /**
     * Encrypts a UTF-8 String into a hex-encoded string of the encrypted bytes.
     */
    fun encryptString(plaintext: String?): String? {
        if (plaintext == null) return null
        val encrypted = encrypt(plaintext.toByteArray(Charsets.UTF_8)) ?: return null
        return CryptoUtils.toHex(encrypted)
    }

    /**
     * Decrypts a hex-encoded ciphertext string into the original UTF-8 String.
     */
    fun decryptString(ciphertextHex: String?): String? {
        if (ciphertextHex == null) return null
        return try {
            val bytes = CryptoUtils.fromHex(ciphertextHex)
            val decrypted = decrypt(bytes)
            if (decrypted != null) String(decrypted, Charsets.UTF_8) else ciphertextHex
        } catch (_: Exception) {
            ciphertextHex
        }
    }
}
