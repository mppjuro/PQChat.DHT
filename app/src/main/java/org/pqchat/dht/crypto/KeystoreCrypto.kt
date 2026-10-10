package org.pqchat.dht.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore AES-256-GCM encryption provider for Room database sensitive fields
 * (chainKeyIn, chainKeyOut, textContent, imageBytes, skippedKeys, rekeyOffers, chunks) per AGENTS.md §2.
 *
 * Security properties:
 * - Fail-closed on Android: requires hardware-backed AndroidKeyStore master key.
 * - In JVM unit tests: only allows fallback via an explicitly injected test key provider (no hardcoded keys).
 * - Row binding: ciphertexts are cryptographically bound to their enclosing table and primary key (AAD: table+id).
 * - Integrity: on decryption failure, throws an exception and NEVER returns raw/unauthenticated data.
 */
object KeystoreCrypto {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "pqchat_db_master_key"
    private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH_BITS = 128
    const val GCM_IV_LENGTH_BYTES = 12

    const val MAGIC_ROW_BOUND: Byte = 0x51 // ASCII 'Q'

    // Injected key provider used strictly in JVM unit test environments
    @Volatile
    private var testKeyProvider: (() -> SecretKey)? = null

    /**
     * Injects a SecretKey provider for JVM unit tests where AndroidKeyStore is unavailable.
     * In production, this must remain null to guarantee fail-closed security.
     */
    fun setTestKeyProvider(provider: (() -> SecretKey)?) {
        testKeyProvider = provider
    }

    /**
     * Injects a static SecretKey for JVM unit tests.
     */
    fun setTestSecretKey(key: SecretKey?) {
        testKeyProvider = if (key != null) { { key } } else null
    }

    /**
     * Resets the test provider to simulate production fail-closed state.
     */
    fun resetForTesting() {
        testKeyProvider = null
    }

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
            // AndroidKeyStore unavailable — check injected test provider (JVM unit tests only)
            testKeyProvider?.invoke()
                ?: throw IllegalStateException(
                    "AndroidKeyStore is unavailable and no test key provider was registered. Fail-closed."
                )
        }
    }

    /**
     * Computes the Additional Authenticated Data (AAD) for row-level binding: table + "+" + id.
     */
    fun buildRowAad(table: String, id: String): ByteArray {
        return "$table+$id".toByteArray(Charsets.UTF_8)
    }

    data class DecryptedRow(
        val plaintext: ByteArray?,
        val table: String?,
        val id: String?
    )

    /**
     * Encrypts plaintext bytes with row-bound AAD:
     * Header format: [MAGIC 1B] + [tableLen 1B] + [table] + [idLen 2B] + [id] + [IV 12B] + [Ciphertext + Tag 16B].
     * AAD = table + id.
     */
    fun encrypt(plaintext: ByteArray?, table: String, id: String): ByteArray? {
        if (plaintext == null) return null
        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val aad = buildRowAad(table, id)
        cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext)
        val iv = cipher.iv

        val tableBytes = table.toByteArray(Charsets.UTF_8)
        val idBytes = id.toByteArray(Charsets.UTF_8)
        require(tableBytes.size <= 255) { "Table name too long (${tableBytes.size} bytes > 255)" }
        require(idBytes.size <= 65535) { "Row ID too long (${idBytes.size} bytes > 65535)" }

        val totalSize = 1 + 1 + tableBytes.size + 2 + idBytes.size + iv.size + ciphertext.size
        val out = ByteArray(totalSize)
        var idx = 0
        out[idx++] = MAGIC_ROW_BOUND
        out[idx++] = tableBytes.size.toByte()
        System.arraycopy(tableBytes, 0, out, idx, tableBytes.size)
        idx += tableBytes.size
        out[idx++] = ((idBytes.size ushr 8) and 0xFF).toByte()
        out[idx++] = (idBytes.size and 0xFF).toByte()
        System.arraycopy(idBytes, 0, out, idx, idBytes.size)
        idx += idBytes.size
        System.arraycopy(iv, 0, out, idx, iv.size)
        idx += iv.size
        System.arraycopy(ciphertext, 0, out, idx, ciphertext.size)
        return out
    }

    /**
     * Encrypts plaintext bytes with optional AAD.
     * If aad contains "table+id", row-bound format is used. Otherwise standard [IV 12B] + [Ciphertext + Tag 16B] is produced.
     */
    fun encrypt(plaintext: ByteArray?, aad: ByteArray? = null): ByteArray? {
        if (plaintext == null) return null
        if (aad != null && aad.isNotEmpty()) {
            val aadStr = String(aad, Charsets.UTF_8)
            val parts = aadStr.split('+', limit = 2)
            if (parts.size == 2) {
                return encrypt(plaintext, parts[0], parts[1])
            }
        }
        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        if (aad != null && aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        val result = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, result, 0, iv.size)
        System.arraycopy(ciphertext, 0, result, iv.size, ciphertext.size)
        return result
    }

    /**
     * Decrypts ciphertext and extracts row metadata (table, id) from header if present.
     * Enforces fail-closed behavior: never returns raw input on authentication failure.
     */
    fun decryptWithRowMetadata(
        encrypted: ByteArray?,
        expectedTable: String? = null,
        expectedId: String? = null
    ): DecryptedRow {
        if (encrypted == null) return DecryptedRow(null, null, null)
        if (encrypted.isEmpty()) {
            throw IllegalArgumentException("Ciphertext is empty")
        }

        if (encrypted[0] == MAGIC_ROW_BOUND && encrypted.size >= 1 + 1 + 2 + GCM_IV_LENGTH_BYTES + 16) {
            var offset = 1
            val tableLen = encrypted[offset++].toInt() and 0xFF
            if (offset + tableLen > encrypted.size) {
                throw IllegalArgumentException("Malformed row-bound header: table length exceeds payload")
            }
            val table = String(encrypted, offset, tableLen, Charsets.UTF_8)
            offset += tableLen

            if (offset + 2 > encrypted.size) {
                throw IllegalArgumentException("Malformed row-bound header: id length truncated")
            }
            val idLen = ((encrypted[offset++].toInt() and 0xFF) shl 8) or (encrypted[offset++].toInt() and 0xFF)
            if (offset + idLen + GCM_IV_LENGTH_BYTES + 16 > encrypted.size) {
                throw IllegalArgumentException("Malformed row-bound header: ciphertext payload truncated")
            }
            val id = String(encrypted, offset, idLen, Charsets.UTF_8)
            offset += idLen

            if (expectedTable != null && table != expectedTable) {
                throw AEADBadTagException("Table mismatch: expected $expectedTable but found $table")
            }
            if (expectedId != null && id != expectedId) {
                throw AEADBadTagException("Row ID mismatch: expected $expectedId but found $id")
            }

            val aad = buildRowAad(table, id)
            val secretKey = getOrCreateSecretKey()
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, encrypted, offset, GCM_IV_LENGTH_BYTES)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            cipher.updateAAD(aad)
            val cipherOffset = offset + GCM_IV_LENGTH_BYTES
            val plain = cipher.doFinal(encrypted, cipherOffset, encrypted.size - cipherOffset)
            return DecryptedRow(plain, table, id)
        } else {
            if (expectedTable != null || expectedId != null) {
                throw AEADBadTagException("Ciphertext lacks required row-bound AAD header for table=$expectedTable, id=$expectedId")
            }
            if (encrypted.size < GCM_IV_LENGTH_BYTES + 16) {
                throw IllegalArgumentException("Ciphertext too short (${encrypted.size} bytes) for IV and GCM tag")
            }
            val secretKey = getOrCreateSecretKey()
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, encrypted, 0, GCM_IV_LENGTH_BYTES)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            val plain = cipher.doFinal(encrypted, GCM_IV_LENGTH_BYTES, encrypted.size - GCM_IV_LENGTH_BYTES)
            return DecryptedRow(plain, null, null)
        }
    }

    /**
     * Decrypts row-bound ciphertext and validates expected table and row ID.
     */
    fun decrypt(encrypted: ByteArray?, table: String, id: String): ByteArray? {
        if (encrypted == null) return null
        return decryptWithRowMetadata(encrypted, expectedTable = table, expectedId = id).plaintext
    }

    /**
     * Decrypts ciphertext with optional AAD.
     */
    fun decrypt(encrypted: ByteArray?, aad: ByteArray? = null): ByteArray? {
        if (encrypted == null) return null
        if (aad != null && aad.isNotEmpty()) {
            val aadStr = String(aad, Charsets.UTF_8)
            val parts = aadStr.split('+', limit = 2)
            if (parts.size == 2) {
                return decrypt(encrypted, parts[0], parts[1])
            }
            if (encrypted.size < GCM_IV_LENGTH_BYTES + 16) {
                throw IllegalArgumentException("Ciphertext too short for IV and GCM tag")
            }
            val secretKey = getOrCreateSecretKey()
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, encrypted, 0, GCM_IV_LENGTH_BYTES)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            cipher.updateAAD(aad)
            return cipher.doFinal(encrypted, GCM_IV_LENGTH_BYTES, encrypted.size - GCM_IV_LENGTH_BYTES)
        }
        return decryptWithRowMetadata(encrypted).plaintext
    }

    /**
     * Encrypts a UTF-8 String with row-bound AAD.
     */
    fun encryptString(plaintext: String?, table: String, id: String): String? {
        if (plaintext == null) return null
        val enc = encrypt(plaintext.toByteArray(Charsets.UTF_8), table, id) ?: return null
        return CryptoUtils.toHex(enc)
    }

    /**
     * Decrypts a hex-encoded row-bound string.
     */
    fun decryptString(ciphertextHex: String?, table: String, id: String): String? {
        if (ciphertextHex == null) return null
        val bytes = CryptoUtils.fromHex(ciphertextHex)
        val dec = decrypt(bytes, table, id) ?: return null
        return String(dec, Charsets.UTF_8)
    }

    /**
     * Encrypts a UTF-8 String into a hex-encoded string of the encrypted bytes.
     */
    fun encryptString(plaintext: String?, aad: ByteArray? = null): String? {
        if (plaintext == null) return null
        val encrypted = encrypt(plaintext.toByteArray(Charsets.UTF_8), aad) ?: return null
        return CryptoUtils.toHex(encrypted)
    }

    /**
     * Decrypts a hex-encoded ciphertext string into the original UTF-8 String.
     */
    fun decryptString(ciphertextHex: String?, aad: ByteArray? = null): String? {
        if (ciphertextHex == null) return null
        val bytes = CryptoUtils.fromHex(ciphertextHex)
        val decrypted = decrypt(bytes, aad) ?: return null
        return String(decrypted, Charsets.UTF_8)
    }
}
