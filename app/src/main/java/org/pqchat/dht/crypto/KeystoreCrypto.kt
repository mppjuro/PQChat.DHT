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

    const val MAGIC_ROW_BOUND: Byte = 0x51 // ASCII 'Q' - v1 (table+id)
    const val MAGIC_ROW_BOUND_V2: Byte = 0x52 // ASCII 'R' - v2 (table+id+column)

    // Injected key provider used strictly in JVM unit test environments
    @Volatile
    private var testKeyProvider: (() -> SecretKey)? = null

    @Volatile
    private var isKeyWiped: Boolean = false

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
        isKeyWiped = false
    }

    /**
     * Checks if the master key has been permanently wiped via Duress PIN.
     */
    fun isMasterKeyWiped(): Boolean = isKeyWiped

    /**
     * Checks if the master key currently exists in AndroidKeyStore (or test provider).
     */
    fun hasMasterKey(): Boolean {
        if (isKeyWiped) return false
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.containsAlias(KEY_ALIAS)
        } catch (_: Throwable) {
            testKeyProvider != null
        }
    }

    /**
     * Permanently deletes the AES-256 master key from hardware AndroidKeyStore (Duress wipe).
     * Once destroyed, all past encrypted data in the Room database is irreversibly unrecoverable.
     * Subsequent encryption/decryption calls will immediately fail closed.
     */
    fun deleteMasterKey(): Boolean {
        isKeyWiped = true
        var deleted = false
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
                deleted = true
            }
        } catch (_: Throwable) {
            // AndroidKeyStore unavailable
        }
        if (testKeyProvider != null) {
            testKeyProvider = null
            deleted = true
        }
        return deleted
    }

    private fun getOrCreateSecretKey(): SecretKey {
        if (isKeyWiped) {
            throw IllegalStateException(
                "AndroidKeyStore master key was permanently destroyed by Duress wipe. Fail-closed."
            )
        }
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            if (keyStore.containsAlias(KEY_ALIAS)) {
                (keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
            } else {
                generateMasterKey()
            }
        } catch (_: Throwable) {
            // AndroidKeyStore unavailable — check injected test provider (JVM unit tests only)
            testKeyProvider?.invoke()
                ?: throw IllegalStateException(
                    "AndroidKeyStore is unavailable and no test key provider was registered. Fail-closed."
                )
        }
    }

    data class MasterKeyConfig(
        val alias: String,
        val keySize: Int,
        val blockModes: List<String>,
        val encryptionPaddings: List<String>,
        val useStrongBox: Boolean,
        val unlockedDeviceRequired: Boolean
    )

    fun getMasterKeyConfig(useStrongBox: Boolean, unlockedDeviceRequired: Boolean): MasterKeyConfig {
        return MasterKeyConfig(
            alias = KEY_ALIAS,
            keySize = 256,
            blockModes = listOf(KeyProperties.BLOCK_MODE_GCM),
            encryptionPaddings = listOf(KeyProperties.ENCRYPTION_PADDING_NONE),
            useStrongBox = useStrongBox,
            unlockedDeviceRequired = unlockedDeviceRequired
        )
    }

    /**
     * Generates AES-256 master key in hardware AndroidKeyStore:
     * 1. Attempts StrongBox HSM with setUnlockedDeviceRequired(true) on API 28+
     * 2. Falls back to standard TEE with setUnlockedDeviceRequired(true) if StrongBox is unavailable
     * 3. Falls back to standard TEE without unlocked requirement for legacy / unsupported devices
     */
    fun generateMasterKey(
        sdkInt: Int = android.os.Build.VERSION.SDK_INT,
        generator: (useStrongBox: Boolean, unlockedDeviceRequired: Boolean) -> SecretKey = { sb, udr ->
            generateKeyWithSpec(sb, udr)
        }
    ): SecretKey {
        if (sdkInt >= android.os.Build.VERSION_CODES.P) {
            // 1. Try hardware StrongBox HSM (Dedicated Security Chip / Titan M)
            try {
                return generator(true, true)
            } catch (_: Throwable) {
                // StrongBox not available on device hardware: proceed to standard TEE fallback
            }

            // 2. Try standard hardware TEE Keymaster with Unlocked Device requirement
            try {
                return generator(false, true)
            } catch (_: Throwable) {
                // If unlocked device required is not supported by OEM TEE implementation
            }
        }

        // 3. Fallback to standard hardware key without API 28+ constraints
        return generator(false, false)
    }

    private fun generateKeyWithSpec(useStrongBox: Boolean, unlockedDeviceRequired: Boolean): SecretKey {
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = buildKeyGenParameterSpec(useStrongBox, unlockedDeviceRequired)
        keyGen.init(spec)
        return keyGen.generateKey()
    }

    /**
     * Builds KeyGenParameterSpec with StrongBox and UnlockedDevice options.
     */
    fun buildKeyGenParameterSpec(useStrongBox: Boolean, unlockedDeviceRequired: Boolean): KeyGenParameterSpec {
        val config = getMasterKeyConfig(useStrongBox, unlockedDeviceRequired)
        val builder = KeyGenParameterSpec.Builder(
            config.alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(config.keySize)

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            if (config.useStrongBox) {
                builder.setIsStrongBoxBacked(true)
            }
            if (config.unlockedDeviceRequired) {
                builder.setUnlockedDeviceRequired(true)
            }
        }

        return builder.build()
    }

    /**
     * Computes the Additional Authenticated Data (AAD) for row-level and column-level binding:
     * table + "+" + id + "+" + column (if column is present), or table + "+" + id.
     */
    fun buildRowAad(table: String, id: String, column: String? = null): ByteArray {
        return if (column != null && column.isNotEmpty()) {
            "$table+$id+$column".toByteArray(Charsets.UTF_8)
        } else {
            "$table+$id".toByteArray(Charsets.UTF_8)
        }
    }

    data class DecryptedRow(
        val plaintext: ByteArray?,
        val table: String?,
        val id: String?,
        val column: String? = null
    )

    /**
     * Encrypts plaintext bytes with row-bound (and optionally column-bound) AAD:
     * If column is provided, uses v2 header:
     * [MAGIC_ROW_BOUND_V2 1B (0x52)] + [tableLen 1B] + [table] + [idLen 2B] + [id] + [colLen 1B] + [column] + [IV 12B] + [Ciphertext + Tag 16B].
     * AAD = table + "+" + id + "+" + column.
     * Otherwise uses legacy v1 header:
     * [MAGIC_ROW_BOUND 1B (0x51)] + [tableLen 1B] + [table] + [idLen 2B] + [id] + [IV 12B] + [Ciphertext + Tag 16B].
     * AAD = table + "+" + id.
     */
    fun encrypt(plaintext: ByteArray?, table: String, id: String, column: String? = null): ByteArray? {
        if (plaintext == null) return null
        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val aad = buildRowAad(table, id, column)
        cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext)
        val iv = cipher.iv

        val tableBytes = table.toByteArray(Charsets.UTF_8)
        val idBytes = id.toByteArray(Charsets.UTF_8)
        require(tableBytes.size <= 255) { "Table name too long (${tableBytes.size} bytes > 255)" }
        require(idBytes.size <= 65535) { "Row ID too long (${idBytes.size} bytes > 65535)" }

        if (column != null && column.isNotEmpty()) {
            val colBytes = column.toByteArray(Charsets.UTF_8)
            require(colBytes.size <= 255) { "Column name too long (${colBytes.size} bytes > 255)" }
            val totalSize = 1 + 1 + tableBytes.size + 2 + idBytes.size + 1 + colBytes.size + iv.size + ciphertext.size
            val out = ByteArray(totalSize)
            var idx = 0
            out[idx++] = MAGIC_ROW_BOUND_V2
            out[idx++] = tableBytes.size.toByte()
            System.arraycopy(tableBytes, 0, out, idx, tableBytes.size)
            idx += tableBytes.size
            out[idx++] = ((idBytes.size ushr 8) and 0xFF).toByte()
            out[idx++] = (idBytes.size and 0xFF).toByte()
            System.arraycopy(idBytes, 0, out, idx, idBytes.size)
            idx += idBytes.size
            out[idx++] = colBytes.size.toByte()
            System.arraycopy(colBytes, 0, out, idx, colBytes.size)
            idx += colBytes.size
            System.arraycopy(iv, 0, out, idx, iv.size)
            idx += iv.size
            System.arraycopy(ciphertext, 0, out, idx, ciphertext.size)
            return out
        } else {
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
    }

    /**
     * Encrypts plaintext bytes with optional AAD.
     * If aad contains "table+id+column" or "table+id", row/column-bound format is used.
     * Otherwise standard [IV 12B] + [Ciphertext + Tag 16B] is produced.
     */
    fun encrypt(plaintext: ByteArray?, aad: ByteArray? = null): ByteArray? {
        if (plaintext == null) return null
        if (aad != null && aad.isNotEmpty()) {
            val aadStr = String(aad, Charsets.UTF_8)
            val parts = aadStr.split('+', limit = 3)
            if (parts.size == 3) {
                return encrypt(plaintext, parts[0], parts[1], parts[2])
            } else if (parts.size == 2) {
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
     * Decrypts ciphertext and extracts row and column metadata (table, id, column) from header if present.
     * Enforces fail-closed behavior: never returns raw input on authentication failure.
     */
    fun decryptWithRowMetadata(
        encrypted: ByteArray?,
        expectedTable: String? = null,
        expectedId: String? = null,
        expectedColumn: String? = null
    ): DecryptedRow {
        if (encrypted == null) return DecryptedRow(null, null, null, null)
        if (encrypted.isEmpty()) {
            throw IllegalArgumentException("Ciphertext is empty")
        }

        if (encrypted[0] == MAGIC_ROW_BOUND_V2 && encrypted.size >= 1 + 1 + 2 + 1 + GCM_IV_LENGTH_BYTES + 16) {
            var offset = 1
            val tableLen = encrypted[offset++].toInt() and 0xFF
            if (offset + tableLen > encrypted.size) {
                throw IllegalArgumentException("Malformed row-bound v2 header: table length exceeds payload")
            }
            val table = String(encrypted, offset, tableLen, Charsets.UTF_8)
            offset += tableLen

            if (offset + 2 > encrypted.size) {
                throw IllegalArgumentException("Malformed row-bound v2 header: id length truncated")
            }
            val idLen = ((encrypted[offset++].toInt() and 0xFF) shl 8) or (encrypted[offset++].toInt() and 0xFF)
            if (offset + idLen > encrypted.size) {
                throw IllegalArgumentException("Malformed row-bound v2 header: id exceeds payload")
            }
            val id = String(encrypted, offset, idLen, Charsets.UTF_8)
            offset += idLen

            if (offset + 1 > encrypted.size) {
                throw IllegalArgumentException("Malformed row-bound v2 header: column length truncated")
            }
            val colLen = encrypted[offset++].toInt() and 0xFF
            if (offset + colLen + GCM_IV_LENGTH_BYTES + 16 > encrypted.size) {
                throw IllegalArgumentException("Malformed row-bound v2 header: ciphertext payload truncated")
            }
            val column = String(encrypted, offset, colLen, Charsets.UTF_8)
            offset += colLen

            if (expectedTable != null && table != expectedTable) {
                throw AEADBadTagException("Table mismatch: expected $expectedTable but found $table")
            }
            if (expectedId != null && id != expectedId) {
                throw AEADBadTagException("Row ID mismatch: expected $expectedId but found $id")
            }
            if (expectedColumn != null && column != expectedColumn) {
                throw AEADBadTagException("Column mismatch: expected $expectedColumn but found $column")
            }

            val aad = buildRowAad(table, id, column)
            val secretKey = getOrCreateSecretKey()
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, encrypted, offset, GCM_IV_LENGTH_BYTES)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            cipher.updateAAD(aad)
            val cipherOffset = offset + GCM_IV_LENGTH_BYTES
            val plain = cipher.doFinal(encrypted, cipherOffset, encrypted.size - cipherOffset)
            return DecryptedRow(plain, table, id, column)
        } else if (encrypted[0] == MAGIC_ROW_BOUND && encrypted.size >= 1 + 1 + 2 + GCM_IV_LENGTH_BYTES + 16) {
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
            if (expectedColumn != null) {
                throw AEADBadTagException("Column mismatch: expected $expectedColumn but ciphertext is legacy v1 without column binding")
            }

            val aad = buildRowAad(table, id)
            val secretKey = getOrCreateSecretKey()
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, encrypted, offset, GCM_IV_LENGTH_BYTES)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            cipher.updateAAD(aad)
            val cipherOffset = offset + GCM_IV_LENGTH_BYTES
            val plain = cipher.doFinal(encrypted, cipherOffset, encrypted.size - cipherOffset)
            return DecryptedRow(plain, table, id, null)
        } else {
            if (expectedTable != null || expectedId != null || expectedColumn != null) {
                throw AEADBadTagException("Ciphertext lacks required row-bound AAD header for table=$expectedTable, id=$expectedId, column=$expectedColumn")
            }
            if (encrypted.size < GCM_IV_LENGTH_BYTES + 16) {
                throw IllegalArgumentException("Ciphertext too short (${encrypted.size} bytes) for IV and GCM tag")
            }
            val secretKey = getOrCreateSecretKey()
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, encrypted, 0, GCM_IV_LENGTH_BYTES)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            val plain = cipher.doFinal(encrypted, GCM_IV_LENGTH_BYTES, encrypted.size - GCM_IV_LENGTH_BYTES)
            return DecryptedRow(plain, null, null, null)
        }
    }

    /**
     * Decrypts row-bound ciphertext and validates expected table, row ID, and column.
     */
    fun decrypt(encrypted: ByteArray?, table: String, id: String, column: String? = null): ByteArray? {
        if (encrypted == null) return null
        return decryptWithRowMetadata(encrypted, expectedTable = table, expectedId = id, expectedColumn = column).plaintext
    }

    /**
     * Decrypts ciphertext with optional AAD.
     */
    fun decrypt(encrypted: ByteArray?, aad: ByteArray? = null): ByteArray? {
        if (encrypted == null) return null
        if (aad != null && aad.isNotEmpty()) {
            val aadStr = String(aad, Charsets.UTF_8)
            val parts = aadStr.split('+', limit = 3)
            if (parts.size == 3) {
                return decrypt(encrypted, parts[0], parts[1], parts[2])
            } else if (parts.size == 2) {
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
     * Encrypts a UTF-8 String with row-bound (and optionally column-bound) AAD.
     */
    fun encryptString(plaintext: String?, table: String, id: String, column: String? = null): String? {
        if (plaintext == null) return null
        val enc = encrypt(plaintext.toByteArray(Charsets.UTF_8), table, id, column) ?: return null
        return CryptoUtils.toHex(enc)
    }

    /**
     * Decrypts a hex-encoded row-bound (and optionally column-bound) string.
     */
    fun decryptString(ciphertextHex: String?, table: String, id: String, column: String? = null): String? {
        if (ciphertextHex == null) return null
        val bytes = CryptoUtils.fromHex(ciphertextHex)
        val dec = decrypt(bytes, table, id, column) ?: return null
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
