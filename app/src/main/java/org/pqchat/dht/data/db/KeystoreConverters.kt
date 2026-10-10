package org.pqchat.dht.data.db

import androidx.room.TypeConverter
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.KeystoreCrypto

/**
 * Encrypted byte array wrapper for Room database storage.
 * Automatically encrypted with Android Keystore AES-256-GCM and bound to table+id when persisted.
 */
data class EncryptedBlob(
    val raw: ByteArray,
    val boundTable: String? = null,
    val boundId: String? = null
) {
    val size: Int get() = raw.size
    fun copyOf(): ByteArray = raw.copyOf()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other is EncryptedBlob) return raw.contentEquals(other.raw)
        if (other is ByteArray) return raw.contentEquals(other)
        return false
    }

    override fun hashCode(): Int = raw.contentHashCode()
}

/**
 * Encrypted string wrapper for Room database storage.
 * Automatically encrypted with Android Keystore AES-256-GCM and bound to table+id when persisted.
 */
data class EncryptedText(
    val raw: String,
    val boundTable: String? = null,
    val boundId: String? = null
) : CharSequence by raw {
    override fun toString(): String = raw

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other is EncryptedText) return raw == other.raw
        if (other is CharSequence) return raw == other.toString()
        return false
    }

    override fun hashCode(): Int = raw.hashCode()
}

/**
 * Room TypeConverters providing transparent Android Keystore encryption
 * with row-bound AAD for sensitive fields per AGENTS.md §2.
 */
class KeystoreConverters {

    @TypeConverter
    fun toDatabaseBlob(encrypted: EncryptedBlob?): ByteArray? {
        if (encrypted == null) return null
        return if (encrypted.boundTable != null && encrypted.boundId != null) {
            KeystoreCrypto.encrypt(encrypted.raw, encrypted.boundTable, encrypted.boundId)
        } else {
            KeystoreCrypto.encrypt(encrypted.raw)
        }
    }

    @TypeConverter
    fun fromDatabaseBlob(blob: ByteArray?): EncryptedBlob? {
        if (blob == null) return null
        val result = KeystoreCrypto.decryptWithRowMetadata(blob)
        return result.plaintext?.let { EncryptedBlob(it, result.table, result.id) }
    }

    @TypeConverter
    fun toDatabaseText(encrypted: EncryptedText?): String? {
        if (encrypted == null) return null
        val bytes = if (encrypted.boundTable != null && encrypted.boundId != null) {
            KeystoreCrypto.encrypt(encrypted.raw.toByteArray(Charsets.UTF_8), encrypted.boundTable, encrypted.boundId)
        } else {
            KeystoreCrypto.encrypt(encrypted.raw.toByteArray(Charsets.UTF_8))
        } ?: return null
        return CryptoUtils.toHex(bytes)
    }

    @TypeConverter
    fun fromDatabaseText(textHex: String?): EncryptedText? {
        if (textHex == null) return null
        val bytes = CryptoUtils.fromHex(textHex)
        val result = KeystoreCrypto.decryptWithRowMetadata(bytes)
        return result.plaintext?.let { EncryptedText(String(it, Charsets.UTF_8), result.table, result.id) }
    }
}
