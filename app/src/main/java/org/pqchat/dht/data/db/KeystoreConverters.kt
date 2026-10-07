package org.pqchat.dht.data.db

import androidx.room.TypeConverter
import org.pqchat.dht.crypto.KeystoreCrypto

/**
 * Encrypted byte array wrapper for Room database storage.
 * Automatically encrypted with Android Keystore AES-256-GCM when persisted.
 */
data class EncryptedBlob(val raw: ByteArray) {
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
 * Automatically encrypted with Android Keystore AES-256-GCM when persisted.
 */
data class EncryptedText(val raw: String) : CharSequence by raw {
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
 * for sensitive fields per AGENTS.md §2.
 */
class KeystoreConverters {

    @TypeConverter
    fun toDatabaseBlob(encrypted: EncryptedBlob?): ByteArray? {
        return KeystoreCrypto.encrypt(encrypted?.raw)
    }

    @TypeConverter
    fun fromDatabaseBlob(blob: ByteArray?): EncryptedBlob? {
        return KeystoreCrypto.decrypt(blob)?.let { EncryptedBlob(it) }
    }

    @TypeConverter
    fun toDatabaseText(encrypted: EncryptedText?): String? {
        return KeystoreCrypto.encryptString(encrypted?.raw)
    }

    @TypeConverter
    fun fromDatabaseText(text: String?): EncryptedText? {
        return KeystoreCrypto.decryptString(text)?.let { EncryptedText(it) }
    }
}
