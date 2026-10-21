package org.pqchat.dht.data.db

import androidx.room.TypeConverter
import javax.crypto.AEADBadTagException
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.KeystoreCrypto

/**
 * Encrypted byte array wrapper for Room database storage.
 * Automatically encrypted with Android Keystore AES-256-GCM and bound to table+id when persisted.
 */
data class EncryptedBlob(
    val raw: ByteArray,
    val boundTable: String? = null,
    val boundId: String? = null,
    val boundColumn: String? = null
) {
    val size: Int get() = raw.size
    fun copyOf(): ByteArray = raw.copyOf()

    /**
     * Validates that this ciphertext was bound to the expected table, row ID, and column.
     * Throws [AEADBadTagException] if a row-swap, table-swap, or column-swap attack occurred.
     */
    fun validateRowBinding(
        expectedTable: String,
        expectedId: String,
        expectedColumn: String? = null,
        fieldName: String = "field"
    ) {
        if (boundTable != expectedTable || boundId != expectedId || (expectedColumn != null && boundColumn != expectedColumn)) {
            throw AEADBadTagException(
                "Row/column binding mismatch on $fieldName: expected table='$expectedTable', id='$expectedId', column='$expectedColumn', " +
                "but got table='${boundTable ?: "<unbound>"}', id='${boundId ?: "<unbound>"}', column='${boundColumn ?: "<unbound>"}'"
            )
        }
    }

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
 * Automatically encrypted with Android Keystore AES-256-GCM and bound to table+id+column when persisted.
 */
data class EncryptedText(
    val raw: String,
    val boundTable: String? = null,
    val boundId: String? = null,
    val boundColumn: String? = null
) : CharSequence by raw {
    override fun toString(): String = raw

    /**
     * Validates that this ciphertext was bound to the expected table, row ID, and column.
     * Throws [AEADBadTagException] if a row-swap, table-swap, or column-swap attack occurred.
     */
    fun validateRowBinding(
        expectedTable: String,
        expectedId: String,
        expectedColumn: String? = null,
        fieldName: String = "field"
    ) {
        if (boundTable != expectedTable || boundId != expectedId || (expectedColumn != null && boundColumn != expectedColumn)) {
            throw AEADBadTagException(
                "Row/column binding mismatch on $fieldName: expected table='$expectedTable', id='$expectedId', column='$expectedColumn', " +
                "but got table='${boundTable ?: "<unbound>"}', id='${boundId ?: "<unbound>"}', column='${boundColumn ?: "<unbound>"}'"
            )
        }
    }

    fun take(n: Int): String = raw.take(n)
    fun uppercase(): String = raw.uppercase()
    fun lowercase(): String = raw.lowercase()
    fun ifEmpty(defaultValue: () -> String): String = raw.ifEmpty(defaultValue)
    fun isBlank(): Boolean = raw.isBlank()
    fun isNotBlank(): Boolean = raw.isNotBlank()
    fun isEmpty(): Boolean = raw.isEmpty()
    fun isNotEmpty(): Boolean = raw.isNotEmpty()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other is EncryptedText) return raw == other.raw
        if (other is CharSequence) return raw == other.toString()
        return false
    }

    override fun hashCode(): Int = raw.hashCode()
}

/**
 * Encrypted 64-bit Long wrapper for Room database storage.
 * Automatically encrypted with Android Keystore AES-256-GCM and bound to table+id+column (MAGIC_ROW_BOUND_V2) when persisted.
 */
data class EncryptedLong(
    val raw: Long,
    val boundTable: String? = null,
    val boundId: String? = null,
    val boundColumn: String? = null
) : Comparable<EncryptedLong> {
    override fun compareTo(other: EncryptedLong): Int = raw.compareTo(other.raw)
    operator fun compareTo(other: Long): Int = raw.compareTo(other)
    operator fun compareTo(other: Int): Int = raw.compareTo(other.toLong())
    operator fun times(other: Long): Long = raw * other
    operator fun times(other: Int): Long = raw * other.toLong()
    operator fun plus(other: Long): Long = raw + other
    operator fun minus(other: Long): Long = raw - other
    fun toLong(): Long = raw
    fun toInt(): Int = raw.toInt()

    /**
     * Validates that this ciphertext was bound to the expected table, row ID, and column.
     * Throws [AEADBadTagException] if a row-swap, table-swap, or column-swap attack occurred.
     */
    fun validateRowBinding(
        expectedTable: String,
        expectedId: String,
        expectedColumn: String? = null,
        fieldName: String = "field"
    ) {
        if (boundTable != expectedTable || boundId != expectedId || (expectedColumn != null && boundColumn != expectedColumn)) {
            throw AEADBadTagException(
                "Row/column binding mismatch on $fieldName: expected table='$expectedTable', id='$expectedId', column='$expectedColumn', " +
                "but got table='${boundTable ?: "<unbound>"}', id='${boundId ?: "<unbound>"}', column='${boundColumn ?: "<unbound>"}'"
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other is EncryptedLong) return raw == other.raw
        if (other is Number) return raw == other.toLong()
        return false
    }

    override fun hashCode(): Int = raw.hashCode()

    override fun toString(): String = raw.toString()
}

/**
 * Room TypeConverters providing transparent Android Keystore encryption
 * with row-bound and column-bound AAD for sensitive fields per AGENTS.md §2.
 */
class KeystoreConverters {

    @TypeConverter
    fun toDatabaseBlob(encrypted: EncryptedBlob?): ByteArray? {
        if (encrypted == null) return null
        require(encrypted.boundTable != null && encrypted.boundId != null && encrypted.boundColumn != null) {
            "EncryptedBlob must be bound with MAGIC_ROW_BOUND_V2 (boundTable, boundId, boundColumn must be non-null)"
        }
        return KeystoreCrypto.encrypt(encrypted.raw, encrypted.boundTable, encrypted.boundId, encrypted.boundColumn)
    }

    @TypeConverter
    fun fromDatabaseBlob(blob: ByteArray?): EncryptedBlob? {
        if (blob == null) return null
        val result = KeystoreCrypto.decryptWithRowMetadata(blob)
        return result.plaintext?.let { EncryptedBlob(it, result.table, result.id, result.column) }
    }

    @TypeConverter
    fun toDatabaseText(encrypted: EncryptedText?): String? {
        if (encrypted == null) return null
        require(encrypted.boundTable != null && encrypted.boundId != null && encrypted.boundColumn != null) {
            "EncryptedText must be bound with MAGIC_ROW_BOUND_V2 (boundTable, boundId, boundColumn must be non-null)"
        }
        val bytes = KeystoreCrypto.encrypt(encrypted.raw.toByteArray(Charsets.UTF_8), encrypted.boundTable, encrypted.boundId, encrypted.boundColumn)
            ?: return null
        return CryptoUtils.toHex(bytes)
    }

    @TypeConverter
    fun fromDatabaseText(textHex: String?): EncryptedText? {
        if (textHex == null) return null
        val bytes = CryptoUtils.fromHex(textHex)
        val result = KeystoreCrypto.decryptWithRowMetadata(bytes)
        return result.plaintext?.let { EncryptedText(String(it, Charsets.UTF_8), result.table, result.id, result.column) }
    }

    @TypeConverter
    fun toDatabaseLong(encrypted: EncryptedLong?): String? {
        if (encrypted == null) return null
        require(encrypted.boundTable != null && encrypted.boundId != null && encrypted.boundColumn != null) {
            "EncryptedLong must be bound with MAGIC_ROW_BOUND_V2 (boundTable, boundId, boundColumn must be non-null)"
        }
        val buffer = java.nio.ByteBuffer.allocate(8).putLong(encrypted.raw).array()
        val bytes = KeystoreCrypto.encrypt(buffer, encrypted.boundTable, encrypted.boundId, encrypted.boundColumn)
            ?: return null
        return CryptoUtils.toHex(bytes)
    }

    @TypeConverter
    fun fromDatabaseLong(textHex: String?): EncryptedLong? {
        if (textHex == null) return null
        val bytes = CryptoUtils.fromHex(textHex)
        val result = KeystoreCrypto.decryptWithRowMetadata(bytes)
        return result.plaintext?.let {
            val longVal = java.nio.ByteBuffer.wrap(it).long
            EncryptedLong(longVal, result.table, result.id, result.column)
        }
    }
}
