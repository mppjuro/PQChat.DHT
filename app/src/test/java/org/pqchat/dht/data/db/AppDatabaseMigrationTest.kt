package org.pqchat.dht.data.db

import android.database.Cursor
import androidx.sqlite.db.SupportSQLiteDatabase
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.pqchat.dht.crypto.KeystoreCrypto
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Proxy
import java.security.GeneralSecurityException
import javax.crypto.spec.SecretKeySpec

class AppDatabaseMigrationTest {

    private val testMasterKey = SecretKeySpec(ByteArray(32) { (it * 13 + 5).toByte() }, "AES")

    @Before
    fun setUp() {
        KeystoreCrypto.setTestSecretKey(testMasterKey)
    }

    private data class SkippedRow(
        val contactId: String,
        val slotIndex: Int,
        var msgKey: ByteArray,
        var edPrivateKeySeed: ByteArray
    )

    private data class OfferRow(
        val contactId: String,
        var skNew: ByteArray
    )

    private data class ChunkRow(
        val transferId: String,
        val chunkIndex: Int,
        var data: ByteArray
    )

    private fun createCursor(rows: List<List<Any>>): Cursor {
        var index = -1
        return Proxy.newProxyInstance(
            Cursor::class.java.classLoader,
            arrayOf(Cursor::class.java),
            InvocationHandler { _, method, args ->
                when (method.name) {
                    "moveToNext" -> {
                        index++
                        index < rows.size
                    }
                    "getString" -> {
                        val col = args[0] as Int
                        rows[index][col] as String
                    }
                    "getInt" -> {
                        val col = args[0] as Int
                        rows[index][col] as Int
                    }
                    "getBlob" -> {
                        val col = args[0] as Int
                        rows[index][col] as ByteArray
                    }
                    "close" -> null
                    else -> null
                }
            }
        ) as Cursor
    }

    @Test
    fun testMigration6To7EncryptsSensitiveDataAtRestWithRowBinding() {
        // Pre-migration plain data
        val rawMsgKey = ByteArray(32) { 0x11 }
        val rawEdSeed = ByteArray(32) { 0x22 }
        val rawSkNew = ByteArray(1632) { 0x33 } // ML-KEM private key
        val rawChunkData = "High-Resolution Image Chunk".toByteArray(Charsets.UTF_8)

        val skippedKeys = mutableListOf(
            SkippedRow("alice", 42, rawMsgKey.copyOf(), rawEdSeed.copyOf())
        )
        val pendingOffers = mutableListOf(
            OfferRow("bob", rawSkNew.copyOf())
        )
        val chunks = mutableListOf(
            ChunkRow("transfer_abc", 3, rawChunkData.copyOf())
        )

        // Mock SupportSQLiteDatabase
        val dbProxy = Proxy.newProxyInstance(
            SupportSQLiteDatabase::class.java.classLoader,
            arrayOf(SupportSQLiteDatabase::class.java),
            InvocationHandler { _, method, args ->
                when (method.name) {
                    "query" -> {
                        val sql = args[0] as String
                        when {
                            sql.contains("skipped_keys") -> {
                                val cursorRows = skippedKeys.map {
                                    listOf(it.contactId, it.slotIndex, it.msgKey, it.edPrivateKeySeed)
                                }
                                createCursor(cursorRows)
                            }
                            sql.contains("pending_rekey_offers") -> {
                                val cursorRows = pendingOffers.map {
                                    listOf(it.contactId, it.skNew)
                                }
                                createCursor(cursorRows)
                            }
                            sql.contains("chunks") -> {
                                val cursorRows = chunks.map {
                                    listOf(it.transferId, it.chunkIndex, it.data)
                                }
                                createCursor(cursorRows)
                            }
                            else -> createCursor(emptyList())
                        }
                    }
                    "execSQL" -> {
                        val sql = args[0] as String
                        val bindArgs = (args[1] as Array<*>).filterNotNull()
                        when {
                            sql.contains("UPDATE skipped_keys") -> {
                                val encMsgKey = bindArgs[0] as ByteArray
                                val encEdSeed = bindArgs[1] as ByteArray
                                val contactId = bindArgs[2] as String
                                val slotIndex = bindArgs[3] as Int
                                val row = skippedKeys.first { it.contactId == contactId && it.slotIndex == slotIndex }
                                row.msgKey = encMsgKey
                                row.edPrivateKeySeed = encEdSeed
                            }
                            sql.contains("UPDATE pending_rekey_offers") -> {
                                val encSkNew = bindArgs[0] as ByteArray
                                val contactId = bindArgs[1] as String
                                val row = pendingOffers.first { it.contactId == contactId }
                                row.skNew = encSkNew
                            }
                            sql.contains("UPDATE chunks") -> {
                                val encData = bindArgs[0] as ByteArray
                                val transferId = bindArgs[1] as String
                                val chunkIndex = bindArgs[2] as Int
                                val row = chunks.first { it.transferId == transferId && it.chunkIndex == chunkIndex }
                                row.data = encData
                            }
                        }
                        null
                    }
                    else -> null
                }
            }
        ) as SupportSQLiteDatabase

        // Execute MIGRATION_6_7
        AppDatabase.MIGRATION_6_7.migrate(dbProxy)

        // 1. Verify skipped_keys migration
        val migratedSkipped = skippedKeys.first()
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND, migratedSkipped.msgKey[0])
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND, migratedSkipped.edPrivateKeySeed[0])
        assertFalse("Ciphertext must not match raw plaintext", rawMsgKey.contentEquals(migratedSkipped.msgKey))
        assertFalse("Ciphertext must not match raw plaintext", rawEdSeed.contentEquals(migratedSkipped.edPrivateKeySeed))

        val decMsgKey = KeystoreCrypto.decrypt(migratedSkipped.msgKey, "skipped_keys", "alice_42")
        assertNotNull(decMsgKey)
        assertArrayEquals(rawMsgKey, decMsgKey)

        val decEdSeed = KeystoreCrypto.decrypt(migratedSkipped.edPrivateKeySeed, "skipped_keys", "alice_42")
        assertNotNull(decEdSeed)
        assertArrayEquals(rawEdSeed, decEdSeed)

        // 2. Verify pending_rekey_offers migration
        val migratedOffer = pendingOffers.first()
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND, migratedOffer.skNew[0])
        assertFalse("Ciphertext must not match raw plaintext", rawSkNew.contentEquals(migratedOffer.skNew))

        val decSkNew = KeystoreCrypto.decrypt(migratedOffer.skNew, "pending_rekey_offers", "bob")
        assertNotNull(decSkNew)
        assertArrayEquals(rawSkNew, decSkNew)

        // 3. Verify chunks migration
        val migratedChunk = chunks.first()
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND, migratedChunk.data[0])
        assertFalse("Ciphertext must not match raw plaintext", rawChunkData.contentEquals(migratedChunk.data))

        val decChunk = KeystoreCrypto.decrypt(migratedChunk.data, "chunks", "transfer_abc_3")
        assertNotNull(decChunk)
        assertArrayEquals(rawChunkData, decChunk)

        // 4. Verify AAD row-binding security (cross-row swap attempt rejected)
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decrypt(migratedSkipped.msgKey, "skipped_keys", "charlie_99")
        }
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decrypt(migratedOffer.skNew, "pending_rekey_offers", "charlie")
        }
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decrypt(migratedChunk.data, "chunks", "transfer_xyz_0")
        }
    }
}
