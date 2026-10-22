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

    private fun createCursor(rows: List<List<Any?>>): Cursor {
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
                        rows[index][col] as? String
                    }
                    "getInt" -> {
                        val col = args[0] as Int
                        (rows[index][col] as? Number)?.toInt() ?: 0
                    }
                    "getLong" -> {
                        val col = args[0] as Int
                        (rows[index][col] as? Number)?.toLong() ?: 0L
                    }
                    "getBlob" -> {
                        val col = args[0] as Int
                        rows[index][col] as? ByteArray
                    }
                    "isNull" -> {
                        val col = args[0] as Int
                        rows[index][col] == null
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

    @Test
    fun testMigration7To8AddsIsVerifiedColumnToContacts() {
        var executedSql = ""
        val dbProxy = Proxy.newProxyInstance(
            SupportSQLiteDatabase::class.java.classLoader,
            arrayOf(SupportSQLiteDatabase::class.java),
            InvocationHandler { _, method, args ->
                if (method.name == "execSQL") {
                    executedSql = args[0] as String
                }
                null
            }
        ) as SupportSQLiteDatabase

        AppDatabase.MIGRATION_7_8.migrate(dbProxy)

        assertTrue(
            "Migration 7->8 must alter contacts table to add isVerified column",
            executedSql.contains("ALTER TABLE contacts ADD COLUMN isVerified INTEGER NOT NULL DEFAULT 0")
        )
    }

    private data class ContactRow(
        val id: String,
        var name: String,
        var chainKeyOut: ByteArray,
        var chainKeyIn: ByteArray,
        var sas: String,
        var fingerprint: String
    )

    private data class GroupRow(
        val groupId: String,
        var groupName: String,
        var myChainKeyOut: ByteArray
    )

    private data class GroupMemberRow(
        val groupId: String,
        val memberId: String,
        var memberName: String,
        var chainKeyIn: ByteArray
    )

    private data class MessageRow(
        val id: Long,
        val contactId: String,
        val isOutgoing: Int,
        val seqEpoch: Int,
        val seqNum: Int,
        var textContent: String?,
        var imageBytes: ByteArray?,
        var ackRatchetKey: ByteArray?,
        var slotEdSeed: ByteArray?,
        var senderMemberId: String?,
        var senderName: String?
    )

    private data class PendingTransferRow(
        val transferId: String,
        var baseEdSeed: ByteArray,
        var baseMsgKey: ByteArray
    )

    @Test
    fun testMigration10To11ReEncryptsToV2WithColumnBindingAndEncryptsMetadata() {
        val rawChainOut = ByteArray(64) { 0x01 }
        val rawChainIn = ByteArray(64) { 0x02 }
        val rawGroupKey = ByteArray(64) { 0x03 }
        val rawMemberKey = ByteArray(64) { 0x04 }
        val rawMsgKey = ByteArray(32) { 0x05 }
        val rawEdSeed = ByteArray(32) { 0x06 }
        val rawSkNew = ByteArray(1632) { 0x07 }
        val rawChunkData = "Image Chunk Binary Payload".toByteArray()
        val rawBaseSeed = ByteArray(32) { 0x08 }
        val rawBaseKey = ByteArray(32) { 0x09 }

        // V10 pre-migration data:
        // Plain text metadata and V1 encrypted row-bound blobs
        val contacts = mutableListOf(
            ContactRow(
                id = "peer_alice",
                name = "Alice Wonderland",
                chainKeyOut = KeystoreCrypto.encrypt(rawChainOut, "contacts", "peer_alice")!!,
                chainKeyIn = KeystoreCrypto.encrypt(rawChainIn, "contacts", "peer_alice")!!,
                sas = "9988",
                fingerprint = "FP-ALICE-10"
            )
        )
        val groups = mutableListOf(
            GroupRow(
                groupId = "group_quantum",
                groupName = "Quantum Vanguard",
                myChainKeyOut = KeystoreCrypto.encrypt(rawGroupKey, "groups", "group_quantum")!!
            )
        )
        val members = mutableListOf(
            GroupMemberRow(
                groupId = "group_quantum",
                memberId = "member_bob",
                memberName = "Bob Builder",
                chainKeyIn = KeystoreCrypto.encrypt(rawMemberKey, "group_members", "group_quantum_member_bob")!!
            )
        )
        val messages = mutableListOf(
            MessageRow(
                id = 101L,
                contactId = "peer_alice",
                isOutgoing = 0,
                seqEpoch = 0,
                seqNum = 7,
                textContent = KeystoreCrypto.encryptString("Sensitive message content", "messages", "peer_alice")!!,
                imageBytes = null,
                ackRatchetKey = null,
                slotEdSeed = null,
                senderMemberId = "alice_uuid_val",
                senderName = "Alice Wonderland"
            )
        )
        val skippedKeys = mutableListOf(
            SkippedRow(
                contactId = "peer_alice",
                slotIndex = 3,
                msgKey = KeystoreCrypto.encrypt(rawMsgKey, "skipped_keys", "peer_alice_3")!!,
                edPrivateKeySeed = KeystoreCrypto.encrypt(rawEdSeed, "skipped_keys", "peer_alice_3")!!
            )
        )
        val pendingOffers = mutableListOf(
            OfferRow(
                contactId = "peer_alice",
                skNew = KeystoreCrypto.encrypt(rawSkNew, "pending_rekey_offers", "peer_alice")!!
            )
        )
        val chunks = mutableListOf(
            ChunkRow(
                transferId = "transfer_42",
                chunkIndex = 1,
                data = KeystoreCrypto.encrypt(rawChunkData, "chunks", "transfer_42_1")!!
            )
        )
        val pendingTransfers = mutableListOf(
            PendingTransferRow(
                transferId = "transfer_42",
                baseEdSeed = KeystoreCrypto.encrypt(rawBaseSeed, "pending_chunk_transfers", "transfer_42_seed")!!,
                baseMsgKey = KeystoreCrypto.encrypt(rawBaseKey, "pending_chunk_transfers", "transfer_42_key")!!
            )
        )

        val dbProxy = Proxy.newProxyInstance(
            SupportSQLiteDatabase::class.java.classLoader,
            arrayOf(SupportSQLiteDatabase::class.java),
            InvocationHandler { _, method, args ->
                when (method.name) {
                    "query" -> {
                        val sql = args[0] as String
                        when {
                            sql.contains("FROM contacts") -> {
                                val rows = contacts.map {
                                    listOf(it.id, it.name, it.chainKeyOut, it.chainKeyIn, it.sas, it.fingerprint)
                                }
                                createCursor(rows)
                            }
                            sql.contains("FROM groups") -> {
                                val rows = groups.map {
                                    listOf(it.groupId, it.groupName, it.myChainKeyOut)
                                }
                                createCursor(rows)
                            }
                            sql.contains("FROM group_members") -> {
                                val rows = members.map {
                                    listOf(it.groupId, it.memberId, it.memberName, it.chainKeyIn)
                                }
                                createCursor(rows)
                            }
                            sql.contains("FROM messages") -> {
                                val rows = messages.map {
                                    listOf(it.id, it.contactId, it.isOutgoing, it.seqEpoch, it.seqNum, it.textContent, it.imageBytes, it.ackRatchetKey, it.slotEdSeed, it.senderMemberId, it.senderName)
                                }
                                createCursor(rows)
                            }
                            sql.contains("FROM skipped_keys") -> {
                                val rows = skippedKeys.map {
                                    listOf(it.contactId, it.slotIndex, it.msgKey, it.edPrivateKeySeed)
                                }
                                createCursor(rows)
                            }
                            sql.contains("FROM pending_rekey_offers") -> {
                                val rows = pendingOffers.map {
                                    listOf(it.contactId, it.skNew)
                                }
                                createCursor(rows)
                            }
                            sql.contains("FROM chunks") -> {
                                val rows = chunks.map {
                                    listOf(it.transferId, it.chunkIndex, it.data)
                                }
                                createCursor(rows)
                            }
                            sql.contains("FROM pending_chunk_transfers") -> {
                                val rows = pendingTransfers.map {
                                    listOf(it.transferId, it.baseEdSeed, it.baseMsgKey)
                                }
                                createCursor(rows)
                            }
                            else -> createCursor(emptyList())
                        }
                    }
                    "execSQL" -> {
                        val sql = args[0] as String
                        val bindArgs = (args[1] as Array<*>).toList()
                        when {
                            sql.contains("UPDATE contacts") -> {
                                val id = bindArgs[5] as String
                                val row = contacts.first { it.id == id }
                                row.name = bindArgs[0] as String
                                row.chainKeyOut = bindArgs[1] as ByteArray
                                row.chainKeyIn = bindArgs[2] as ByteArray
                                row.sas = bindArgs[3] as String
                                row.fingerprint = bindArgs[4] as String
                            }
                            sql.contains("UPDATE groups") -> {
                                val id = bindArgs[2] as String
                                val row = groups.first { it.groupId == id }
                                row.groupName = bindArgs[0] as String
                                row.myChainKeyOut = bindArgs[1] as ByteArray
                            }
                            sql.contains("UPDATE group_members") -> {
                                val gId = bindArgs[2] as String
                                val mId = bindArgs[3] as String
                                val row = members.first { it.groupId == gId && it.memberId == mId }
                                row.memberName = bindArgs[0] as String
                                row.chainKeyIn = bindArgs[1] as ByteArray
                            }
                            sql.contains("UPDATE messages") -> {
                                val id = bindArgs[6] as Long
                                val row = messages.first { it.id == id }
                                row.textContent = bindArgs[0] as? String
                                row.imageBytes = bindArgs[1] as? ByteArray
                                row.ackRatchetKey = bindArgs[2] as? ByteArray
                                row.slotEdSeed = bindArgs[3] as? ByteArray
                                row.senderMemberId = bindArgs[4] as? String
                                row.senderName = bindArgs[5] as? String
                            }
                            sql.contains("UPDATE skipped_keys") -> {
                                val contactId = bindArgs[2] as String
                                val slotIndex = bindArgs[3] as Int
                                val row = skippedKeys.first { it.contactId == contactId && it.slotIndex == slotIndex }
                                row.msgKey = bindArgs[0] as ByteArray
                                row.edPrivateKeySeed = bindArgs[1] as ByteArray
                            }
                            sql.contains("UPDATE pending_rekey_offers") -> {
                                val contactId = bindArgs[1] as String
                                val row = pendingOffers.first { it.contactId == contactId }
                                row.skNew = bindArgs[0] as ByteArray
                            }
                            sql.contains("UPDATE chunks") -> {
                                val transferId = bindArgs[1] as String
                                val chunkIndex = bindArgs[2] as Int
                                val row = chunks.first { it.transferId == transferId && it.chunkIndex == chunkIndex }
                                row.data = bindArgs[0] as ByteArray
                            }
                            sql.contains("UPDATE pending_chunk_transfers") -> {
                                val transferId = bindArgs[2] as String
                                val row = pendingTransfers.first { it.transferId == transferId }
                                row.baseEdSeed = bindArgs[0] as ByteArray
                                row.baseMsgKey = bindArgs[1] as ByteArray
                            }
                        }
                        null
                    }
                    else -> null
                }
            }
        ) as SupportSQLiteDatabase

        // Execute MIGRATION_10_11
        AppDatabase.MIGRATION_10_11.migrate(dbProxy)

        // 1. Verify contacts: metadata is now encrypted with MAGIC_ROW_BOUND_V2, blobs have V2 header and column binding
        val c = contacts.first()
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, c.chainKeyOut[0])
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, c.chainKeyIn[0])
        assertFalse("Metadata name must not be plain text", c.name == "Alice Wonderland")
        assertFalse("Metadata sas must not be plain text", c.sas == "9988")
        assertFalse("Metadata fingerprint must not be plain text", c.fingerprint == "FP-ALICE-10")

        val decName = KeystoreCrypto.decryptString(c.name, "contacts", "peer_alice", "name")
        assertEquals("Alice Wonderland", decName)
        val decSas = KeystoreCrypto.decryptString(c.sas, "contacts", "peer_alice", "sas")
        assertEquals("9988", decSas)
        val decFp = KeystoreCrypto.decryptString(c.fingerprint, "contacts", "peer_alice", "fingerprint")
        assertEquals("FP-ALICE-10", decFp)
        val decChainOut = KeystoreCrypto.decrypt(c.chainKeyOut, "contacts", "peer_alice", "chainKeyOut")
        assertArrayEquals(rawChainOut, decChainOut)
        val decChainIn = KeystoreCrypto.decrypt(c.chainKeyIn, "contacts", "peer_alice", "chainKeyIn")
        assertArrayEquals(rawChainIn, decChainIn)

        // Verify Column-Swap resistance: decrypting chainKeyOut with column 'chainKeyIn' must fail!
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decrypt(c.chainKeyOut, "contacts", "peer_alice", "chainKeyIn")
        }

        // 2. Verify groups: groupName encrypted, myChainKeyOut bound to 'myChainKeyOut'
        val g = groups.first()
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, g.myChainKeyOut[0])
        assertFalse("Group name must not be plain text", g.groupName == "Quantum Vanguard")
        val decGroupName = KeystoreCrypto.decryptString(g.groupName, "groups", "group_quantum", "groupName")
        assertEquals("Quantum Vanguard", decGroupName)
        val decGroupKey = KeystoreCrypto.decrypt(g.myChainKeyOut, "groups", "group_quantum", "myChainKeyOut")
        assertArrayEquals(rawGroupKey, decGroupKey)

        // 3. Verify group_members: memberName encrypted, chainKeyIn bound to 'chainKeyIn'
        val m = members.first()
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, m.chainKeyIn[0])
        assertFalse("Member name must not be plain text", m.memberName == "Bob Builder")
        val decMemberName = KeystoreCrypto.decryptString(m.memberName, "group_members", "group_quantum_member_bob", "memberName")
        assertEquals("Bob Builder", decMemberName)
        val decMemberKey = KeystoreCrypto.decrypt(m.chainKeyIn, "group_members", "group_quantum_member_bob", "chainKeyIn")
        assertArrayEquals(rawMemberKey, decMemberKey)

        // 4. Verify messages: rowId is '${contactId}_${seqEpoch}_${seqNum}_${isOutgoing}'
        val msg = messages.first()
        val expectedMsgRowId = MessageEntity.computeMessageRowId("peer_alice", 0, 7, false)
        assertEquals("peer_alice_0_7_false", expectedMsgRowId)
        assertNotNull(msg.textContent)
        assertFalse("Message content must be encrypted", msg.textContent!!.contains("Sensitive"))
        val decContent = KeystoreCrypto.decryptString(msg.textContent!!, "messages", expectedMsgRowId, "textContent")
        assertEquals("Sensitive message content", decContent)
        val decSenderId = KeystoreCrypto.decryptString(msg.senderMemberId!!, "messages", expectedMsgRowId, "senderMemberId")
        assertEquals("alice_uuid_val", decSenderId)
        val decSenderName = KeystoreCrypto.decryptString(msg.senderName!!, "messages", expectedMsgRowId, "senderName")
        assertEquals("Alice Wonderland", decSenderName)

        // Verify intra-row message column swap resistance:
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decryptString(msg.textContent!!, "messages", expectedMsgRowId, "senderName")
        }

        // 5. Verify skipped_keys, pending_rekey_offers, chunks, pending_chunk_transfers
        val sk = skippedKeys.first()
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, sk.msgKey[0])
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, sk.edPrivateKeySeed[0])
        assertArrayEquals(rawMsgKey, KeystoreCrypto.decrypt(sk.msgKey, "skipped_keys", "peer_alice_3", "msgKey"))
        assertArrayEquals(rawEdSeed, KeystoreCrypto.decrypt(sk.edPrivateKeySeed, "skipped_keys", "peer_alice_3", "edPrivateKeySeed"))

        val off = pendingOffers.first()
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, off.skNew[0])
        assertArrayEquals(rawSkNew, KeystoreCrypto.decrypt(off.skNew, "pending_rekey_offers", "peer_alice", "skNew"))

        val chk = chunks.first()
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, chk.data[0])
        assertArrayEquals(rawChunkData, KeystoreCrypto.decrypt(chk.data, "chunks", "transfer_42_1", "data"))

        val pct = pendingTransfers.first()
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, pct.baseEdSeed[0])
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, pct.baseMsgKey[0])
        assertArrayEquals(rawBaseSeed, KeystoreCrypto.decrypt(pct.baseEdSeed, "pending_chunk_transfers", "transfer_42_seed", "baseEdSeed"))
        assertArrayEquals(rawBaseKey, KeystoreCrypto.decrypt(pct.baseMsgKey, "pending_chunk_transfers", "transfer_42_key", "baseMsgKey"))
    }

    @Test
    fun testMigration11To12AddsEphemeralColumnsAndIndex() {
        val executedSql = mutableListOf<String>()
        val dbProxy = Proxy.newProxyInstance(
            SupportSQLiteDatabase::class.java.classLoader,
            arrayOf(SupportSQLiteDatabase::class.java),
            InvocationHandler { _, method, args ->
                if (method.name == "execSQL") {
                    executedSql.add(args[0] as String)
                }
                null
            }
        ) as SupportSQLiteDatabase

        AppDatabase.MIGRATION_11_12.migrate(dbProxy)

        assertTrue(executedSql.any { it.contains("ALTER TABLE messages ADD COLUMN ephemeralTtlSeconds") })
        assertTrue(executedSql.any { it.contains("ALTER TABLE messages ADD COLUMN expiresAtTimestamp") })
        assertTrue(executedSql.any { it.contains("CREATE INDEX IF NOT EXISTS index_messages_expiresAtTimestamp ON messages") })
    }

    @Test
    fun testMigration13To14EncryptsRemainingSensitiveColumnsWithV2Binding() {
        data class TestMessageRow(
            val id: Long,
            val contactId: String,
            val isOutgoing: Int,
            val seqEpoch: Int,
            val seqNum: Int,
            val ackNum: Int,
            val timestamp: Long,
            val textContent: String?,
            val imageBytes: ByteArray?,
            val status: String,
            val retryCount: Int,
            val lastAttemptTimestamp: Long,
            val ackTarget: ByteArray?,
            val ackRatchetKey: ByteArray?,
            val slotTarget: ByteArray?,
            val slotEdSeed: ByteArray?,
            val senderMemberId: String?,
            val senderName: String?,
            val ephemeralTtlSeconds: Long,
            val expiresAtTimestamp: Long?,
            val reaction: String?
        )

        data class NewMessageRow(
            val id: Long,
            val contactId: String,
            val isOutgoing: Int,
            val seqEpoch: Int,
            val seqNum: Int,
            val ackNum: Int,
            val timestamp: Long,
            val textContent: String?,
            val imageBytes: ByteArray?,
            val status: String,
            val retryCount: Int,
            val lastAttemptTimestamp: Long,
            val ackTarget: ByteArray?,
            val ackRatchetKey: ByteArray?,
            val slotTarget: ByteArray?,
            val slotEdSeed: ByteArray?,
            val senderMemberId: String?,
            val senderName: String?,
            val ephemeralTtlSeconds: String,
            val expiresAtTimestamp: String?,
            val reaction: String?
        )

        val oldMessages = listOf(
            TestMessageRow(
                id = 1L,
                contactId = "alice",
                isOutgoing = 1,
                seqEpoch = 0,
                seqNum = 5,
                ackNum = 0,
                timestamp = 1000L,
                textContent = "Sample Text",
                imageBytes = null,
                status = "SENT",
                retryCount = 0,
                lastAttemptTimestamp = 1000L,
                ackTarget = null,
                ackRatchetKey = null,
                slotTarget = null,
                slotEdSeed = null,
                senderMemberId = null,
                senderName = null,
                ephemeralTtlSeconds = 60L,
                expiresAtTimestamp = 1060L,
                reaction = "🔥"
            )
        )

        data class TransferRow(val transferId: String, var missingIndices: String)
        val transfers = mutableListOf(
            TransferRow("transfer_abc", "0,1,2")
        )

        data class ChunkItem(val transferId: String, val chunkIndex: Int, var data: ByteArray)
        val rawChunkData = "Raw image payload".toByteArray(Charsets.UTF_8)
        val chunkItems = mutableListOf(
            ChunkItem("transfer_abc", 0, rawChunkData.copyOf())
        )

        val newMessages = mutableListOf<NewMessageRow>()
        val executedSql = mutableListOf<String>()

        val dbProxy = Proxy.newProxyInstance(
            SupportSQLiteDatabase::class.java.classLoader,
            arrayOf(SupportSQLiteDatabase::class.java),
            InvocationHandler { _, method, args ->
                when (method.name) {
                    "query" -> {
                        val sql = args[0] as String
                        when {
                            sql.contains("FROM messages") -> {
                                val rows = oldMessages.map { m ->
                                    listOf(
                                        m.id, m.contactId, m.isOutgoing, m.seqEpoch, m.seqNum, m.ackNum, m.timestamp,
                                        m.textContent, m.imageBytes, m.status, m.retryCount, m.lastAttemptTimestamp,
                                        m.ackTarget, m.ackRatchetKey, m.slotTarget, m.slotEdSeed,
                                        m.senderMemberId, m.senderName, m.ephemeralTtlSeconds, m.expiresAtTimestamp, m.reaction
                                    )
                                }
                                createCursor(rows)
                            }
                            sql.contains("FROM pending_chunk_transfers") -> {
                                val rows = transfers.map { t -> listOf(t.transferId, t.missingIndices) }
                                createCursor(rows)
                            }
                            sql.contains("FROM chunks") -> {
                                val rows = chunkItems.map { c -> listOf(c.transferId, c.chunkIndex, c.data) }
                                createCursor(rows)
                            }
                            else -> createCursor(emptyList())
                        }
                    }
                    "execSQL" -> {
                        val sql = args[0] as String
                        executedSql.add(sql)
                        if (args.size > 1 && args[1] is Array<*>) {
                            val bindArgs = args[1] as Array<*>
                            if (sql.contains("INSERT INTO messages_new")) {
                                newMessages.add(
                                    NewMessageRow(
                                        id = (bindArgs[0] as Number).toLong(),
                                        contactId = bindArgs[1] as String,
                                        isOutgoing = (bindArgs[2] as Number).toInt(),
                                        seqEpoch = (bindArgs[3] as Number).toInt(),
                                        seqNum = (bindArgs[4] as Number).toInt(),
                                        ackNum = (bindArgs[5] as Number).toInt(),
                                        timestamp = (bindArgs[6] as Number).toLong(),
                                        textContent = bindArgs[7] as? String,
                                        imageBytes = bindArgs[8] as? ByteArray,
                                        status = bindArgs[9] as String,
                                        retryCount = (bindArgs[10] as Number).toInt(),
                                        lastAttemptTimestamp = (bindArgs[11] as Number).toLong(),
                                        ackTarget = bindArgs[12] as? ByteArray,
                                        ackRatchetKey = bindArgs[13] as? ByteArray,
                                        slotTarget = bindArgs[14] as? ByteArray,
                                        slotEdSeed = bindArgs[15] as? ByteArray,
                                        senderMemberId = bindArgs[16] as? String,
                                        senderName = bindArgs[17] as? String,
                                        ephemeralTtlSeconds = bindArgs[18] as String,
                                        expiresAtTimestamp = bindArgs[19] as? String,
                                        reaction = bindArgs[20] as? String
                                    )
                                )
                            } else if (sql.contains("UPDATE pending_chunk_transfers SET missingIndices = ?")) {
                                val encHex = bindArgs[0] as String
                                val transferId = bindArgs[1] as String
                                transfers.first { it.transferId == transferId }.missingIndices = encHex
                            } else if (sql.contains("UPDATE chunks SET data = ?")) {
                                val data = bindArgs[0] as ByteArray
                                val transferId = bindArgs[1] as String
                                val chunkIndex = (bindArgs[2] as Number).toInt()
                                chunkItems.first { it.transferId == transferId && it.chunkIndex == chunkIndex }.data = data
                            }
                        }
                        null
                    }
                    else -> null
                }
            }
        ) as SupportSQLiteDatabase

        AppDatabase.MIGRATION_13_14.migrate(dbProxy)

        // Verify table recreation executed
        assertTrue(executedSql.any { it.contains("DROP TABLE messages") })
        assertTrue(executedSql.any { it.contains("ALTER TABLE messages_new RENAME TO messages") })

        // Verify messages encrypted values
        assertEquals(1, newMessages.size)
        val migratedMsg = newMessages.first()
        val expectedMsgRowId = MessageEntity.computeMessageRowId("alice", 0, 5, true)

        // ephemeralTtlSeconds
        val decTtl = KeystoreCrypto.decryptLong(migratedMsg.ephemeralTtlSeconds, "messages", expectedMsgRowId, "ephemeralTtlSeconds")
        assertEquals(60L, decTtl)

        // expiresAtTimestamp
        assertNotNull(migratedMsg.expiresAtTimestamp)
        val decExpires = KeystoreCrypto.decryptLong(migratedMsg.expiresAtTimestamp!!, "messages", expectedMsgRowId, "expiresAtTimestamp")
        assertEquals(1060L, decExpires)

        // reaction
        assertNotNull(migratedMsg.reaction)
        val decReaction = KeystoreCrypto.decryptString(migratedMsg.reaction!!, "messages", expectedMsgRowId, "reaction")
        assertEquals("🔥", decReaction)

        // Intra-row column-swap attack resistance
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decryptString(migratedMsg.reaction, "messages", expectedMsgRowId, "textContent")
        }
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decryptLong(migratedMsg.ephemeralTtlSeconds, "messages", expectedMsgRowId, "expiresAtTimestamp")
        }

        // pending_chunk_transfers missingIndices
        val updatedTransfer = transfers.first()
        val decMissing = KeystoreCrypto.decryptString(updatedTransfer.missingIndices, "pending_chunk_transfers", "transfer_abc", "missingIndices")
        assertEquals("0,1,2", decMissing)

        // chunks data
        val updatedChunk = chunkItems.first()
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, updatedChunk.data[0])
        val decData = KeystoreCrypto.decrypt(updatedChunk.data, "chunks", "transfer_abc_0", "data")
        assertArrayEquals(rawChunkData, decData)
    }

    @Test
    fun testMigration14To15AddsVoiceColumns() {
        val executedSql = mutableListOf<String>()
        val dbProxy = Proxy.newProxyInstance(
            SupportSQLiteDatabase::class.java.classLoader,
            arrayOf(SupportSQLiteDatabase::class.java),
            InvocationHandler { _, method, args ->
                when (method.name) {
                    "execSQL" -> {
                        val sql = args[0] as String
                        executedSql.add(sql)
                        null
                    }
                    else -> null
                }
            }
        ) as SupportSQLiteDatabase

        AppDatabase.MIGRATION_14_15.migrate(dbProxy)

        assertTrue(executedSql.any { it.contains("ALTER TABLE messages ADD COLUMN voiceBytes BLOB") })
        assertTrue(executedSql.any { it.contains("ALTER TABLE messages ADD COLUMN voiceDurationMs INTEGER NOT NULL DEFAULT 0") })
    }

    @Test
    fun testMigration15To16AddsPollTablesAndColumn() {
        val executedSql = mutableListOf<String>()
        val dbProxy = Proxy.newProxyInstance(
            SupportSQLiteDatabase::class.java.classLoader,
            arrayOf(SupportSQLiteDatabase::class.java),
            InvocationHandler { _, method, args ->
                when (method.name) {
                    "execSQL" -> {
                        val sql = args[0] as String
                        executedSql.add(sql)
                        null
                    }
                    else -> null
                }
            }
        ) as SupportSQLiteDatabase

        AppDatabase.MIGRATION_15_16.migrate(dbProxy)

        assertTrue(executedSql.any { it.contains("ALTER TABLE messages ADD COLUMN pollId TEXT") })
        assertTrue(executedSql.any { it.contains("CREATE TABLE IF NOT EXISTS polls") })
        assertTrue(executedSql.any { it.contains("CREATE INDEX IF NOT EXISTS index_polls_groupId ON polls (groupId)") })
        assertTrue(executedSql.any { it.contains("CREATE TABLE IF NOT EXISTS poll_votes") })
        assertTrue(executedSql.any { it.contains("CREATE INDEX IF NOT EXISTS index_poll_votes_pollId ON poll_votes (pollId)") })
    }
}

