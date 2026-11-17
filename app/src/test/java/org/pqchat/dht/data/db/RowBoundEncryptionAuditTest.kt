package org.pqchat.dht.data.db

import android.database.Cursor
import androidx.room.Database
import androidx.room.Room
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.KeystoreCrypto
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.security.GeneralSecurityException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Full reflection + on-disk SQLite forensic audit test verifying that every sensitive column
 * across all Room entities (including [PollEntity] and [PollVoteEntity]) is encrypted at rest
 * with [KeystoreCrypto.MAGIC_ROW_BOUND_V2] (`0x52`, `AAD = table+id+column`), blocks legacy
 * V1 (`0x51`) / raw ciphertext downgrades, and zeroes RAM key material via `zeroSensitiveMemory()`.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RowBoundEncryptionAuditTest {

    private val testMasterKey = SecretKeySpec(ByteArray(32) { (it * 41 + 9).toByte() }, "AES")
    private lateinit var dbFile: File
    private lateinit var db: AppDatabase

    @Before
    fun setUp() {
        KeystoreCrypto.setTestSecretKey(testMasterKey)
        val context = RuntimeEnvironment.getApplication()
        dbFile = File(context.cacheDir, "audit_sqlite_${System.nanoTime()}.db")
        if (dbFile.exists()) dbFile.delete()
        db = Room.databaseBuilder(context, AppDatabase::class.java, dbFile.absolutePath)
            .allowMainThreadQueries()
            .build()
    }

    @After
    fun tearDown() {
        db.close()
        dbFile.delete()
        File("${dbFile.absolutePath}-wal").delete()
        File("${dbFile.absolutePath}-shm").delete()
        KeystoreCrypto.resetForTesting()
    }

    @Test
    fun testReflectionAuditAllDatabaseEntitiesUseEncryptedWrappersForSensitiveColumns() {
        val discoveredTables = mutableSetOf<String>()
        db.openHelper.writableDatabase.query(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT IN ('android_metadata', 'sqlite_sequence', 'room_master_table')"
        ).use { cursor ->
            while (cursor.moveToNext()) {
                discoveredTables.add(cursor.getString(0))
            }
        }

        val expectedTables = setOf(
            "contacts",
            "messages",
            "chunks",
            "pending_chunk_transfers",
            "dht_node_cache",
            "pending_rekey_offers",
            "skipped_keys",
            "groups",
            "group_members",
            "polls",
            "poll_votes"
        )
        assertEquals("Every AppDatabase table must be covered by the forensic audit", expectedTables, discoveredTables)

        val expectedEncryptedColumnsByClass = mapOf(
            ContactEntity::class.java to mapOf(
                "name" to EncryptedText::class.java,
                "chainKeyOut" to EncryptedBlob::class.java,
                "chainKeyIn" to EncryptedBlob::class.java,
                "sas" to EncryptedText::class.java,
                "fingerprint" to EncryptedText::class.java
            ),
            MessageEntity::class.java to mapOf(
                "textContent" to EncryptedText::class.java,
                "imageBytes" to EncryptedBlob::class.java,
                "ackRatchetKey" to EncryptedBlob::class.java,
                "slotEdSeed" to EncryptedBlob::class.java,
                "senderMemberId" to EncryptedText::class.java,
                "senderName" to EncryptedText::class.java,
                "ephemeralTtlSeconds" to EncryptedLong::class.java,
                "expiresAtTimestamp" to EncryptedLong::class.java,
                "reaction" to EncryptedText::class.java,
                "voiceBytes" to EncryptedBlob::class.java
            ),
            SkippedKeyEntity::class.java to mapOf(
                "msgKey" to EncryptedBlob::class.java,
                "edPrivateKeySeed" to EncryptedBlob::class.java
            ),
            PendingRekeyOfferEntity::class.java to mapOf(
                "skNew" to EncryptedBlob::class.java
            ),
            ChunkEntity::class.java to mapOf(
                "data" to EncryptedBlob::class.java
            ),
            PendingChunkTransferEntity::class.java to mapOf(
                "missingIndices" to EncryptedText::class.java,
                "baseEdSeed" to EncryptedBlob::class.java,
                "baseMsgKey" to EncryptedBlob::class.java
            ),
            GroupEntity::class.java to mapOf(
                "groupName" to EncryptedText::class.java,
                "myChainKeyOut" to EncryptedBlob::class.java
            ),
            GroupMemberEntity::class.java to mapOf(
                "memberName" to EncryptedText::class.java,
                "chainKeyIn" to EncryptedBlob::class.java
            ),
            PollEntity::class.java to mapOf(
                "creatorMemberId" to EncryptedText::class.java,
                "creatorName" to EncryptedText::class.java,
                "question" to EncryptedText::class.java,
                "optionsJson" to EncryptedText::class.java
            ),
            PollVoteEntity::class.java to mapOf(
                "memberName" to EncryptedText::class.java,
                "selectedBitmask" to EncryptedLong::class.java,
                "voteTimestamp" to EncryptedLong::class.java
            )
        )

        val unencryptedStructuralColumnsByClass = mapOf(
            ContactEntity::class.java to setOf("id", "counterOut", "counterIn", "rekeyEpoch", "receivedBitmapBase", "receivedBitmap", "lastActive", "isInitiator", "isVerified"),
            MessageEntity::class.java to setOf("id", "contactId", "isOutgoing", "seqEpoch", "seqNum", "ackNum", "timestamp", "status", "retryCount", "lastAttemptTimestamp", "ackTarget", "slotTarget", "voiceDurationMs", "pollId"),
            SkippedKeyEntity::class.java to setOf("contactId", "slotIndex", "target", "createdAt", "expiresAt"),
            PendingRekeyOfferEntity::class.java to setOf("contactId", "epoch", "pkNew", "offerSeqNum", "createdAt"),
            ChunkEntity::class.java to setOf("transferId", "chunkIndex", "totalChunks"),
            PendingChunkTransferEntity::class.java to setOf("transferId", "contactId", "seqNum", "totalChunks", "direction", "isSelf", "ackNum", "timestampUTC", "createdAt", "expiresAt"),
            GroupEntity::class.java to setOf("groupId", "myMemberId", "myCounterOut", "groupEpoch", "createdAt", "lastActive", "isActive"),
            GroupMemberEntity::class.java to setOf("groupId", "memberId", "contactId", "counterIn", "receivedBitmapBase", "receivedBitmap", "joinedAt", "isActive"),
            PollEntity::class.java to setOf("pollId", "groupId", "isMultiChoice", "expirationTimestamp", "createdAt", "isClosed"),
            PollVoteEntity::class.java to setOf("pollId", "memberId")
        )

        val wrapperTypes = setOf(EncryptedBlob::class.java, EncryptedText::class.java, EncryptedLong::class.java)

        for ((entityClass, expectedFields) in expectedEncryptedColumnsByClass) {
            for ((fieldName, expectedType) in expectedFields) {
                val field = entityClass.getDeclaredField(fieldName)
                assertEquals(
                    "Sensitive field ${entityClass.simpleName}.$fieldName must be encrypted wrapper ${expectedType.simpleName}",
                    expectedType,
                    field.type
                )
            }
            val allowlistedUnencrypted = unencryptedStructuralColumnsByClass[entityClass] ?: emptySet()
            for (field in entityClass.declaredFields) {
                if (java.lang.reflect.Modifier.isStatic(field.modifiers)) continue
                if (field.name.startsWith("$")) continue
                if (field.name !in expectedFields.keys && field.name !in allowlistedUnencrypted) {
                    assertTrue(
                        "Audited field ${entityClass.simpleName}.${field.name} (${field.type.simpleName}) is neither encrypted nor explicitly allowlisted",
                        field.type in wrapperTypes
                    )
                }
            }
            val validateMethod = entityClass.methods.firstOrNull { it.name == "validateRowBinding" }
            assertNotNull("${entityClass.simpleName} must declare validateRowBinding()", validateMethod)
        }

        val zeroingEntities = listOf(
            ContactEntity::class.java,
            MessageEntity::class.java,
            GroupEntity::class.java,
            GroupMemberEntity::class.java,
            PendingChunkTransferEntity::class.java
        )
        for (clazz in zeroingEntities) {
            assertNotNull(
                "${clazz.simpleName} must declare zeroSensitiveMemory()",
                clazz.methods.firstOrNull { it.name == "zeroSensitiveMemory" }
            )
        }
    }

    @Test
    fun testSqliteDiskAuditZeroPlaintextWrittenAcrossAllTablesIncludingPollsAndVotes(): Unit = runBlocking {
        val canaryContactName = "CANARY_CONTACT_ALICE_9911"
        val canarySas = "CANARY_SAS_84729104"
        val canaryFp = "CANARY_FINGERPRINT_SHA256_ABCD"
        val canaryMsgText = "CANARY_MESSAGE_PLAINTEXT_TOP_SECRET"
        val canaryReaction = "CANARY_REACTION_OK"
        val canarySenderId = "CANARY_SENDER_UUID_007"
        val canarySenderName = "CANARY_SENDER_DISPLAY_ALICE"
        val canaryGroupName = "CANARY_SECRET_GROUP_TITLE"
        val canaryMemberName = "CANARY_GROUP_MEMBER_CHARLIE"
        val canaryPollCreatorId = "CANARY_POLL_CREATOR_MEMBER_42"
        val canaryPollCreatorName = "CANARY_POLL_CREATOR_ALICE"
        val canaryPollQuestion = "CANARY_SECRET_POLL_QUESTION_XYZ"
        val canaryPollOption1 = "CANARY_SECRET_OPTION_ALPHA"
        val canaryPollOption2 = "CANARY_SECRET_OPTION_BETA"
        val canaryVoterName = "CANARY_POLL_VOTER_BOB"
        val canaryMissingIdx = "7,11,13"
        val sentinelBitmask = 1984736251 // 10-digit non-hex-colliding bitmask marker
        val sentinelVoteTs = 1794987654321L
        val sentinelTtl = 43207984726153L // 14-digit sentinel avoids random 5-char hex ciphertext collisions
        val sentinelExpires = 1794999888777L

        val canaryChainOut = "CANARY_SECRET_CHAIN_OUT_32BYTES!".toByteArray(Charsets.US_ASCII)
        val canaryChainIn = "CANARY_SECRET_CHAIN_IN__32BYTES!".toByteArray(Charsets.US_ASCII)
        val canaryImageBytes = "CANARY_IMAGE_PAYLOAD_SECRET_BYTES".toByteArray(Charsets.US_ASCII)
        val canaryVoiceBytes = "CANARY_VOICE_LPC10_SECRET_BYTES".toByteArray(Charsets.US_ASCII)
        val canaryAckKey = "CANARY_ACK_RATCHET_KEY_32_BYTES!".toByteArray(Charsets.US_ASCII)
        val canaryEdSeed = "CANARY_SLOT_ED25519_SEED_32BYTES".toByteArray(Charsets.US_ASCII)
        val canarySkippedKey = "CANARY_SKIPPED_MSG_KEY_32_BYTES!".toByteArray(Charsets.US_ASCII)
        val canarySkippedSeed = "CANARY_SKIPPED_ED_SEED_32_BYTES!".toByteArray(Charsets.US_ASCII)
        val canaryRekeySk = "CANARY_MLKEM_REKEY_PRIV_KEY_64B_".toByteArray(Charsets.US_ASCII)
        val canaryChunkBytes = "CANARY_CHUNK_BINARY_SECRET_BLOCK".toByteArray(Charsets.US_ASCII)
        val canaryPendingSeed = "CANARY_PENDING_CHUNK_ED_SEED_32B".toByteArray(Charsets.US_ASCII)
        val canaryPendingKey = "CANARY_PENDING_CHUNK_MSG_KEY_32B".toByteArray(Charsets.US_ASCII)
        val canaryGroupChainOut = "CANARY_GROUP_OUT_CHAIN_KEY_32B!!".toByteArray(Charsets.US_ASCII)
        val canaryGroupChainIn = "CANARY_GROUP_IN_CHAIN_KEY_32B!!!".toByteArray(Charsets.US_ASCII)

        db.contactDao().insertOrUpdate(
            ContactEntity(
                id = "contact_audit_1",
                name = canaryContactName,
                chainKeyOut = canaryChainOut,
                chainKeyIn = canaryChainIn,
                counterOut = 1,
                counterIn = 2,
                sas = canarySas,
                fingerprint = canaryFp
            )
        )
        db.messageDao().insertMessage(
            MessageEntity(
                contactId = "contact_audit_1",
                isOutgoing = true,
                seqEpoch = 0,
                seqNum = 9,
                textContent = canaryMsgText,
                imageBytes = canaryImageBytes,
                ackRatchetKey = canaryAckKey,
                slotEdSeed = canaryEdSeed,
                senderMemberId = canarySenderId,
                senderName = canarySenderName,
                ephemeralTtlSeconds = sentinelTtl,
                expiresAtTimestamp = sentinelExpires,
                reaction = canaryReaction,
                voiceBytes = canaryVoiceBytes,
                voiceDurationMs = 1500
            )
        )
        db.skippedKeyDao().insertOrUpdate(
            SkippedKeyEntity(
                contactId = "contact_audit_1",
                slotIndex = 3,
                msgKey = canarySkippedKey,
                target = ByteArray(20) { 0x11 },
                edPrivateKeySeed = canarySkippedSeed
            )
        )
        db.pendingRekeyOfferDao().insertOrUpdate(
            PendingRekeyOfferEntity(
                contactId = "contact_audit_1",
                epoch = 4L,
                skNew = canaryRekeySk,
                pkNew = ByteArray(32) { 0x22 },
                offerSeqNum = 10
            )
        )
        db.chunkDao().insertChunk(
            ChunkEntity(
                transferId = "transfer_audit_1",
                chunkIndex = 0,
                totalChunks = 4,
                data = canaryChunkBytes
            )
        )
        db.chunkDao().insertPendingTransfer(
            PendingChunkTransferEntity(
                transferId = "transfer_audit_1",
                contactId = "contact_audit_1",
                seqNum = 5,
                totalChunks = 4,
                missingIndices = canaryMissingIdx,
                baseEdSeed = canaryPendingSeed,
                baseMsgKey = canaryPendingKey,
                direction = "AliceToBob"
            )
        )
        db.groupDao().insertOrUpdate(
            GroupEntity(
                groupId = "group_audit_1",
                groupName = canaryGroupName,
                myMemberId = "member_self",
                myChainKeyOut = canaryGroupChainOut,
                myCounterOut = 1
            )
        )
        db.groupMemberDao().insertOrUpdate(
            GroupMemberEntity(
                groupId = "group_audit_1",
                memberId = "member_charlie",
                contactId = "contact_audit_1",
                memberName = canaryMemberName,
                chainKeyIn = canaryGroupChainIn,
                counterIn = 2
            )
        )
        db.pollDao().insertOrUpdatePoll(
            PollEntity(
                pollId = "poll_audit_1",
                groupId = "group_audit_1",
                creatorMemberId = canaryPollCreatorId,
                creatorName = canaryPollCreatorName,
                question = canaryPollQuestion,
                optionsJson = "[\"$canaryPollOption1\",\"$canaryPollOption2\"]",
                isMultiChoice = true,
                expirationTimestamp = 1800000000000L
            )
        )
        db.pollDao().insertOrUpdateVote(
            PollVoteEntity(
                pollId = "poll_audit_1",
                memberId = "voter_bob_id",
                memberName = canaryVoterName,
                selectedBitmask = sentinelBitmask,
                voteTimestamp = sentinelVoteTs
            )
        )

        val sqliteDb = db.openHelper.writableDatabase
        sqliteDb.query("PRAGMA wal_checkpoint(FULL)").use { it.moveToFirst() }

        // Inspect raw SQLite columns directly without Room TypeConverters
        fun assertRawHexTextColumnV2(table: String, whereClause: String, column: String, expectedRowId: String, forbiddenSubstr: String) {
            sqliteDb.query("SELECT $column FROM $table WHERE $whereClause").use { cursor ->
                assertTrue("Expected row in $table for $column", cursor.moveToFirst())
                assertEquals(
                    "$table.$column must be stored as encrypted hex STRING",
                    Cursor.FIELD_TYPE_STRING,
                    cursor.getType(0)
                )
                val stored = cursor.getString(0)
                assertFalse("Plaintext leaked in $table.$column", stored.contains(forbiddenSubstr))
                val cipherBytes = CryptoUtils.fromHex(stored)
                assertEquals(
                    "$table.$column must carry MAGIC_ROW_BOUND_V2 (0x52)",
                    KeystoreCrypto.MAGIC_ROW_BOUND_V2,
                    cipherBytes[0]
                )
                val dec = KeystoreCrypto.decryptRowBoundV2(cipherBytes, table, expectedRowId, column)
                assertEquals(table, dec.table)
                assertEquals(expectedRowId, dec.id)
                assertEquals(column, dec.column)
            }
        }

        fun assertRawBlobColumnV2(table: String, whereClause: String, column: String, expectedRowId: String, forbiddenBytes: ByteArray) {
            sqliteDb.query("SELECT $column FROM $table WHERE $whereClause").use { cursor ->
                assertTrue("Expected row in $table for $column", cursor.moveToFirst())
                assertEquals(
                    "$table.$column must be stored as encrypted BLOB",
                    Cursor.FIELD_TYPE_BLOB,
                    cursor.getType(0)
                )
                val stored = cursor.getBlob(0)
                assertFalse(
                    "Plaintext bytes leaked in $table.$column",
                    containsSubarray(stored, forbiddenBytes)
                )
                assertEquals(
                    "$table.$column must carry MAGIC_ROW_BOUND_V2 (0x52)",
                    KeystoreCrypto.MAGIC_ROW_BOUND_V2,
                    stored[0]
                )
                val dec = KeystoreCrypto.decryptRowBoundV2(stored, table, expectedRowId, column)
                assertEquals(table, dec.table)
                assertEquals(expectedRowId, dec.id)
                assertEquals(column, dec.column)
            }
        }

        assertRawHexTextColumnV2("contacts", "id = 'contact_audit_1'", "name", "contact_audit_1", canaryContactName)
        assertRawHexTextColumnV2("contacts", "id = 'contact_audit_1'", "sas", "contact_audit_1", canarySas)
        assertRawHexTextColumnV2("contacts", "id = 'contact_audit_1'", "fingerprint", "contact_audit_1", canaryFp)
        assertRawBlobColumnV2("contacts", "id = 'contact_audit_1'", "chainKeyOut", "contact_audit_1", canaryChainOut)
        assertRawBlobColumnV2("contacts", "id = 'contact_audit_1'", "chainKeyIn", "contact_audit_1", canaryChainIn)

        val msgRowId = MessageEntity.computeMessageRowId("contact_audit_1", 0, 9, true)
        assertRawHexTextColumnV2("messages", "seqNum = 9", "textContent", msgRowId, canaryMsgText)
        assertRawHexTextColumnV2("messages", "seqNum = 9", "senderMemberId", msgRowId, canarySenderId)
        assertRawHexTextColumnV2("messages", "seqNum = 9", "senderName", msgRowId, canarySenderName)
        assertRawHexTextColumnV2("messages", "seqNum = 9", "reaction", msgRowId, canaryReaction)
        assertRawHexTextColumnV2("messages", "seqNum = 9", "ephemeralTtlSeconds", msgRowId, sentinelTtl.toString())
        assertRawHexTextColumnV2("messages", "seqNum = 9", "expiresAtTimestamp", msgRowId, sentinelExpires.toString())
        assertRawBlobColumnV2("messages", "seqNum = 9", "imageBytes", msgRowId, canaryImageBytes)
        assertRawBlobColumnV2("messages", "seqNum = 9", "voiceBytes", msgRowId, canaryVoiceBytes)
        assertRawBlobColumnV2("messages", "seqNum = 9", "ackRatchetKey", msgRowId, canaryAckKey)
        assertRawBlobColumnV2("messages", "seqNum = 9", "slotEdSeed", msgRowId, canaryEdSeed)

        assertRawBlobColumnV2("skipped_keys", "contactId = 'contact_audit_1'", "msgKey", "contact_audit_1_3", canarySkippedKey)
        assertRawBlobColumnV2("skipped_keys", "contactId = 'contact_audit_1'", "edPrivateKeySeed", "contact_audit_1_3", canarySkippedSeed)
        assertRawBlobColumnV2("pending_rekey_offers", "contactId = 'contact_audit_1'", "skNew", "contact_audit_1", canaryRekeySk)
        assertRawBlobColumnV2("chunks", "transferId = 'transfer_audit_1'", "data", "transfer_audit_1_0", canaryChunkBytes)
        assertRawHexTextColumnV2("pending_chunk_transfers", "transferId = 'transfer_audit_1'", "missingIndices", "transfer_audit_1", canaryMissingIdx)
        assertRawBlobColumnV2("pending_chunk_transfers", "transferId = 'transfer_audit_1'", "baseEdSeed", "transfer_audit_1_seed", canaryPendingSeed)
        assertRawBlobColumnV2("pending_chunk_transfers", "transferId = 'transfer_audit_1'", "baseMsgKey", "transfer_audit_1_key", canaryPendingKey)
        assertRawHexTextColumnV2("groups", "groupId = 'group_audit_1'", "groupName", "group_audit_1", canaryGroupName)
        assertRawBlobColumnV2("groups", "groupId = 'group_audit_1'", "myChainKeyOut", "group_audit_1", canaryGroupChainOut)
        assertRawHexTextColumnV2("group_members", "memberId = 'member_charlie'", "memberName", "group_audit_1_member_charlie", canaryMemberName)
        assertRawBlobColumnV2("group_members", "memberId = 'member_charlie'", "chainKeyIn", "group_audit_1_member_charlie", canaryGroupChainIn)

        assertRawHexTextColumnV2("polls", "pollId = 'poll_audit_1'", "creatorMemberId", "poll_audit_1", canaryPollCreatorId)
        assertRawHexTextColumnV2("polls", "pollId = 'poll_audit_1'", "creatorName", "poll_audit_1", canaryPollCreatorName)
        assertRawHexTextColumnV2("polls", "pollId = 'poll_audit_1'", "question", "poll_audit_1", canaryPollQuestion)
        assertRawHexTextColumnV2("polls", "pollId = 'poll_audit_1'", "optionsJson", "poll_audit_1", canaryPollOption1)

        val voteRowId = PollVoteEntity.computeVoteRowId("poll_audit_1", "voter_bob_id")
        assertRawHexTextColumnV2("poll_votes", "pollId = 'poll_audit_1'", "memberName", voteRowId, canaryVoterName)
        assertRawHexTextColumnV2("poll_votes", "pollId = 'poll_audit_1'", "selectedBitmask", voteRowId, sentinelBitmask.toString())
        assertRawHexTextColumnV2("poll_votes", "pollId = 'poll_audit_1'", "voteTimestamp", voteRowId, sentinelVoteTs.toString())

        // Verify Room round-trip decryption returns exact values
        val loadedPoll = db.pollDao().getPoll("poll_audit_1")!!
        assertEquals(canaryPollCreatorId, loadedPoll.rawCreatorMemberId)
        assertEquals(canaryPollCreatorName, loadedPoll.rawCreatorName)
        assertEquals(canaryPollQuestion, loadedPoll.rawQuestion)
        assertEquals(listOf(canaryPollOption1, canaryPollOption2), loadedPoll.optionsList)

        val loadedVotes = db.pollDao().getVotesForPoll("poll_audit_1")
        assertEquals(1, loadedVotes.size)
        assertEquals(canaryVoterName, loadedVotes[0].rawMemberName)
        assertEquals(sentinelBitmask, loadedVotes[0].rawSelectedBitmask)
        assertEquals(sentinelVoteTs, loadedVotes[0].rawVoteTimestamp)

        // Close DB and scan raw SQLite file bytes on disk for zero plaintext leakage
        db.close()
        val diskBytes = dbFile.readBytes()
        val forbiddenStrings = listOf(
            canaryContactName, canarySas, canaryFp, canaryMsgText, canaryReaction,
            canarySenderId, canarySenderName, canaryGroupName, canaryMemberName,
            canaryPollCreatorId, canaryPollCreatorName, canaryPollQuestion,
            canaryPollOption1, canaryPollOption2, canaryVoterName, canaryMissingIdx,
            sentinelTtl.toString(), sentinelExpires.toString(), sentinelBitmask.toString(), sentinelVoteTs.toString()
        )
        for (secret in forbiddenStrings) {
            assertFalse(
                "Raw SQLite database file on disk must NOT contain plaintext '$secret'",
                containsSubarray(diskBytes, secret.toByteArray(Charsets.UTF_8))
            )
        }
        val forbiddenByteArrays = listOf(
            canaryChainOut, canaryChainIn, canaryImageBytes, canaryVoiceBytes, canaryAckKey,
            canaryEdSeed, canarySkippedKey, canarySkippedSeed, canaryRekeySk,
            canaryChunkBytes, canaryPendingSeed, canaryPendingKey, canaryGroupChainOut, canaryGroupChainIn
        )
        for (secretBytes in forbiddenByteArrays) {
            assertFalse(
                "Raw SQLite database file on disk must NOT contain plaintext binary secret '${String(secretBytes, Charsets.US_ASCII)}'",
                containsSubarray(diskBytes, secretBytes)
            )
        }
        val forbiddenLongs = listOf(sentinelTtl, sentinelExpires, sentinelBitmask.toLong(), sentinelVoteTs)
        for (secretLong in forbiddenLongs) {
            val rawBeBytes = java.nio.ByteBuffer.allocate(8).putLong(secretLong).array()
            assertFalse(
                "Raw SQLite database file on disk must NOT contain unencrypted 64-bit integer $secretLong",
                containsSubarray(diskBytes, rawBeBytes)
            )
        }
    }

    @Test
    fun testPollAndPollVoteRowBindingSwapAndDowngradeRejection(): Unit = runBlocking {
        val poll = PollEntity(
            pollId = "poll_swap_1",
            groupId = "grp_1",
            creatorMemberId = "creator_id",
            creatorName = "Creator",
            question = "Secret Poll?",
            optionsJson = "[\"Yes\",\"No\"]",
            isMultiChoice = false,
            expirationTimestamp = 1900000000000L
        )
        val vote = PollVoteEntity(
            pollId = "poll_swap_1",
            memberId = "member_alice",
            memberName = "Alice",
            selectedBitmask = 2,
            voteTimestamp = 1794900000123L
        )

        // 1. Intra-row column swaps throw AEADBadTagException
        assertThrows(AEADBadTagException::class.java) {
            poll.copy(question = poll.optionsJson)
        }
        assertThrows(AEADBadTagException::class.java) {
            poll.copy(creatorName = poll.creatorMemberId)
        }
        assertThrows(AEADBadTagException::class.java) {
            vote.copy(selectedBitmask = vote.voteTimestamp)
        }

        // 2. Cross-row / cross-table swaps throw AEADBadTagException
        val poll2 = poll.copy(
            pollId = "poll_swap_2",
            creatorMemberId = EncryptedText("creator_id", "polls", "poll_swap_2", "creatorMemberId"),
            creatorName = EncryptedText("Creator", "polls", "poll_swap_2", "creatorName"),
            question = EncryptedText("Secret Poll?", "polls", "poll_swap_2", "question"),
            optionsJson = EncryptedText("[\"Yes\",\"No\"]", "polls", "poll_swap_2", "optionsJson")
        )
        assertThrows(AEADBadTagException::class.java) {
            poll2.copy(question = poll.question)
        }

        // 3. Database downgrade attack: replace V2 ciphertext with V1 (0x51) or raw AES-GCM ciphertext
        db.pollDao().insertOrUpdatePoll(poll)
        val legacyV1Hex = CryptoUtils.toHex(
            KeystoreCrypto.encrypt("Downgraded V1 question".toByteArray(), "polls", "poll_swap_1")!!
        )
        db.openHelper.writableDatabase.execSQL(
            "UPDATE polls SET question = ? WHERE pollId = ?",
            arrayOf(legacyV1Hex, "poll_swap_1")
        )
        assertThrows(AEADBadTagException::class.java) {
            runBlocking { db.pollDao().getPoll("poll_swap_1") }
        }

        // Raw unheaded AES-GCM ciphertext (both normal IV and IV[0] == 0x52 collision) must be blocked
        val normalIv = ByteArray(KeystoreCrypto.GCM_IV_LENGTH_BYTES) { 0x01 }
        val rawCipher = Cipher.getInstance("AES/GCM/NoPadding")
        rawCipher.init(Cipher.ENCRYPT_MODE, testMasterKey, GCMParameterSpec(128, normalIv))
        val rawHex = CryptoUtils.toHex(normalIv + rawCipher.doFinal("Raw unheaded question".toByteArray()))
        db.openHelper.writableDatabase.execSQL(
            "UPDATE polls SET question = ? WHERE pollId = ?",
            arrayOf(rawHex, "poll_swap_1")
        )
        assertThrows(AEADBadTagException::class.java) {
            runBlocking { db.pollDao().getPoll("poll_swap_1") }
        }

        val customIv = CryptoUtils.secureRandomBytes(KeystoreCrypto.GCM_IV_LENGTH_BYTES)
        customIv[0] = KeystoreCrypto.MAGIC_ROW_BOUND_V2
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, testMasterKey, GCMParameterSpec(128, customIv))
        val ct = cipher.doFinal("Raw unheaded question".toByteArray())
        val rawCollidingHex = CryptoUtils.toHex(customIv + ct)
        db.openHelper.writableDatabase.execSQL(
            "UPDATE polls SET question = ? WHERE pollId = ?",
            arrayOf(rawCollidingHex, "poll_swap_1")
        )
        val collidingEx = assertThrows(Exception::class.java) {
            runBlocking { db.pollDao().getPoll("poll_swap_1") }
        }
        assertTrue(
            "Colliding IV raw ciphertext must fail closed",
            collidingEx is GeneralSecurityException || collidingEx is IllegalArgumentException
        )
    }

    @Test
    fun testZeroSensitiveMemoryWipesInMemoryBuffersAcrossEntities() {
        val contact = ContactEntity(
            id = "c1",
            name = "Alice",
            chainKeyOut = ByteArray(64) { 0x5A },
            chainKeyIn = ByteArray(64) { 0x6B },
            counterOut = 1,
            counterIn = 2
        )
        val message = MessageEntity(
            contactId = "c1",
            isOutgoing = true,
            seqNum = 1,
            textContent = "hi",
            imageBytes = ByteArray(32) { 0x1A },
            ackRatchetKey = ByteArray(32) { 0x2B },
            slotEdSeed = ByteArray(32) { 0x3C },
            voiceBytes = ByteArray(48) { 0x4D }
        )
        val group = GroupEntity(
            groupId = "g1",
            groupName = "Group",
            myMemberId = "m1",
            myChainKeyOut = ByteArray(64) { 0x7E },
            myCounterOut = 0
        )
        val groupMember = GroupMemberEntity(
            groupId = "g1",
            memberId = "m2",
            memberName = "Bob",
            chainKeyIn = ByteArray(64) { 0x7F },
            counterIn = 0
        )
        val pendingChunk = PendingChunkTransferEntity(
            transferId = "t1",
            contactId = "c1",
            seqNum = 3,
            totalChunks = 2,
            missingIndices = "0,1",
            baseEdSeed = ByteArray(32) { 0x21 },
            baseMsgKey = ByteArray(32) { 0x22 },
            direction = "AliceToBob"
        )

        contact.zeroSensitiveMemory()
        message.zeroSensitiveMemory()
        group.zeroSensitiveMemory()
        groupMember.zeroSensitiveMemory()
        pendingChunk.zeroSensitiveMemory()

        assertTrue(contact.rawChainKeyOut.all { it == 0.toByte() })
        assertTrue(contact.rawChainKeyIn.all { it == 0.toByte() })
        assertTrue(message.rawImageBytes!!.all { it == 0.toByte() })
        assertTrue(message.rawAckRatchetKey!!.all { it == 0.toByte() })
        assertTrue(message.rawSlotEdSeed!!.all { it == 0.toByte() })
        assertTrue(message.rawVoiceBytes!!.all { it == 0.toByte() })
        assertTrue(group.rawMyChainKeyOut.all { it == 0.toByte() })
        assertTrue(groupMember.rawChainKeyIn.all { it == 0.toByte() })
        assertTrue(pendingChunk.rawBaseEdSeed.all { it == 0.toByte() })
        assertTrue(pendingChunk.rawBaseMsgKey.all { it == 0.toByte() })
    }

    @Test
    fun testRealSqliteMigration16To17PreservesAndEncryptsPollsAndPollVotes(): Unit = runBlocking {
        val context = RuntimeEnvironment.getApplication()
        val migDbFile = File(context.cacheDir, "mig_16_17_${System.nanoTime()}.db")
        try {
            // Create genuine v16 SQLite schema + plaintext poll and poll_votes rows
            val helper: SupportSQLiteOpenHelper = FrameworkSQLiteOpenHelperFactory().create(
                SupportSQLiteOpenHelper.Configuration.builder(context)
                    .name(migDbFile.absolutePath)
                    .callback(object : SupportSQLiteOpenHelper.Callback(16) {
                        override fun onCreate(db: SupportSQLiteDatabase) {
                            db.execSQL("""
                                CREATE TABLE IF NOT EXISTS contacts (
                                    id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL,
                                    chainKeyOut BLOB NOT NULL, chainKeyIn BLOB NOT NULL,
                                    counterOut INTEGER NOT NULL, counterIn INTEGER NOT NULL,
                                    rekeyEpoch INTEGER NOT NULL, receivedBitmapBase INTEGER NOT NULL,
                                    receivedBitmap BLOB NOT NULL, lastActive INTEGER NOT NULL,
                                    isInitiator INTEGER NOT NULL, sas TEXT NOT NULL,
                                    fingerprint TEXT NOT NULL, isVerified INTEGER NOT NULL
                                )
                            """.trimIndent())
                            db.execSQL("""
                                CREATE TABLE IF NOT EXISTS messages (
                                    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, contactId TEXT NOT NULL,
                                    isOutgoing INTEGER NOT NULL, seqEpoch INTEGER NOT NULL,
                                    seqNum INTEGER NOT NULL, ackNum INTEGER NOT NULL,
                                    timestamp INTEGER NOT NULL, textContent TEXT, imageBytes BLOB,
                                    status TEXT NOT NULL, retryCount INTEGER NOT NULL,
                                    lastAttemptTimestamp INTEGER NOT NULL, ackTarget BLOB,
                                    ackRatchetKey BLOB, slotTarget BLOB, slotEdSeed BLOB,
                                    senderMemberId TEXT, senderName TEXT,
                                    ephemeralTtlSeconds TEXT NOT NULL, expiresAtTimestamp TEXT,
                                    reaction TEXT, voiceBytes BLOB, voiceDurationMs INTEGER NOT NULL, pollId TEXT
                                )
                            """.trimIndent())
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_messages_contactId_seqEpoch_seqNum ON messages (contactId, seqEpoch, seqNum)")
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_messages_timestamp ON messages (timestamp)")
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_messages_expiresAtTimestamp ON messages (expiresAtTimestamp)")
                            db.execSQL("CREATE TABLE IF NOT EXISTS chunks (transferId TEXT NOT NULL, chunkIndex INTEGER NOT NULL, totalChunks INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (transferId, chunkIndex))")
                            db.execSQL("CREATE TABLE IF NOT EXISTS pending_chunk_transfers (transferId TEXT NOT NULL PRIMARY KEY, contactId TEXT NOT NULL, seqNum INTEGER NOT NULL, totalChunks INTEGER NOT NULL, missingIndices TEXT NOT NULL, baseEdSeed BLOB NOT NULL, baseMsgKey BLOB NOT NULL, direction TEXT NOT NULL, isSelf INTEGER NOT NULL, ackNum INTEGER NOT NULL, timestampUTC INTEGER NOT NULL, createdAt INTEGER NOT NULL, expiresAt INTEGER NOT NULL)")
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_pending_chunk_transfers_contactId ON pending_chunk_transfers (contactId)")
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_pending_chunk_transfers_expiresAt ON pending_chunk_transfers (expiresAt)")
                            db.execSQL("CREATE TABLE IF NOT EXISTS dht_node_cache (ip TEXT NOT NULL, port INTEGER NOT NULL, lastSeen INTEGER NOT NULL, rttMs INTEGER NOT NULL, nodeIdHex TEXT, PRIMARY KEY (ip, port))")
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_dht_node_cache_rttMs ON dht_node_cache (rttMs)")
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_dht_node_cache_lastSeen ON dht_node_cache (lastSeen)")
                            db.execSQL("CREATE TABLE IF NOT EXISTS pending_rekey_offers (contactId TEXT NOT NULL PRIMARY KEY, epoch INTEGER NOT NULL, skNew BLOB NOT NULL, pkNew BLOB NOT NULL, offerSeqNum INTEGER NOT NULL, createdAt INTEGER NOT NULL)")
                            db.execSQL("CREATE TABLE IF NOT EXISTS skipped_keys (contactId TEXT NOT NULL, slotIndex INTEGER NOT NULL, msgKey BLOB NOT NULL, target BLOB NOT NULL, edPrivateKeySeed BLOB NOT NULL, createdAt INTEGER NOT NULL, expiresAt INTEGER NOT NULL, PRIMARY KEY (contactId, slotIndex))")
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_skipped_keys_expiresAt ON skipped_keys (expiresAt)")
                            db.execSQL("CREATE TABLE IF NOT EXISTS groups (groupId TEXT NOT NULL PRIMARY KEY, groupName TEXT NOT NULL, myMemberId TEXT NOT NULL, myChainKeyOut BLOB NOT NULL, myCounterOut INTEGER NOT NULL, groupEpoch INTEGER NOT NULL, createdAt INTEGER NOT NULL, lastActive INTEGER NOT NULL, isActive INTEGER NOT NULL)")
                            db.execSQL("CREATE TABLE IF NOT EXISTS group_members (groupId TEXT NOT NULL, memberId TEXT NOT NULL, contactId TEXT, memberName TEXT NOT NULL, chainKeyIn BLOB NOT NULL, counterIn INTEGER NOT NULL, receivedBitmapBase INTEGER NOT NULL, receivedBitmap BLOB NOT NULL, joinedAt INTEGER NOT NULL, isActive INTEGER NOT NULL, PRIMARY KEY (groupId, memberId))")
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_group_members_groupId ON group_members (groupId)")
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_group_members_contactId ON group_members (contactId)")
                            db.execSQL("CREATE TABLE IF NOT EXISTS polls (pollId TEXT NOT NULL PRIMARY KEY, groupId TEXT NOT NULL, creatorMemberId TEXT NOT NULL, creatorName TEXT NOT NULL, question TEXT NOT NULL, optionsJson TEXT NOT NULL, isMultiChoice INTEGER NOT NULL, expirationTimestamp INTEGER NOT NULL, createdAt INTEGER NOT NULL, isClosed INTEGER NOT NULL)")
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_polls_groupId ON polls (groupId)")
                            db.execSQL("CREATE TABLE IF NOT EXISTS poll_votes (pollId TEXT NOT NULL, memberId TEXT NOT NULL, memberName TEXT NOT NULL, selectedBitmask INTEGER NOT NULL, voteTimestamp INTEGER NOT NULL, PRIMARY KEY (pollId, memberId))")
                            db.execSQL("CREATE INDEX IF NOT EXISTS index_poll_votes_pollId ON poll_votes (pollId)")

                            db.execSQL(
                                "INSERT INTO polls VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                arrayOf<Any>("p_legacy", "g1", "creator_uuid", "Alice", "Meetup time?", "[\"18:00\",\"20:00\"]", 0, 1900000000000L, 1794000000000L, 0)
                            )
                            db.execSQL(
                                "INSERT INTO poll_votes VALUES (?, ?, ?, ?, ?)",
                                arrayOf<Any>("p_legacy", "voter_uuid", "Bob", 2, 1794000123456L)
                            )
                        }

                        override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {}
                    })
                    .build()
            )
            helper.writableDatabase.close()
            helper.close()

            // Open with Room v17 and MIGRATION_16_17
            val migratedDb = Room.databaseBuilder(context, AppDatabase::class.java, migDbFile.absolutePath)
                .addMigrations(AppDatabase.MIGRATION_16_17)
                .allowMainThreadQueries()
                .build()
            try {
                val poll = migratedDb.pollDao().getPoll("p_legacy")!!
                assertEquals("creator_uuid", poll.rawCreatorMemberId)
                assertEquals("Alice", poll.rawCreatorName)
                assertEquals("Meetup time?", poll.rawQuestion)
                assertEquals(listOf("18:00", "20:00"), poll.optionsList)

                val votes = migratedDb.pollDao().getVotesForPoll("p_legacy")
                assertEquals(1, votes.size)
                assertEquals("Bob", votes[0].rawMemberName)
                assertEquals(2, votes[0].rawSelectedBitmask)
                assertEquals(1794000123456L, votes[0].rawVoteTimestamp)
            } finally {
                migratedDb.close()
            }
        } finally {
            migDbFile.delete()
            File("${migDbFile.absolutePath}-wal").delete()
            File("${migDbFile.absolutePath}-shm").delete()
        }
    }

    private fun containsSubarray(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..(haystack.size - needle.size)) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }
}
