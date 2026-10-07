package org.pqchat.dht.data.db

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "contacts")
data class ContactEntity(
    @PrimaryKey
    val id: String,
    val name: String,
    val chainKeyOut: ByteArray, // 64 bytes
    val chainKeyIn: ByteArray,  // 64 bytes
    val counterOut: Int,
    val counterIn: Int,
    val rekeyEpoch: Long = 0L,
    val receivedBitmapBase: Int = 0,
    val receivedBitmap: ByteArray = ByteArray(128), // 1024-bit sliding window
    val lastActive: Long = System.currentTimeMillis()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ContactEntity) return false
        return id == other.id && name == other.name &&
                chainKeyOut.contentEquals(other.chainKeyOut) &&
                chainKeyIn.contentEquals(other.chainKeyIn) &&
                counterOut == other.counterOut &&
                counterIn == other.counterIn &&
                rekeyEpoch == other.rekeyEpoch &&
                receivedBitmapBase == other.receivedBitmapBase &&
                receivedBitmap.contentEquals(other.receivedBitmap) &&
                lastActive == other.lastActive
    }

    override fun hashCode(): Int = id.hashCode()
}

@Entity(
    tableName = "messages",
    indices = [
        Index(value = ["contactId", "seqEpoch", "seqNum"]),
        Index(value = ["timestamp"])
    ]
)
data class MessageEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val contactId: String,
    val isOutgoing: Boolean,
    val seqEpoch: Int = 0,
    val seqNum: Int,
    val ackNum: Int = 0,
    val timestamp: Long,
    val textContent: String?,
    val imageBytes: ByteArray? = null,
    val status: String, // QUEUED, SENDING, SENT_DHT, DELIVERED, CONFIRMED_DHT
    val retryCount: Int = 0,
    val lastAttemptTimestamp: Long = 0L
)

@Entity(
    tableName = "skipped_keys",
    primaryKeys = ["contactId", "slotIndex"],
    indices = [
        Index(value = ["expiresAt"])
    ]
)
data class SkippedKeyEntity(
    val contactId: String,
    val slotIndex: Int,
    val msgKey: ByteArray, // 32 bytes AES key
    val target: ByteArray, // 20 bytes DHT target
    val edPrivateKeySeed: ByteArray, // 32 bytes
    val createdAt: Long = System.currentTimeMillis(),
    val expiresAt: Long = System.currentTimeMillis() + 72 * 3600 * 1000L // 72h TTL per BEP 44 buffer
) {
    fun destroy() {
        java.util.Arrays.fill(msgKey, 0.toByte())
        java.util.Arrays.fill(edPrivateKeySeed, 0.toByte())
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SkippedKeyEntity) return false
        return contactId == other.contactId && slotIndex == other.slotIndex &&
                msgKey.contentEquals(other.msgKey) && target.contentEquals(other.target) &&
                edPrivateKeySeed.contentEquals(other.edPrivateKeySeed) &&
                createdAt == other.createdAt && expiresAt == other.expiresAt
    }

    override fun hashCode(): Int = 31 * contactId.hashCode() + slotIndex
}

@Dao
interface SkippedKeyDao {
    @Query("SELECT * FROM skipped_keys WHERE contactId = :contactId ORDER BY slotIndex ASC")
    suspend fun getSkippedKeysForContact(contactId: String): List<SkippedKeyEntity>

    @Query("SELECT * FROM skipped_keys WHERE contactId = :contactId AND slotIndex = :slotIndex LIMIT 1")
    suspend fun getSkippedKey(contactId: String, slotIndex: Int): SkippedKeyEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdate(skippedKey: SkippedKeyEntity)

    @Query("DELETE FROM skipped_keys WHERE contactId = :contactId AND slotIndex = :slotIndex")
    suspend fun deleteSkippedKey(contactId: String, slotIndex: Int)

    @Query("DELETE FROM skipped_keys WHERE expiresAt < :now")
    suspend fun deleteExpiredKeys(now: Long = System.currentTimeMillis())

    @Query("SELECT COUNT(*) FROM skipped_keys WHERE contactId = :contactId")
    suspend fun countSkippedKeys(contactId: String): Int

    @Query("DELETE FROM skipped_keys WHERE contactId = :contactId AND slotIndex IN (SELECT slotIndex FROM skipped_keys WHERE contactId = :contactId ORDER BY createdAt ASC LIMIT :count)")
    suspend fun deleteOldestSkippedKeys(contactId: String, count: Int)
}

@Entity(tableName = "pending_rekey_offers")
data class PendingRekeyOfferEntity(
    @PrimaryKey
    val contactId: String,
    val epoch: Long,
    val skNew: ByteArray, // ML-KEM private key
    val pkNew: ByteArray, // ML-KEM public key
    val offerSeqNum: Int,
    val createdAt: Long = System.currentTimeMillis()
) {
    fun destroy() {
        java.util.Arrays.fill(skNew, 0.toByte())
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PendingRekeyOfferEntity) return false
        return contactId == other.contactId && epoch == other.epoch &&
                skNew.contentEquals(other.skNew) && pkNew.contentEquals(other.pkNew) &&
                offerSeqNum == other.offerSeqNum
    }

    override fun hashCode(): Int = contactId.hashCode()
}

@Dao
interface PendingRekeyOfferDao {
    @Query("SELECT * FROM pending_rekey_offers WHERE contactId = :contactId LIMIT 1")
    suspend fun getPendingOffer(contactId: String): PendingRekeyOfferEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdate(offer: PendingRekeyOfferEntity)

    @Query("DELETE FROM pending_rekey_offers WHERE contactId = :contactId")
    suspend fun deletePendingOffer(contactId: String)
}

@Entity(
    tableName = "chunks",
    primaryKeys = ["transferId", "chunkIndex"]
)
data class ChunkEntity(
    val transferId: String,
    val chunkIndex: Int,
    val totalChunks: Int,
    val data: ByteArray
)

@Dao
interface ContactDao {
    @Query("SELECT * FROM contacts ORDER BY lastActive DESC")
    fun getAllContactsFlow(): Flow<List<ContactEntity>>

    @Query("SELECT * FROM contacts WHERE id = :id LIMIT 1")
    suspend fun getContactById(id: String): ContactEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdate(contact: ContactEntity)

    @Query("UPDATE contacts SET counterOut = :counterOut, chainKeyOut = :chainKeyOut WHERE id = :id")
    suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: ByteArray)

    @Query("UPDATE contacts SET counterOut = :counterOut, chainKeyOut = :chainKeyOut, rekeyEpoch = :rekeyEpoch WHERE id = :id")
    suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: ByteArray, rekeyEpoch: Long)

    @Query("UPDATE contacts SET counterIn = :counterIn, chainKeyIn = :chainKeyIn WHERE id = :id")
    suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: ByteArray)

    @Query("UPDATE contacts SET counterIn = :counterIn, chainKeyIn = :chainKeyIn, receivedBitmapBase = :bitmapBase, receivedBitmap = :bitmap WHERE id = :id")
    suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: ByteArray, bitmapBase: Int, bitmap: ByteArray)

    @Query("UPDATE contacts SET counterIn = :counterIn, chainKeyIn = :chainKeyIn, rekeyEpoch = :rekeyEpoch WHERE id = :id")
    suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: ByteArray, rekeyEpoch: Long)

    @Query("UPDATE contacts SET counterIn = :counterIn, chainKeyIn = :chainKeyIn, rekeyEpoch = :rekeyEpoch, receivedBitmapBase = :bitmapBase, receivedBitmap = :bitmap WHERE id = :id")
    suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: ByteArray, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray)

    @Query("UPDATE contacts SET rekeyEpoch = :rekeyEpoch WHERE id = :id")
    suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long)

    @Query("DELETE FROM contacts WHERE id = :id")
    suspend fun deleteContact(id: String)
}

@Dao
interface MessageDao {
    @Query("SELECT * FROM messages WHERE contactId = :contactId ORDER BY timestamp ASC")
    fun getMessagesForContactFlow(contactId: String): Flow<List<MessageEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertMessage(message: MessageEntity): Long

    @Query("UPDATE messages SET status = :status WHERE id = :id")
    suspend fun updateStatus(id: Long, status: String)

    @Query("UPDATE messages SET status = :status, seqNum = :seqNum WHERE id = :id")
    suspend fun updateMessageStatusAndSeq(id: Long, status: String, seqNum: Int)

    @Query("UPDATE messages SET status = :status, retryCount = :retryCount, lastAttemptTimestamp = :timestamp WHERE id = :id")
    suspend fun updateMessageRetry(id: Long, status: String, retryCount: Int, timestamp: Long)

    @Query("SELECT * FROM messages WHERE contactId = :contactId AND isOutgoing = 1 AND status = 'QUEUED' ORDER BY id ASC")
    suspend fun getQueuedMessagesForContact(contactId: String): List<MessageEntity>

    @Query("SELECT * FROM messages WHERE isOutgoing = 1 AND status = 'QUEUED' ORDER BY id ASC")
    suspend fun getAllQueuedMessages(): List<MessageEntity>

    @Query("UPDATE messages SET status = :status WHERE contactId = :contactId AND seqNum = :seqNum AND isOutgoing = :isOutgoing")
    suspend fun updateStatusForSeq(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String)

    @Query("UPDATE messages SET status = :status, isOutgoing = :isOutgoing WHERE contactId = :contactId AND seqNum = :seqNum")
    suspend fun updateMessageStatusAndDirection(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String)

    @Query("UPDATE messages SET isOutgoing = 0 WHERE contactId = :contactId AND status = 'CONFIRMED_DHT'")
    suspend fun normalizeConfirmedSelfNotes(contactId: String)

    @Query("DELETE FROM messages WHERE contactId = :contactId")
    suspend fun deleteMessagesForContact(contactId: String)

    @Query("SELECT EXISTS(SELECT 1 FROM messages WHERE contactId = :contactId AND seqEpoch = :seqEpoch AND seqNum = :seqNum AND isOutgoing = :isOutgoing)")
    suspend fun existsMessageWithEpoch(contactId: String, seqEpoch: Int, seqNum: Int, isOutgoing: Boolean): Boolean

    @Query("SELECT EXISTS(SELECT 1 FROM messages WHERE contactId = :contactId AND seqNum = :seqNum AND isOutgoing = :isOutgoing)")
    suspend fun existsMessage(contactId: String, seqNum: Int, isOutgoing: Boolean): Boolean
}

@Dao
interface ChunkDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertChunk(chunk: ChunkEntity)

    @Query("SELECT * FROM chunks WHERE transferId = :transferId ORDER BY chunkIndex ASC")
    suspend fun getChunksForTransfer(transferId: String): List<ChunkEntity>

    @Query("SELECT COUNT(*) FROM chunks WHERE transferId = :transferId")
    suspend fun countChunks(transferId: String): Int

    @Query("DELETE FROM chunks WHERE transferId = :transferId")
    suspend fun deleteChunks(transferId: String)
}

@Entity(
    tableName = "dht_node_cache",
    primaryKeys = ["ip", "port"],
    indices = [
        Index(value = ["rttMs"]),
        Index(value = ["lastSeen"])
    ]
)
data class DhtNodeCacheEntity(
    val ip: String,
    val port: Int,
    val lastSeen: Long = System.currentTimeMillis(),
    val rttMs: Long = 0L,
    val nodeIdHex: String? = null
)

@Dao
interface DhtNodeCacheDao {
    @Query("SELECT * FROM dht_node_cache ORDER BY rttMs ASC LIMIT :limit")
    suspend fun getFastestNodes(limit: Int = 40): List<DhtNodeCacheEntity>

    @Query("SELECT * FROM dht_node_cache ORDER BY rttMs ASC")
    suspend fun getAllNodes(): List<DhtNodeCacheEntity>

    @Query("SELECT * FROM dht_node_cache WHERE ip = :ip AND port = :port LIMIT 1")
    suspend fun getNode(ip: String, port: Int): DhtNodeCacheEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdate(node: DhtNodeCacheEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdateAll(nodes: List<DhtNodeCacheEntity>)

    @Query("DELETE FROM dht_node_cache WHERE ip = :ip AND port = :port")
    suspend fun deleteNode(ip: String, port: Int)

    @Transaction
    suspend fun upsertAndTrim(node: DhtNodeCacheEntity, maxCount: Int = 40) {
        insertOrUpdate(node)
        val all = getAllNodes()
        if (all.size > maxCount) {
            val toRemove = all.drop(maxCount)
            for (item in toRemove) {
                deleteNode(item.ip, item.port)
            }
        }
    }

    @Transaction
    suspend fun trimToFastest(maxCount: Int = 40) {
        val all = getAllNodes()
        if (all.size > maxCount) {
            val toRemove = all.drop(maxCount)
            for (item in toRemove) {
                deleteNode(item.ip, item.port)
            }
        }
    }

    @Query("DELETE FROM dht_node_cache")
    suspend fun clearAll()

    @Query("SELECT COUNT(*) FROM dht_node_cache")
    suspend fun count(): Int
}

