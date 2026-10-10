package org.pqchat.dht.data.db

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "contacts")
data class ContactEntity(
    @PrimaryKey
    val id: String,
    val name: String,
    val chainKeyOut: EncryptedBlob, // 64 bytes
    val chainKeyIn: EncryptedBlob,  // 64 bytes
    val counterOut: Int,
    val counterIn: Int,
    val rekeyEpoch: Long = 0L,
    val receivedBitmapBase: Int = 0,
    val receivedBitmap: ByteArray = ByteArray(128), // 1024-bit sliding window
    val lastActive: Long = System.currentTimeMillis(),
    val isInitiator: Boolean = true,
    val sas: String = "",
    val fingerprint: String = "",
    val isVerified: Boolean = false
) {
    @Ignore
    constructor(
        id: String,
        name: String,
        chainKeyOut: ByteArray,
        chainKeyIn: ByteArray,
        counterOut: Int,
        counterIn: Int,
        rekeyEpoch: Long = 0L,
        receivedBitmapBase: Int = 0,
        receivedBitmap: ByteArray = ByteArray(128),
        lastActive: Long = System.currentTimeMillis(),
        isInitiator: Boolean = true,
        sas: String = "",
        fingerprint: String = "",
        isVerified: Boolean = false
    ) : this(
        id = id,
        name = name,
        chainKeyOut = EncryptedBlob(chainKeyOut, "contacts", id),
        chainKeyIn = EncryptedBlob(chainKeyIn, "contacts", id),
        counterOut = counterOut,
        counterIn = counterIn,
        rekeyEpoch = rekeyEpoch,
        receivedBitmapBase = receivedBitmapBase,
        receivedBitmap = receivedBitmap,
        lastActive = lastActive,
        isInitiator = isInitiator,
        sas = sas,
        fingerprint = fingerprint,
        isVerified = isVerified
    )

    val rawChainKeyOut: ByteArray get() = chainKeyOut.raw
    val rawChainKeyIn: ByteArray get() = chainKeyIn.raw

    val outboundDirection: String
        get() = if (isInitiator) "AliceToBob" else "BobToAlice"

    val inboundDirection: String
        get() = if (id == "self_notes_loopback") {
            "AliceToBob"
        } else {
            if (isInitiator) "BobToAlice" else "AliceToBob"
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ContactEntity) return false
        return id == other.id && name == other.name &&
                chainKeyOut == other.chainKeyOut &&
                chainKeyIn == other.chainKeyIn &&
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
    val textContent: EncryptedText? = null,
    val imageBytes: EncryptedBlob? = null,
    val status: String, // QUEUED, SENDING, SENT_DHT, PENDING_DELIVERY, DELIVERED, CONFIRMED_DHT
    val retryCount: Int = 0,
    val lastAttemptTimestamp: Long = 0L,
    val ackTarget: ByteArray? = null,
    val ackRatchetKey: EncryptedBlob? = null,
    val slotTarget: ByteArray? = null,
    val slotEdSeed: EncryptedBlob? = null
) {
    @Ignore
    constructor(
        id: Long = 0,
        contactId: String,
        isOutgoing: Boolean,
        seqEpoch: Int = 0,
        seqNum: Int,
        ackNum: Int = 0,
        timestamp: Long,
        textContent: String?,
        imageBytes: ByteArray? = null,
        status: String,
        retryCount: Int = 0,
        lastAttemptTimestamp: Long = 0L,
        ackTarget: ByteArray? = null,
        ackRatchetKey: ByteArray? = null,
        slotTarget: ByteArray? = null,
        slotEdSeed: ByteArray? = null
    ) : this(
        id = id,
        contactId = contactId,
        isOutgoing = isOutgoing,
        seqEpoch = seqEpoch,
        seqNum = seqNum,
        ackNum = ackNum,
        timestamp = timestamp,
        textContent = textContent?.let { EncryptedText(it, "messages", "${contactId}_${seqNum}") },
        imageBytes = imageBytes?.let { EncryptedBlob(it, "messages", "${contactId}_${seqNum}") },
        status = status,
        retryCount = retryCount,
        lastAttemptTimestamp = lastAttemptTimestamp,
        ackTarget = ackTarget,
        ackRatchetKey = ackRatchetKey?.let { EncryptedBlob(it, "messages", "${contactId}_${seqNum}") },
        slotTarget = slotTarget,
        slotEdSeed = slotEdSeed?.let { EncryptedBlob(it, "messages", "${contactId}_${seqNum}") }
    )

    val rawTextContent: String? get() = textContent?.raw
    val rawImageBytes: ByteArray? get() = imageBytes?.raw
    val rawAckRatchetKey: ByteArray? get() = ackRatchetKey?.raw
    val rawSlotEdSeed: ByteArray? get() = slotEdSeed?.raw
}

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
    val msgKey: EncryptedBlob, // 32 bytes AES key (encrypted at rest)
    val target: ByteArray, // 20 bytes DHT target (public routing address)
    val edPrivateKeySeed: EncryptedBlob, // 32 bytes (encrypted at rest)
    val createdAt: Long = System.currentTimeMillis(),
    val expiresAt: Long = System.currentTimeMillis() + 72 * 3600 * 1000L // 72h TTL per BEP 44 buffer
) {
    @Ignore
    constructor(
        contactId: String,
        slotIndex: Int,
        msgKey: ByteArray,
        target: ByteArray,
        edPrivateKeySeed: ByteArray,
        createdAt: Long = System.currentTimeMillis(),
        expiresAt: Long = System.currentTimeMillis() + 72 * 3600 * 1000L
    ) : this(
        contactId = contactId,
        slotIndex = slotIndex,
        msgKey = EncryptedBlob(msgKey, "skipped_keys", "${contactId}_${slotIndex}"),
        target = target,
        edPrivateKeySeed = EncryptedBlob(edPrivateKeySeed, "skipped_keys", "${contactId}_${slotIndex}"),
        createdAt = createdAt,
        expiresAt = expiresAt
    )

    val rawMsgKey: ByteArray get() = msgKey.raw
    val rawEdPrivateKeySeed: ByteArray get() = edPrivateKeySeed.raw

    fun destroy() {
        msgKey.raw.fill(0)
        edPrivateKeySeed.raw.fill(0)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SkippedKeyEntity) return false
        return contactId == other.contactId && slotIndex == other.slotIndex &&
                msgKey == other.msgKey && target.contentEquals(other.target) &&
                edPrivateKeySeed == other.edPrivateKeySeed &&
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

    suspend fun insertOrUpdate(
        contactId: String,
        slotIndex: Int,
        msgKey: ByteArray,
        target: ByteArray,
        edPrivateKeySeed: ByteArray,
        createdAt: Long = System.currentTimeMillis(),
        expiresAt: Long = System.currentTimeMillis() + 72 * 3600 * 1000L
    ) {
        insertOrUpdate(
            SkippedKeyEntity(
                contactId = contactId,
                slotIndex = slotIndex,
                msgKey = msgKey,
                target = target,
                edPrivateKeySeed = edPrivateKeySeed,
                createdAt = createdAt,
                expiresAt = expiresAt
            )
        )
    }

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
    val skNew: EncryptedBlob, // ML-KEM private key (encrypted at rest)
    val pkNew: ByteArray, // ML-KEM public key
    val offerSeqNum: Int,
    val createdAt: Long = System.currentTimeMillis()
) {
    @Ignore
    constructor(
        contactId: String,
        epoch: Long,
        skNew: ByteArray,
        pkNew: ByteArray,
        offerSeqNum: Int,
        createdAt: Long = System.currentTimeMillis()
    ) : this(
        contactId = contactId,
        epoch = epoch,
        skNew = EncryptedBlob(skNew, "pending_rekey_offers", contactId),
        pkNew = pkNew,
        offerSeqNum = offerSeqNum,
        createdAt = createdAt
    )

    val rawSkNew: ByteArray get() = skNew.raw

    fun destroy() {
        skNew.raw.fill(0)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PendingRekeyOfferEntity) return false
        return contactId == other.contactId && epoch == other.epoch &&
                skNew == other.skNew && pkNew.contentEquals(other.pkNew) &&
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

    suspend fun insertOrUpdate(
        contactId: String,
        epoch: Long,
        skNew: ByteArray,
        pkNew: ByteArray,
        offerSeqNum: Int,
        createdAt: Long = System.currentTimeMillis()
    ) {
        insertOrUpdate(
            PendingRekeyOfferEntity(
                contactId = contactId,
                epoch = epoch,
                skNew = skNew,
                pkNew = pkNew,
                offerSeqNum = offerSeqNum,
                createdAt = createdAt
            )
        )
    }

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
    val data: EncryptedBlob // Chunk binary data (encrypted at rest)
) {
    @Ignore
    constructor(
        transferId: String,
        chunkIndex: Int,
        totalChunks: Int,
        data: ByteArray
    ) : this(
        transferId = transferId,
        chunkIndex = chunkIndex,
        totalChunks = totalChunks,
        data = EncryptedBlob(data, "chunks", "${transferId}_${chunkIndex}")
    )

    val rawData: ByteArray get() = data.raw

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ChunkEntity) return false
        return transferId == other.transferId && chunkIndex == other.chunkIndex &&
                totalChunks == other.totalChunks && data == other.data
    }

    override fun hashCode(): Int = 31 * transferId.hashCode() + chunkIndex
}

@Dao
interface ChunkDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertChunk(chunk: ChunkEntity)

    suspend fun insertChunk(
        transferId: String,
        chunkIndex: Int,
        totalChunks: Int,
        data: ByteArray
    ) {
        insertChunk(
            ChunkEntity(
                transferId = transferId,
                chunkIndex = chunkIndex,
                totalChunks = totalChunks,
                data = data
            )
        )
    }

    @Query("SELECT * FROM chunks WHERE transferId = :transferId ORDER BY chunkIndex ASC")
    suspend fun getChunksForTransfer(transferId: String): List<ChunkEntity>

    @Query("SELECT COUNT(*) FROM chunks WHERE transferId = :transferId")
    suspend fun countChunks(transferId: String): Int

    @Query("DELETE FROM chunks WHERE transferId = :transferId")
    suspend fun deleteChunks(transferId: String)
}

@Dao
interface ContactDao {
    @Query("SELECT * FROM contacts ORDER BY lastActive DESC")
    fun getAllContactsFlow(): Flow<List<ContactEntity>>

    @Query("SELECT * FROM contacts WHERE id = :id LIMIT 1")
    suspend fun getContactById(id: String): ContactEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdate(contact: ContactEntity)

    @Query("UPDATE contacts SET counterOut = :counterOut, chainKeyOut = :chainKeyOut WHERE id = :id")
    suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: EncryptedBlob)

    @Query("UPDATE contacts SET counterOut = :counterOut, chainKeyOut = :chainKeyOut, rekeyEpoch = :rekeyEpoch WHERE id = :id")
    suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: EncryptedBlob, rekeyEpoch: Long)

    @Query("UPDATE contacts SET counterIn = :counterIn, chainKeyIn = :chainKeyIn WHERE id = :id")
    suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob)

    @Query("UPDATE contacts SET counterIn = :counterIn, chainKeyIn = :chainKeyIn, receivedBitmapBase = :bitmapBase, receivedBitmap = :bitmap WHERE id = :id")
    suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray)

    @Query("UPDATE contacts SET counterIn = :counterIn, chainKeyIn = :chainKeyIn, rekeyEpoch = :rekeyEpoch WHERE id = :id")
    suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long)

    @Query("UPDATE contacts SET counterIn = :counterIn, chainKeyIn = :chainKeyIn, rekeyEpoch = :rekeyEpoch, receivedBitmapBase = :bitmapBase, receivedBitmap = :bitmap WHERE id = :id")
    suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray)

    suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: ByteArray) {
        updateOutgoingState(id, counterOut, EncryptedBlob(chainKeyOut, "contacts", id))
    }

    suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: ByteArray, rekeyEpoch: Long) {
        updateOutgoingStateAndEpoch(id, counterOut, EncryptedBlob(chainKeyOut, "contacts", id), rekeyEpoch)
    }

    suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: ByteArray) {
        updateIncomingState(id, counterIn, EncryptedBlob(chainKeyIn, "contacts", id))
    }

    suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: ByteArray, bitmapBase: Int, bitmap: ByteArray) {
        updateIncomingStateWithBitmap(id, counterIn, EncryptedBlob(chainKeyIn, "contacts", id), bitmapBase, bitmap)
    }

    suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: ByteArray, rekeyEpoch: Long) {
        updateIncomingStateAndEpoch(id, counterIn, EncryptedBlob(chainKeyIn, "contacts", id), rekeyEpoch)
    }

    suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: ByteArray, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {
        updateIncomingStateAndEpochWithBitmap(id, counterIn, EncryptedBlob(chainKeyIn, "contacts", id), rekeyEpoch, bitmapBase, bitmap)
    }

    @Query("UPDATE contacts SET rekeyEpoch = :rekeyEpoch WHERE id = :id")
    suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long)

    @Query("UPDATE contacts SET isVerified = :isVerified WHERE id = :id")
    suspend fun updateVerifiedStatus(id: String, isVerified: Boolean)

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

    @Query("SELECT * FROM messages WHERE contactId = :contactId AND isOutgoing = 1 AND status IN ('PENDING_DELIVERY', 'SENT_DHT') ORDER BY id ASC")
    suspend fun getPendingDeliveryMessagesForContact(contactId: String): List<MessageEntity>

    @Query("SELECT * FROM messages WHERE isOutgoing = 1 AND status IN ('PENDING_DELIVERY', 'SENT_DHT') ORDER BY id ASC")
    suspend fun getAllPendingDeliveryMessages(): List<MessageEntity>
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

