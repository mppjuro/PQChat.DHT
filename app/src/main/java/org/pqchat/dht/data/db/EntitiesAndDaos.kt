package org.pqchat.dht.data.db

import androidx.room.*
import javax.crypto.AEADBadTagException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

@Entity(tableName = "contacts")
data class ContactEntity(
    @PrimaryKey
    val id: String,
    val name: EncryptedText,
    val chainKeyOut: EncryptedBlob, // 64 bytes
    val chainKeyIn: EncryptedBlob,  // 64 bytes
    val counterOut: Int,
    val counterIn: Int,
    val rekeyEpoch: Long = 0L,
    val receivedBitmapBase: Int = 0,
    val receivedBitmap: ByteArray = ByteArray(128), // 1024-bit sliding window
    val lastActive: Long = System.currentTimeMillis(),
    val isInitiator: Boolean = true,
    val sas: EncryptedText = EncryptedText("", "contacts", id, "sas"),
    val fingerprint: EncryptedText = EncryptedText("", "contacts", id, "fingerprint"),
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
        name = EncryptedText(name, "contacts", id, "name"),
        chainKeyOut = EncryptedBlob(chainKeyOut, "contacts", id, "chainKeyOut"),
        chainKeyIn = EncryptedBlob(chainKeyIn, "contacts", id, "chainKeyIn"),
        counterOut = counterOut,
        counterIn = counterIn,
        rekeyEpoch = rekeyEpoch,
        receivedBitmapBase = receivedBitmapBase,
        receivedBitmap = receivedBitmap,
        lastActive = lastActive,
        isInitiator = isInitiator,
        sas = EncryptedText(sas, "contacts", id, "sas"),
        fingerprint = EncryptedText(fingerprint, "contacts", id, "fingerprint"),
        isVerified = isVerified
    )

    @Ignore
    constructor(
        id: String,
        name: String,
        chainKeyOut: EncryptedBlob,
        chainKeyIn: EncryptedBlob,
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
        name = EncryptedText(name, "contacts", id, "name"),
        chainKeyOut = if (chainKeyOut.boundColumn == null) EncryptedBlob(chainKeyOut.raw, "contacts", id, "chainKeyOut") else chainKeyOut,
        chainKeyIn = if (chainKeyIn.boundColumn == null) EncryptedBlob(chainKeyIn.raw, "contacts", id, "chainKeyIn") else chainKeyIn,
        counterOut = counterOut,
        counterIn = counterIn,
        rekeyEpoch = rekeyEpoch,
        receivedBitmapBase = receivedBitmapBase,
        receivedBitmap = receivedBitmap,
        lastActive = lastActive,
        isInitiator = isInitiator,
        sas = EncryptedText(sas, "contacts", id, "sas"),
        fingerprint = EncryptedText(fingerprint, "contacts", id, "fingerprint"),
        isVerified = isVerified
    )

    init {
        validateRowBinding()
    }

    fun validateRowBinding() {
        chainKeyOut.validateRowBinding("contacts", id, "chainKeyOut", "chainKeyOut")
        chainKeyIn.validateRowBinding("contacts", id, "chainKeyIn", "chainKeyIn")
        name.validateRowBinding("contacts", id, "name", "name")
        sas.validateRowBinding("contacts", id, "sas", "sas")
        fingerprint.validateRowBinding("contacts", id, "fingerprint", "fingerprint")
    }

    val rawName: String get() = name.raw
    val rawSas: String get() = sas.raw
    val rawFingerprint: String get() = fingerprint.raw
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
                lastActive == other.lastActive &&
                isInitiator == other.isInitiator &&
                sas == other.sas &&
                fingerprint == other.fingerprint &&
                isVerified == other.isVerified
    }

    override fun hashCode(): Int = id.hashCode()
}

@Entity(
    tableName = "messages",
    indices = [
        Index(value = ["contactId", "seqEpoch", "seqNum"]),
        Index(value = ["timestamp"]),
        Index(value = ["expiresAtTimestamp"])
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
    val timestamp: Long = System.currentTimeMillis(),
    val textContent: EncryptedText? = null,
    val imageBytes: EncryptedBlob? = null,
    val status: String = "PENDING", // QUEUED, SENDING, SENT_DHT, PENDING_DELIVERY, DELIVERED, CONFIRMED_DHT
    val retryCount: Int = 0,
    val lastAttemptTimestamp: Long = 0L,
    val ackTarget: ByteArray? = null,
    val ackRatchetKey: EncryptedBlob? = null,
    val slotTarget: ByteArray? = null,
    val slotEdSeed: EncryptedBlob? = null,
    val senderMemberId: EncryptedText? = null,
    val senderName: EncryptedText? = null,
    val ephemeralTtlSeconds: EncryptedLong = EncryptedLong(0L, "messages", computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing), "ephemeralTtlSeconds"),
    val expiresAtTimestamp: EncryptedLong? = null,
    val reaction: EncryptedText? = null,
    val voiceBytes: EncryptedBlob? = null,
    val voiceDurationMs: Int = 0,
    val pollId: String? = null
) {
    companion object {
        fun computeMessageRowId(contactId: String, seqEpoch: Int, seqNum: Int, isOutgoing: Boolean): String =
            "${contactId}_${seqEpoch}_${seqNum}_${isOutgoing}"
    }

    val messageRowId: String
        get() = computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing)

    @Ignore
    constructor(
        id: Long = 0,
        contactId: String,
        isOutgoing: Boolean,
        seqEpoch: Int = 0,
        seqNum: Int,
        ackNum: Int = 0,
        timestamp: Long = System.currentTimeMillis(),
        textContent: String?,
        imageBytes: ByteArray? = null,
        status: String = "PENDING",
        retryCount: Int = 0,
        lastAttemptTimestamp: Long = 0L,
        ackTarget: ByteArray? = null,
        ackRatchetKey: ByteArray? = null,
        slotTarget: ByteArray? = null,
        slotEdSeed: ByteArray? = null,
        senderMemberId: String? = null,
        senderName: String? = null,
        ephemeralTtlSeconds: Long = 0L,
        expiresAtTimestamp: Long? = null,
        reaction: String? = null,
        voiceBytes: ByteArray? = null,
        voiceDurationMs: Int = 0,
        pollId: String? = null
    ) : this(
        id = id,
        contactId = contactId,
        isOutgoing = isOutgoing,
        seqEpoch = seqEpoch,
        seqNum = seqNum,
        ackNum = ackNum,
        timestamp = timestamp,
        textContent = textContent?.let {
            EncryptedText(it, "messages", computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing), "textContent")
        },
        imageBytes = imageBytes?.let {
            EncryptedBlob(it, "messages", computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing), "imageBytes")
        },
        status = status,
        retryCount = retryCount,
        lastAttemptTimestamp = lastAttemptTimestamp,
        ackTarget = ackTarget,
        ackRatchetKey = ackRatchetKey?.let {
            EncryptedBlob(it, "messages", computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing), "ackRatchetKey")
        },
        slotTarget = slotTarget,
        slotEdSeed = slotEdSeed?.let {
            EncryptedBlob(it, "messages", computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing), "slotEdSeed")
        },
        senderMemberId = senderMemberId?.let {
            EncryptedText(it, "messages", computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing), "senderMemberId")
        },
        senderName = senderName?.let {
            EncryptedText(it, "messages", computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing), "senderName")
        },
        ephemeralTtlSeconds = EncryptedLong(ephemeralTtlSeconds, "messages", computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing), "ephemeralTtlSeconds"),
        expiresAtTimestamp = expiresAtTimestamp?.let {
            EncryptedLong(it, "messages", computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing), "expiresAtTimestamp")
        },
        reaction = reaction?.let {
            EncryptedText(it, "messages", computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing), "reaction")
        },
        voiceBytes = voiceBytes?.let {
            EncryptedBlob(it, "messages", computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing), "voiceBytes")
        },
        voiceDurationMs = voiceDurationMs,
        pollId = pollId
    )

    @Ignore
    constructor(
        id: Long = 0,
        contactId: String,
        isOutgoing: Boolean,
        seqEpoch: Int = 0,
        seqNum: Int,
        ackNum: Int = 0,
        timestamp: Long = System.currentTimeMillis(),
        imageBytes: ByteArray,
        status: String = "PENDING",
        retryCount: Int = 0,
        lastAttemptTimestamp: Long = 0L,
        ackTarget: ByteArray? = null,
        ackRatchetKey: ByteArray? = null,
        slotTarget: ByteArray? = null,
        slotEdSeed: ByteArray? = null,
        senderMemberId: String? = null,
        senderName: String? = null,
        ephemeralTtlSeconds: Long = 0L,
        expiresAtTimestamp: Long? = null,
        reaction: String? = null,
        pollId: String? = null
    ) : this(
        id = id,
        contactId = contactId,
        isOutgoing = isOutgoing,
        seqEpoch = seqEpoch,
        seqNum = seqNum,
        ackNum = ackNum,
        timestamp = timestamp,
        textContent = null as String?,
        imageBytes = imageBytes,
        status = status,
        retryCount = retryCount,
        lastAttemptTimestamp = lastAttemptTimestamp,
        ackTarget = ackTarget,
        ackRatchetKey = ackRatchetKey,
        slotTarget = slotTarget,
        slotEdSeed = slotEdSeed,
        senderMemberId = senderMemberId,
        senderName = senderName,
        ephemeralTtlSeconds = ephemeralTtlSeconds,
        expiresAtTimestamp = expiresAtTimestamp,
        reaction = reaction,
        voiceBytes = null,
        voiceDurationMs = 0,
        pollId = pollId
    )

    @Ignore
    constructor(
        id: Long = 0,
        contactId: String,
        isOutgoing: Boolean,
        seqEpoch: Int = 0,
        seqNum: Int,
        ackNum: Int = 0,
        timestamp: Long = System.currentTimeMillis(),
        voiceBytes: ByteArray,
        voiceDurationMs: Int,
        status: String = "PENDING",
        retryCount: Int = 0,
        lastAttemptTimestamp: Long = 0L,
        ackTarget: ByteArray? = null,
        ackRatchetKey: ByteArray? = null,
        slotTarget: ByteArray? = null,
        slotEdSeed: ByteArray? = null,
        senderMemberId: String? = null,
        senderName: String? = null,
        ephemeralTtlSeconds: Long = 0L,
        expiresAtTimestamp: Long? = null,
        reaction: String? = null,
        pollId: String? = null
    ) : this(
        id = id,
        contactId = contactId,
        isOutgoing = isOutgoing,
        seqEpoch = seqEpoch,
        seqNum = seqNum,
        ackNum = ackNum,
        timestamp = timestamp,
        textContent = null as String?,
        imageBytes = null,
        status = status,
        retryCount = retryCount,
        lastAttemptTimestamp = lastAttemptTimestamp,
        ackTarget = ackTarget,
        ackRatchetKey = ackRatchetKey,
        slotTarget = slotTarget,
        slotEdSeed = slotEdSeed,
        senderMemberId = senderMemberId,
        senderName = senderName,
        ephemeralTtlSeconds = ephemeralTtlSeconds,
        expiresAtTimestamp = expiresAtTimestamp,
        reaction = reaction,
        voiceBytes = voiceBytes,
        voiceDurationMs = voiceDurationMs,
        pollId = pollId
    )

    init {
        validateRowBinding()
    }

    fun validateRowBinding() {
        val expectedId = messageRowId

        fun checkBlob(blob: EncryptedBlob?, col: String) {
            blob?.validateRowBinding("messages", expectedId, col, col)
        }

        fun checkText(text: EncryptedText?, col: String) {
            text?.validateRowBinding("messages", expectedId, col, col)
        }

        fun checkLong(num: EncryptedLong?, col: String) {
            num?.validateRowBinding("messages", expectedId, col, col)
        }

        checkText(textContent, "textContent")
        checkBlob(imageBytes, "imageBytes")
        checkBlob(ackRatchetKey, "ackRatchetKey")
        checkBlob(slotEdSeed, "slotEdSeed")
        checkText(senderMemberId, "senderMemberId")
        checkText(senderName, "senderName")
        checkLong(ephemeralTtlSeconds, "ephemeralTtlSeconds")
        checkLong(expiresAtTimestamp, "expiresAtTimestamp")
        checkText(reaction, "reaction")
        checkBlob(voiceBytes, "voiceBytes")
    }

    val rawTextContent: String? get() = textContent?.raw
    val rawImageBytes: ByteArray? get() = imageBytes?.raw
    val rawAckRatchetKey: ByteArray? get() = ackRatchetKey?.raw
    val rawSlotEdSeed: ByteArray? get() = slotEdSeed?.raw
    val rawSenderMemberId: String? get() = senderMemberId?.raw
    val rawSenderName: String? get() = senderName?.raw
    val rawEphemeralTtlSeconds: Long get() = ephemeralTtlSeconds.raw
    val rawExpiresAtTimestamp: Long? get() = expiresAtTimestamp?.raw
    val rawReaction: String? get() = reaction?.raw
    val rawVoiceBytes: ByteArray? get() = voiceBytes?.raw
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
        msgKey = EncryptedBlob(msgKey, "skipped_keys", "${contactId}_${slotIndex}", "msgKey"),
        target = target,
        edPrivateKeySeed = EncryptedBlob(edPrivateKeySeed, "skipped_keys", "${contactId}_${slotIndex}", "edPrivateKeySeed"),
        createdAt = createdAt,
        expiresAt = expiresAt
    )

    init {
        validateRowBinding()
    }

    fun validateRowBinding() {
        val expectedId = "${contactId}_${slotIndex}"
        msgKey.validateRowBinding("skipped_keys", expectedId, "msgKey", "msgKey")
        edPrivateKeySeed.validateRowBinding("skipped_keys", expectedId, "edPrivateKeySeed", "edPrivateKeySeed")
    }

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
        skNew = EncryptedBlob(skNew, "pending_rekey_offers", contactId, "skNew"),
        pkNew = pkNew,
        offerSeqNum = offerSeqNum,
        createdAt = createdAt
    )

    init {
        validateRowBinding()
    }

    fun validateRowBinding() {
        skNew.validateRowBinding("pending_rekey_offers", contactId, "skNew", "skNew")
    }

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

    @Query("SELECT * FROM pending_rekey_offers WHERE contactId = :contactId LIMIT 1")
    fun getPendingOfferFlow(contactId: String): Flow<PendingRekeyOfferEntity?>

    fun isRekeyPendingFlow(contactId: String): Flow<Boolean> =
        getPendingOfferFlow(contactId).map { it != null }

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
        data = EncryptedBlob(data, "chunks", "${transferId}_${chunkIndex}", "data")
    )

    init {
        validateRowBinding()
    }

    fun validateRowBinding() {
        val expectedId = "${transferId}_${chunkIndex}"
        data.validateRowBinding("chunks", expectedId, "data", "data")
    }

    val rawData: ByteArray get() = data.raw

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ChunkEntity) return false
        return transferId == other.transferId && chunkIndex == other.chunkIndex &&
                totalChunks == other.totalChunks && data == other.data
    }

    override fun hashCode(): Int = 31 * transferId.hashCode() + chunkIndex
}

@Entity(
    tableName = "pending_chunk_transfers",
    indices = [
        Index("contactId"),
        Index("expiresAt")
    ]
)
data class PendingChunkTransferEntity(
    @PrimaryKey val transferId: String,
    val contactId: String,
    val seqNum: Int,
    val totalChunks: Int,
    val missingIndices: EncryptedText,
    val baseEdSeed: EncryptedBlob,
    val baseMsgKey: EncryptedBlob,
    val direction: String,
    val isSelf: Boolean = false,
    val ackNum: Int = 0,
    val timestampUTC: Long = System.currentTimeMillis(),
    val createdAt: Long = System.currentTimeMillis(),
    val expiresAt: Long = System.currentTimeMillis() + 72 * 3600 * 1000L
) {
    @Ignore
    constructor(
        transferId: String,
        contactId: String,
        seqNum: Int,
        totalChunks: Int,
        missingIndices: List<Int>,
        baseEdSeed: ByteArray,
        baseMsgKey: ByteArray,
        direction: String,
        isSelf: Boolean = false,
        ackNum: Int = 0,
        timestampUTC: Long = System.currentTimeMillis(),
        createdAt: Long = System.currentTimeMillis(),
        expiresAt: Long = System.currentTimeMillis() + 72 * 3600 * 1000L
    ) : this(
        transferId = transferId,
        contactId = contactId,
        seqNum = seqNum,
        totalChunks = totalChunks,
        missingIndices = EncryptedText(missingIndices.joinToString(","), "pending_chunk_transfers", transferId, "missingIndices"),
        baseEdSeed = EncryptedBlob(baseEdSeed, "pending_chunk_transfers", "${transferId}_seed", "baseEdSeed"),
        baseMsgKey = EncryptedBlob(baseMsgKey, "pending_chunk_transfers", "${transferId}_key", "baseMsgKey"),
        direction = direction,
        isSelf = isSelf,
        ackNum = ackNum,
        timestampUTC = timestampUTC,
        createdAt = createdAt,
        expiresAt = expiresAt
    )

    @Ignore
    constructor(
        transferId: String,
        contactId: String,
        seqNum: Int,
        totalChunks: Int,
        missingIndices: String,
        baseEdSeed: ByteArray,
        baseMsgKey: ByteArray,
        direction: String,
        isSelf: Boolean = false,
        ackNum: Int = 0,
        timestampUTC: Long = System.currentTimeMillis(),
        createdAt: Long = System.currentTimeMillis(),
        expiresAt: Long = System.currentTimeMillis() + 72 * 3600 * 1000L
    ) : this(
        transferId = transferId,
        contactId = contactId,
        seqNum = seqNum,
        totalChunks = totalChunks,
        missingIndices = EncryptedText(missingIndices, "pending_chunk_transfers", transferId, "missingIndices"),
        baseEdSeed = EncryptedBlob(baseEdSeed, "pending_chunk_transfers", "${transferId}_seed", "baseEdSeed"),
        baseMsgKey = EncryptedBlob(baseMsgKey, "pending_chunk_transfers", "${transferId}_key", "baseMsgKey"),
        direction = direction,
        isSelf = isSelf,
        ackNum = ackNum,
        timestampUTC = timestampUTC,
        createdAt = createdAt,
        expiresAt = expiresAt
    )

    @Ignore
    constructor(
        transferId: String,
        contactId: String,
        seqNum: Int,
        totalChunks: Int,
        missingIndices: String,
        baseEdSeed: EncryptedBlob,
        baseMsgKey: EncryptedBlob,
        direction: String,
        isSelf: Boolean = false,
        ackNum: Int = 0,
        timestampUTC: Long = System.currentTimeMillis(),
        createdAt: Long = System.currentTimeMillis(),
        expiresAt: Long = System.currentTimeMillis() + 72 * 3600 * 1000L
    ) : this(
        transferId = transferId,
        contactId = contactId,
        seqNum = seqNum,
        totalChunks = totalChunks,
        missingIndices = EncryptedText(missingIndices, "pending_chunk_transfers", transferId, "missingIndices"),
        baseEdSeed = if (baseEdSeed.boundColumn == null) EncryptedBlob(baseEdSeed.raw, "pending_chunk_transfers", "${transferId}_seed", "baseEdSeed") else baseEdSeed,
        baseMsgKey = if (baseMsgKey.boundColumn == null) EncryptedBlob(baseMsgKey.raw, "pending_chunk_transfers", "${transferId}_key", "baseMsgKey") else baseMsgKey,
        direction = direction,
        isSelf = isSelf,
        ackNum = ackNum,
        timestampUTC = timestampUTC,
        createdAt = createdAt,
        expiresAt = expiresAt
    )

    init {
        validateRowBinding()
    }

    fun validateRowBinding() {
        baseEdSeed.validateRowBinding("pending_chunk_transfers", "${transferId}_seed", "baseEdSeed", "baseEdSeed")
        baseMsgKey.validateRowBinding("pending_chunk_transfers", "${transferId}_key", "baseMsgKey", "baseMsgKey")
        missingIndices.validateRowBinding("pending_chunk_transfers", transferId, "missingIndices", "missingIndices")
    }

    val rawBaseEdSeed: ByteArray get() = baseEdSeed.raw
    val rawBaseMsgKey: ByteArray get() = baseMsgKey.raw
    val rawMissingIndices: String get() = missingIndices.raw

    fun parseMissingIndices(): List<Int> {
        if (missingIndices.raw.isBlank()) return emptyList()
        return missingIndices.raw.split(",").mapNotNull { it.trim().toIntOrNull() }
    }
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

    @Query("SELECT chunkIndex FROM chunks WHERE transferId = :transferId ORDER BY chunkIndex ASC")
    suspend fun getExistingChunkIndices(transferId: String): List<Int>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPendingTransfer(transfer: PendingChunkTransferEntity)

    @Query("SELECT * FROM pending_chunk_transfers WHERE transferId = :transferId LIMIT 1")
    suspend fun getPendingTransfer(transferId: String): PendingChunkTransferEntity?

    @Query("SELECT * FROM pending_chunk_transfers WHERE contactId = :contactId ORDER BY createdAt ASC")
    suspend fun getPendingTransfersForContact(contactId: String): List<PendingChunkTransferEntity>

    @Query("SELECT * FROM pending_chunk_transfers ORDER BY createdAt ASC")
    suspend fun getAllPendingTransfers(): List<PendingChunkTransferEntity>

    @Query("UPDATE pending_chunk_transfers SET missingIndices = :missingIndices WHERE transferId = :transferId")
    suspend fun updateMissingIndices(transferId: String, missingIndices: EncryptedText)

    suspend fun updateMissingIndices(transferId: String, missingIndices: String) {
        updateMissingIndices(transferId, EncryptedText(missingIndices, "pending_chunk_transfers", transferId, "missingIndices"))
    }

    @Query("DELETE FROM pending_chunk_transfers WHERE transferId = :transferId")
    suspend fun deletePendingTransfer(transferId: String)

    @Query("DELETE FROM chunks WHERE transferId IN (SELECT transferId FROM pending_chunk_transfers WHERE expiresAt < :now)")
    suspend fun deleteExpiredChunks(now: Long = System.currentTimeMillis())

    @Query("DELETE FROM pending_chunk_transfers WHERE expiresAt < :now")
    suspend fun deleteExpiredPendingTransfers(now: Long = System.currentTimeMillis())

    suspend fun purgeExpiredTransfers(now: Long = System.currentTimeMillis()) {
        deleteExpiredChunks(now)
        deleteExpiredPendingTransfers(now)
    }
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
        updateOutgoingState(id, counterOut, EncryptedBlob(chainKeyOut, "contacts", id, "chainKeyOut"))
    }

    suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: ByteArray, rekeyEpoch: Long) {
        updateOutgoingStateAndEpoch(id, counterOut, EncryptedBlob(chainKeyOut, "contacts", id, "chainKeyOut"), rekeyEpoch)
    }

    suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: ByteArray) {
        updateIncomingState(id, counterIn, EncryptedBlob(chainKeyIn, "contacts", id, "chainKeyIn"))
    }

    suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: ByteArray, bitmapBase: Int, bitmap: ByteArray) {
        updateIncomingStateWithBitmap(id, counterIn, EncryptedBlob(chainKeyIn, "contacts", id, "chainKeyIn"), bitmapBase, bitmap)
    }

    suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: ByteArray, rekeyEpoch: Long) {
        updateIncomingStateAndEpoch(id, counterIn, EncryptedBlob(chainKeyIn, "contacts", id, "chainKeyIn"), rekeyEpoch)
    }

    suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: ByteArray, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {
        updateIncomingStateAndEpochWithBitmap(id, counterIn, EncryptedBlob(chainKeyIn, "contacts", id, "chainKeyIn"), rekeyEpoch, bitmapBase, bitmap)
    }

    @Query("UPDATE contacts SET rekeyEpoch = :rekeyEpoch WHERE id = :id")
    suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long)

    @Query("UPDATE contacts SET isVerified = :isVerified WHERE id = :id")
    suspend fun updateVerifiedStatus(id: String, isVerified: Boolean)

    @Query("UPDATE contacts SET name = :name WHERE id = :id")
    suspend fun updateContactName(id: String, name: EncryptedText)

    suspend fun updateContactName(id: String, name: String) {
        updateContactName(id, EncryptedText(name, "contacts", id, "name"))
    }

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

    @Query("SELECT * FROM messages WHERE id = :id LIMIT 1")
    suspend fun getMessageById(id: Long): MessageEntity?

    @Query("UPDATE messages SET status = :status, seqNum = :seqNum, ackNum = :ackNum, timestamp = :timestamp, slotTarget = :slotTarget, slotEdSeed = :slotEdSeed, ackTarget = :ackTarget, ackRatchetKey = :ackRatchetKey, retryCount = :retryCount, textContent = :textContent, imageBytes = :imageBytes WHERE id = :id")
    suspend fun updateMessageForResend(
        id: Long,
        status: String,
        seqNum: Int,
        ackNum: Int,
        timestamp: Long,
        slotTarget: ByteArray?,
        slotEdSeed: EncryptedBlob?,
        ackTarget: ByteArray?,
        ackRatchetKey: EncryptedBlob?,
        retryCount: Int,
        textContent: EncryptedText? = null,
        imageBytes: EncryptedBlob? = null
    )

    @Query("SELECT * FROM messages WHERE expiresAtTimestamp IS NOT NULL")
    suspend fun getMessagesWithExpiration(): List<MessageEntity>

    suspend fun getExpiredMessages(now: Long = System.currentTimeMillis()): List<MessageEntity> {
        return getMessagesWithExpiration().filter { msg ->
            val exp = msg.rawExpiresAtTimestamp
            exp != null && exp <= now
        }
    }

    @Query("UPDATE messages SET expiresAtTimestamp = :expiresAt WHERE id = :id AND expiresAtTimestamp IS NULL")
    suspend fun updateExpiresAtTimestampById(id: Long, expiresAt: EncryptedLong)

    suspend fun markMessageReadAndStartTtl(id: Long, expiresAt: Long) {
        val msg = getMessageById(id) ?: return
        if (msg.expiresAtTimestamp != null) return
        val encryptedExpiresAt = EncryptedLong(expiresAt, "messages", msg.messageRowId, "expiresAtTimestamp")
        updateExpiresAtTimestampById(id, encryptedExpiresAt)
    }

    @Query("SELECT * FROM messages WHERE contactId = :contactId AND expiresAtTimestamp IS NULL")
    suspend fun getMessagesWithoutExpirationForContact(contactId: String): List<MessageEntity>

    suspend fun getUnreadEphemeralMessagesForContact(contactId: String): List<MessageEntity> {
        return getMessagesWithoutExpirationForContact(contactId).filter { msg ->
            msg.rawEphemeralTtlSeconds > 0
        }
    }

    @Query("UPDATE messages SET textContent = :wipedText, imageBytes = :wipedImage, voiceBytes = :wipedVoice, reaction = NULL WHERE id = :id")
    suspend fun wipeMessageContent(id: Long, wipedText: EncryptedText?, wipedImage: EncryptedBlob?, wipedVoice: EncryptedBlob? = null)

    @Query("UPDATE messages SET reaction = :reaction WHERE id = :id")
    suspend fun updateMessageReactionById(id: Long, reaction: EncryptedText?)

    suspend fun updateMessageReactionById(id: Long, reaction: String?) {
        val msg = getMessageById(id) ?: return
        val encReaction = reaction?.let {
            EncryptedText(it, "messages", msg.messageRowId, "reaction")
        }
        updateMessageReactionById(id, encReaction)
    }

    @Query("UPDATE messages SET reaction = :reaction WHERE contactId = :contactId AND seqEpoch = :seqEpoch AND seqNum = :seqNum AND isOutgoing = :isOutgoing")
    suspend fun updateMessageReaction(contactId: String, seqEpoch: Int, seqNum: Int, isOutgoing: Boolean, reaction: EncryptedText?)

    suspend fun updateMessageReaction(contactId: String, seqEpoch: Int, seqNum: Int, isOutgoing: Boolean, reaction: String?) {
        val rowId = MessageEntity.computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing)
        val encReaction = reaction?.let {
            EncryptedText(it, "messages", rowId, "reaction")
        }
        updateMessageReaction(contactId, seqEpoch, seqNum, isOutgoing, encReaction)
    }

    @Query("SELECT * FROM messages WHERE contactId = :contactId AND seqEpoch = :seqEpoch AND seqNum = :seqNum LIMIT 1")
    suspend fun getMessageByContactAndSeq(contactId: String, seqEpoch: Int, seqNum: Int): MessageEntity?

    suspend fun updateMessageReactionAnyDirection(contactId: String, seqEpoch: Int, seqNum: Int, reaction: String?) {
        val msg = getMessageByContactAndSeq(contactId, seqEpoch, seqNum) ?: return
        val rowId = MessageEntity.computeMessageRowId(contactId, seqEpoch, seqNum, msg.isOutgoing)
        val encReaction = reaction?.let {
            EncryptedText(it, "messages", rowId, "reaction")
        }
        updateMessageReaction(contactId, seqEpoch, seqNum, msg.isOutgoing, encReaction)
    }

    @Query("DELETE FROM messages WHERE id = :id")
    suspend fun deleteMessageById(id: Long)
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

@Entity(tableName = "groups")
data class GroupEntity(
    @PrimaryKey
    val groupId: String,
    val groupName: EncryptedText,
    val myMemberId: String,
    val myChainKeyOut: EncryptedBlob,
    val myCounterOut: Int,
    val groupEpoch: Long = 0L,
    val createdAt: Long = System.currentTimeMillis(),
    val lastActive: Long = System.currentTimeMillis(),
    val isActive: Boolean = true
) {
    @Ignore
    constructor(
        groupId: String,
        groupName: String,
        myMemberId: String,
        myChainKeyOut: ByteArray,
        myCounterOut: Int,
        groupEpoch: Long = 0L,
        createdAt: Long = System.currentTimeMillis(),
        lastActive: Long = System.currentTimeMillis(),
        isActive: Boolean = true
    ) : this(
        groupId = groupId,
        groupName = EncryptedText(groupName, "groups", groupId, "groupName"),
        myMemberId = myMemberId,
        myChainKeyOut = EncryptedBlob(myChainKeyOut, "groups", groupId, "myChainKeyOut"),
        myCounterOut = myCounterOut,
        groupEpoch = groupEpoch,
        createdAt = createdAt,
        lastActive = lastActive,
        isActive = isActive
    )

    @Ignore
    constructor(
        groupId: String,
        groupName: String,
        myMemberId: String,
        myChainKeyOut: EncryptedBlob,
        myCounterOut: Int,
        groupEpoch: Long = 0L,
        createdAt: Long = System.currentTimeMillis(),
        lastActive: Long = System.currentTimeMillis(),
        isActive: Boolean = true
    ) : this(
        groupId = groupId,
        groupName = EncryptedText(groupName, "groups", groupId, "groupName"),
        myMemberId = myMemberId,
        myChainKeyOut = if (myChainKeyOut.boundColumn == null) EncryptedBlob(myChainKeyOut.raw, "groups", groupId, "myChainKeyOut") else myChainKeyOut,
        myCounterOut = myCounterOut,
        groupEpoch = groupEpoch,
        createdAt = createdAt,
        lastActive = lastActive,
        isActive = isActive
    )

    init {
        validateRowBinding()
    }

    fun validateRowBinding() {
        myChainKeyOut.validateRowBinding("groups", groupId, "myChainKeyOut", "myChainKeyOut")
        groupName.validateRowBinding("groups", groupId, "groupName", "groupName")
    }

    val rawGroupName: String get() = groupName.raw
    val rawMyChainKeyOut: ByteArray get() = myChainKeyOut.raw

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is GroupEntity) return false
        return groupId == other.groupId &&
                groupName == other.groupName &&
                myMemberId == other.myMemberId &&
                myChainKeyOut == other.myChainKeyOut &&
                myCounterOut == other.myCounterOut &&
                groupEpoch == other.groupEpoch &&
                createdAt == other.createdAt &&
                lastActive == other.lastActive &&
                isActive == other.isActive
    }

    override fun hashCode(): Int = groupId.hashCode()
}

@Entity(
    tableName = "group_members",
    primaryKeys = ["groupId", "memberId"],
    indices = [
        Index(value = ["groupId"]),
        Index(value = ["contactId"])
    ]
)
data class GroupMemberEntity(
    val groupId: String,
    val memberId: String,
    val contactId: String? = null,
    val memberName: EncryptedText,
    val chainKeyIn: EncryptedBlob,
    val counterIn: Int,
    val receivedBitmapBase: Int = 0,
    val receivedBitmap: ByteArray = ByteArray(128),
    val joinedAt: Long = System.currentTimeMillis(),
    val isActive: Boolean = true
) {
    @Ignore
    constructor(
        groupId: String,
        memberId: String,
        contactId: String? = null,
        memberName: String,
        chainKeyIn: ByteArray,
        counterIn: Int,
        receivedBitmapBase: Int = 0,
        receivedBitmap: ByteArray = ByteArray(128),
        joinedAt: Long = System.currentTimeMillis(),
        isActive: Boolean = true
    ) : this(
        groupId = groupId,
        memberId = memberId,
        contactId = contactId,
        memberName = EncryptedText(memberName, "group_members", "${groupId}_${memberId}", "memberName"),
        chainKeyIn = EncryptedBlob(chainKeyIn, "group_members", "${groupId}_${memberId}", "chainKeyIn"),
        counterIn = counterIn,
        receivedBitmapBase = receivedBitmapBase,
        receivedBitmap = receivedBitmap,
        joinedAt = joinedAt,
        isActive = isActive
    )

    @Ignore
    constructor(
        groupId: String,
        memberId: String,
        contactId: String? = null,
        memberName: String,
        chainKeyIn: EncryptedBlob,
        counterIn: Int,
        receivedBitmapBase: Int = 0,
        receivedBitmap: ByteArray = ByteArray(128),
        joinedAt: Long = System.currentTimeMillis(),
        isActive: Boolean = true
    ) : this(
        groupId = groupId,
        memberId = memberId,
        contactId = contactId,
        memberName = EncryptedText(memberName, "group_members", "${groupId}_${memberId}", "memberName"),
        chainKeyIn = if (chainKeyIn.boundColumn == null) EncryptedBlob(chainKeyIn.raw, "group_members", "${groupId}_${memberId}", "chainKeyIn") else chainKeyIn,
        counterIn = counterIn,
        receivedBitmapBase = receivedBitmapBase,
        receivedBitmap = receivedBitmap,
        joinedAt = joinedAt,
        isActive = isActive
    )

    init {
        validateRowBinding()
    }

    fun validateRowBinding() {
        val expectedId = "${groupId}_${memberId}"
        chainKeyIn.validateRowBinding("group_members", expectedId, "chainKeyIn", "chainKeyIn")
        memberName.validateRowBinding("group_members", expectedId, "memberName", "memberName")
    }

    val rawMemberName: String get() = memberName.raw
    val rawChainKeyIn: ByteArray get() = chainKeyIn.raw

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is GroupMemberEntity) return false
        return groupId == other.groupId &&
                memberId == other.memberId &&
                contactId == other.contactId &&
                memberName == other.memberName &&
                chainKeyIn == other.chainKeyIn &&
                counterIn == other.counterIn &&
                receivedBitmapBase == other.receivedBitmapBase &&
                receivedBitmap.contentEquals(other.receivedBitmap) &&
                joinedAt == other.joinedAt &&
                isActive == other.isActive
    }

    override fun hashCode(): Int {
        var result = groupId.hashCode()
        result = 31 * result + memberId.hashCode()
        return result
    }
}

@Dao
interface GroupDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdate(group: GroupEntity)

    @Query("SELECT * FROM groups WHERE groupId = :groupId LIMIT 1")
    suspend fun getGroupById(groupId: String): GroupEntity?

    @Query("SELECT * FROM groups WHERE isActive = 1 ORDER BY lastActive DESC")
    fun getAllGroupsFlow(): Flow<List<GroupEntity>>

    @Query("SELECT * FROM groups WHERE isActive = 1 ORDER BY lastActive DESC")
    suspend fun getAllActiveGroups(): List<GroupEntity>

    @Query("UPDATE groups SET myCounterOut = :counterOut, myChainKeyOut = :chainKeyOut, lastActive = :lastActive WHERE groupId = :groupId")
    suspend fun updateOutgoingState(groupId: String, counterOut: Int, chainKeyOut: EncryptedBlob, lastActive: Long = System.currentTimeMillis())

    @Query("UPDATE groups SET groupEpoch = :epoch, myCounterOut = :counterOut, myChainKeyOut = :chainKeyOut, lastActive = :lastActive WHERE groupId = :groupId")
    suspend fun updateRekeyedState(groupId: String, epoch: Long, counterOut: Int, chainKeyOut: EncryptedBlob, lastActive: Long = System.currentTimeMillis())

    suspend fun updateOutgoingState(groupId: String, counterOut: Int, chainKeyOut: ByteArray, lastActive: Long = System.currentTimeMillis()) {
        updateOutgoingState(groupId, counterOut, EncryptedBlob(chainKeyOut, "groups", groupId, "myChainKeyOut"), lastActive)
    }

    suspend fun updateRekeyedState(groupId: String, epoch: Long, counterOut: Int, chainKeyOut: ByteArray, lastActive: Long = System.currentTimeMillis()) {
        updateRekeyedState(groupId, epoch, counterOut, EncryptedBlob(chainKeyOut, "groups", groupId, "myChainKeyOut"), lastActive)
    }

    @Query("UPDATE groups SET isActive = :isActive WHERE groupId = :groupId")
    suspend fun updateActiveStatus(groupId: String, isActive: Boolean)

    @Query("DELETE FROM groups WHERE groupId = :groupId")
    suspend fun deleteGroup(groupId: String)
}

@Dao
interface GroupMemberDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdate(member: GroupMemberEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdateAll(members: List<GroupMemberEntity>)

    @Query("SELECT * FROM group_members WHERE groupId = :groupId AND memberId = :memberId LIMIT 1")
    suspend fun getMember(groupId: String, memberId: String): GroupMemberEntity?

    @Query("SELECT * FROM group_members WHERE groupId = :groupId AND isActive = 1")
    suspend fun getMembersForGroup(groupId: String): List<GroupMemberEntity>

    @Query("SELECT * FROM group_members WHERE groupId = :groupId AND isActive = 1")
    fun getMembersForGroupFlow(groupId: String): Flow<List<GroupMemberEntity>>

    @Query("UPDATE group_members SET counterIn = :counterIn, chainKeyIn = :chainKeyIn, receivedBitmapBase = :bitmapBase, receivedBitmap = :bitmap WHERE groupId = :groupId AND memberId = :memberId")
    suspend fun updateMemberIncomingStateWithBitmap(
        groupId: String,
        memberId: String,
        counterIn: Int,
        chainKeyIn: EncryptedBlob,
        bitmapBase: Int,
        bitmap: ByteArray
    )

    suspend fun updateMemberIncomingStateWithBitmap(
        groupId: String,
        memberId: String,
        counterIn: Int,
        chainKeyIn: ByteArray,
        bitmapBase: Int,
        bitmap: ByteArray
    ) {
        updateMemberIncomingStateWithBitmap(
            groupId = groupId,
            memberId = memberId,
            counterIn = counterIn,
            chainKeyIn = EncryptedBlob(chainKeyIn, "group_members", "${groupId}_${memberId}", "chainKeyIn"),
            bitmapBase = bitmapBase,
            bitmap = bitmap
        )
    }

    @Query("UPDATE group_members SET isActive = 0 WHERE groupId = :groupId AND memberId = :memberId")
    suspend fun markMemberInactive(groupId: String, memberId: String)

    @Query("DELETE FROM group_members WHERE groupId = :groupId AND memberId = :memberId")
    suspend fun deleteMember(groupId: String, memberId: String)

    @Query("DELETE FROM group_members WHERE groupId = :groupId")
    suspend fun deleteMembersForGroup(groupId: String)
}

@Entity(
    tableName = "polls",
    indices = [
        Index(value = ["groupId"])
    ]
)
data class PollEntity(
    @PrimaryKey
    val pollId: String,
    val groupId: String,
    val creatorMemberId: String,
    val creatorName: String,
    val question: String,
    val optionsJson: String,
    val isMultiChoice: Boolean,
    val expirationTimestamp: Long,
    val createdAt: Long = System.currentTimeMillis(),
    val isClosed: Boolean = false
) {
    val optionsList: List<String>
        get() = try {
            val array = org.json.JSONArray(optionsJson)
            val list = mutableListOf<String>()
            for (i in 0 until array.length()) {
                list.add(array.getString(i))
            }
            list
        } catch (_: Exception) {
            emptyList()
        }
}

@Entity(
    tableName = "poll_votes",
    primaryKeys = ["pollId", "memberId"],
    indices = [
        Index(value = ["pollId"])
    ]
)
data class PollVoteEntity(
    val pollId: String,
    val memberId: String,
    val memberName: String,
    val selectedBitmask: Int,
    val voteTimestamp: Long
)

@Dao
interface PollDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdatePoll(poll: PollEntity)

    @Query("SELECT * FROM polls WHERE pollId = :pollId LIMIT 1")
    suspend fun getPoll(pollId: String): PollEntity?

    @Query("SELECT * FROM polls WHERE pollId = :pollId LIMIT 1")
    fun getPollFlow(pollId: String): Flow<PollEntity?>

    @Query("SELECT * FROM polls WHERE groupId = :groupId ORDER BY createdAt DESC")
    fun getPollsForGroupFlow(groupId: String): Flow<List<PollEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdateVote(vote: PollVoteEntity)

    @Query("SELECT * FROM poll_votes WHERE pollId = :pollId")
    suspend fun getVotesForPoll(pollId: String): List<PollVoteEntity>

    @Query("SELECT * FROM poll_votes WHERE pollId = :pollId")
    fun getVotesForPollFlow(pollId: String): Flow<List<PollVoteEntity>>

    @Query("UPDATE polls SET isClosed = 1 WHERE pollId = :pollId")
    suspend fun closePoll(pollId: String)
}

