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
                lastActive == other.lastActive
    }

    override fun hashCode(): Int = id.hashCode()
}

@Entity(
    tableName = "messages",
    indices = [
        Index(value = ["contactId", "seqNum"]),
        Index(value = ["timestamp"])
    ]
)
data class MessageEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val contactId: String,
    val isOutgoing: Boolean,
    val seqNum: Int,
    val ackNum: Int = 0,
    val timestamp: Long,
    val textContent: String?,
    val imageBytes: ByteArray? = null,
    val status: String // SENDING, SENT_DHT, RECEIVED, DELIVERED
)

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

    @Query("UPDATE contacts SET counterIn = :counterIn, chainKeyIn = :chainKeyIn WHERE id = :id")
    suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: ByteArray)

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

    @Query("UPDATE messages SET status = :status WHERE contactId = :contactId AND seqNum = :seqNum AND isOutgoing = :isOutgoing")
    suspend fun updateStatusForSeq(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String)

    @Query("UPDATE messages SET status = :status, isOutgoing = :isOutgoing WHERE contactId = :contactId AND seqNum = :seqNum")
    suspend fun updateMessageStatusAndDirection(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String)

    @Query("UPDATE messages SET isOutgoing = 0 WHERE contactId = :contactId AND status = 'CONFIRMED_DHT'")
    suspend fun normalizeConfirmedSelfNotes(contactId: String)

    @Query("DELETE FROM messages WHERE contactId = :contactId")
    suspend fun deleteMessagesForContact(contactId: String)

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
