package org.pqchat.dht.test

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import org.pqchat.dht.data.db.EncryptedBlob
import org.pqchat.dht.data.db.EncryptedText
import org.pqchat.dht.data.db.MessageDao
import org.pqchat.dht.data.db.MessageEntity
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

open class BaseFakeMessageDao : MessageDao {
    val messages = CopyOnWriteArrayList<MessageEntity>()
    private val idCounter = AtomicLong(1L)

    override fun getMessagesForContactFlow(contactId: String): Flow<List<MessageEntity>> =
        MutableStateFlow(messages.filter { it.contactId == contactId })

    override suspend fun insertMessage(message: MessageEntity): Long {
        val id = if (message.id != 0L) message.id else idCounter.getAndIncrement()
        messages.add(message.copy(id = id))
        return id
    }

    override suspend fun updateStatus(id: Long, status: String) {
        val idx = messages.indexOfFirst { it.id == id }
        if (idx >= 0) messages[idx] = messages[idx].copy(status = status)
    }

    override suspend fun updateMessageStatusAndSeq(id: Long, status: String, seqNum: Int) {
        val idx = messages.indexOfFirst { it.id == id }
        if (idx >= 0) messages[idx] = messages[idx].copy(status = status, seqNum = seqNum)
    }

    override suspend fun updateMessageRetry(id: Long, status: String, retryCount: Int, timestamp: Long) {
        val idx = messages.indexOfFirst { it.id == id }
        if (idx >= 0) messages[idx] =
            messages[idx].copy(status = status, retryCount = retryCount, lastAttemptTimestamp = timestamp)
    }

    override suspend fun getQueuedMessagesForContact(contactId: String): List<MessageEntity> =
        messages.filter { it.contactId == contactId && it.isOutgoing && it.status == "QUEUED" }.sortedBy { it.id }

    override suspend fun getAllQueuedMessages(): List<MessageEntity> =
        messages.filter { it.isOutgoing && it.status == "QUEUED" }.sortedBy { it.id }

    override suspend fun updateStatusForSeq(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String) {
        val idx = messages.indexOfFirst { it.contactId == contactId && it.seqNum == seqNum && it.isOutgoing == isOutgoing }
        if (idx >= 0) messages[idx] = messages[idx].copy(status = status)
    }

    override suspend fun updateMessageStatusAndDirection(
        contactId: String,
        seqNum: Int,
        isOutgoing: Boolean,
        status: String
    ) {
        val idx = messages.indexOfFirst { it.contactId == contactId && it.seqNum == seqNum }
        if (idx >= 0) messages[idx] = messages[idx].copy(status = status, isOutgoing = isOutgoing)
    }

    override suspend fun normalizeConfirmedSelfNotes(contactId: String) {}

    override suspend fun deleteMessagesForContact(contactId: String) {
        messages.removeAll { it.contactId == contactId }
    }

    override suspend fun existsMessageWithEpoch(
        contactId: String,
        seqEpoch: Int,
        seqNum: Int,
        isOutgoing: Boolean
    ): Boolean =
        messages.any { it.contactId == contactId && it.seqEpoch == seqEpoch && it.seqNum == seqNum && it.isOutgoing == isOutgoing }

    override suspend fun existsMessage(contactId: String, seqNum: Int, isOutgoing: Boolean): Boolean =
        messages.any { it.contactId == contactId && it.seqNum == seqNum && it.isOutgoing == isOutgoing }

    override suspend fun getPendingDeliveryMessagesForContact(contactId: String): List<MessageEntity> =
        messages.filter { it.contactId == contactId && it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }
            .sortedBy { it.id }

    override suspend fun getAllPendingDeliveryMessages(): List<MessageEntity> =
        messages.filter { it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }
            .sortedBy { it.id }

    override suspend fun getMessageById(id: Long): MessageEntity? =
        messages.firstOrNull { it.id == id }

    override suspend fun updateMessageForResend(
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
        textContent: EncryptedText?,
        imageBytes: EncryptedBlob?
    ) {
        val idx = messages.indexOfFirst { it.id == id }
        if (idx >= 0) {
            val old = messages[idx]
            val newRowId = MessageEntity.computeMessageRowId(old.contactId, old.seqEpoch, seqNum, old.isOutgoing)
            val updatedText = textContent ?: old.textContent?.raw?.let {
                EncryptedText(it, "messages", newRowId, "textContent")
            }
            val updatedImage = imageBytes ?: old.imageBytes?.raw?.let {
                EncryptedBlob(it, "messages", newRowId, "imageBytes")
            }
            val updatedEdSeed = slotEdSeed ?: old.slotEdSeed?.raw?.let {
                EncryptedBlob(it, "messages", newRowId, "slotEdSeed")
            }
            val updatedAckKey = ackRatchetKey ?: old.ackRatchetKey?.raw?.let {
                EncryptedBlob(it, "messages", newRowId, "ackRatchetKey")
            }
            val updatedSenderMemberId = old.senderMemberId?.raw?.let {
                EncryptedText(it, "messages", newRowId, "senderMemberId")
            }
            val updatedSenderName = old.senderName?.raw?.let {
                EncryptedText(it, "messages", newRowId, "senderName")
            }
            messages[idx] = old.copy(
                status = status,
                seqNum = seqNum,
                ackNum = ackNum,
                timestamp = timestamp,
                slotTarget = slotTarget,
                slotEdSeed = updatedEdSeed,
                ackTarget = ackTarget,
                ackRatchetKey = updatedAckKey,
                retryCount = retryCount,
                textContent = updatedText,
                imageBytes = updatedImage,
                senderMemberId = updatedSenderMemberId,
                senderName = updatedSenderName
            )
        }
    }
}
