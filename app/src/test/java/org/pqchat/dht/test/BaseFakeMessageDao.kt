package org.pqchat.dht.test

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import org.pqchat.dht.data.db.EncryptedBlob
import org.pqchat.dht.data.db.EncryptedLong
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
            val updatedEphemeralTtl = EncryptedLong(old.rawEphemeralTtlSeconds, "messages", newRowId, "ephemeralTtlSeconds")
            val updatedExpiresAt = old.rawExpiresAtTimestamp?.let {
                EncryptedLong(it, "messages", newRowId, "expiresAtTimestamp")
            }
            val updatedReaction = old.rawReaction?.let {
                EncryptedText(it, "messages", newRowId, "reaction")
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
                senderName = updatedSenderName,
                ephemeralTtlSeconds = updatedEphemeralTtl,
                expiresAtTimestamp = updatedExpiresAt,
                reaction = updatedReaction
            )
        }
    }

    override suspend fun getMessagesWithExpiration(): List<MessageEntity> =
        messages.filter { it.expiresAtTimestamp != null }

    override suspend fun updateExpiresAtTimestampById(id: Long, expiresAt: EncryptedLong) {
        val idx = messages.indexOfFirst { it.id == id }
        if (idx >= 0 && messages[idx].expiresAtTimestamp == null) {
            messages[idx] = messages[idx].copy(expiresAtTimestamp = expiresAt)
        }
    }

    override suspend fun getMessagesWithoutExpirationForContact(contactId: String): List<MessageEntity> =
        messages.filter { it.contactId == contactId && it.expiresAtTimestamp == null }

    override suspend fun getMessageByContactAndSeq(contactId: String, seqEpoch: Int, seqNum: Int): MessageEntity? =
        messages.firstOrNull { it.contactId == contactId && it.seqEpoch == seqEpoch && it.seqNum == seqNum }

    override suspend fun getExpiredMessages(now: Long): List<MessageEntity> =
        messages.filter { it.expiresAtTimestamp != null && (it.rawExpiresAtTimestamp ?: Long.MAX_VALUE) <= now }

    override suspend fun markMessageReadAndStartTtl(id: Long, expiresAt: Long) {
        val idx = messages.indexOfFirst { it.id == id }
        if (idx >= 0 && messages[idx].expiresAtTimestamp == null) {
            val rowId = messages[idx].messageRowId
            messages[idx] = messages[idx].copy(
                expiresAtTimestamp = EncryptedLong(expiresAt, "messages", rowId, "expiresAtTimestamp")
            )
        }
    }

    override suspend fun getUnreadEphemeralMessagesForContact(contactId: String): List<MessageEntity> =
        messages.filter { it.contactId == contactId && it.rawEphemeralTtlSeconds > 0 && it.expiresAtTimestamp == null }

    override suspend fun wipeMessageContent(id: Long, wipedText: EncryptedText?, wipedImage: EncryptedBlob?) {
        val idx = messages.indexOfFirst { it.id == id }
        if (idx >= 0) {
            messages[idx] = messages[idx].copy(textContent = wipedText, imageBytes = wipedImage)
        }
    }

    override suspend fun deleteMessageById(id: Long) {
        messages.removeIf { it.id == id }
    }

    override suspend fun updateMessageReactionById(id: Long, reaction: EncryptedText?) {
        val idx = messages.indexOfFirst { it.id == id }
        if (idx >= 0) {
            messages[idx] = messages[idx].copy(reaction = reaction)
        }
    }

    override suspend fun updateMessageReactionById(id: Long, reaction: String?) {
        val idx = messages.indexOfFirst { it.id == id }
        if (idx >= 0) {
            val enc = reaction?.let { EncryptedText(it, "messages", messages[idx].messageRowId, "reaction") }
            messages[idx] = messages[idx].copy(reaction = enc)
        }
    }

    override suspend fun updateMessageReaction(
        contactId: String,
        seqEpoch: Int,
        seqNum: Int,
        isOutgoing: Boolean,
        reaction: EncryptedText?
    ) {
        val idx = messages.indexOfFirst {
            it.contactId == contactId && it.seqEpoch == seqEpoch && it.seqNum == seqNum && it.isOutgoing == isOutgoing
        }
        if (idx >= 0) {
            messages[idx] = messages[idx].copy(reaction = reaction)
        }
    }

    override suspend fun updateMessageReaction(
        contactId: String,
        seqEpoch: Int,
        seqNum: Int,
        isOutgoing: Boolean,
        reaction: String?
    ) {
        val idx = messages.indexOfFirst {
            it.contactId == contactId && it.seqEpoch == seqEpoch && it.seqNum == seqNum && it.isOutgoing == isOutgoing
        }
        if (idx >= 0) {
            val enc = reaction?.let { EncryptedText(it, "messages", messages[idx].messageRowId, "reaction") }
            messages[idx] = messages[idx].copy(reaction = enc)
        }
    }

    override suspend fun updateMessageReactionAnyDirection(
        contactId: String,
        seqEpoch: Int,
        seqNum: Int,
        reaction: String?
    ) {
        val idx = messages.indexOfFirst {
            it.contactId == contactId && it.seqEpoch == seqEpoch && it.seqNum == seqNum
        }
        if (idx >= 0) {
            val enc = reaction?.let { EncryptedText(it, "messages", messages[idx].messageRowId, "reaction") }
            messages[idx] = messages[idx].copy(reaction = enc)
        }
    }
}

