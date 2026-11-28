package org.pqchat.dht.traffic

import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Data holder for a pending acknowledgment waiting to be transmitted
 * inside background cover traffic or piggybacked onto an outgoing user message.
 */
class PendingAck(
    val contactId: String,
    val messageId: String,
    ratchetKey: ByteArray,
    val seqNum: Int,
    val timestamp: Long = System.currentTimeMillis(),
    val readBaseSeq: Int? = null,
    val readSeqBitmap: Long = 0L,
    val dhtSeq: Long = org.pqchat.dht.dht.leaf.DhtClient.DEFAULT_MUTABLE_SEQ
) {
    val ratchetKey: ByteArray = ratchetKey.copyOf()

    fun zeroSensitiveMemory() {
        ratchetKey.fill(0)
    }

    fun withReadReceipt(readBaseSeq: Int, readSeqBitmap: Long): PendingAck =
        PendingAck(
            contactId = contactId,
            messageId = messageId,
            ratchetKey = ratchetKey,
            seqNum = seqNum,
            timestamp = timestamp,
            readBaseSeq = readBaseSeq,
            readSeqBitmap = readSeqBitmap,
            dhtSeq = dhtSeq
        )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PendingAck) return false
        return contactId == other.contactId &&
                messageId == other.messageId &&
                ratchetKey.contentEquals(other.ratchetKey) &&
                seqNum == other.seqNum &&
                readBaseSeq == other.readBaseSeq &&
                readSeqBitmap == other.readSeqBitmap &&
                dhtSeq == other.dhtSeq
    }

    override fun hashCode(): Int {
        var result = contactId.hashCode()
        result = 31 * result + messageId.hashCode()
        result = 31 * result + ratchetKey.contentHashCode()
        result = 31 * result + seqNum
        result = 31 * result + (readBaseSeq ?: 0)
        result = 31 * result + readSeqBitmap.hashCode()
        result = 31 * result + dhtSeq.hashCode()
        return result
    }
}

/**
 * Thread-safe queue buffering message acknowledgments for cover-traffic emission.
 */
class PendingAckQueue {
    private val queue = ConcurrentLinkedQueue<PendingAck>()

    fun enqueue(ack: PendingAck) {
        queue.add(ack)
    }

    fun poll(): PendingAck? = queue.poll()

    fun peek(): PendingAck? = queue.peek()

    val size: Int get() = queue.size

    fun isEmpty(): Boolean = queue.isEmpty()

    fun clear() {
        queue.clear()
    }

    /**
     * Removes all pending ACKs for a contact where seqNum <= upToSeqNum.
     * When a user sends a normal response, the received sequence is piggybacked directly,
     * so dedicated cover-traffic ACKs for those messages are cancelled.
     *
     * @return Number of ACKs removed from the queue.
     */
    fun removeForContact(contactId: String, upToSeqNum: Int = Int.MAX_VALUE): Int {
        var removed = 0
        val iterator = queue.iterator()
        while (iterator.hasNext()) {
            val item = iterator.next()
            if (item.contactId == contactId && item.seqNum <= upToSeqNum) {
                iterator.remove()
                removed++
            }
        }
        return removed
    }

    /**
     * Attaches or updates a zero-overhead read receipt bitmap on any queued ACKs for [contactId].
     *
     * @return Number of queued ACKs updated in place.
     */
    @Synchronized
    fun attachReadReceiptForContact(contactId: String, readBaseSeq: Int, readSeqBitmap: Long): Int {
        if (queue.isEmpty() || readSeqBitmap == 0L) return 0
        var updated = 0
        val snapshot = ArrayList<PendingAck>(queue.size)
        while (true) {
            val item = queue.poll() ?: break
            if (item.contactId == contactId) {
                val upgraded = item.withReadReceipt(readBaseSeq, readSeqBitmap)
                item.zeroSensitiveMemory()
                snapshot.add(upgraded)
                updated++
            } else {
                snapshot.add(item)
            }
        }
        snapshot.forEach { queue.add(it) }
        return updated
    }

    fun getAll(): List<PendingAck> = queue.toList()
}
