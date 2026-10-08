package org.pqchat.dht.traffic

import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Data holder for a pending acknowledgment waiting to be transmitted
 * inside background cover traffic or piggybacked onto an outgoing user message.
 */
data class PendingAck(
    val contactId: String,
    val messageId: String,
    val ratchetKey: ByteArray,
    val seqNum: Int,
    val timestamp: Long = System.currentTimeMillis()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PendingAck) return false
        return contactId == other.contactId &&
                messageId == other.messageId &&
                ratchetKey.contentEquals(other.ratchetKey) &&
                seqNum == other.seqNum
    }

    override fun hashCode(): Int {
        var result = contactId.hashCode()
        result = 31 * result + messageId.hashCode()
        result = 31 * result + ratchetKey.contentHashCode()
        result = 31 * result + seqNum
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

    fun getAll(): List<PendingAck> = queue.toList()
}
