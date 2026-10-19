package org.pqchat.dht.traffic

import org.pqchat.dht.dht.leaf.DhtClient
import java.util.concurrent.ConcurrentLinkedDeque

/**
 * Data holder for a 900-byte pre-packed wire frame queued for emission
 * strictly on Poisson process ticks (Strict Poisson Traffic Shaping).
 */
data class OutboundPoissonFrame(
    val target: ByteArray,
    val payload: ByteArray,
    val seq: Long = DhtClient.DEFAULT_MUTABLE_SEQ,
    val salt: ByteArray? = null,
    val sk: ByteArray,
    val skipLocalStore: Boolean = false,
    val seqNum: Int = 0,
    val messageId: Long? = null,
    val contactId: String? = null,
    val timestamp: Long = System.currentTimeMillis(),
    val onSent: (suspend (success: Boolean) -> Unit)? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is OutboundPoissonFrame) return false
        return target.contentEquals(other.target) &&
                payload.contentEquals(other.payload) &&
                seq == other.seq &&
                sk.contentEquals(other.sk) &&
                seqNum == other.seqNum &&
                messageId == other.messageId &&
                contactId == other.contactId
    }

    override fun hashCode(): Int {
        var result = target.contentHashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + seq.hashCode()
        result = 31 * result + sk.contentHashCode()
        result = 31 * result + seqNum
        result = 31 * result + (messageId?.hashCode() ?: 0)
        result = 31 * result + (contactId?.hashCode() ?: 0)
        return result
    }
}

/**
 * Thread-safe queue buffering outgoing user messages, rekey frames, or image chunks
 * to be emitted strictly on Poisson process ticks (Strict Poisson Traffic Shaping),
 * masking transmission timing, burstiness, and active chatting sessions.
 */
class OutboundPoissonQueue {
    private val queue = ConcurrentLinkedDeque<OutboundPoissonFrame>()

    /**
     * Appends an outbound frame to the queue (FIFO).
     */
    fun enqueue(frame: OutboundPoissonFrame) {
        queue.addLast(frame)
    }

    /**
     * Pushes an outbound frame to the head of the queue.
     */
    fun pushFront(frame: OutboundPoissonFrame) {
        queue.addFirst(frame)
    }

    fun poll(): OutboundPoissonFrame? = queue.pollFirst()

    fun peek(): OutboundPoissonFrame? = queue.peekFirst()

    val size: Int get() = queue.size

    fun isEmpty(): Boolean = queue.isEmpty()

    fun clear() {
        queue.clear()
    }

    fun removeForMessage(messageId: Long): Boolean = removeForMessageId(messageId)

    fun removeForMessageId(messageId: Long): Boolean {
        val iterator = queue.iterator()
        while (iterator.hasNext()) {
            if (iterator.next().messageId == messageId) {
                iterator.remove()
                return true
            }
        }
        return false
    }

    fun getAll(): List<OutboundPoissonFrame> = queue.toList()
}
