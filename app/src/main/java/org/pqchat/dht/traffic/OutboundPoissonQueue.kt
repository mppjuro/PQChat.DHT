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
    val isDummyCover: Boolean = false,
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
                contactId == other.contactId &&
                isDummyCover == other.isDummyCover
    }

    override fun hashCode(): Int {
        var result = target.contentHashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + seq.hashCode()
        result = 31 * result + sk.contentHashCode()
        result = 31 * result + seqNum
        result = 31 * result + (messageId?.hashCode() ?: 0)
        result = 31 * result + (contactId?.hashCode() ?: 0)
        result = 31 * result + isDummyCover.hashCode()
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

    companion object {
        fun createDummyFrame(): OutboundPoissonFrame {
            val dummySeed = org.pqchat.dht.crypto.CryptoUtils.secureRandomBytes(32)
            val dummyKeyPair = org.pqchat.dht.crypto.Ed25519Engine.generateKeyPairFromSeed(dummySeed)
            val target = org.pqchat.dht.crypto.Ed25519Engine.computeTarget(dummyKeyPair.publicKey)
            val payload = org.pqchat.dht.crypto.CryptoUtils.secureRandomBytes(org.pqchat.dht.crypto.BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)
            return OutboundPoissonFrame(
                target = target,
                payload = payload,
                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                salt = null,
                sk = dummySeed,
                skipLocalStore = true,
                isDummyCover = true
            )
        }
    }

    /**
     * Appends an outbound frame to the queue (FIFO).
     */
    fun enqueue(frame: OutboundPoissonFrame) {
        queue.addLast(frame)
    }

    /**
     * Enqueues multiple frames with deterministic interleaving to eliminate
     * fan-out burstiness (Group Fan-Out Burst).
     *
     * If the queue already contains existing frames, the incoming frames are evenly
     * interleaved with the existing frames. If the queue has fewer frames than required
     * to space out adjacent group frames, dummy cover traffic frames are deterministically
     * interleaved between them so that no two group packets are emitted on immediately
     * consecutive Poisson ticks.
     */
    fun enqueueInterleaved(
        frames: List<OutboundPoissonFrame>,
        dummyFactory: (() -> OutboundPoissonFrame)? = null
    ) {
        if (frames.isEmpty()) return
        if (frames.size == 1) {
            queue.addLast(frames[0])
            return
        }

        synchronized(queue) {
            val existing = ArrayList<OutboundPoissonFrame>(queue.size)
            while (true) {
                val f = queue.pollFirst() ?: break
                existing.add(f)
            }

            val interleaved = ArrayList<OutboundPoissonFrame>(existing.size + frames.size * 2)

            if (existing.isEmpty()) {
                // If queue is empty, space out group frames with dummy cover frames
                for (i in frames.indices) {
                    if (i > 0 && dummyFactory != null) {
                        interleaved.add(dummyFactory.invoke())
                    }
                    interleaved.add(frames[i])
                }
            } else {
                // Interleave frames across existing queue items with deterministic stride
                val totalSlots = existing.size + frames.size
                var frameIdx = 0
                var existingIdx = 0
                val stride = totalSlots.toDouble() / frames.size
                var lastWasGroupFrame = false

                for (pos in 0 until totalSlots) {
                    val shouldPlaceGroupFrame = frameIdx < frames.size &&
                            (pos >= (frameIdx * stride).toInt() || existingIdx >= existing.size)

                    if (shouldPlaceGroupFrame) {
                        if (dummyFactory != null && lastWasGroupFrame) {
                            interleaved.add(dummyFactory.invoke())
                        }
                        interleaved.add(frames[frameIdx++])
                        lastWasGroupFrame = true
                    } else if (existingIdx < existing.size) {
                        interleaved.add(existing[existingIdx++])
                        lastWasGroupFrame = false
                    }
                }

                while (frameIdx < frames.size) {
                    if (dummyFactory != null && lastWasGroupFrame) {
                        interleaved.add(dummyFactory.invoke())
                    }
                    interleaved.add(frames[frameIdx++])
                    lastWasGroupFrame = true
                }
                while (existingIdx < existing.size) {
                    interleaved.add(existing[existingIdx++])
                    lastWasGroupFrame = false
                }
            }

            for (f in interleaved) {
                queue.addLast(f)
            }
        }
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
