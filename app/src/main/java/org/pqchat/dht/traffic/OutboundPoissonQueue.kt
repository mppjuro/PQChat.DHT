package org.pqchat.dht.traffic

import org.pqchat.dht.dht.leaf.DhtClient
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentLinkedDeque

/**
 * Priority classes for outbound traffic shaping per AGENTS.md.
 * 1: Urgent Rekey / Handshake (strict priority, weight 8)
 * 2: 1-on-1 direct messages, reactions, location pins (weight 4)
 * 3: Group messages (weight 2)
 * 4: PNG8 image chunks (weight 1)
 * 5: Cover ACK / Blind Republish / Decoy (weight 1)
 */
enum class PacketClass(val priority: Int, val weight: Int) {
    URGENT_CONTROL(1, 8),          // 1: urgent Rekey/Handshake/Canary
    DIRECT_MESSAGE(2, 4),          // 2: 1-on-1 messages and reactions
    GROUP_MESSAGE(3, 2),           // 3: group messages and polls
    IMAGE_CHUNK(4, 1),             // 4: PNG8 image chunks
    BACKGROUND_COVER(5, 1);        // 5: Cover ACK / Blind Republish / Decoy

    companion object {
        fun fromType(msgType: Byte, isGroup: Boolean = false): PacketClass {
            return when (msgType) {
                0x01.toByte(), 0x03.toByte(), 0x04.toByte(), 0x06.toByte(), 0x0B.toByte() -> URGENT_CONTROL
                0x05.toByte() -> IMAGE_CHUNK
                0x0A.toByte() -> GROUP_MESSAGE
                0x02.toByte(), 0x07.toByte(), 0x08.toByte(), 0x09.toByte() -> if (isGroup) GROUP_MESSAGE else DIRECT_MESSAGE
                else -> DIRECT_MESSAGE
            }
        }
    }
}

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
    val packetClass: PacketClass = if (isDummyCover) PacketClass.BACKGROUND_COVER else PacketClass.DIRECT_MESSAGE,
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
                isDummyCover == other.isDummyCover &&
                packetClass == other.packetClass
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
        result = 31 * result + packetClass.hashCode()
        return result
    }
}

/**
 * Thread-safe queue buffering outgoing user messages, rekey frames, or image chunks
 * to be emitted strictly on Poisson process ticks (Strict Poisson Traffic Shaping),
 * implementing Weighted Fair Queuing (WFQ) / prioritized interleaving of 5 packet classes
 * to eliminate Head-of-Line Blocking for 1-on-1 chats while keeping strictly exponential
 * Poisson departures on UDP output.
 */
class OutboundPoissonQueue {
    private val classQueues = mapOf(
        PacketClass.URGENT_CONTROL to ConcurrentLinkedDeque<OutboundPoissonFrame>(),
        PacketClass.DIRECT_MESSAGE to ConcurrentLinkedDeque<OutboundPoissonFrame>(),
        PacketClass.GROUP_MESSAGE to ConcurrentLinkedDeque<OutboundPoissonFrame>(),
        PacketClass.IMAGE_CHUNK to ConcurrentLinkedDeque<OutboundPoissonFrame>(),
        PacketClass.BACKGROUND_COVER to ConcurrentLinkedDeque<OutboundPoissonFrame>()
    )

    companion object {
        // 8-slot fair schedule cycle: Direct (50%), Group (25%), Image (12.5%), Cover (12.5%)
        val WFQ_CYCLE = listOf(
            PacketClass.DIRECT_MESSAGE,
            PacketClass.GROUP_MESSAGE,
            PacketClass.DIRECT_MESSAGE,
            PacketClass.IMAGE_CHUNK,
            PacketClass.DIRECT_MESSAGE,
            PacketClass.GROUP_MESSAGE,
            PacketClass.DIRECT_MESSAGE,
            PacketClass.BACKGROUND_COVER
        )

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
                isDummyCover = true,
                packetClass = PacketClass.BACKGROUND_COVER
            )
        }
    }

    private var currentScheduleIndex = 0

    /**
     * Appends an outbound frame to its respective class queue in WFQ.
     */
    fun enqueue(frame: OutboundPoissonFrame) {
        synchronized(this) {
            classQueues[frame.packetClass]!!.addLast(frame)
        }
    }

    /**
     * Enqueues multiple frames with deterministic interleaving to eliminate
     * fan-out burstiness (Group Fan-Out Burst).
     */
    fun enqueueInterleaved(
        frames: List<OutboundPoissonFrame>,
        dummyFactory: (() -> OutboundPoissonFrame)? = null
    ) {
        if (frames.isEmpty()) return
        synchronized(this) {
            val targetQueue = classQueues[PacketClass.GROUP_MESSAGE]!!
            if (frames.size == 1 && dummyFactory == null) {
                targetQueue.addLast(frames[0].copy(packetClass = PacketClass.GROUP_MESSAGE))
                return
            }

            val existing = ArrayList<OutboundPoissonFrame>(targetQueue.size)
            while (true) {
                val f = targetQueue.pollFirst() ?: break
                existing.add(f)
            }

            val interleaved = ArrayList<OutboundPoissonFrame>(existing.size + frames.size * 2)

            if (existing.isEmpty()) {
                // If queue is empty, space out group frames with dummy cover frames
                for (i in frames.indices) {
                    if (i > 0 && dummyFactory != null) {
                        interleaved.add(dummyFactory.invoke())
                    }
                    interleaved.add(frames[i].copy(packetClass = PacketClass.GROUP_MESSAGE))
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
                        interleaved.add(frames[frameIdx++].copy(packetClass = PacketClass.GROUP_MESSAGE))
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
                    interleaved.add(frames[frameIdx++].copy(packetClass = PacketClass.GROUP_MESSAGE))
                    lastWasGroupFrame = true
                }

                while (existingIdx < existing.size) {
                    interleaved.add(existing[existingIdx++])
                    lastWasGroupFrame = false
                }
            }

            for (f in interleaved) {
                targetQueue.addLast(f)
            }
        }
    }

    /**
     * Pushes an outbound frame to the head of its class queue.
     */
    fun pushFront(frame: OutboundPoissonFrame) {
        synchronized(this) {
            classQueues[frame.packetClass]!!.addFirst(frame)
        }
    }

    fun poll(): OutboundPoissonFrame? = poll(null)

    /**
     * Polls the next frame using Weighted Fair Queuing (WFQ).
     * Class 1 (Urgent Rekey/Handshake) has strict priority.
     * Classes 2..5 are interleaved according to the 8-slot WFQ cycle.
     */
    fun poll(coverProvider: (() -> OutboundPoissonFrame?)? = null): OutboundPoissonFrame? {
        synchronized(this) {
            // Priority 1: Urgent Rekey / Handshake
            val urgent = classQueues[PacketClass.URGENT_CONTROL]!!.pollFirst()
            if (urgent != null) return urgent

            val hasDirect = classQueues[PacketClass.DIRECT_MESSAGE]!!.isNotEmpty()
            val hasGroup = classQueues[PacketClass.GROUP_MESSAGE]!!.isNotEmpty()
            val hasImage = classQueues[PacketClass.IMAGE_CHUNK]!!.isNotEmpty()
            val hasCover = classQueues[PacketClass.BACKGROUND_COVER]!!.isNotEmpty()

            if (!hasDirect && !hasGroup && !hasImage && !hasCover && coverProvider == null) {
                return null
            }

            for (step in 0 until WFQ_CYCLE.size) {
                val slotIdx = (currentScheduleIndex + step) % WFQ_CYCLE.size
                val targetClass = WFQ_CYCLE[slotIdx]
                val q = classQueues[targetClass]!!

                if (q.isNotEmpty()) {
                    currentScheduleIndex = (slotIdx + 1) % WFQ_CYCLE.size
                    return q.pollFirst()
                } else if (targetClass == PacketClass.BACKGROUND_COVER) {
                    if (coverProvider != null) {
                        val coverFrame = coverProvider.invoke()
                        if (coverFrame != null) {
                            currentScheduleIndex = (slotIdx + 1) % WFQ_CYCLE.size
                            return coverFrame
                        }
                    } else if (hasDirect || hasGroup || hasImage) {
                        // Yield slot to external cover traffic if user queues are active
                        currentScheduleIndex = (slotIdx + 1) % WFQ_CYCLE.size
                        return null
                    }
                }
            }

            // Fallback: poll whatever is non-empty
            for (c in listOf(PacketClass.DIRECT_MESSAGE, PacketClass.GROUP_MESSAGE, PacketClass.IMAGE_CHUNK, PacketClass.BACKGROUND_COVER)) {
                val q = classQueues[c]!!
                if (q.isNotEmpty()) return q.pollFirst()
            }
            return coverProvider?.invoke()
        }
    }

    fun peek(): OutboundPoissonFrame? {
        synchronized(this) {
            val urgent = classQueues[PacketClass.URGENT_CONTROL]!!.peekFirst()
            if (urgent != null) return urgent
            for (step in 0 until WFQ_CYCLE.size) {
                val slotIdx = (currentScheduleIndex + step) % WFQ_CYCLE.size
                val targetClass = WFQ_CYCLE[slotIdx]
                val f = classQueues[targetClass]!!.peekFirst()
                if (f != null) return f
            }
            return null
        }
    }

    val size: Int
        get() = synchronized(this) {
            classQueues.values.sumOf { it.size }
        }

    fun isEmpty(): Boolean = size == 0

    fun clear() {
        synchronized(this) {
            classQueues.values.forEach { it.clear() }
            currentScheduleIndex = 0
        }
    }

    fun removeForMessage(messageId: Long): Boolean = removeForMessageId(messageId)

    fun removeForMessageId(messageId: Long): Boolean {
        synchronized(this) {
            var removed = false
            for (q in classQueues.values) {
                val iter = q.iterator()
                while (iter.hasNext()) {
                    if (iter.next().messageId == messageId) {
                        iter.remove()
                        removed = true
                    }
                }
            }
            return removed
        }
    }

    fun getAll(): List<OutboundPoissonFrame> {
        synchronized(this) {
            val result = mutableListOf<OutboundPoissonFrame>()
            result.addAll(classQueues[PacketClass.URGENT_CONTROL]!!)

            val dDirect = ArrayDeque(classQueues[PacketClass.DIRECT_MESSAGE]!!)
            val dGroup = ArrayDeque(classQueues[PacketClass.GROUP_MESSAGE]!!)
            val dImage = ArrayDeque(classQueues[PacketClass.IMAGE_CHUNK]!!)
            val dCover = ArrayDeque(classQueues[PacketClass.BACKGROUND_COVER]!!)

            val tempQueues = mapOf(
                PacketClass.DIRECT_MESSAGE to dDirect,
                PacketClass.GROUP_MESSAGE to dGroup,
                PacketClass.IMAGE_CHUNK to dImage,
                PacketClass.BACKGROUND_COVER to dCover
            )

            var simIndex = currentScheduleIndex
            while (dDirect.isNotEmpty() || dGroup.isNotEmpty() || dImage.isNotEmpty() || dCover.isNotEmpty()) {
                var found = false
                for (step in 0 until WFQ_CYCLE.size) {
                    val slotIdx = (simIndex + step) % WFQ_CYCLE.size
                    val targetClass = WFQ_CYCLE[slotIdx]
                    val q = tempQueues[targetClass]
                    if (q != null && q.isNotEmpty()) {
                        result.add(q.removeFirst())
                        simIndex = (slotIdx + 1) % WFQ_CYCLE.size
                        found = true
                        break
                    }
                }
                if (!found) {
                    for (q in tempQueues.values) {
                        if (q.isNotEmpty()) {
                            result.add(q.removeFirst())
                            break
                        }
                    }
                }
            }
            return result
        }
    }
}
