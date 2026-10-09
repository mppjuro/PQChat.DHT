package org.pqchat.dht.traffic

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.dht.leaf.DhtClient
import kotlin.math.ln

/**
 * Poisson Process Cover Traffic Generator (Chaffing).
 *
 * Intervals delta_t follow an exponential distribution:
 * delta_t = - (1 / lambda) * ln(U), where U ~ Uniform(0, 1)
 *
 * Masks transmission patterns so external observers cannot distinguish
 * between real conversations and background noise.
 */
class PoissonTrafficGenerator(
    private val dhtLeafNode: DhtClient,
    private val lambda: Double = 1.0 / 480.0, // average once every 8 minutes (480s)
    val pendingAckQueue: PendingAckQueue = PendingAckQueue(),
    val decoyTargetPool: DecoyTargetPool = DecoyTargetPool.defaultInstance
) {
    data class CoverEvent(
        val timestamp: Long,
        val targetHex: String,
        val intervalSeconds: Double,
        val isAck: Boolean = false
    )

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val _eventFlow = MutableSharedFlow<CoverEvent>(replay = 50)
    val eventFlow: SharedFlow<CoverEvent> = _eventFlow.asSharedFlow()

    @Volatile
    private var isRunning = false

    /**
     * Compute next Poisson interval delta_t in milliseconds.
     */
    fun computeNextIntervalMs(currentLambda: Double = lambda): Long {
        val u = CryptoUtils.secureRandom.nextDouble().coerceIn(1e-10, 1.0 - 1e-10)
        val deltaSeconds = -(1.0 / currentLambda) * ln(u)
        return (deltaSeconds * 1000.0).toLong().coerceAtLeast(1000L)
    }

    /**
     * Emits a single cover traffic tick:
     * If pendingAckQueue has an item, replaces the dummy with an encrypted Cover-Traffic ACK token.
     * Otherwise emits a CSPRNG dummy packet.
     */
    suspend fun processCoverTrafficTick(delayMs: Long = 0L): CoverEvent {
        val pendingAck = pendingAckQueue.poll()
        val event = if (pendingAck != null) {
            val ackSeed = org.pqchat.dht.protocol.CoverAckProtocol.deriveAckSeed(pendingAck.ratchetKey, pendingAck.messageId)
            val ackTarget = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(pendingAck.ratchetKey, pendingAck.messageId)
            val ackPayload = org.pqchat.dht.protocol.CoverAckProtocol.createAckPayload(
                ratchetKey = pendingAck.ratchetKey,
                messageId = pendingAck.messageId,
                seqNum = pendingAck.seqNum
            )
            dhtLeafNode.putMutable(
                target = ackTarget,
                v = ackPayload,
                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                salt = null,
                sk = ackSeed
            )
            decoyTargetPool.registerPopulatedTarget(ackTarget)
            CoverEvent(
                timestamp = System.currentTimeMillis(),
                targetHex = CryptoUtils.toHex(ackTarget),
                intervalSeconds = delayMs / 1000.0,
                isAck = true
            )
        } else {
            val publishedTarget = dhtLeafNode.sendCoverTrafficDummy()
            val actualTarget = publishedTarget ?: CryptoUtils.secureRandomBytes(20)
            decoyTargetPool.registerPopulatedTarget(actualTarget)
            CoverEvent(
                timestamp = System.currentTimeMillis(),
                targetHex = CryptoUtils.toHex(actualTarget),
                intervalSeconds = delayMs / 1000.0,
                isAck = false
            )
        }
        _eventFlow.emit(event)
        return event
    }

    fun start() {
        if (isRunning) return
        isRunning = true

        scope.launch {
            while (isRunning) {
                val delayMs = computeNextIntervalMs()
                delay(delayMs)
                if (!isRunning) break

                try {
                    processCoverTrafficTick(delayMs)
                } catch (_: Exception) {}
            }
        }
    }

    fun stop() {
        isRunning = false
        scope.cancel()
    }
}
