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
    val lambda: Double = 1.0 / 480.0, // average once every 8 minutes (480s)
    val pendingAckQueue: PendingAckQueue = PendingAckQueue(),
    val outboundPoissonQueue: OutboundPoissonQueue = OutboundPoissonQueue(),
    val decoyTargetPool: DecoyTargetPool = DecoyTargetPool.defaultInstance,
    val blindRepublishPool: BlindRepublishPool = BlindRepublishPool.defaultInstance,
    var isCrowdsourcedRepublishEnabled: Boolean = true,
    var crowdsourcedRepublishEnabledProvider: (() -> Boolean)? = null,
    var researchTelemetryProvider: (() -> org.pqchat.dht.research.ResearchTelemetryManager?)? = {
        try {
            org.pqchat.dht.PQChatApplication.instance.researchTelemetryManager
        } catch (_: Throwable) {
            null
        }
    },
    private val random: java.util.Random = CryptoUtils.secureRandom
) {
    data class CoverEvent(
        val timestamp: Long,
        val targetHex: String,
        val intervalSeconds: Double,
        val isAck: Boolean = false,
        val isBlindRepublish: Boolean = false,
        val isFirstSend: Boolean = false,
        val payloadSize: Int = 900
    )

    fun isCrowdsourcedEnabled(): Boolean =
        crowdsourcedRepublishEnabledProvider?.invoke() ?: isCrowdsourcedRepublishEnabled

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val _eventFlow = MutableSharedFlow<CoverEvent>(replay = 50)
    val eventFlow: SharedFlow<CoverEvent> = _eventFlow.asSharedFlow()

    @Volatile
    private var isRunning = false

    /**
     * Compute next Poisson interval delta_t in milliseconds.
     */
    fun computeNextIntervalMs(currentLambda: Double = lambda): Long {
        val u = random.nextDouble().coerceIn(1e-10, 1.0 - 1e-10)
        val deltaSeconds = -(1.0 / currentLambda) * ln(u)
        return (deltaSeconds * 1000.0).toLong().coerceAtLeast(1000L)
    }

    /**
     * Emits a single cover traffic tick according to strict priority order:
     * 1. Priority 1: Pending user message from OutboundPoissonQueue (Strict Poisson Traffic Shaping, FIRST_SEND).
     * 2. Priority 2: Pending encrypted Cover-Traffic ACK token (COVER_ACK_SENT).
     * 3. Priority 3: Crowdsourced third-party BEP 44 republish from BlindRepublishPool (CROWD_REPUBLISH).
     * 4. Priority 4 (Fallback): Synthetic CSPRNG dummy decoy packet (COVER_DUMMY_SENT).
     */
    suspend fun processCoverTrafficTick(delayMs: Long = 0L): CoverEvent {
        if (dhtLeafNode.torTransportMode == org.pqchat.dht.dht.leaf.TorTransportMode.BLOCKED_ERROR) {
            val event = CoverEvent(
                timestamp = System.currentTimeMillis(),
                targetHex = "",
                intervalSeconds = delayMs / 1000.0,
                isAck = false,
                isBlindRepublish = false,
                isFirstSend = false,
                payloadSize = 0
            )
            _eventFlow.emit(event)
            return event
        }

        val outboundFrame = outboundPoissonQueue.poll()
        val event = if (outboundFrame != null) {
            val tStart = System.currentTimeMillis()
            val ok = dhtLeafNode.putMutable(
                target = outboundFrame.target,
                v = outboundFrame.payload,
                seq = outboundFrame.seq,
                salt = outboundFrame.salt,
                sk = outboundFrame.sk,
                skipLocalStore = outboundFrame.skipLocalStore
            )
            val rttMs = System.currentTimeMillis() - tStart
            try {
                researchTelemetryProvider?.invoke()?.recordPacketEvent(
                    role = org.pqchat.dht.research.PacketRole.FIRST_SEND,
                    target = outboundFrame.target,
                    seqNum = outboundFrame.seqNum.toLong(),
                    payloadBytes = outboundFrame.payload.size,
                    rttMs = rttMs,
                    nodesQueried = dhtLeafNode.lastNodesQueried,
                    nodesResponded = dhtLeafNode.lastNodesResponded,
                    lookupHops = dhtLeafNode.lastLookupHops,
                    success = ok,
                    republishAttempt = 0
                )
            } catch (_: Throwable) {}
            decoyTargetPool.registerPopulatedTarget(outboundFrame.target)
            try {
                outboundFrame.onSent?.invoke(ok)
            } catch (_: Throwable) {}
            CoverEvent(
                timestamp = System.currentTimeMillis(),
                targetHex = CryptoUtils.toHex(outboundFrame.target),
                intervalSeconds = delayMs / 1000.0,
                isAck = false,
                isBlindRepublish = false,
                isFirstSend = true,
                payloadSize = outboundFrame.payload.size
            )
        } else {
            val pendingAck = pendingAckQueue.poll()
            if (pendingAck != null) {
                val ackSeed = org.pqchat.dht.protocol.CoverAckProtocol.deriveAckSeed(pendingAck.ratchetKey, pendingAck.messageId)
                val ackTarget = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(pendingAck.ratchetKey, pendingAck.messageId)
                val ackPayload = org.pqchat.dht.protocol.CoverAckProtocol.createAckPayload(
                    ratchetKey = pendingAck.ratchetKey,
                    messageId = pendingAck.messageId,
                    seqNum = pendingAck.seqNum
                )
                val tStart = System.currentTimeMillis()
                val ok = dhtLeafNode.putMutable(
                    target = ackTarget,
                    v = ackPayload,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = ackSeed
                )
                val rttMs = System.currentTimeMillis() - tStart
                try {
                    researchTelemetryProvider?.invoke()?.recordPacketEvent(
                        role = org.pqchat.dht.research.PacketRole.COVER_ACK_SENT,
                        target = ackTarget,
                        payloadBytes = ackPayload.size,
                        rttMs = rttMs,
                        nodesQueried = dhtLeafNode.lastNodesQueried,
                        nodesResponded = dhtLeafNode.lastNodesResponded,
                        lookupHops = dhtLeafNode.lastLookupHops,
                        success = ok
                    )
                } catch (_: Throwable) {}
                decoyTargetPool.registerPopulatedTarget(ackTarget)
                CoverEvent(
                    timestamp = System.currentTimeMillis(),
                    targetHex = CryptoUtils.toHex(ackTarget),
                    intervalSeconds = delayMs / 1000.0,
                    isAck = true,
                    isBlindRepublish = false,
                    isFirstSend = false,
                    payloadSize = ackPayload.size
                )
            } else if (isCrowdsourcedEnabled() && blindRepublishPool.size() > 0) {
                val entry = blindRepublishPool.sampleRandomEntry()
                if (entry != null) {
                    val tStart = System.currentTimeMillis()
                    val ok = dhtLeafNode.putMutablePreSigned(
                        target = entry.target,
                        v = entry.v,
                        seq = entry.seq,
                        salt = entry.salt,
                        pk = entry.publicKey,
                        sig = entry.sig,
                        skipLocalStore = false
                    )
                    val rttMs = System.currentTimeMillis() - tStart
                    try {
                        researchTelemetryProvider?.invoke()?.recordPacketEvent(
                            role = org.pqchat.dht.research.PacketRole.CROWD_REPUBLISH,
                            target = entry.target,
                            seqNum = entry.seq,
                            payloadBytes = entry.v.size,
                            rttMs = rttMs,
                            nodesQueried = dhtLeafNode.lastNodesQueried,
                            nodesResponded = dhtLeafNode.lastNodesResponded,
                            lookupHops = dhtLeafNode.lastLookupHops,
                            success = ok
                        )
                    } catch (_: Throwable) {}
                    decoyTargetPool.registerPopulatedTarget(entry.target)
                    CoverEvent(
                        timestamp = System.currentTimeMillis(),
                        targetHex = CryptoUtils.toHex(entry.target),
                        intervalSeconds = delayMs / 1000.0,
                        isAck = false,
                        isBlindRepublish = true,
                        isFirstSend = false,
                        payloadSize = entry.v.size
                    )
                } else {
                    emitDummyCover(delayMs)
                }
            } else {
                emitDummyCover(delayMs)
            }
        }
        _eventFlow.emit(event)
        return event
    }

    private suspend fun emitDummyCover(delayMs: Long): CoverEvent {
        val publishedTarget = dhtLeafNode.sendCoverTrafficDummy()
        val actualTarget = publishedTarget ?: CryptoUtils.secureRandomBytes(20)
        try {
            researchTelemetryProvider?.invoke()?.recordPacketEvent(
                role = org.pqchat.dht.research.PacketRole.COVER_DUMMY_SENT,
                target = actualTarget,
                payloadBytes = 900,
                nodesQueried = dhtLeafNode.lastNodesQueried,
                nodesResponded = dhtLeafNode.lastNodesResponded,
                lookupHops = dhtLeafNode.lastLookupHops,
                success = publishedTarget != null
            )
        } catch (_: Throwable) {}
        decoyTargetPool.registerPopulatedTarget(actualTarget)
        return CoverEvent(
            timestamp = System.currentTimeMillis(),
            targetHex = CryptoUtils.toHex(actualTarget),
            intervalSeconds = delayMs / 1000.0,
            isAck = false,
            isBlindRepublish = false,
            isFirstSend = false
        )
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

    /**
     * Immediately triggers processing of a pending cover traffic tick (e.g. when Tor connection is established).
     */
    fun triggerImmediateTick() {
        if (!isRunning) return
        scope.launch {
            try {
                processCoverTrafficTick(0L)
            } catch (_: Exception) {}
        }
    }
}
