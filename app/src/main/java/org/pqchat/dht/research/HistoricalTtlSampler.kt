package org.pqchat.dht.research

import kotlinx.coroutines.*
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.dht.leaf.DhtClient
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Historical Packet Retention & Expiration Sampler for Master's Thesis Research.
 *
 * Requirements addressed:
 * - Periodically (every ~15 minutes) queries BitTorrent Mainline DHT for historical packet targets.
 * - Determines the exact time-to-live (TTL) and moment of expiration for original messages on the DHT.
 * - Compares empirical survival curves: records subject to periodic republish vs records without republish.
 * - Supports injection of calibration probe pairs (1 with republish, 1 without republish) for baseline analysis.
 */
class HistoricalTtlSampler(
    private val dhtClient: DhtClient,
    private val onSampleRecorded: (TtlSampleEvent) -> Unit,
    @Volatile var probeIntervalMs: Long = DEFAULT_PROBE_INTERVAL_MS,
    private val probeIntervalFlow: kotlinx.coroutines.flow.StateFlow<Long>? = null,
    private val resourceProfiler: org.pqchat.dht.debug.AndroidResourceProfiler? = null,
    private val networkTypeProvider: (() -> String)? = null
) {
    companion object {
        const val DEFAULT_PROBE_INTERVAL_MS = 15 * 60 * 1000L // 15 minut
        const val MAX_TRACKED_AGE_MS = 72 * 60 * 60 * 1000L   // 72 godziny
    }

    data class TrackedPacket(
        val target: ByteArray,
        val targetPrefix: String, // 8 hex chars
        val initialPutEpochMs: Long,
        val republishActive: Boolean,
        var lastSeenAliveMs: Long = initialPutEpochMs,
        var isExpired: Boolean = false,
        var consecutiveMisses: Int = 0
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is TrackedPacket) return false
            return target.contentEquals(other.target)
        }

        override fun hashCode(): Int = target.contentHashCode()
    }

    private val trackedPackets = ConcurrentHashMap<String, TrackedPacket>()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var samplerJob: Job? = null
    private val isRunning = AtomicBoolean(false)

    /**
     * Registers a newly transmitted packet for ongoing historical DHT retention sampling.
     */
    fun trackPacket(
        target: ByteArray,
        initialPutEpochMs: Long = System.currentTimeMillis(),
        republishActive: Boolean = true
    ) {
        val prefix = CryptoUtils.toHex(target).take(8)
        val tracked = TrackedPacket(
            target = target.copyOf(),
            targetPrefix = prefix,
            initialPutEpochMs = initialPutEpochMs,
            republishActive = republishActive,
            lastSeenAliveMs = initialPutEpochMs
        )
        trackedPackets[prefix] = tracked
    }

    /**
     * Injects a synthetic calibration probe pair into the DHT to measure baseline node churn:
     * - One packet configured with active republish
     * - One packet without republish (decay control)
     */
    suspend fun injectCalibrationProbePair(): Boolean = withContext(Dispatchers.IO) {
        try {
            val now = System.currentTimeMillis()

            // 1. Packet without republish (unrefreshed decay baseline)
            val seedDecay = CryptoUtils.secureRandomBytes(32)
            val keyPairDecay = Ed25519Engine.generateKeyPairFromSeed(seedDecay)
            val targetDecay = Ed25519Engine.computeTarget(keyPairDecay.publicKey)
            val payloadDecay = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

            val okDecay = dhtClient.putMutable(
                target = targetDecay,
                v = payloadDecay,
                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                salt = null,
                sk = seedDecay,
                skipLocalStore = false
            )
            if (okDecay) {
                trackPacket(targetDecay, initialPutEpochMs = now, republishActive = false)
            }

            // 2. Packet with republish active
            val seedRepub = CryptoUtils.secureRandomBytes(32)
            val keyPairRepub = Ed25519Engine.generateKeyPairFromSeed(seedRepub)
            val targetRepub = Ed25519Engine.computeTarget(keyPairRepub.publicKey)
            val payloadRepub = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

            val okRepub = dhtClient.putMutable(
                target = targetRepub,
                v = payloadRepub,
                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                salt = null,
                sk = seedRepub,
                skipLocalStore = false
            )
            if (okRepub) {
                trackPacket(targetRepub, initialPutEpochMs = now, republishActive = true)
            }

            return@withContext okDecay || okRepub
        } catch (_: Exception) {
            return@withContext false
        }
    }

    /**
     * Executes a single sampling pass over all tracked historical packet targets.
     * When probing, uses probeAllReplicas=true to count responding replicas without early cancellation,
     * recording multi-point retention decay curves (nodesResponded from K to 0).
     */
    suspend fun executeSamplingPass(
        currentTimeMs: Long = System.currentTimeMillis(),
        sessionId: String = "session"
    ): Int = withContext(Dispatchers.IO) {
        var samplesCount = 0
        val items = trackedPackets.values.toList()

        for (item in items) {
            val ageMs = (currentTimeMs - item.initialPutEpochMs).coerceAtLeast(0L)
            if (ageMs > MAX_TRACKED_AGE_MS || item.isExpired) {
                continue
            }

            val tStart = System.currentTimeMillis()
            // Probe DHT for this item across all replicas (skipLocalStore = true to query external network nodes)
            val retrieved = try {
                dhtClient.getMutable(
                    target = item.target,
                    salt = null,
                    skipLocalStore = true,
                    timeoutMs = 4000L,
                    probeAllReplicas = true
                )
            } catch (_: Exception) {
                null
            }
            val probeRttMs = System.currentTimeMillis() - tStart

            val isAlive = (retrieved != null)
            val elapsedMinutes = ageMs / (60.0 * 1000.0)
            val elapsedHours = ageMs / (3600.0 * 1000.0)

            val nodesQueried = retrieved?.nodesQueried?.takeIf { it > 0 } ?: dhtClient.lastNodesQueried
            val nodesResponded = if (isAlive) {
                (retrieved.nodesResponded.takeIf { it > 0 } ?: dhtClient.lastNodesResponded).coerceAtLeast(1)
            } else {
                0
            }
            val lookupHops = retrieved?.lookupHops?.takeIf { it > 0 } ?: dhtClient.lastLookupHops

            var confirmedLifespanMin: Double? = null

            if (isAlive && nodesResponded > 0) {
                item.lastSeenAliveMs = currentTimeMs
                item.consecutiveMisses = 0
            } else {
                item.consecutiveMisses++
                // Require 2 consecutive misses or >2h elapsed to declare definitive expiration
                if (item.consecutiveMisses >= 2 || elapsedHours >= 2.0) {
                    item.isExpired = true
                    val totalLifespanMs = (item.lastSeenAliveMs - item.initialPutEpochMs).coerceAtLeast(0L)
                    confirmedLifespanMin = totalLifespanMs / (60.0 * 1000.0)
                }
            }

            val sample = TtlSampleEvent(
                sessionId = sessionId,
                timestampEpochMs = currentTimeMs,
                targetPrefix = item.targetPrefix,
                initialPutEpochMs = item.initialPutEpochMs,
                elapsedMinutes = elapsedMinutes,
                elapsedHours = elapsedHours,
                republishActive = item.republishActive,
                isAlive = isAlive && nodesResponded > 0,
                nodesQueried = nodesQueried,
                nodesResponded = nodesResponded,
                lookupHops = lookupHops,
                probeRttMs = probeRttMs,
                confirmedLifespanMinutes = confirmedLifespanMin,
                networkType = networkTypeProvider?.invoke() ?: "UNKNOWN",
                pollingState = resourceProfiler?.getPollingState() ?: "UNKNOWN",
                replicationK = dhtClient.replicationK,
                poissonLambda = resourceProfiler?.getPoissonLambda() ?: (1.0 / 480.0),
                batteryCurrentUa = resourceProfiler?.queryBatteryCurrentNowUa() ?: 0L,
                batteryLevelPct = resourceProfiler?.queryBatteryLevelPercent() ?: 100
            )

            onSampleRecorded(sample)
            samplesCount++
        }

        return@withContext samplesCount
    }

    fun start(sessionIdProvider: () -> String) {
        if (isRunning.compareAndSet(false, true)) {
            samplerJob = scope.launch {
                // Initial calibration probe injection on start
                injectCalibrationProbePair()

                // Dynamically observe settingsManager.statsProbeIntervalMs if provided
                probeIntervalFlow?.let { flow ->
                    launch {
                        flow.collect { newInterval ->
                            if (newInterval > 0L) {
                                probeIntervalMs = newInterval
                            }
                        }
                    }
                }

                while (isActive) {
                    val currentInterval = probeIntervalFlow?.value ?: probeIntervalMs
                    delay(currentInterval.coerceAtLeast(1000L))
                    val sessionId = sessionIdProvider()
                    executeSamplingPass(System.currentTimeMillis(), sessionId)
                }
            }
        }
    }

    fun stop() {
        isRunning.set(false)
        samplerJob?.cancel()
    }

    fun getTrackedCount(): Int = trackedPackets.size
    fun getActiveTrackingCount(): Int = trackedPackets.values.count { !it.isExpired }
}
