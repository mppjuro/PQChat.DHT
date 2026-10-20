package org.pqchat.dht.research

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.content.FileProvider
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.pqchat.dht.BuildConfig
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.dht.leaf.DhtClient
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.FileWriter
import java.io.PrintWriter
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Central Coordinator for Academic Research Telemetry in PQChat DHT (Local-First Architecture).
 *
 * Designed for Master's Thesis empirical analysis:
 * - Differentiates original packets (FIRST_SEND) vs own republish (OWN_REPUBLISH) vs crowdsourced relay (CROWD_REPUBLISH) vs received (PACKET_RECEIVED).
 * - Conducts periodic (15-min) historical DHT retention sampling to determine exact packet expiration and survival curves.
 * - Local-First Batch Archiving: Maintains persistent CSV files and dumps resource usage from AndroidResourceProfiler on device.
 * - Compresses all CSVs and session_manifest.json with SHA-256 hashes into a single .zip bundle.
 * - Supports instant offline sharing via Android FileProvider / ACTION_SEND or Cloud Firestore sync (Firebase Spark plan compliant).
 * - Strictly zero plaintext, zero cryptographic keys, and default-off user privacy.
 */
class ResearchTelemetryManager(
    private val context: Context? = null,
    private val settingsManager: AppSettingsManager? = null,
    private val dhtClient: DhtClient? = null,
    val firebaseSync: FirebaseResearchSync = FirebaseResearchSync(context),
    val resourceProfiler: org.pqchat.dht.debug.AndroidResourceProfiler? = null,
    val baseDir: File? = null,
    customTtlSampler: HistoricalTtlSampler? = null
) {
    val sessionId: String = UUID.randomUUID().toString().take(12)

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _eventsCount = MutableStateFlow(0)
    val eventsCount: StateFlow<Int> = _eventsCount.asStateFlow()

    private val _firstSendCount = MutableStateFlow(0)
    val firstSendCount: StateFlow<Int> = _firstSendCount.asStateFlow()

    private val _ownRepublishCount = MutableStateFlow(0)
    val ownRepublishCount: StateFlow<Int> = _ownRepublishCount.asStateFlow()

    private val _crowdRepublishCount = MutableStateFlow(0)
    val crowdRepublishCount: StateFlow<Int> = _crowdRepublishCount.asStateFlow()

    private val _packetsReceivedCount = MutableStateFlow(0)
    val packetsReceivedCount: StateFlow<Int> = _packetsReceivedCount.asStateFlow()

    private val _ttlSamplesCount = MutableStateFlow(0)
    val ttlSamplesCount: StateFlow<Int> = _ttlSamplesCount.asStateFlow()

    val syncStatus: StateFlow<String> = firebaseSync.syncStatus

    // In-flight message tracking for republish end-to-end analysis
    private val inFlightRepublishes = ConcurrentHashMap<String, InFlightTracker>()

    // In-memory aggregates for Firestore batch metric synchronization
    private val rttSamples = ConcurrentLinkedQueue<Long>()
    private val aliveTtlCount = AtomicInteger(0)
    private val expiredTtlCount = AtomicInteger(0)
    private val deliveredAckCount = AtomicInteger(0)
    private val totalDeliveredLatencyMs = AtomicLong(0L)

    // Traffic shaping & anonymity tracking
    private val lastOutboundPacketTimestampMs = AtomicLong(0L)
    private val outboundIntervalsMs = ConcurrentLinkedQueue<Long>()
    private val realMsgCount = AtomicInteger(0)
    private val coverDummyCount = AtomicInteger(0)
    private val blindRepublishCount = AtomicInteger(0)
    private val decoyGetCount = AtomicInteger(0)
    private val tombstoneCount = AtomicInteger(0)
    private val totalOutboundPackets = AtomicInteger(0)

    // Target ID prefix frequency distribution for Shannon entropy (256 bins for byte 0)
    private val targetPrefixByteCounts = java.util.concurrent.atomic.AtomicIntegerArray(256)
    private val totalTargetPrefixSamples = AtomicInteger(0)

    // Ed25519 signature & response validation stats
    private val totalEd25519Queries = AtomicInteger(0)
    private val totalEd25519NodesQueried = AtomicInteger(0)
    private val totalEd25519NodesValid = AtomicInteger(0)

    // Physical network RTT distributions
    private val networkRttMap = ConcurrentHashMap<String, ConcurrentLinkedQueue<Long>>()

    // Chunk resumption telemetry
    private val chunkTransfersTotal = AtomicInteger(0)
    private val chunkTransfersResumed = AtomicInteger(0)
    private val chunkTransfersSuccessful = AtomicInteger(0)

    // Group chat metrics
    private val groupLatencyBySize = ConcurrentHashMap<Int, ConcurrentLinkedQueue<Long>>()
    private val groupDeliverySkews = ConcurrentLinkedQueue<Long>()
    private val keyRotationConvergenceList = ConcurrentLinkedQueue<Long>()
    private val totalGroupMessagesTracked = AtomicInteger(0)
    private val totalKeyRotationsTracked = AtomicInteger(0)

    // Historical retention samples cache for survival curves
    private val ttlSamplesHistory = ConcurrentLinkedQueue<TtlSampleEvent>()

    private data class InFlightTracker(
        val messagePrefix: String,
        val initialSentMs: Long,
        val republishAttempts: AtomicInteger = AtomicInteger(0),
        var timeToFirstRepublishMs: Long = 0L,
        var crowdRelayed: Boolean = false
    )

    private val telemetryDir: File by lazy {
        val base = baseDir
            ?: context?.getExternalFilesDir(null)
            ?: context?.filesDir
            ?: File(System.getProperty("java.io.tmpdir") ?: ".", "pqchat_research_telemetry")
        val dir = File(base, "research_telemetry")
        if (!dir.exists()) dir.mkdirs()
        dir
    }

    val masterCsvFile: File by lazy { File(telemetryDir, "research_telemetry_master.csv") }
    val packetEventsCsvFile: File by lazy { File(telemetryDir, "research_packet_events.csv") }
    val ttlSamplesCsvFile: File by lazy { File(telemetryDir, "research_ttl_samples.csv") }
    val republishSummaryCsvFile: File by lazy { File(telemetryDir, "research_republish_analysis.csv") }
    val resourceProfileCsvFile: File by lazy { File(telemetryDir, "research_resource_profile.csv") }
    val groupEventsCsvFile: File by lazy { File(telemetryDir, "research_group_events.csv") }

    private val csvLock = Any()

    val ttlSampler: HistoricalTtlSampler? = customTtlSampler ?: if (dhtClient != null) {
        HistoricalTtlSampler(
            dhtClient = dhtClient,
            probeIntervalFlow = settingsManager?.statsProbeIntervalMs,
            resourceProfiler = resourceProfiler,
            networkTypeProvider = { detectCurrentNetworkType() },
            onSampleRecorded = { sample ->
                recordTtlSampleInternal(sample)
            }
        )
    } else null

    init {
        initCsvFiles()

        // Listen to settings toggle changes
        scope.launch {
            settingsManager?.isAnonymousStatsEnabled?.collect { enabled ->
                if (enabled) {
                    ttlSampler?.start { sessionId }
                    firebaseSync.ensureAuthenticated()
                } else {
                    ttlSampler?.stop()
                }
            }
        }

        // Periodic background auto-sync check (every 30 minutes with random jitter, strictly on Wi-Fi and not actively profiling)
        scope.launch {
            while (isActive) {
                val jitter = (-5 * 60 * 1000L..5 * 60 * 1000L).random()
                val nextDelay = (30 * 60 * 1000L + jitter).coerceAtLeast(10 * 60 * 1000L)
                delay(nextDelay)
                val isProfiling = resourceProfiler?.isProfiling?.value == true
                if (isEnabled && firebaseSync.isSafeToSync(isProfiling) && firebaseSync.isFirebaseConfigured()) {
                    try {
                        val (deviceInfo, metrics) = computeSessionPayload()
                        firebaseSync.syncResearchSession(sessionId, deviceInfo, metrics, isManual = false)
                    } catch (_: Exception) {}
                }
            }
        }
    }

    val isEnabled: Boolean
        get() = settingsManager?.isAnonymousStatsEnabled?.value == true

    fun detectCurrentNetworkType(): String {
        if (dhtClient?.isTorRoutingActive == true) {
            return "TOR_SOCKS5"
        }
        val ctx = context ?: return "UNKNOWN"
        return try {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager
            val net = cm?.activeNetwork
            val caps = cm?.getNetworkCapabilities(net)
            when {
                caps == null -> "UNKNOWN"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> "WIFI"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> "LTE_CELLULAR"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) -> "ETHERNET"
                else -> "UNKNOWN"
            }
        } catch (_: Throwable) {
            "UNKNOWN"
        }
    }

    private fun initCsvFiles() {
        synchronized(csvLock) {
            if (!masterCsvFile.exists()) masterCsvFile.writeText(ResearchCsvSchema.MASTER_CSV_HEADER + "\n")
            if (!packetEventsCsvFile.exists()) packetEventsCsvFile.writeText(PacketTelemetryEvent.CSV_HEADER + "\n")
            if (!ttlSamplesCsvFile.exists()) ttlSamplesCsvFile.writeText(TtlSampleEvent.CSV_HEADER + "\n")
            if (!republishSummaryCsvFile.exists()) republishSummaryCsvFile.writeText(RepublishAnalysisSummary.CSV_HEADER + "\n")
            if (!resourceProfileCsvFile.exists()) {
                resourceProfileCsvFile.writeText(org.pqchat.dht.debug.AndroidResourceProfiler.ResourceSample.CSV_HEADER + "\n")
            }
            if (!groupEventsCsvFile.exists()) {
                groupEventsCsvFile.writeText(GroupTelemetryEvent.CSV_HEADER + "\n")
            }
        }
    }

    /**
     * Records an outbound or inbound packet event.
     */
    fun recordPacketEvent(
        role: PacketRole,
        target: ByteArray,
        seqNum: Long = 1L,
        payloadBytes: Int = 900,
        rttMs: Long = 0L,
        nodesQueried: Int = dhtClient?.lastNodesQueried ?: 0,
        nodesResponded: Int = dhtClient?.lastNodesResponded ?: 0,
        lookupHops: Int = dhtClient?.lastLookupHops ?: 0,
        success: Boolean = true,
        republishAttempt: Int = 0,
        messageAgeMs: Long = 0L,
        networkType: String? = null,
        pollingState: String? = null,
        replicationK: Int? = null,
        poissonLambda: Double? = null,
        batteryCurrentUa: Long? = null,
        batteryLevelPct: Int? = null,
        errorCode: String? = null
    ) {
        if (!isEnabled) return

        val targetPrefix = CryptoUtils.toHex(target).take(8)
        val now = System.currentTimeMillis()

        if (rttMs > 0L && rttSamples.size < 2000) {
            rttSamples.add(rttMs)
        }

        val resolvedNetworkType = networkType ?: detectCurrentNetworkType()
        val resolvedPollingState = pollingState ?: (resourceProfiler?.getPollingState() ?: "UNKNOWN")
        val resolvedReplicationK = replicationK ?: (dhtClient?.replicationK ?: 8)
        val resolvedPoissonLambda = poissonLambda ?: (resourceProfiler?.getPoissonLambda() ?: (1.0 / 480.0))
        val resolvedBatteryCurrentUa = batteryCurrentUa ?: (resourceProfiler?.queryBatteryCurrentNowUa() ?: 0L)
        val resolvedBatteryLevelPct = batteryLevelPct ?: (resourceProfiler?.queryBatteryLevelPercent() ?: 100)

        // 1. Traffic Shaping & Anonymity Efficacy Tracking
        val isOutbound = role in setOf(
            PacketRole.FIRST_SEND,
            PacketRole.OWN_REPUBLISH,
            PacketRole.CROWD_REPUBLISH,
            PacketRole.TOMBSTONE_SENT,
            PacketRole.COVER_ACK_SENT,
            PacketRole.COVER_DUMMY_SENT,
            PacketRole.DECOY_GET
        )

        if (isOutbound) {
            totalOutboundPackets.incrementAndGet()
            when (role) {
                PacketRole.FIRST_SEND -> realMsgCount.incrementAndGet()
                PacketRole.COVER_DUMMY_SENT -> coverDummyCount.incrementAndGet()
                PacketRole.CROWD_REPUBLISH -> blindRepublishCount.incrementAndGet()
                PacketRole.DECOY_GET -> decoyGetCount.incrementAndGet()
                PacketRole.TOMBSTONE_SENT -> tombstoneCount.incrementAndGet()
                else -> {}
            }
            val prevOutbound = lastOutboundPacketTimestampMs.getAndSet(now)
            if (prevOutbound > 0L) {
                val interval = (now - prevOutbound).coerceAtLeast(0L)
                if (outboundIntervalsMs.size < 5000) {
                    outboundIntervalsMs.add(interval)
                }
            }
        }

        // 2. Shannon Entropy of Target Prefixes (evaluated on first byte: 256 states)
        if (target.isNotEmpty()) {
            val firstByte = target[0].toInt() and 0xFF
            targetPrefixByteCounts.incrementAndGet(firstByte)
            totalTargetPrefixSamples.incrementAndGet()
        }

        // 3. Node query tracking & Ed25519 signature validation
        if (nodesQueried > 0) {
            totalEd25519Queries.incrementAndGet()
            totalEd25519NodesQueried.addAndGet(nodesQueried)
            totalEd25519NodesValid.addAndGet(nodesResponded.coerceAtLeast(0))
        }

        // 4. Physical network RTT distribution
        if (rttMs > 0L) {
            val netList = networkRttMap.computeIfAbsent(resolvedNetworkType) { ConcurrentLinkedQueue() }
            if (netList.size < 2000) {
                netList.add(rttMs)
            }
        }

        val event = PacketTelemetryEvent(
            sessionId = sessionId,
            timestampEpochMs = now,
            role = role,
            targetPrefix = targetPrefix,
            seqNum = seqNum,
            payloadBytes = payloadBytes,
            rttMs = rttMs,
            nodesQueried = nodesQueried,
            nodesResponded = nodesResponded,
            lookupHops = lookupHops,
            success = success,
            republishAttempt = republishAttempt,
            messageAgeMs = messageAgeMs,
            networkType = resolvedNetworkType,
            pollingState = resolvedPollingState,
            replicationK = resolvedReplicationK,
            poissonLambda = resolvedPoissonLambda,
            batteryCurrentUa = resolvedBatteryCurrentUa,
            batteryLevelPct = resolvedBatteryLevelPct,
            errorCode = errorCode
        )

        // Increment live UI counters
        _eventsCount.value += 1
        when (role) {
            PacketRole.FIRST_SEND -> {
                _firstSendCount.value += 1
                inFlightRepublishes[targetPrefix] = InFlightTracker(targetPrefix, now)
                ttlSampler?.trackPacket(target, initialPutEpochMs = now, republishActive = true)
            }
            PacketRole.OWN_REPUBLISH -> {
                _ownRepublishCount.value += 1
                val tracker = inFlightRepublishes[targetPrefix]
                if (tracker != null) {
                    val attempt = tracker.republishAttempts.incrementAndGet()
                    if (attempt == 1) {
                        tracker.timeToFirstRepublishMs = (now - tracker.initialSentMs).coerceAtLeast(0L)
                    }
                }
            }
            PacketRole.CROWD_REPUBLISH -> {
                _crowdRepublishCount.value += 1
                inFlightRepublishes[targetPrefix]?.crowdRelayed = true
            }
            PacketRole.PACKET_RECEIVED -> {
                _packetsReceivedCount.value += 1
            }
            else -> {}
        }

        // Append to local CSV files immediately
        appendPacketEventCsv(event)
    }

    /**
     * Records a Decoy Target query emitted to camouflage real contact rendezvous.
     */
    fun recordDecoyGet(
        target: ByteArray,
        rttMs: Long = 0L,
        nodesQueried: Int = 0,
        nodesResponded: Int = 0
    ) {
        recordPacketEvent(
            role = PacketRole.DECOY_GET,
            target = target,
            rttMs = rttMs,
            nodesQueried = nodesQueried,
            nodesResponded = nodesResponded,
            success = true
        )
    }

    /**
     * Records block/chunk transfer telemetry for multi-frame media resumption analysis.
     */
    fun recordChunkTransfer(wasResumed: Boolean, wasSuccessful: Boolean) {
        if (!isEnabled) return
        chunkTransfersTotal.incrementAndGet()
        if (wasResumed) {
            chunkTransfersResumed.incrementAndGet()
            if (wasSuccessful) {
                chunkTransfersSuccessful.incrementAndGet()
            }
        }
    }

    /**
     * Records group chat message fan-out delivery latency and skew.
     */
    fun recordGroupMessageDelivery(
        groupId: ByteArray,
        groupSizeM: Int,
        latencyMs: Long,
        fanOutSkewMs: Long = 0L,
        epoch: Long = 1L
    ) {
        if (!isEnabled) return
        totalGroupMessagesTracked.incrementAndGet()
        groupLatencyBySize.computeIfAbsent(groupSizeM) { ConcurrentLinkedQueue() }.add(latencyMs)
        if (fanOutSkewMs > 0L) {
            groupDeliverySkews.add(fanOutSkewMs)
        }
        val prefix = CryptoUtils.toHex(groupId).take(8)
        val event = GroupTelemetryEvent(
            sessionId = sessionId,
            eventType = if (fanOutSkewMs > 0L) "FAN_OUT_SKEW" else "BROADCAST",
            groupIdPrefix = prefix,
            groupSizeM = groupSizeM,
            latencyMs = latencyMs,
            fanOutSkewMs = fanOutSkewMs,
            epoch = epoch
        )
        appendGroupEventCsv(event)
    }

    /**
     * Records group key rotation convergence time (GROUP_SUBTYPE_REKEY).
     */
    fun recordKeyRotationConvergence(
        groupId: ByteArray,
        groupSizeM: Int,
        convergenceMs: Long,
        epoch: Long = 1L
    ) {
        if (!isEnabled) return
        totalKeyRotationsTracked.incrementAndGet()
        keyRotationConvergenceList.add(convergenceMs)
        val prefix = CryptoUtils.toHex(groupId).take(8)
        val event = GroupTelemetryEvent(
            sessionId = sessionId,
            eventType = "KEY_ROTATION",
            groupIdPrefix = prefix,
            groupSizeM = groupSizeM,
            latencyMs = convergenceMs,
            keyRotationConvergenceMs = convergenceMs,
            epoch = epoch
        )
        appendGroupEventCsv(event)
    }

    /**
     * Records delivery ACK confirmation for a previously sent message.
     */
    fun recordDeliveryAck(
        target: ByteArray,
        deliveredEpochMs: Long = System.currentTimeMillis()
    ) {
        if (!isEnabled) return
        val prefix = CryptoUtils.toHex(target).take(8)
        val tracker = inFlightRepublishes.remove(prefix) ?: return

        val latency = (deliveredEpochMs - tracker.initialSentMs).coerceAtLeast(0L)
        deliveredAckCount.incrementAndGet()
        totalDeliveredLatencyMs.addAndGet(latency)

        val summary = RepublishAnalysisSummary(
            messagePrefix = prefix,
            sessionId = sessionId,
            initialSentEpochMs = tracker.initialSentMs,
            deliveredEpochMs = deliveredEpochMs,
            isDelivered = true,
            totalRepublishes = tracker.republishAttempts.get(),
            timeToFirstRepublishMs = tracker.timeToFirstRepublishMs,
            endToEndDeliveryLatencyMs = latency,
            crowdRelayed = tracker.crowdRelayed,
            finalStatus = "DELIVERED"
        )

        appendRepublishSummaryCsv(summary)
    }

    fun recordTtlSample(sample: TtlSampleEvent) {
        if (!isEnabled) return
        val enriched = if (sample.networkType == "UNKNOWN" || sample.pollingState == "UNKNOWN") {
            sample.copy(
                networkType = if (sample.networkType == "UNKNOWN") detectCurrentNetworkType() else sample.networkType,
                pollingState = if (sample.pollingState == "UNKNOWN") (resourceProfiler?.getPollingState() ?: "UNKNOWN") else sample.pollingState,
                replicationK = if (sample.replicationK == 8 && (dhtClient?.replicationK ?: 8) != 8) (dhtClient?.replicationK ?: 8) else sample.replicationK,
                poissonLambda = if (sample.poissonLambda == (1.0 / 480.0) && resourceProfiler != null) resourceProfiler.getPoissonLambda() else sample.poissonLambda,
                batteryCurrentUa = if (sample.batteryCurrentUa == 0L && resourceProfiler != null) resourceProfiler.queryBatteryCurrentNowUa() else sample.batteryCurrentUa,
                batteryLevelPct = if (sample.batteryLevelPct == -1 && resourceProfiler != null) resourceProfiler.queryBatteryLevelPercent() else sample.batteryLevelPct
            )
        } else {
            sample
        }
        _ttlSamplesCount.value += 1
        if (enriched.isAlive) {
            aliveTtlCount.incrementAndGet()
        } else {
            expiredTtlCount.incrementAndGet()
        }
        if (ttlSamplesHistory.size < 5000) {
            ttlSamplesHistory.add(enriched)
        }
        appendTtlSampleCsv(enriched)
    }

    private fun recordTtlSampleInternal(sample: TtlSampleEvent) {
        recordTtlSample(sample)
    }

    private fun appendPacketEventCsv(event: PacketTelemetryEvent) {
        synchronized(csvLock) {
            try {
                PrintWriter(FileWriter(packetEventsCsvFile, true)).use { it.println(event.toCsvRow()) }
                PrintWriter(FileWriter(masterCsvFile, true)).use { it.println(event.toMasterCsvRow()) }
            } catch (_: Exception) {}
        }
    }

    private fun appendGroupEventCsv(event: GroupTelemetryEvent) {
        synchronized(csvLock) {
            try {
                PrintWriter(FileWriter(groupEventsCsvFile, true)).use { it.println(event.toCsvRow()) }
                PrintWriter(FileWriter(masterCsvFile, true)).use { it.println(event.toMasterCsvRow()) }
            } catch (_: Exception) {}
        }
    }

    private fun appendTtlSampleCsv(sample: TtlSampleEvent) {
        synchronized(csvLock) {
            try {
                PrintWriter(FileWriter(ttlSamplesCsvFile, true)).use { it.println(sample.toCsvRow()) }
                PrintWriter(FileWriter(masterCsvFile, true)).use { it.println(sample.toMasterCsvRow()) }
            } catch (_: Exception) {}
        }
    }

    private fun appendRepublishSummaryCsv(summary: RepublishAnalysisSummary) {
        synchronized(csvLock) {
            try {
                PrintWriter(FileWriter(republishSummaryCsvFile, true)).use { it.println(summary.toCsvRow()) }
                PrintWriter(FileWriter(masterCsvFile, true)).use { it.println(summary.toMasterCsvRow()) }
            } catch (_: Exception) {}
        }
    }

    fun computeTrafficShapingStats(): TrafficShapingStats {
        val intervals = outboundIntervalsMs.toList()
        val count = intervals.size
        val totalOut = totalOutboundPackets.get()
        val realCount = realMsgCount.get()
        val dummyCount = coverDummyCount.get()
        val blindCount = blindRepublishCount.get()
        val decoyCount = decoyGetCount.get()
        val tombCount = tombstoneCount.get()

        val realPct = if (totalOut > 0) (realCount.toDouble() / totalOut * 100.0) else 0.0
        val dummyPct = if (totalOut > 0) (dummyCount.toDouble() / totalOut * 100.0) else 0.0
        val blindPct = if (totalOut > 0) (blindCount.toDouble() / totalOut * 100.0) else 0.0
        val decoyPct = if (totalOut > 0) (decoyCount.toDouble() / totalOut * 100.0) else 0.0
        val tombPct = if (totalOut > 0) (tombCount.toDouble() / totalOut * 100.0) else 0.0

        // Target Prefix Shannon Entropy
        val totalPrefixes = totalTargetPrefixSamples.get()
        var entropyBits = 0.0
        if (totalPrefixes > 0) {
            for (i in 0 until 256) {
                val c = targetPrefixByteCounts.get(i)
                if (c > 0) {
                    val p = c.toDouble() / totalPrefixes
                    entropyBits -= p * (kotlin.math.ln(p) / kotlin.math.ln(2.0))
                }
            }
        }
        val entropyNormalized = (entropyBits / 8.0) * 100.0

        if (count == 0) {
            return TrafficShapingStats(
                sampleCount = 0,
                meanInterPacketMs = 0.0,
                varianceInterPacketMs = 0.0,
                coefficientOfVariation = 0.0,
                kolmogorovSmirnovD = 0.0,
                realMsgCount = realCount,
                coverDummyCount = dummyCount,
                blindRepublishCount = blindCount,
                decoyGetCount = decoyCount,
                tombstoneCount = tombCount,
                totalOutboundPackets = totalOut,
                realMsgPercent = realPct,
                coverDummyPercent = dummyPct,
                blindRepublishPercent = blindPct,
                decoyGetPercent = decoyPct,
                tombstonePercent = tombPct,
                targetEntropyBits = entropyBits,
                targetEntropyNormalized = entropyNormalized
            )
        }

        val meanMs = intervals.average()
        val varianceMs = if (count > 1) {
            intervals.map { (it - meanMs) * (it - meanMs) }.sum() / (count - 1)
        } else 0.0
        val stdDevMs = kotlin.math.sqrt(varianceMs)
        val cv = if (meanMs > 0.0) (stdDevMs / meanMs) else 0.0

        // Kolmogorov-Smirnov test against exponential distribution F(x) = 1 - exp(-lambda * x)
        val ksD = if (count >= 2 && meanMs > 0.0) {
            val meanSec = meanMs / 1000.0
            val lambdaHat = 1.0 / meanSec
            val sortedSec = intervals.map { it / 1000.0 }.sorted()
            var maxD = 0.0
            for (i in 0 until count) {
                val x = sortedSec[i]
                val fTheo = 1.0 - kotlin.math.exp(-lambdaHat * x)
                val fnUpper = (i + 1).toDouble() / count
                val fnLower = i.toDouble() / count
                val dPlus = kotlin.math.abs(fnUpper - fTheo)
                val dMinus = kotlin.math.abs(fTheo - fnLower)
                maxD = maxOf(maxD, dPlus, dMinus)
            }
            maxD
        } else 0.0

        return TrafficShapingStats(
            sampleCount = count,
            meanInterPacketMs = meanMs,
            varianceInterPacketMs = varianceMs,
            coefficientOfVariation = cv,
            kolmogorovSmirnovD = ksD,
            realMsgCount = realCount,
            coverDummyCount = dummyCount,
            blindRepublishCount = blindCount,
            decoyGetCount = decoyCount,
            tombstoneCount = tombCount,
            totalOutboundPackets = totalOut,
            realMsgPercent = realPct,
            coverDummyPercent = dummyPct,
            blindRepublishPercent = blindPct,
            decoyGetPercent = decoyPct,
            tombstonePercent = tombPct,
            targetEntropyBits = entropyBits,
            targetEntropyNormalized = entropyNormalized
        )
    }

    fun computeNetworkRttStats(): List<NetworkTypeRttStats> {
        val result = mutableListOf<NetworkTypeRttStats>()
        for ((netType, queue) in networkRttMap) {
            val samples = queue.toList().sorted()
            if (samples.isEmpty()) continue
            val count = samples.size
            val min = samples.first()
            val max = samples.last()
            val avg = samples.average()
            val p50 = samples[(count * 0.50).toInt().coerceAtMost(count - 1)]
            val p90 = samples[(count * 0.90).toInt().coerceAtMost(count - 1)]
            val p99 = samples[(count * 0.99).toInt().coerceAtMost(count - 1)]
            result.add(
                NetworkTypeRttStats(
                    networkType = netType,
                    sampleCount = count,
                    minMs = min,
                    maxMs = max,
                    avgMs = avg,
                    p50Ms = p50,
                    p90Ms = p90,
                    p99Ms = p99
                )
            )
        }
        return result
    }

    fun computeChunkResumptionStats(): ChunkResumptionStats {
        val total = chunkTransfersTotal.get()
        val resumed = chunkTransfersResumed.get()
        val success = chunkTransfersSuccessful.get()
        val rate = if (resumed > 0) (success.toDouble() / resumed * 100.0) else 0.0
        return ChunkResumptionStats(
            totalTransfers = total,
            resumedTransfers = resumed,
            successfulResumptions = success,
            resumptionSuccessRate = rate
        )
    }

    fun computeGroupChatStats(): GroupChatResearchStats {
        val latencyMap = mutableMapOf<String, Double>()
        for ((size, latencies) in groupLatencyBySize) {
            val list = latencies.toList()
            if (list.isNotEmpty()) {
                latencyMap["size_$size"] = list.average()
            }
        }
        val skews = groupDeliverySkews.toList()
        val avgSkew = if (skews.isNotEmpty()) skews.average() else 0.0
        val maxSkew = if (skews.isNotEmpty()) skews.maxOrNull() ?: 0L else 0L

        val rekeys = keyRotationConvergenceList.toList()
        val avgRekey = if (rekeys.isNotEmpty()) rekeys.average() else 0.0

        return GroupChatResearchStats(
            latencyByGroupSize = latencyMap,
            avgFanOutDeliverySkewMs = avgSkew,
            maxFanOutDeliverySkewMs = maxSkew,
            avgKeyRotationConvergenceMs = avgRekey,
            totalGroupMessagesTracked = totalGroupMessagesTracked.get(),
            totalKeyRotationsTracked = totalKeyRotationsTracked.get()
        )
    }

    fun computeRetentionCurveStats(): List<RetentionSurvivalPoint> {
        val samples = ttlSamplesHistory.toList()
        val horizons = listOf(
            Pair("5m", 5.0 / 60.0),
            Pair("1h", 1.0),
            Pair("2h", 2.0),
            Pair("6h", 6.0),
            Pair("12h", 12.0),
            Pair("24h", 24.0),
            Pair("48h", 48.0)
        )
        val result = mutableListOf<RetentionSurvivalPoint>()
        for ((label, targetHours) in horizons) {
            for (republish in listOf(false, true)) {
                val matching = samples.filter { sample ->
                    sample.republishActive == republish &&
                    kotlin.math.abs(sample.elapsedHours - targetHours) <= (targetHours * 0.40).coerceAtLeast(0.05)
                }
                val total = matching.size
                val alive = matching.count { it.isAlive }
                val rate = if (total > 0) (alive.toDouble() / total * 100.0) else 0.0
                result.add(
                    RetentionSurvivalPoint(
                        horizonLabel = label,
                        horizonHours = targetHours,
                        totalSamples = total,
                        aliveSamples = alive,
                        survivalRatePercent = rate,
                        republishActive = republish
                    )
                )
            }
        }
        return result
    }

    fun computeEd25519SignatureStats(): Map<String, Any> {
        val queries = totalEd25519Queries.get()
        val nodesQueried = totalEd25519NodesQueried.get()
        val nodesValid = totalEd25519NodesValid.get()
        val ratio = if (nodesQueried > 0) (nodesValid.toDouble() / nodesQueried * 100.0) else 0.0
        return mapOf(
            "totalQueries" to queries,
            "totalNodesQueried" to nodesQueried,
            "totalNodesValid" to nodesValid,
            "validSignatureRatioPercent" to ratio
        )
    }

    fun computeRttStats(): Map<String, Any> {
        val rtts = rttSamples.toList().sorted()
        if (rtts.isEmpty()) {
            return mapOf(
                "count" to 0,
                "minMs" to 0L,
                "maxMs" to 0L,
                "avgMs" to 0.0,
                "p50Ms" to 0L,
                "p90Ms" to 0L,
                "p99Ms" to 0L
            )
        }
        val count = rtts.size
        val min = rtts.first()
        val max = rtts.last()
        val avg = rtts.average()
        val p50 = rtts[(count * 0.50).toInt().coerceAtMost(count - 1)]
        val p90 = rtts[(count * 0.90).toInt().coerceAtMost(count - 1)]
        val p99 = rtts[(count * 0.99).toInt().coerceAtMost(count - 1)]
        return mapOf(
            "count" to count,
            "minMs" to min,
            "maxMs" to max,
            "avgMs" to avg,
            "p50Ms" to p50,
            "p90Ms" to p90,
            "p99Ms" to p99
        )
    }

    fun computeTtlStats(): Map<String, Any> {
        val alive = aliveTtlCount.get()
        val expired = expiredTtlCount.get()
        val total = alive + expired
        val rate = if (total > 0) (alive.toDouble() / total * 100.0) else 0.0
        return mapOf(
            "totalSamples" to total,
            "aliveCount" to alive,
            "expiredCount" to expired,
            "survivalRatePercent" to rate
        )
    }

    fun computeRepublishStats(): Map<String, Any> {
        val delivered = deliveredAckCount.get()
        val firstSends = firstSendCount.value
        val rate = if (firstSends > 0) (delivered.toDouble() / firstSends * 100.0).coerceAtMost(100.0) else 0.0
        val avgLatency = if (delivered > 0) (totalDeliveredLatencyMs.get().toDouble() / delivered) else 0.0
        return mapOf(
            "trackedMessages" to firstSends,
            "deliveredCount" to delivered,
            "deliveryRatePercent" to rate,
            "avgLatencyMs" to avgLatency,
            "ownRepublishes" to ownRepublishCount.value,
            "crowdRelays" to crowdRepublishCount.value
        )
    }

    fun computeResourceStats(): Map<String, Any> {
        val profiler = resourceProfiler ?: return emptyMap()
        val samples = profiler.samples
        if (samples.isEmpty()) return emptyMap()
        val avgBatteryCurrentUa = samples.map { it.batteryCurrentNowUa }.average()
        val firstSample = samples.first()
        val lastSample = samples.last()
        val batteryDrop = (firstSample.batteryLevelPercent - lastSample.batteryLevelPercent).coerceAtLeast(0)
        val maxWakeLockMs = samples.maxOfOrNull { it.wakeLockDurationMs } ?: 0L
        val totalDhtBytesSent = (lastSample.dhtBytesSent - firstSample.dhtBytesSent).coerceAtLeast(0L)
        val totalDhtBytesReceived = (lastSample.dhtBytesReceived - firstSample.dhtBytesReceived).coerceAtLeast(0L)
        return mapOf(
            "samplesCount" to samples.size,
            "avgBatteryCurrentUa" to avgBatteryCurrentUa,
            "batteryDropPercent" to batteryDrop,
            "maxWakeLockDurationMs" to maxWakeLockMs,
            "dhtBytesSent" to totalDhtBytesSent,
            "dhtBytesReceived" to totalDhtBytesReceived
        )
    }

    /**
     * Prepares device metadata and aggregated metrics conforming to `firestore.rules`.
     * If the bundle size is <= 600 KB, embeds the complete raw CSV bundle as Base64 in `metrics`.
     */
    fun computeSessionPayload(): Pair<Map<String, Any>, Map<String, Any>> {
        val manifest = generateManifestData()
        val zipFile = buildCompressedResearchBundle()

        val bundleBase64: String
        val bundleStatus: String
        val zipSize = zipFile.length()

        if (zipSize in 1..600_000) {
            val bytes = zipFile.readBytes()
            bundleBase64 = Base64.getEncoder().encodeToString(bytes)
            bundleStatus = "EMBEDDED_ZIP_BASE64"
        } else if (zipSize > 600_000) {
            bundleBase64 = "OMITTED_EXCEEDS_600KB"
            bundleStatus = "Available via local device export (.ZIP) to preserve Firestore 1MB limit"
        } else {
            bundleBase64 = ""
            bundleStatus = "EMPTY"
        }

        val deviceInfo: Map<String, Any> = mapOf(
            "sessionId" to sessionId,
            "deviceModel" to manifest.deviceModel,
            "androidVersion" to manifest.androidVersion,
            "appVersion" to manifest.appVersion,
            "versionCode" to manifest.versionCode
        )

        val metrics: Map<String, Any> = mapOf(
            "totalEvents" to manifest.totalEvents,
            "firstSendCount" to manifest.firstSendCount,
            "ownRepublishCount" to manifest.ownRepublishCount,
            "crowdRepublishCount" to manifest.crowdRepublishCount,
            "packetsReceivedCount" to manifest.packetsReceivedCount,
            "ttlSamplesCount" to manifest.ttlSamplesCount,
            "rttStats" to computeRttStats(),
            "ttlStats" to computeTtlStats(),
            "republishStats" to computeRepublishStats(),
            "resourceStats" to computeResourceStats(),
            "trafficShapingStats" to computeTrafficShapingStats().toMap(),
            "networkRttStats" to computeNetworkRttStats().map { it.toMap() },
            "chunkResumptionStats" to computeChunkResumptionStats().toMap(),
            "groupChatStats" to computeGroupChatStats().toMap(),
            "retentionCurveStats" to computeRetentionCurveStats().map { it.toMap() },
            "ed25519SignatureStats" to computeEd25519SignatureStats(),
            "fileChecksums" to manifest.fileChecksums,
            "manifestSha256" to manifest.manifestSha256,
            "bundleZipSizeBytes" to zipSize,
            "bundleZipStatus" to bundleStatus,
            "bundleZipBase64" to bundleBase64
        )

        return Pair(deviceInfo, metrics)
    }

    /**
     * Generates SessionManifest containing device specs, counters, and SHA-256 hashes of all CSV files.
     */
    fun generateManifestData(): SessionManifest {
        val checksums = mutableMapOf<String, String>()
        if (masterCsvFile.exists() && masterCsvFile.length() > 0) checksums[masterCsvFile.name] = computeSha256(masterCsvFile)
        if (ttlSamplesCsvFile.exists() && ttlSamplesCsvFile.length() > 0) checksums[ttlSamplesCsvFile.name] = computeSha256(ttlSamplesCsvFile)
        if (republishSummaryCsvFile.exists() && republishSummaryCsvFile.length() > 0) checksums[republishSummaryCsvFile.name] = computeSha256(republishSummaryCsvFile)
        if (resourceProfileCsvFile.exists() && resourceProfileCsvFile.length() > 0) checksums[resourceProfileCsvFile.name] = computeSha256(resourceProfileCsvFile)
        if (packetEventsCsvFile.exists() && packetEventsCsvFile.length() > 0) checksums[packetEventsCsvFile.name] = computeSha256(packetEventsCsvFile)
        if (groupEventsCsvFile.exists() && groupEventsCsvFile.length() > 0) checksums[groupEventsCsvFile.name] = computeSha256(groupEventsCsvFile)

        val now = System.currentTimeMillis()
        val manifest = SessionManifest(
            sessionId = sessionId,
            appVersion = try { BuildConfig.VERSION_NAME } catch (_: Throwable) { "1.0.0" },
            versionCode = try { BuildConfig.VERSION_CODE } catch (_: Throwable) { 1 },
            deviceModel = Build.MODEL ?: "GenericAndroid",
            androidVersion = Build.VERSION.SDK_INT,
            createdEpochMs = now,
            isoCreatedAt = formatEpochIso(now),
            totalEvents = eventsCount.value,
            firstSendCount = firstSendCount.value,
            ownRepublishCount = ownRepublishCount.value,
            crowdRepublishCount = crowdRepublishCount.value,
            packetsReceivedCount = packetsReceivedCount.value,
            ttlSamplesCount = ttlSamplesCount.value,
            fileChecksums = checksums
        )
        manifest.manifestSha256 = computeSha256(manifest.toJsonString())
        return manifest
    }

    /**
     * Packs all primary CSV files (master, ttl_samples, republish_analysis, resource_profile, packet_events, group_events)
     * and session_manifest.json into a compressed ZIP archive.
     */
    fun buildCompressedResearchBundle(): File {
        val dir = telemetryDir

        // 1. Export latest resource profiling samples
        try {
            resourceProfiler?.exportToCsvFile(dir, "research_resource_profile.csv")
        } catch (_: Exception) {}

        // Ensure headers exist
        initCsvFiles()

        // 2. Generate and write session_manifest.json
        val manifest = generateManifestData()
        val manifestFile = File(dir, "session_manifest.json")
        manifestFile.writeText(manifest.toJsonString(), Charsets.UTF_8)

        // 3. Create compressed ZIP archive
        val timestamp = System.currentTimeMillis()
        val zipFile = File(dir, "pqchat_research_${sessionId}_${timestamp}.zip")

        val filesToZip = listOf(
            masterCsvFile,
            ttlSamplesCsvFile,
            republishSummaryCsvFile,
            resourceProfileCsvFile,
            packetEventsCsvFile,
            groupEventsCsvFile,
            manifestFile
        ).filter { it.exists() && it.length() > 0 }

        ZipOutputStream(BufferedOutputStream(FileOutputStream(zipFile))).use { zos ->
            for (file in filesToZip) {
                val entry = ZipEntry(file.name)
                zos.putNextEntry(entry)
                file.inputStream().use { it.copyTo(zos) }
                zos.closeEntry()
            }
        }

        return zipFile
    }

    /**
     * Creates an Android Intent to share the generated research CSV with external apps (Drive, Gmail, USB, etc.).
     */
    fun createShareCsvIntent(context: Context): Intent? {
        val file = masterCsvFile
        if (!file.exists() || file.length() == 0L) return null

        val uri = try {
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        } catch (_: Exception) {
            Uri.fromFile(file)
        }

        return Intent(Intent.ACTION_SEND).apply {
            type = "text/csv"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "PQChat Research Telemetry Master CSV ($sessionId)")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }

    /**
     * Creates an Android Intent to share the full compressed ZIP bundle (.zip) with external apps
     * (Google Drive, PC, messaging, email) without requiring Firebase.
     */
    fun createShareZipIntent(context: Context): Intent? {
        val zipFile = try {
            buildCompressedResearchBundle()
        } catch (_: Exception) {
            null
        } ?: return null

        if (!zipFile.exists() || zipFile.length() == 0L) return null

        val uri = try {
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", zipFile)
        } catch (_: Exception) {
            Uri.fromFile(zipFile)
        }

        return Intent(Intent.ACTION_SEND).apply {
            type = "application/zip"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "PQChat Research Telemetry Bundle ($sessionId)")
            putExtra(Intent.EXTRA_TEXT, "Paczka badawcza PQChat DHT (sesja: $sessionId)")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }

    /**
     * Manually triggers an immediate batch synchronization to Google Cloud Firestore (Firebase Spark free tier).
     */
    suspend fun forceFirebaseSync(): Boolean = withContext(Dispatchers.IO) {
        if (!firebaseSync.isFirebaseConfigured()) return@withContext false
        val (deviceInfo, metrics) = computeSessionPayload()
        firebaseSync.syncResearchSession(sessionId, deviceInfo, metrics, isManual = true)
    }

    fun stop() {
        scope.cancel()
        ttlSampler?.stop()
        firebaseSync.stop()
    }
}
