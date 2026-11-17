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
    customTtlSampler: HistoricalTtlSampler? = null,
    private val maxCsvFileBytes: Long = DEFAULT_MAX_CSV_FILE_BYTES,
    private val maxChunkZipBytes: Long = DEFAULT_MAX_CHUNK_ZIP_BYTES,
    private val clockProvider: () -> Long = { System.currentTimeMillis() }
) {
    companion object {
        const val DEFAULT_MAX_CSV_FILE_BYTES = 1_500_000L
        const val DEFAULT_MAX_CHUNK_ZIP_BYTES = 550_000L

        private val STUDENT_T_95_TABLE = doubleArrayOf(
            12.7062, 4.3027, 3.1824, 2.7764, 2.5706, 2.4469, 2.3646, 2.3060, 2.2622, 2.2281,
            2.2010, 2.1788, 2.1604, 2.1448, 2.1314, 2.1199, 2.1098, 2.1009, 2.0930, 2.0860,
            2.0796, 2.0739, 2.0687, 2.0639, 2.0595, 2.0555, 2.0518, 2.0484, 2.0452, 2.0423
        )

        fun studentTCritical95(degreesOfFreedom: Int): Double {
            if (degreesOfFreedom <= 0) return 1.959964
            if (degreesOfFreedom <= STUDENT_T_95_TABLE.size) return STUDENT_T_95_TABLE[degreesOfFreedom - 1]
            return 1.959964
        }
    }

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
    private val directDeliveredWithoutTrackerCount = AtomicInteger(0)
    private val totalDeliveredLatencyMs = AtomicLong(0L)

    // Traffic shaping & anonymity tracking
    private val lastOutboundPacketTimestampMs = AtomicLong(0L)
    private val outboundIntervalsMs = ConcurrentLinkedQueue<Long>()
    private val configuredLambdaSamples = ConcurrentLinkedQueue<Double>()
    private val realMsgCount = AtomicInteger(0)
    private val coverDummyCount = AtomicInteger(0)
    private val blindRepublishCount = AtomicInteger(0)
    private val decoyGetCount = AtomicInteger(0)
    private val tombstoneCount = AtomicInteger(0)
    private val totalOutboundPackets = AtomicInteger(0)

    // Target ID prefix frequency distribution for Shannon entropy (256 bins for byte 0 + 16 hex nibble bins)
    private val targetPrefixByteCounts = java.util.concurrent.atomic.AtomicIntegerArray(256)
    private val totalTargetPrefixSamples = AtomicInteger(0)
    private val targetNibbleCounts = java.util.concurrent.atomic.AtomicIntegerArray(16)
    private val totalTargetNibbleSamples = AtomicInteger(0)
    private val uniqueTargetPrefixes = ConcurrentHashMap.newKeySet<String>()

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

    // Group chat & masking metrics
    private data class GroupMaskingRecord(
        val groupSizeM: Int,
        val uniqueTargetCount: Int,
        val interleavedCoverCount: Int,
        val fanOutSkewMs: Long,
        val decorrelationScore: Double,
        val coverPaddingRatio: Double,
        val maskingCoefficient: Double
    )

    private val groupLatencyBySize = ConcurrentHashMap<Int, ConcurrentLinkedQueue<Long>>()
    private val groupDeliverySkews = ConcurrentLinkedQueue<Long>()
    private val groupMaskingRecords = ConcurrentLinkedQueue<GroupMaskingRecord>()
    private val keyRotationConvergenceList = ConcurrentLinkedQueue<Long>()
    private val totalGroupMessagesTracked = AtomicInteger(0)
    private val totalKeyRotationsTracked = AtomicInteger(0)

    // Historical retention samples cache for survival curves
    private val ttlSamplesHistory = ConcurrentLinkedQueue<TtlSampleEvent>()

    // Hardware battery current samples fallback when AndroidResourceProfiler has < 2 snapshots
    private val packetBatteryCurrentSamples = ConcurrentLinkedQueue<Pair<Long, Long>>()

    // Adversarial & Anomaly Counters
    private val badEd25519SigCount = AtomicInteger(0)
    private val badAeadTagCount = AtomicInteger(0)
    private val seqRollbackCount = AtomicInteger(0)
    private val slidingWindowDuplicateCount = AtomicInteger(0)
    private val blockedTorColdStartLeaksCount = AtomicInteger(0)
    private val otherAnomalyCount = AtomicInteger(0)

    // Traffic interval scheduling and wake-up jitter
    private val theoreticalDelaysMs = ConcurrentLinkedQueue<Long>()
    private val actualTrafficDelaysMs = ConcurrentLinkedQueue<Long>()
    private val wakeUpJittersMs = ConcurrentLinkedQueue<Long>()
    private val packetRoleCounts = ConcurrentHashMap<String, AtomicInteger>()

    // DHT Retention & Kademlia Convergence
    private val putLatencySamples = ConcurrentLinkedQueue<Long>()
    private val getLatencySamples = ConcurrentLinkedQueue<Long>()
    private val queriedNodesList = ConcurrentLinkedQueue<Int>()
    private val totalKrpcTimeouts = AtomicInteger(0)
    private val totalDhtOps = AtomicInteger(0)
    private val totalPreWarmingHits = AtomicInteger(0)
    private val totalPreWarmingAttempts = AtomicInteger(0)
    private val totalFastTerminatedOps = AtomicInteger(0)
    private val subnet24Counts = ConcurrentHashMap<String, AtomicInteger>()
    private val totalSubnetSamples = AtomicInteger(0)

    // End-to-End Delivery & Rekeying
    private val deliveryLatencyByLifecycleMap = ConcurrentHashMap<String, ConcurrentLinkedQueue<Long>>()
    private val deliveryLatencyByTransportMap = ConcurrentHashMap<String, ConcurrentLinkedQueue<Long>>()
    private val coverAckLatencyByLifecycleMap = ConcurrentHashMap<String, ConcurrentLinkedQueue<Long>>()
    private val pqcRekeyDurationsMs = ConcurrentLinkedQueue<Long>()
    private val groupRotationDurationsMs = ConcurrentLinkedQueue<Long>()

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
    val trafficIntervalsCsvFile: File by lazy { File(telemetryDir, "research_traffic_intervals.csv") }
    val kademliaConvergenceCsvFile: File by lazy { File(telemetryDir, "research_kademlia_convergence.csv") }
    val adversarialEventsCsvFile: File by lazy { File(telemetryDir, "research_adversarial_events.csv") }

    private val csvLock = Any()
    private val csvRotationSequence = AtomicInteger(0)

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
                        val payloads = computeChunkedSessionPayloads()
                        firebaseSync.syncResearchSessionChunks(sessionId, payloads, isManual = false)
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
            if (!trafficIntervalsCsvFile.exists()) {
                trafficIntervalsCsvFile.writeText(TrafficIntervalEvent.CSV_HEADER + "\n")
            }
            if (!kademliaConvergenceCsvFile.exists()) {
                kademliaConvergenceCsvFile.writeText(DhtConvergenceEvent.CSV_HEADER + "\n")
            }
            if (!adversarialEventsCsvFile.exists()) {
                adversarialEventsCsvFile.writeText(AdversarialTelemetryEvent.CSV_HEADER + "\n")
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
        errorCode: String? = null,
        timestampEpochMs: Long = clockProvider()
    ) {
        if (!isEnabled) return

        val targetPrefix = CryptoUtils.toHex(target).take(8)
        val now = timestampEpochMs

        if (rttMs > 0L && rttSamples.size < 2000) {
            rttSamples.add(rttMs)
        }

        val resolvedNetworkType = networkType ?: detectCurrentNetworkType()
        val resolvedPollingState = pollingState ?: (resourceProfiler?.getPollingState() ?: "UNKNOWN")
        val resolvedReplicationK = replicationK ?: (dhtClient?.replicationK ?: 8)
        val resolvedPoissonLambda = poissonLambda ?: (resourceProfiler?.getPoissonLambda() ?: (1.0 / 480.0))
        val resolvedBatteryCurrentUa = batteryCurrentUa ?: (resourceProfiler?.queryBatteryCurrentNowUa() ?: 0L)
        val resolvedBatteryLevelPct = batteryLevelPct ?: (resourceProfiler?.queryBatteryLevelPercent() ?: 100)

        if (resolvedPoissonLambda > 0.0 && configuredLambdaSamples.size < 5000) {
            configuredLambdaSamples.add(resolvedPoissonLambda)
        }
        if (resolvedBatteryCurrentUa != 0L && packetBatteryCurrentSamples.size < 5000) {
            packetBatteryCurrentSamples.add(now to resolvedBatteryCurrentUa)
        }

        // Track distribution of all observed packet roles
        packetRoleCounts.computeIfAbsent(role.name) { AtomicInteger(0) }.incrementAndGet()

        // 1. Traffic Shaping & Anonymity Efficacy Tracking
        val isOutbound = role in setOf(
            PacketRole.FIRST_SEND,
            PacketRole.GROUP_FAN_OUT,
            PacketRole.OWN_REPUBLISH,
            PacketRole.CROWD_REPUBLISH,
            PacketRole.TOMBSTONE_SENT,
            PacketRole.COVER_ACK_SENT,
            PacketRole.COVER_DUMMY_SENT,
            PacketRole.POLL_BATCH_REAL,
            PacketRole.POLL_BATCH_DECOY,
            PacketRole.DECOY_GET
        )

        if (isOutbound) {
            totalOutboundPackets.incrementAndGet()
            when (role) {
                PacketRole.FIRST_SEND, PacketRole.GROUP_FAN_OUT, PacketRole.POLL_BATCH_REAL -> realMsgCount.incrementAndGet()
                PacketRole.COVER_DUMMY_SENT -> coverDummyCount.incrementAndGet()
                PacketRole.CROWD_REPUBLISH -> blindRepublishCount.incrementAndGet()
                PacketRole.DECOY_GET, PacketRole.POLL_BATCH_DECOY -> decoyGetCount.incrementAndGet()
                PacketRole.TOMBSTONE_SENT -> tombstoneCount.incrementAndGet()
                else -> {}
            }
            val prevOutbound = lastOutboundPacketTimestampMs.getAndSet(now)
            if (prevOutbound > 0L && now >= prevOutbound) {
                val interval = now - prevOutbound
                if (outboundIntervalsMs.size < 10_000) {
                    outboundIntervalsMs.add(interval)
                }
            }
        }

        // 2. Shannon Entropy of Target Prefixes (256 bins for byte 0 + 16 hex nibble bins)
        if (target.isNotEmpty()) {
            val firstByte = target[0].toInt() and 0xFF
            targetPrefixByteCounts.incrementAndGet(firstByte)
            totalTargetPrefixSamples.incrementAndGet()
            if (uniqueTargetPrefixes.size < 50_000) {
                uniqueTargetPrefixes.add(targetPrefix)
            }
            for (ch in targetPrefix) {
                val nibble = ch.digitToIntOrNull(16)
                if (nibble != null) {
                    targetNibbleCounts.incrementAndGet(nibble)
                    totalTargetNibbleSamples.incrementAndGet()
                }
            }
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
                ttlSampler?.trackPacket(
                    target = target,
                    initialPutEpochMs = now,
                    republishActive = true,
                    republishMode = RepublishMode.OWN_REPUBLISH
                )
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
                val tracker = inFlightRepublishes[targetPrefix]
                if (tracker != null) {
                    tracker.crowdRelayed = true
                } else {
                    ttlSampler?.trackPacket(
                        target = target,
                        initialPutEpochMs = now,
                        republishActive = true,
                        republishMode = RepublishMode.CROWD_REPUBLISH
                    )
                }
            }
            PacketRole.PACKET_RECEIVED -> {
                _packetsReceivedCount.value += 1
            }
            else -> {}
        }

        // Append to local CSV files immediately with automatic rotation
        appendCsvRow(packetEventsCsvFile, PacketTelemetryEvent.CSV_HEADER, event.toCsvRow(), alsoMaster = true, masterRow = event.toMasterCsvRow())
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
     * Records group chat message fan-out delivery latency, skew, and recipient masking properties.
     */
    fun recordGroupMessageDelivery(
        groupId: ByteArray,
        groupSizeM: Int,
        latencyMs: Long,
        fanOutSkewMs: Long = 0L,
        epoch: Long = 1L,
        uniqueTargetCount: Int = groupSizeM,
        interleavedCoverCount: Int = 0
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
            timestampEpochMs = clockProvider(),
            eventType = if (fanOutSkewMs > 0L) "FAN_OUT_SKEW" else "BROADCAST",
            groupIdPrefix = prefix,
            groupSizeM = groupSizeM,
            latencyMs = latencyMs,
            fanOutSkewMs = fanOutSkewMs,
            epoch = epoch,
            uniqueTargetCount = uniqueTargetCount,
            interleavedCoverCount = interleavedCoverCount
        )
        val decorrelation = event.targetDecorrelationRatio
        val coverRatio = event.coverPaddingRatio
        val temporalDispersion = if (groupSizeM <= 1) {
            1.0
        } else {
            1.0 - kotlin.math.exp(-fanOutSkewMs.coerceAtLeast(0L).toDouble() / 1000.0)
        }
        val burstMasking = maxOf(coverRatio, temporalDispersion)
        val maskingCoeff = (decorrelation * (0.5 + 0.5 * burstMasking)).coerceIn(0.0, 1.0)
        if (groupMaskingRecords.size < 5000) {
            groupMaskingRecords.add(
                GroupMaskingRecord(
                    groupSizeM = groupSizeM,
                    uniqueTargetCount = uniqueTargetCount,
                    interleavedCoverCount = interleavedCoverCount,
                    fanOutSkewMs = fanOutSkewMs,
                    decorrelationScore = decorrelation,
                    coverPaddingRatio = coverRatio,
                    maskingCoefficient = maskingCoeff
                )
            )
        }
        appendCsvRow(groupEventsCsvFile, GroupTelemetryEvent.CSV_HEADER, event.toCsvRow(), alsoMaster = true, masterRow = event.toMasterCsvRow())
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
            timestampEpochMs = clockProvider(),
            eventType = "KEY_ROTATION",
            groupIdPrefix = prefix,
            groupSizeM = groupSizeM,
            latencyMs = convergenceMs,
            keyRotationConvergenceMs = convergenceMs,
            epoch = epoch
        )
        appendCsvRow(groupEventsCsvFile, GroupTelemetryEvent.CSV_HEADER, event.toCsvRow(), alsoMaster = true, masterRow = event.toMasterCsvRow())
    }

    /**
     * Records delivery ACK confirmation for a previously sent message.
     */
    fun recordDeliveryAck(
        target: ByteArray,
        deliveredEpochMs: Long = clockProvider()
    ) {
        recordDeliveryAckInternal(target, deliveredEpochMs)
    }

    private fun recordDeliveryAckInternal(
        target: ByteArray,
        deliveredEpochMs: Long = clockProvider()
    ): Boolean {
        if (!isEnabled) return false
        val prefix = CryptoUtils.toHex(target).take(8)
        val tracker = inFlightRepublishes.remove(prefix) ?: return false

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

        appendCsvRow(republishSummaryCsvFile, RepublishAnalysisSummary.CSV_HEADER, summary.toCsvRow(), alsoMaster = true, masterRow = summary.toMasterCsvRow())
        return true
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
        if (ttlSamplesHistory.size < 10_000) {
            ttlSamplesHistory.add(enriched)
        }
        appendCsvRow(ttlSamplesCsvFile, TtlSampleEvent.CSV_HEADER, enriched.toCsvRow(), alsoMaster = true, masterRow = enriched.toMasterCsvRow())
    }

    private fun recordTtlSampleInternal(sample: TtlSampleEvent) {
        recordTtlSample(sample)
    }

    /**
     * Records scheduled vs actual Poisson interval and wake-up jitter.
     */
    fun recordTrafficInterval(
        role: PacketRole,
        scheduledDelayMs: Long,
        actualDelayMs: Long,
        wakeUpJitterMs: Long,
        poissonLambda: Double,
        pollingState: String = resourceProfiler?.getPollingState() ?: "UNKNOWN",
        isScreenOn: Boolean = true
    ) {
        if (!isEnabled) return
        theoreticalDelaysMs.add(scheduledDelayMs)
        if (actualDelayMs >= 0L && actualTrafficDelaysMs.size < 10_000) {
            actualTrafficDelaysMs.add(actualDelayMs)
        }
        if (poissonLambda > 0.0 && configuredLambdaSamples.size < 5000) {
            configuredLambdaSamples.add(poissonLambda)
        }
        wakeUpJittersMs.add(wakeUpJitterMs)
        val event = TrafficIntervalEvent(
            sessionId = sessionId,
            timestampEpochMs = clockProvider(),
            role = role,
            scheduledDelayMs = scheduledDelayMs,
            actualDelayMs = actualDelayMs,
            wakeUpJitterMs = wakeUpJitterMs,
            poissonLambda = poissonLambda,
            pollingState = pollingState,
            isScreenOn = isScreenOn
        )
        appendCsvRow(trafficIntervalsCsvFile, TrafficIntervalEvent.CSV_HEADER, event.toCsvRow())
    }

    /**
     * Records Kademlia routing convergence, replica counts, timeouts and subnet diversity.
     */
    fun recordDhtConvergence(
        operation: String,
        target: ByteArray,
        rttMs: Long,
        nodesQueried: Int,
        nodesResponded: Int,
        timeouts: Int,
        preWarmingHit: Boolean = false,
        fastTerminated: Boolean = false,
        subnets24: List<String> = emptyList()
    ) {
        if (!isEnabled) return
        val targetPrefix = CryptoUtils.toHex(target).take(8)
        if (operation.equals("PUT", ignoreCase = true)) {
            if (rttMs > 0L) putLatencySamples.add(rttMs)
        } else {
            if (rttMs > 0L) getLatencySamples.add(rttMs)
        }
        if (nodesQueried > 0) {
            queriedNodesList.add(nodesQueried)
        }
        totalKrpcTimeouts.addAndGet(timeouts)
        totalDhtOps.incrementAndGet()
        if (preWarmingHit) totalPreWarmingHits.incrementAndGet()
        totalPreWarmingAttempts.incrementAndGet()
        if (fastTerminated) totalFastTerminatedOps.incrementAndGet()

        for (subnet in subnets24) {
            if (subnet.isNotBlank()) {
                subnet24Counts.computeIfAbsent(subnet) { AtomicInteger(0) }.incrementAndGet()
                totalSubnetSamples.incrementAndGet()
            }
        }

        val event = DhtConvergenceEvent(
            sessionId = sessionId,
            timestampEpochMs = clockProvider(),
            operation = operation,
            targetPrefix = targetPrefix,
            rttMs = rttMs,
            nodesQueried = nodesQueried,
            nodesResponded = nodesResponded,
            timeouts = timeouts,
            preWarmingHit = preWarmingHit,
            fastTerminated = fastTerminated,
            uniqueSubnets24Count = subnets24.distinct().size
        )
        appendCsvRow(kademliaConvergenceCsvFile, DhtConvergenceEvent.CSV_HEADER, event.toCsvRow())
    }

    /**
     * Records message delivery latency partitioned by lifecycle and network transport.
     */
    fun recordMessageDelivered(
        target: ByteArray,
        latencyMs: Long,
        lifecycleState: String = resourceProfiler?.getPollingState() ?: "UNKNOWN",
        networkType: String = detectCurrentNetworkType()
    ) {
        if (!isEnabled) return
        deliveryLatencyByLifecycleMap.computeIfAbsent(lifecycleState) { ConcurrentLinkedQueue() }.add(latencyMs)
        deliveryLatencyByTransportMap.computeIfAbsent(networkType) { ConcurrentLinkedQueue() }.add(latencyMs)
        if (!recordDeliveryAckInternal(target)) {
            directDeliveredWithoutTrackerCount.incrementAndGet()
        }
    }

    /**
     * Records Cover ACK latency partitioned by lifecycle state.
     */
    fun recordCoverAckReceived(
        target: ByteArray,
        latencyMs: Long,
        lifecycleState: String = resourceProfiler?.getPollingState() ?: "UNKNOWN"
    ) {
        if (!isEnabled) return
        coverAckLatencyByLifecycleMap.computeIfAbsent(lifecycleState) { ConcurrentLinkedQueue() }.add(latencyMs)
        recordPacketEvent(
            role = PacketRole.COVER_ACK_RECEIVED,
            target = target,
            rttMs = latencyMs,
            success = true
        )
    }

    /**
     * Records duration of hybrid PQC rekeying (ML-KEM-512 + X25519).
     */
    fun recordPqcRekeyDuration(durationMs: Long) {
        if (!isEnabled) return
        pqcRekeyDurationsMs.add(durationMs)
    }

    /**
     * Records duration of group key rotation.
     */
    fun recordGroupKeyRotationDuration(durationMs: Long) {
        if (!isEnabled) return
        groupRotationDurationsMs.add(durationMs)
    }

    /**
     * Records protocol violations, tampered frames, or replay attacks.
     */
    fun recordAdversarialEvent(
        anomalyType: String,
        target: ByteArray? = null,
        details: String = "",
        mitigated: Boolean = true
    ) {
        if (!isEnabled) return
        when (anomalyType.uppercase(java.util.Locale.US)) {
            "BAD_ED25519_SIG", "INVALID_SIGNATURE", "BAD_SIGNATURE" -> badEd25519SigCount.incrementAndGet()
            "BAD_AEAD_TAG", "AEAD_BAD_TAG", "INVALID_TAG" -> badAeadTagCount.incrementAndGet()
            "SEQ_ROLLBACK", "SEQUENCE_ROLLBACK", "ROLLBACK_ATTEMPT", "TOMBSTONE_SLOT_DETECTED", "TOMBSTONE_DETECTED" -> seqRollbackCount.incrementAndGet()
            "BITMAP_DUPLICATE", "SLIDING_WINDOW_DUPLICATE", "REPLAY_ATTACK", "REPLAY_ATTACK_ATTEMPT", "REPLAY_ATTEMPT" -> slidingWindowDuplicateCount.incrementAndGet()
            "BLOCKED_TOR_LEAK", "TOR_COLD_START_LEAK", "IP_LEAK_PREVENTED" -> blockedTorColdStartLeaksCount.incrementAndGet()
            else -> otherAnomalyCount.incrementAndGet()
        }
        val targetPrefix = if (target != null && target.isNotEmpty()) CryptoUtils.toHex(target).take(8) else "00000000"
        val event = AdversarialTelemetryEvent(
            sessionId = sessionId,
            timestampEpochMs = clockProvider(),
            anomalyType = anomalyType,
            targetPrefix = targetPrefix,
            details = details,
            mitigated = mitigated
        )
        appendCsvRow(adversarialEventsCsvFile, AdversarialTelemetryEvent.CSV_HEADER, event.toCsvRow())
    }

    private fun rotateCsvIfNeededLocked(file: File, header: String, incomingRowBytes: Int) {
        if (!file.exists()) {
            file.writeText(header + "\n", Charsets.UTF_8)
            return
        }
        val minHeaderSize = header.length + 2
        if (maxCsvFileBytes > minHeaderSize && file.length() > minHeaderSize &&
            file.length() + incomingRowBytes >= maxCsvFileBytes
        ) {
            val baseName = file.nameWithoutExtension
            val seq = csvRotationSequence.incrementAndGet()
            val rotatedName = String.format(java.util.Locale.US, "%s.rot_%04d_%d.csv", baseName, seq, clockProvider())
            val rotatedFile = File(telemetryDir, rotatedName)
            if (file.renameTo(rotatedFile)) {
                file.writeText(header + "\n", Charsets.UTF_8)
            }
        }
    }

    private fun appendCsvRow(
        file: File,
        header: String,
        row: String,
        alsoMaster: Boolean = false,
        masterRow: String? = null
    ) {
        synchronized(csvLock) {
            try {
                rotateCsvIfNeededLocked(file, header, row.length + 1)
                PrintWriter(FileWriter(file, true)).use { it.println(row) }
                if (alsoMaster && masterRow != null) {
                    rotateCsvIfNeededLocked(masterCsvFile, ResearchCsvSchema.MASTER_CSV_HEADER, masterRow.length + 1)
                    PrintWriter(FileWriter(masterCsvFile, true)).use { it.println(masterRow) }
                }
            } catch (_: Exception) {}
        }
    }

    fun getRotatedCsvFiles(): List<File> {
        return telemetryDir.listFiles { f ->
            f.isFile && f.name.contains(".rot_") && f.name.endsWith(".csv")
        }?.sortedBy { it.name }.orEmpty()
    }

    fun getAllTelemetryCsvFiles(): List<File> {
        val active = listOf(
            masterCsvFile,
            ttlSamplesCsvFile,
            republishSummaryCsvFile,
            resourceProfileCsvFile,
            packetEventsCsvFile,
            groupEventsCsvFile,
            trafficIntervalsCsvFile,
            kademliaConvergenceCsvFile,
            adversarialEventsCsvFile
        )
        return (active + getRotatedCsvFiles()).filter { it.exists() && it.length() > 0L }
    }

    /**
     * Asymptotic two-sided Kolmogorov-Smirnov p-value calculation.
     */
    fun computeKolmogorovSmirnovPValue(d: Double, n: Int): Double {
        if (n <= 0 || d <= 0.0) return 1.0
        val sqrtN = kotlin.math.sqrt(n.toDouble())
        val z = (sqrtN + 0.12 + 0.11 / sqrtN) * d
        if (z <= 0.0) return 1.0
        if (z >= 3.0) return 0.0
        var sum = 0.0
        for (k in 1..15) {
            val sign = if (k % 2 == 1) 1.0 else -1.0
            val term = sign * kotlin.math.exp(-2.0 * k * k * z * z)
            sum += term
        }
        val p = 2.0 * sum
        return p.coerceIn(0.0, 1.0)
    }

    /**
     * Computes empirical Kullback-Leibler divergence D_KL(P_emp || Exp(lambda)) in nats
     * using equiprobable quantile binning under the theoretical exponential distribution.
     *
     * Partitioning [0, +inf) into B equiprobable quantile bins ensures every bin has exact
     * theoretical probability q_b = 1/B under Exp(lambda), yielding D_KL >= 0 (0 for exact fit,
     * up to ln(B) for deterministic periodic spikes).
     */
    fun computeExponentialKlDivergenceNats(
        intervalsSec: List<Double>,
        referenceLambda: Double? = null
    ): Double {
        val valid = intervalsSec.filter { it.isFinite() && it >= 0.0 }
        val n = valid.size
        if (n < 5) return 0.0
        val meanSec = valid.average()
        val lambda = referenceLambda?.takeIf { it > 0.0 && it.isFinite() }
            ?: if (meanSec > 0.0) 1.0 / meanSec else return 0.0

        val binCount = kotlin.math.sqrt(n.toDouble()).toInt().coerceIn(5, 20)
        val counts = IntArray(binCount)
        for (x in valid) {
            val u = 1.0 - kotlin.math.exp(-lambda * x)
            val binIdx = (u * binCount).toInt().coerceIn(0, binCount - 1)
            counts[binIdx]++
        }

        val q = 1.0 / binCount.toDouble()
        var dkl = 0.0
        for (c in counts) {
            if (c > 0) {
                val p = c.toDouble() / n.toDouble()
                dkl += p * kotlin.math.ln(p / q)
            }
        }
        return dkl.coerceAtLeast(0.0)
    }

    /**
     * Computes the Anderson-Darling goodness-of-fit statistic (A^2), Stephens modified A*^2,
     * and asymptotic p-value for the exponential distribution Exp(lambda) with estimated rate lambda_hat = 1/mean.
     */
    fun computeAndersonDarlingExponential(intervalsSec: List<Double>): Triple<Double, Double, Double> {
        val sorted = intervalsSec.filter { it.isFinite() && it >= 0.0 }.sorted()
        val n = sorted.size
        if (n < 3) return Triple(0.0, 0.0, 1.0)
        val meanSec = sorted.average()
        if (meanSec <= 0.0) return Triple(0.0, 0.0, 1.0)

        val lambdaHat = 1.0 / meanSec
        var acc = 0.0
        for (i in 0 until n) {
            val wI = (lambdaHat * sorted[i]).coerceAtLeast(1e-15)
            val wRev = (lambdaHat * sorted[n - 1 - i]).coerceAtLeast(0.0)
            val logCdf = if (wI < 35.0) {
                kotlin.math.ln(-java.lang.Math.expm1(-wI))
            } else {
                0.0
            }
            val logSf = -wRev
            acc += (2 * i + 1).toDouble() * (logCdf + logSf)
        }

        val a2 = (-n.toDouble() - acc / n.toDouble()).coerceAtLeast(0.0)
        val a2Star = a2 * (1.0 + 0.6 / n.toDouble())
        val pValue = computeAndersonDarlingExpPValue(a2Star)
        return Triple(a2, a2Star, pValue)
    }

    /**
     * Computes continuous Stephens-calibrated p-value for the exponential Anderson-Darling A*^2 statistic.
     */
    fun computeAndersonDarlingExpPValue(a2Star: Double): Double {
        if (!a2Star.isFinite() || a2Star <= 0.12) return 1.0
        val p = when {
            a2Star < 0.30 -> {
                val dx = a2Star - 0.12
                kotlin.math.exp(-5.8 * dx * dx)
            }
            a2Star < 0.60 -> {
                kotlin.math.exp(0.28370357 - 1.04706567 * a2Star - 1.82138258 * a2Star * a2Star)
            }
            else -> {
                val x = a2Star.coerceAtMost(13.0)
                kotlin.math.exp(0.72367984 - 2.93819843 * x + 0.11173838 * x * x)
            }
        }
        return p.coerceIn(0.0, 1.0)
    }

    private fun computeMeanAndCi95(values: List<Double>): Triple<Double, Double, Double> {
        val n = values.size
        if (n == 0) return Triple(0.0, 0.0, 0.0)
        val mean = values.average()
        if (n == 1) return Triple(mean, mean, mean)
        val variance = values.sumOf { (it - mean) * (it - mean) } / (n - 1).toDouble()
        val se = kotlin.math.sqrt(variance / n.toDouble())
        val tCrit = studentTCritical95(n - 1)
        val half = tCrit * se
        return Triple(mean, mean - half, mean + half)
    }

    fun computeTrafficShapingStats(): TrafficShapingStats {
        val intervals = outboundIntervalsMs.toList().ifEmpty { actualTrafficDelaysMs.toList() }
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

        val theoMeanMs = if (theoreticalDelaysMs.isNotEmpty()) theoreticalDelaysMs.average() else 0.0
        val jitterMeanMs = if (wakeUpJittersMs.isNotEmpty()) wakeUpJittersMs.average() else 0.0
        val jitterMaxMs = wakeUpJittersMs.maxOrNull() ?: 0L

        val roleDist = packetRoleCounts.mapValues { it.value.get() }
        var shannonRoleEntropy = 0.0
        if (totalOut > 0) {
            for ((_, c) in roleDist) {
                if (c > 0) {
                    val p = c.toDouble() / totalOut
                    shannonRoleEntropy -= p * (kotlin.math.ln(p) / kotlin.math.ln(2.0))
                }
            }
        }

        // Target Prefix Shannon Entropy (256-bin byte 0 and 16-bin nibble entropy)
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

        val totalNibbles = totalTargetNibbleSamples.get()
        var nibbleEntropyBits = 0.0
        if (totalNibbles > 0) {
            for (i in 0 until 16) {
                val c = targetNibbleCounts.get(i)
                if (c > 0) {
                    val p = c.toDouble() / totalNibbles
                    nibbleEntropyBits -= p * (kotlin.math.ln(p) / kotlin.math.ln(2.0))
                }
            }
        }
        val nibbleEntropyNormalized = (nibbleEntropyBits / 4.0) * 100.0
        val uniquePrefixes = uniqueTargetPrefixes.size
        val targetUniqueRatio = if (totalPrefixes > 0) uniquePrefixes.toDouble() / totalPrefixes.toDouble() else 0.0

        if (count == 0) {
            return TrafficShapingStats(
                sampleCount = 0,
                meanInterPacketMs = 0.0,
                varianceInterPacketMs = 0.0,
                coefficientOfVariation = 0.0,
                kolmogorovSmirnovD = 0.0,
                kolmogorovSmirnovPValue = 1.0,
                deltaTheoreticalMeanMs = theoMeanMs,
                deltaActualMeanMs = 0.0,
                wakeUpJitterMeanMs = jitterMeanMs,
                wakeUpJitterMaxMs = jitterMaxMs,
                packetRoleDistribution = roleDist,
                shannonEntropyBits = shannonRoleEntropy,
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
                targetEntropyNormalized = entropyNormalized,
                klDivergenceNats = 0.0,
                klDivergenceConfiguredNats = 0.0,
                andersonDarlingA2 = 0.0,
                andersonDarlingA2Star = 0.0,
                andersonDarlingPValue = 1.0,
                targetNibbleEntropyBits = nibbleEntropyBits,
                targetNibbleEntropyNormalized = nibbleEntropyNormalized,
                uniqueTargetPrefixesCount = uniquePrefixes,
                targetUniqueRatio = targetUniqueRatio
            )
        }

        val meanMs = intervals.average()
        val varianceMs = if (count > 1) {
            intervals.sumOf { (it - meanMs) * (it - meanMs) } / (count - 1)
        } else 0.0
        val stdDevMs = kotlin.math.sqrt(varianceMs)
        val cv = if (meanMs > 0.0) (stdDevMs / meanMs) else 0.0

        val intervalsSec = intervals.map { it / 1000.0 }

        // Kolmogorov-Smirnov test against exponential distribution F(x) = 1 - exp(-lambda * x)
        val ksD = if (count >= 2 && meanMs > 0.0) {
            val meanSec = meanMs / 1000.0
            val lambdaHat = 1.0 / meanSec
            val sortedSec = intervalsSec.sorted()
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

        val ksPValue = computeKolmogorovSmirnovPValue(ksD, count)
        val klNats = computeExponentialKlDivergenceNats(intervalsSec)
        val configuredLambda = if (configuredLambdaSamples.isNotEmpty()) {
            configuredLambdaSamples.average().takeIf { it > 0.0 }
        } else null
        val klConfiguredNats = if (configuredLambda != null && theoreticalDelaysMs.isNotEmpty()) {
            computeExponentialKlDivergenceNats(intervalsSec, referenceLambda = configuredLambda)
        } else {
            klNats
        }
        val (adA2, adA2Star, adPValue) = computeAndersonDarlingExponential(intervalsSec)

        return TrafficShapingStats(
            sampleCount = count,
            meanInterPacketMs = meanMs,
            varianceInterPacketMs = varianceMs,
            coefficientOfVariation = cv,
            kolmogorovSmirnovD = ksD,
            kolmogorovSmirnovPValue = ksPValue,
            deltaTheoreticalMeanMs = theoMeanMs,
            deltaActualMeanMs = meanMs,
            wakeUpJitterMeanMs = jitterMeanMs,
            wakeUpJitterMaxMs = jitterMaxMs,
            packetRoleDistribution = roleDist,
            shannonEntropyBits = shannonRoleEntropy,
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
            targetEntropyNormalized = entropyNormalized,
            klDivergenceNats = klNats,
            klDivergenceConfiguredNats = klConfiguredNats,
            andersonDarlingA2 = adA2,
            andersonDarlingA2Star = adA2Star,
            andersonDarlingPValue = adPValue,
            targetNibbleEntropyBits = nibbleEntropyBits,
            targetNibbleEntropyNormalized = nibbleEntropyNormalized,
            uniqueTargetPrefixesCount = uniquePrefixes,
            targetUniqueRatio = targetUniqueRatio
        )
    }

    fun computeDhtConvergenceStats(): DhtRetentionAndConvergenceStats {
        val puts = putLatencySamples.toList().sorted()
        val gets = getLatencySamples.toList().sorted()

        fun percentiles(list: List<Long>): List<Long> {
            if (list.isEmpty()) return listOf(0L, 0L, 0L, 0L)
            val n = list.size
            val p50 = list[(n * 0.50).toInt().coerceAtMost(n - 1)]
            val p90 = list[(n * 0.90).toInt().coerceAtMost(n - 1)]
            val p95 = list[(n * 0.95).toInt().coerceAtMost(n - 1)]
            val p99 = list[(n * 0.99).toInt().coerceAtMost(n - 1)]
            return listOf(p50, p90, p95, p99)
        }

        val putPct = percentiles(puts)
        val getPct = percentiles(gets)

        val queriedNodes = queriedNodesList.toList()
        val avgNodes = if (queriedNodes.isNotEmpty()) queriedNodes.average() else 0.0
        val totalOps = totalDhtOps.get()
        val timeouts = totalKrpcTimeouts.get()
        val timeoutRate = if (totalOps > 0) (timeouts.toDouble() / totalOps * 100.0) else 0.0

        val ttlSamples = ttlSamplesHistory.toList()
        val replicaSurvival = if (ttlSamples.isNotEmpty()) {
            ttlSamples.map { it.replicaSurvivalRatio }.average()
        } else {
            val ttlAlive = aliveTtlCount.get()
            val ttlTotal = ttlAlive + expiredTtlCount.get()
            if (ttlTotal > 0) (ttlAlive.toDouble() / ttlTotal) else 0.0
        }

        val preAttempts = totalPreWarmingAttempts.get()
        val preHits = totalPreWarmingHits.get()
        val preWarmingHitRate = if (preAttempts > 0) (preHits.toDouble() / preAttempts * 100.0) else 0.0

        val fastTermSavings = if (totalOps > 0) (totalFastTerminatedOps.get().toDouble() / totalOps * 100.0) else 0.0

        val totalSubnets = totalSubnetSamples.get()
        var subnetEntropy = 0.0
        if (totalSubnets > 0) {
            for ((_, cnt) in subnet24Counts) {
                val c = cnt.get()
                if (c > 0) {
                    val p = c.toDouble() / totalSubnets
                    subnetEntropy -= p * (kotlin.math.ln(p) / kotlin.math.ln(2.0))
                }
            }
        }

        val decayCurve = computeRetentionCurveStats().map { it.toMap() }
        val modeSurvival = computeReplicaSurvivalByMode().map { it.toMap() }

        return DhtRetentionAndConvergenceStats(
            putLatencyP50Ms = putPct[0],
            putLatencyP90Ms = putPct[1],
            putLatencyP95Ms = putPct[2],
            putLatencyP99Ms = putPct[3],
            getLatencyP50Ms = getPct[0],
            getLatencyP90Ms = getPct[1],
            getLatencyP95Ms = getPct[2],
            getLatencyP99Ms = getPct[3],
            avgNodesQueriedPerOp = avgNodes,
            krpcTimeoutRatePercent = timeoutRate,
            replicaSurvivalRateKAliveOverK = replicaSurvival,
            preWarmingHitRatePercent = preWarmingHitRate,
            fastTerminationSavingsPercent = fastTermSavings,
            subnet24EntropyBits = subnetEntropy,
            ttlDecayCurve = decayCurve,
            replicaSurvivalByMode = modeSurvival
        )
    }

    fun computeE2eDeliveryStats(): EndToEndDeliveryAndRekeyStats {
        val deliveryByLifecycle = mutableMapOf<String, Double>()
        for ((state, samples) in deliveryLatencyByLifecycleMap) {
            val list = samples.toList()
            if (list.isNotEmpty()) {
                deliveryByLifecycle[state] = list.average()
            }
        }

        val deliveryByTransport = mutableMapOf<String, Double>()
        for ((transport, samples) in deliveryLatencyByTransportMap) {
            val list = samples.toList()
            if (list.isNotEmpty()) {
                deliveryByTransport[transport] = list.average()
            }
        }

        val coverAckByLifecycle = mutableMapOf<String, Double>()
        for ((state, samples) in coverAckLatencyByLifecycleMap) {
            val list = samples.toList()
            if (list.isNotEmpty()) {
                coverAckByLifecycle[state] = list.average()
            }
        }

        val pqcRekeys = pqcRekeyDurationsMs.toList()
        val avgPqcRekey = if (pqcRekeys.isNotEmpty()) pqcRekeys.average() else 0.0

        val groupRotations = groupRotationDurationsMs.toList()
        val avgGroupRotation = if (groupRotations.isNotEmpty()) groupRotations.average() else 0.0

        return EndToEndDeliveryAndRekeyStats(
            deliveryLatencyByLifecycle = deliveryByLifecycle,
            deliveryLatencyByTransport = deliveryByTransport,
            coverAckLatencyByLifecycle = coverAckByLifecycle,
            avgPqcRekeyDurationMs = avgPqcRekey,
            avgGroupKeyRotationDurationMs = avgGroupRotation,
            totalPqcRekeys = pqcRekeys.size,
            totalGroupRotations = groupRotations.size
        )
    }

    fun computeAdversarialStats(): AdversarialAnomalyStats {
        val badSig = badEd25519SigCount.get()
        val badTag = badAeadTagCount.get()
        val seqRoll = seqRollbackCount.get()
        val duplicates = slidingWindowDuplicateCount.get()
        val torLeaks = blockedTorColdStartLeaksCount.get()
        val other = otherAnomalyCount.get()
        val total = badSig + badTag + seqRoll + duplicates + torLeaks + other

        return AdversarialAnomalyStats(
            badEd25519SignatureCount = badSig,
            badAeadTagCount = badTag,
            seqRollbackAttemptsCount = seqRoll,
            slidingWindowDuplicateRejections = duplicates,
            blockedTorColdStartLeaks = torLeaks,
            totalAdversarialEvents = total
        )
    }

    fun computeHardwareStats(): HardwareBatteryStats {
        val profiler = resourceProfiler
        val samples = profiler?.samples ?: emptyList()

        var batteryDrainUahPerHour = 0.0
        var batteryPercentPerHour = 0.0
        var totalEnergyDrainUah = 0.0
        var txBytesPerHour = 0L
        var rxBytesPerHour = 0L
        val profileMap = mutableMapOf<String, Map<String, Any>>()

        if (samples.size >= 2) {
            val first = samples.first()
            val last = samples.last()
            val elapsedMs = (last.timestampEpochMs - first.timestampEpochMs).coerceAtLeast(1000L)
            val hours = elapsedMs.toDouble() / (3600.0 * 1000.0)

            val uahDiff = (first.batteryChargeCounterUah - last.batteryChargeCounterUah).coerceAtLeast(0L)
            if (uahDiff > 0L && hours > 0.0) {
                totalEnergyDrainUah = uahDiff.toDouble()
                batteryDrainUahPerHour = totalEnergyDrainUah / hours
            } else {
                val avgCurrentUa = samples.map { kotlin.math.abs(it.batteryCurrentNowUa) }.average()
                if (avgCurrentUa > 0.0) {
                    batteryDrainUahPerHour = avgCurrentUa
                    totalEnergyDrainUah = avgCurrentUa * hours
                }
            }

            val pctDiff = (first.batteryLevelPercent - last.batteryLevelPercent).coerceAtLeast(0)
            if (hours > 0.0) {
                batteryPercentPerHour = pctDiff.toDouble() / hours
            }

            val txDiff = (last.dhtBytesSent - first.dhtBytesSent).coerceAtLeast(0L)
            val rxDiff = (last.dhtBytesReceived - first.dhtBytesReceived).coerceAtLeast(0L)
            if (hours > 0.0) {
                txBytesPerHour = (txDiff / hours).toLong()
                rxBytesPerHour = (rxDiff / hours).toLong()
            }

            val byLambda = samples.groupBy { it.poissonLambda }
            for ((lambda, sList) in byLambda) {
                val avgUa = sList.map { kotlin.math.abs(it.batteryCurrentNowUa) }.average()
                val label = String.format(java.util.Locale.US, "lambda_%.5f", lambda)
                profileMap[label] = mapOf(
                    "sampleCount" to sList.size,
                    "avgBatteryCurrentUa" to avgUa,
                    "lambda" to lambda
                )
            }
        } else {
            val currentSamples = packetBatteryCurrentSamples.toList()
            if (currentSamples.size >= 2) {
                val minTs = currentSamples.minOf { it.first }
                val maxTs = currentSamples.maxOf { it.first }
                val elapsedMs = (maxTs - minTs).coerceAtLeast(1000L)
                val hours = elapsedMs.toDouble() / (3600.0 * 1000.0)
                val avgCurrentUa = currentSamples.map { kotlin.math.abs(it.second) }.average()
                if (avgCurrentUa > 0.0) {
                    batteryDrainUahPerHour = avgCurrentUa
                    totalEnergyDrainUah = avgCurrentUa * hours
                }
            }
        }

        val deliveredRealCount = deliveredAckCount.get() + directDeliveredWithoutTrackerCount.get()
        val sentRealCount = firstSendCount.value
        val energyPerDeliveredMsg = if (deliveredRealCount > 0) totalEnergyDrainUah / deliveredRealCount.toDouble() else 0.0
        val energyPerSentMsg = if (sentRealCount > 0) totalEnergyDrainUah / sentRealCount.toDouble() else 0.0

        val ramPss = queryRamPssKb()

        return HardwareBatteryStats(
            batteryDrainUahPerHour = batteryDrainUahPerHour,
            batteryPercentPerHour = batteryPercentPerHour,
            ramPssKb = ramPss,
            udpTxBytesPerHour = txBytesPerHour,
            udpRxBytesPerHour = rxBytesPerHour,
            statsByPoissonProfile = profileMap,
            totalEnergyDrainUah = totalEnergyDrainUah,
            deliveredRealMessagesCount = deliveredRealCount,
            energyOverheadUahPerDeliveredMsg = energyPerDeliveredMsg,
            energyOverheadUahPerRealSentMsg = energyPerSentMsg
        )
    }

    fun queryRamPssKb(): Long {
        return try {
            android.os.Debug.getPss()
        } catch (_: Throwable) {
            val rt = Runtime.getRuntime()
            (rt.totalMemory() - rt.freeMemory()) / 1024L
        }
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

        val maskRecords = groupMaskingRecords.toList()
        val avgDecorrelation = if (maskRecords.isNotEmpty()) maskRecords.map { it.decorrelationScore }.average() else 0.0
        val avgCoverRatio = if (maskRecords.isNotEmpty()) maskRecords.map { it.coverPaddingRatio }.average() else 0.0
        val avgMasking = if (maskRecords.isNotEmpty()) maskRecords.map { it.maskingCoefficient }.average() else 0.0
        val recipientCorrelation = computeGroupRecipientCorrelation(maskRecords)

        return GroupChatResearchStats(
            latencyByGroupSize = latencyMap,
            avgFanOutDeliverySkewMs = avgSkew,
            maxFanOutDeliverySkewMs = maxSkew,
            avgKeyRotationConvergenceMs = avgRekey,
            totalGroupMessagesTracked = totalGroupMessagesTracked.get(),
            totalKeyRotationsTracked = totalKeyRotationsTracked.get(),
            recipientDecorrelationScore = avgDecorrelation,
            groupMaskingCoefficient = avgMasking,
            groupMaskingPercent = avgMasking * 100.0,
            avgInterleavedCoverRatio = avgCoverRatio,
            recipientCountCorrelation = recipientCorrelation
        )
    }

    /**
     * Computes Pearson correlation between real group size M and observable slot signature.
     * When recipients use unique derived slots and cover padding keeps window size constant (or
     * independent of M), correlation approaches 0.0; unpadded bursts correlate near 1.0.
     */
    private fun computeGroupRecipientCorrelation(records: List<GroupMaskingRecord>): Double {
        if (records.size < 2) return 0.0
        val xs = records.map { it.groupSizeM.toDouble() }
        val ys = records.map { rec ->
            if (rec.uniqueTargetCount <= 1 && rec.groupSizeM > 1) {
                rec.groupSizeM.toDouble()
            } else {
                (rec.groupSizeM + rec.interleavedCoverCount).toDouble()
            }
        }
        val meanX = xs.average()
        val meanY = ys.average()
        var num = 0.0
        var denX = 0.0
        var denY = 0.0
        for (i in xs.indices) {
            val dx = xs[i] - meanX
            val dy = ys[i] - meanY
            num += dx * dy
            denX += dx * dx
            denY += dy * dy
        }
        val denom = kotlin.math.sqrt(denX * denY)
        return if (denom > 1e-12) (num / denom).coerceIn(-1.0, 1.0) else 0.0
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

    /**
     * Computes the BEP 44 replica survival distribution (k_alive / K) across canonical thesis horizons
     * (15m, 1h, 6h, 12h, 24h, 48h, 72h) partitioned into non-overlapping bins by [RepublishMode]:
     * NO_REPUBLISH, OWN_REPUBLISH, and CROWD_REPUBLISH.
     */
    fun computeReplicaSurvivalByMode(): List<ReplicaSurvivalDistributionPoint> {
        val samples = ttlSamplesHistory.toList()
        data class HorizonBin(val label: String, val targetHours: Double, val minHours: Double, val maxHours: Double)
        val horizons = listOf(
            HorizonBin("15m", 0.25, 0.0, 0.625),
            HorizonBin("1h", 1.0, 0.625, 3.5),
            HorizonBin("6h", 6.0, 3.5, 9.0),
            HorizonBin("12h", 12.0, 9.0, 18.0),
            HorizonBin("24h", 24.0, 18.0, 36.0),
            HorizonBin("48h", 48.0, 36.0, 60.0),
            HorizonBin("72h", 72.0, 60.0, Double.POSITIVE_INFINITY)
        )

        val result = mutableListOf<ReplicaSurvivalDistributionPoint>()
        for (h in horizons) {
            for (mode in RepublishMode.entries) {
                val matching = samples.filter { sample ->
                    sample.republishMode == mode &&
                        sample.elapsedHours >= h.minHours &&
                        sample.elapsedHours < h.maxHours
                }
                val total = matching.size
                val alive = matching.count { it.isAlive }
                val binaryPct = if (total > 0) (alive.toDouble() / total.toDouble() * 100.0) else 0.0
                val ratios = matching.map { it.replicaSurvivalRatio }
                val (meanRatio, lowRatio, highRatio) = computeMeanAndCi95(ratios)
                val meanKAlive = if (total > 0) matching.map { it.kAlive.toDouble() }.average() else 0.0
                val meanKTarget = if (total > 0) matching.map { it.replicationK.toDouble() }.average() else 8.0

                result.add(
                    ReplicaSurvivalDistributionPoint(
                        horizonLabel = h.label,
                        horizonHours = h.targetHours,
                        republishMode = mode,
                        totalSamples = total,
                        aliveSamples = alive,
                        binarySurvivalRatePercent = binaryPct,
                        meanReplicaSurvivalRatio = meanRatio.coerceIn(0.0, 1.0),
                        meanKAlive = meanKAlive,
                        targetReplicationK = meanKTarget,
                        ci95LowerRatio = lowRatio.coerceIn(0.0, 1.0),
                        ci95UpperRatio = highRatio.coerceIn(0.0, 1.0)
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
     * Prepares Firestore-compliant session payloads for all ZIP bundle chunks (<= 550 KB each),
     * ensuring multi-day sessions are split across sequential documents without ever falling back to
     * `OMITTED_EXCEEDS_600KB`.
     */
    fun computeChunkedSessionPayloads(
        maxChunkBytes: Long = maxChunkZipBytes
    ): List<Pair<Map<String, Any>, Map<String, Any>>> {
        val manifest = generateManifestData()
        val chunkFiles = buildChunkedResearchBundles(maxChunkBytes = maxChunkBytes)
        val totalChunks = chunkFiles.size.coerceAtLeast(1)
        val bundleGroupId = "${sessionId}_${manifest.createdEpochMs}"

        val deviceInfo: Map<String, Any> = mapOf(
            "sessionId" to sessionId,
            "deviceModel" to manifest.deviceModel,
            "androidVersion" to manifest.androidVersion,
            "appVersion" to manifest.appVersion,
            "versionCode" to manifest.versionCode
        )

        val baseMetrics: Map<String, Any> = mapOf(
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
            "replicaSurvivalByMode" to computeReplicaSurvivalByMode().map { it.toMap() },
            "ed25519SignatureStats" to computeEd25519SignatureStats(),
            "dhtRetentionAndConvergenceStats" to computeDhtConvergenceStats().toMap(),
            "endToEndDeliveryAndRekeyStats" to computeE2eDeliveryStats().toMap(),
            "adversarialAnomalyStats" to computeAdversarialStats().toMap(),
            "hardwareBatteryStats" to computeHardwareStats().toMap(),
            "fileChecksums" to manifest.fileChecksums,
            "manifestSha256" to manifest.manifestSha256
        )

        if (chunkFiles.isEmpty()) {
            val emptyMetrics = baseMetrics + mapOf(
                "bundleZipSizeBytes" to 0L,
                "bundleZipStatus" to "EMPTY",
                "bundleZipBase64" to "",
                "bundleChunkIndex" to 1,
                "bundleTotalChunks" to 1,
                "bundleGroupId" to bundleGroupId
            )
            return listOf(Pair(deviceInfo, emptyMetrics))
        }

        val totalUnchunkedBytes = chunkFiles.sumOf { it.length() }
        return chunkFiles.mapIndexed { idx, chunkFile ->
            val chunkIndex = idx + 1
            val zipSize = chunkFile.length()
            val bytes = if (zipSize > 0L) chunkFile.readBytes() else ByteArray(0)
            val bundleBase64 = if (bytes.isNotEmpty()) Base64.getEncoder().encodeToString(bytes) else ""
            val status = when {
                zipSize == 0L -> "EMPTY"
                totalChunks == 1 -> "EMBEDDED_ZIP_BASE64"
                else -> "CHUNKED_ZIP_BASE64"
            }

            // Include full aggregated metrics in chunk 1 (and compact summary + required counters in subsequent parts)
            val chunkMetrics = if (chunkIndex == 1) {
                baseMetrics + mapOf(
                    "bundleZipSizeBytes" to zipSize,
                    "bundleZipStatus" to status,
                    "bundleZipBase64" to bundleBase64,
                    "bundleChunkIndex" to chunkIndex,
                    "bundleTotalChunks" to totalChunks,
                    "bundleGroupId" to bundleGroupId,
                    "bundleTotalZipBytes" to totalUnchunkedBytes
                )
            } else {
                mapOf(
                    "totalEvents" to manifest.totalEvents,
                    "firstSendCount" to manifest.firstSendCount,
                    "ownRepublishCount" to manifest.ownRepublishCount,
                    "crowdRepublishCount" to manifest.crowdRepublishCount,
                    "packetsReceivedCount" to manifest.packetsReceivedCount,
                    "ttlSamplesCount" to manifest.ttlSamplesCount,
                    "manifestSha256" to manifest.manifestSha256,
                    "bundleZipSizeBytes" to zipSize,
                    "bundleZipStatus" to status,
                    "bundleZipBase64" to bundleBase64,
                    "bundleChunkIndex" to chunkIndex,
                    "bundleTotalChunks" to totalChunks,
                    "bundleGroupId" to bundleGroupId,
                    "bundleTotalZipBytes" to totalUnchunkedBytes
                )
            }
            Pair(deviceInfo, chunkMetrics)
        }
    }

    /**
     * Prepares device metadata and aggregated metrics conforming to `firestore.rules`.
     * Uses chunked ZIP packaging (<= 550 KB) so payload Base64 is always embedded cleanly.
     */
    fun computeSessionPayload(): Pair<Map<String, Any>, Map<String, Any>> {
        return computeChunkedSessionPayloads().first()
    }

    /**
     * Generates SessionManifest containing device specs, counters, and SHA-256 hashes of all CSV files
     * (both active files and rotated segments).
     */
    fun generateManifestData(): SessionManifest {
        val checksums = mutableMapOf<String, String>()
        synchronized(csvLock) {
            for (csvFile in getAllTelemetryCsvFiles()) {
                checksums[csvFile.name] = computeSha256(csvFile)
            }
        }

        val now = clockProvider()
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

    private fun refreshExportFilesAndManifest(): Pair<SessionManifest, File> {
        val dir = telemetryDir
        try {
            resourceProfiler?.exportToCsvFile(dir, "research_resource_profile.csv")
        } catch (_: Exception) {}
        initCsvFiles()
        val manifest = generateManifestData()
        val manifestFile = File(dir, "session_manifest.json")
        manifestFile.writeText(manifest.toJsonString(), Charsets.UTF_8)
        return Pair(manifest, manifestFile)
    }

    /**
     * Packs all CSV files (active + rotated) and session_manifest.json into a compressed ZIP archive.
     */
    fun buildCompressedResearchBundle(): File {
        val dir = telemetryDir
        val (_, manifestFile) = refreshExportFilesAndManifest()

        val timestamp = clockProvider()
        val zipFile = File(dir, "pqchat_research_${sessionId}_${timestamp}.zip")

        val filesToZip = synchronized(csvLock) {
            (getAllTelemetryCsvFiles() + manifestFile).filter { it.exists() && it.length() > 0 }
        }

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
     * Builds one or more compressed ZIP bundles strictly bounded by [maxChunkBytes] (default 550 KB).
     * Automatically includes rotated CSV segments and splits oversized CSV files on newline boundaries
     * while preserving CSV headers in every slice so every part is independently parseable.
     */
    fun buildChunkedResearchBundles(maxChunkBytes: Long = maxChunkZipBytes): List<File> {
        val dir = telemetryDir
        val singleZip = buildCompressedResearchBundle()
        if (singleZip.length() <= maxChunkBytes) {
            return listOf(singleZip)
        }

        // Remove oversized single archive before generating chunked parts
        singleZip.delete()

        val (manifest, manifestFile) = refreshExportFilesAndManifest()
        val manifestBytes = manifestFile.readBytes()
        val effectiveMax = maxChunkBytes.coerceAtLeast(8_192L)
        val manifestMargin = manifestBytes.size + 4_096L
        val maxEntryCompressedBudget = (effectiveMax - manifestMargin).coerceAtLeast(2_048L)

        val csvFiles = synchronized(csvLock) { getAllTelemetryCsvFiles() }
        val namedEntries = mutableListOf<Pair<String, ByteArray>>()
        for (csvFile in csvFiles) {
            namedEntries.addAll(splitCsvFileForChunkBudget(csvFile, maxEntryCompressedBudget))
        }

        val bundleGroupId = "${sessionId}_${clockProvider()}"
        val stagedChunks = mutableListOf<MutableList<Pair<String, ByteArray>>>()
        var currentChunk = mutableListOf<Pair<String, ByteArray>>()

        for (entry in namedEntries) {
            val candidateList = ArrayList<Pair<String, ByteArray>>(currentChunk.size + 3)
            candidateList.addAll(currentChunk)
            candidateList.add(entry)
            if (stagedChunks.isEmpty()) {
                candidateList.add("session_manifest.json" to manifestBytes)
            }
            val estChunkManifest = buildChunkManifestBytes(
                bundleGroupId = bundleGroupId,
                chunkIndex = stagedChunks.size + 1,
                totalChunks = 999,
                createdEpochMs = manifest.createdEpochMs,
                isoCreatedAt = manifest.isoCreatedAt,
                entries = candidateList
            )
            val totalZipBytes = measureZipSizeBytes(candidateList + ("chunk_manifest.json" to estChunkManifest))

            if (totalZipBytes <= effectiveMax) {
                currentChunk.add(entry)
            } else {
                if (currentChunk.isNotEmpty()) {
                    stagedChunks.add(currentChunk)
                    currentChunk = mutableListOf(entry)
                } else {
                    stagedChunks.add(mutableListOf(entry))
                }
            }
        }
        if (currentChunk.isNotEmpty() || stagedChunks.isEmpty()) {
            stagedChunks.add(currentChunk)
        }

        val totalChunks = stagedChunks.size
        val timestamp = clockProvider()
        val outputFiles = mutableListOf<File>()
        for ((idx, entries) in stagedChunks.withIndex()) {
            val chunkIndex = idx + 1
            val finalEntries = ArrayList<Pair<String, ByteArray>>(entries.size + 2)
            finalEntries.addAll(entries)
            if (chunkIndex == 1) {
                finalEntries.add("session_manifest.json" to manifestBytes)
            }
            val chunkManifestBytes = buildChunkManifestBytes(
                bundleGroupId = bundleGroupId,
                chunkIndex = chunkIndex,
                totalChunks = totalChunks,
                createdEpochMs = manifest.createdEpochMs,
                isoCreatedAt = manifest.isoCreatedAt,
                entries = finalEntries
            )
            finalEntries.add("chunk_manifest.json" to chunkManifestBytes)

            val partName = String.format(
                java.util.Locale.US,
                "pqchat_research_%s_%d_part%03d_of_%03d.zip",
                sessionId,
                timestamp,
                chunkIndex,
                totalChunks
            )
            val partFile = File(dir, partName)
            ZipOutputStream(BufferedOutputStream(FileOutputStream(partFile))).use { zos ->
                for ((name, data) in finalEntries) {
                    zos.putNextEntry(ZipEntry(name))
                    zos.write(data)
                    zos.closeEntry()
                }
            }
            outputFiles.add(partFile)
        }

        return outputFiles
    }

    private fun buildChunkManifestBytes(
        bundleGroupId: String,
        chunkIndex: Int,
        totalChunks: Int,
        createdEpochMs: Long,
        isoCreatedAt: String,
        entries: List<Pair<String, ByteArray>>
    ): ByteArray {
        val checksums = linkedMapOf<String, String>()
        for ((name, bytes) in entries) {
            checksums[name] = computeSha256(bytes)
        }
        val manifest = ChunkedBundleManifest(
            bundleGroupId = bundleGroupId,
            sessionId = sessionId,
            chunkIndex = chunkIndex,
            totalChunks = totalChunks,
            createdEpochMs = createdEpochMs,
            isoCreatedAt = isoCreatedAt,
            entryChecksums = checksums
        )
        manifest.chunkSha256 = computeSha256(manifest.toJsonString())
        return manifest.toJsonString().toByteArray(Charsets.UTF_8)
    }

    private fun splitCsvFileForChunkBudget(
        csvFile: File,
        maxCompressedBytes: Long
    ): List<Pair<String, ByteArray>> {
        val rawBytes = csvFile.readBytes()
        if (measureZipSizeBytes(listOf(csvFile.name to rawBytes)) <= maxCompressedBytes) {
            return listOf(csvFile.name to rawBytes)
        }

        val text = rawBytes.toString(Charsets.UTF_8)
        val lines = text.lines().filter { it.isNotEmpty() }
        if (lines.size <= 2) {
            return listOf(csvFile.name to rawBytes)
        }

        val header = lines.first()
        val headerBytes = (header + "\n").toByteArray(Charsets.UTF_8)
        val dataLines = lines.drop(1)
        val stem = csvFile.nameWithoutExtension
        val slices = mutableListOf<Pair<String, ByteArray>>()

        var startIdx = 0
        var partNum = 1
        while (startIdx < dataLines.size) {
            // Binary search largest slice [startIdx, endIdx) that compresses within maxCompressedBytes
            var lo = startIdx + 1
            var hi = dataLines.size
            var bestEnd = lo
            var bestBytes: ByteArray? = null

            // Fast exponential probe from startIdx + 1 upward to avoid full range rebuilds on large files
            var probeStep = 16
            var probeEnd = (startIdx + probeStep).coerceAtMost(dataLines.size)
            while (probeEnd < dataLines.size) {
                val candidate = buildCsvSliceBytes(headerBytes, dataLines, startIdx, probeEnd)
                if (measureZipSizeBytes(listOf("${stem}_p.csv" to candidate)) <= maxCompressedBytes) {
                    bestEnd = probeEnd
                    bestBytes = candidate
                    lo = probeEnd
                    probeStep *= 2
                    probeEnd = (startIdx + probeStep).coerceAtMost(dataLines.size)
                } else {
                    hi = probeEnd - 1
                    break
                }
            }

            if (probeEnd == dataLines.size && bestEnd < dataLines.size) {
                val candidate = buildCsvSliceBytes(headerBytes, dataLines, startIdx, dataLines.size)
                if (measureZipSizeBytes(listOf("${stem}_p.csv" to candidate)) <= maxCompressedBytes) {
                    bestEnd = dataLines.size
                    bestBytes = candidate
                    lo = dataLines.size + 1
                }
            }

            while (lo <= hi) {
                val mid = (lo + hi) ushr 1
                val candidate = buildCsvSliceBytes(headerBytes, dataLines, startIdx, mid)
                if (measureZipSizeBytes(listOf("${stem}_p.csv" to candidate)) <= maxCompressedBytes) {
                    bestEnd = mid
                    bestBytes = candidate
                    lo = mid + 1
                } else {
                    hi = mid - 1
                }
            }

            val finalSliceBytes = bestBytes ?: buildCsvSliceBytes(headerBytes, dataLines, startIdx, bestEnd)
            val sliceName = String.format(java.util.Locale.US, "%s.part%03d.csv", stem, partNum++)
            slices.add(sliceName to finalSliceBytes)
            startIdx = bestEnd
        }

        return slices
    }

    private fun buildCsvSliceBytes(
        headerBytes: ByteArray,
        dataLines: List<String>,
        startIdx: Int,
        endIdxExclusive: Int
    ): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        baos.write(headerBytes)
        for (i in startIdx until endIdxExclusive) {
            baos.write(dataLines[i].toByteArray(Charsets.UTF_8))
            baos.write('\n'.code)
        }
        return baos.toByteArray()
    }

    private fun measureZipSizeBytes(entries: List<Pair<String, ByteArray>>): Long {
        val baos = java.io.ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            for ((name, data) in entries) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(data)
                zos.closeEntry()
            }
        }
        return baos.size().toLong()
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
            putExtra(Intent.EXTRA_TEXT, "PQChat DHT Research Telemetry Bundle (session: $sessionId)")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }

    /**
     * Manually triggers an immediate batch synchronization to Google Cloud Firestore (Firebase Spark free tier).
     * Automatically splits large multi-day sessions into <= 550 KB chunks.
     * Strictly requires explicit user opt-in (isEnabled == true).
     */
    suspend fun forceFirebaseSync(): Boolean = withContext(Dispatchers.IO) {
        if (!isEnabled || !firebaseSync.isFirebaseConfigured()) return@withContext false
        val payloads = computeChunkedSessionPayloads()
        firebaseSync.syncResearchSessionChunks(sessionId, payloads, isManual = true)
    }

    fun stop() {
        scope.cancel()
        ttlSampler?.stop()
        firebaseSync.stop()
    }
}
