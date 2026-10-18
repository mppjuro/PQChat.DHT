package org.pqchat.dht.research

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.dht.leaf.DhtClient
import java.io.File
import java.io.FileWriter
import java.io.PrintWriter
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Central Coordinator for Academic Research Telemetry in PQChat DHT.
 *
 * Designed for Master's Thesis empirical analysis:
 * - Differentiates original packets (FIRST_SEND) vs own republish (OWN_REPUBLISH) vs crowdsourced relay (CROWD_REPUBLISH) vs received (PACKET_RECEIVED).
 * - Conducts periodic (15-min) historical DHT retention sampling to determine exact packet expiration and survival curves.
 * - Maintains complete .csv files locally for plotting/graphing.
 * - Streams structured documents and uploads CSV files to Google Firebase when opted-in by user.
 * - Strictly zero plaintext, zero cryptographic keys, and default-off user privacy.
 */
class ResearchTelemetryManager(
    private val context: Context? = null,
    private val settingsManager: AppSettingsManager? = null,
    private val dhtClient: DhtClient? = null,
    private val firebaseSync: FirebaseResearchSync = FirebaseResearchSync(context),
    val ttlSampler: HistoricalTtlSampler? = if (dhtClient != null) {
        HistoricalTtlSampler(
            dhtClient = dhtClient,
            onSampleRecorded = { /* will be wired in init */ }
        )
    } else null
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

    private data class InFlightTracker(
        val messagePrefix: String,
        val initialSentMs: Long,
        val republishAttempts: AtomicInteger = AtomicInteger(0),
        var timeToFirstRepublishMs: Long = 0L,
        var crowdRelayed: Boolean = false
    )

    private val telemetryDir: File? by lazy {
        context?.let { ctx ->
            val dir = File(ctx.getExternalFilesDir(null) ?: ctx.filesDir, "research_telemetry")
            if (!dir.exists()) dir.mkdirs()
            dir
        }
    }

    val masterCsvFile: File? by lazy { telemetryDir?.let { File(it, "research_telemetry_master.csv") } }
    val packetEventsCsvFile: File? by lazy { telemetryDir?.let { File(it, "research_packet_events.csv") } }
    val ttlSamplesCsvFile: File? by lazy { telemetryDir?.let { File(it, "research_ttl_samples.csv") } }
    val republishSummaryCsvFile: File? by lazy { telemetryDir?.let { File(it, "research_republish_analysis.csv") } }

    private val csvLock = Any()

    private var _activeSampler: HistoricalTtlSampler? = null

    init {
        initCsvFiles()

        // Wire TTL sampler if present
        if (ttlSampler != null) {
            val configuredSampler = HistoricalTtlSampler(
                dhtClient = dhtClient!!,
                onSampleRecorded = { sample ->
                    recordTtlSampleInternal(sample)
                }
            )
            // Replace sampler with wired instance
            _activeSampler = configuredSampler
        }

        // Listen to settings toggle changes
        scope.launch {
            settingsManager?.isAnonymousStatsEnabled?.collect { enabled ->
                if (enabled) {
                    _activeSampler?.start { sessionId }
                    firebaseSync.ensureAuthenticated()
                } else {
                    _activeSampler?.stop()
                }
            }
        }
    }

    val isEnabled: Boolean
        get() = settingsManager?.isAnonymousStatsEnabled?.value == true

    private fun initCsvFiles() {
        synchronized(csvLock) {
            masterCsvFile?.let { if (!it.exists()) it.writeText(ResearchCsvSchema.MASTER_CSV_HEADER + "\n") }
            packetEventsCsvFile?.let { if (!it.exists()) it.writeText(PacketTelemetryEvent.CSV_HEADER + "\n") }
            ttlSamplesCsvFile?.let { if (!it.exists()) it.writeText(TtlSampleEvent.CSV_HEADER + "\n") }
            republishSummaryCsvFile?.let { if (!it.exists()) it.writeText(RepublishAnalysisSummary.CSV_HEADER + "\n") }
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
        nodesQueried: Int = 0,
        nodesResponded: Int = 0,
        success: Boolean = true,
        republishAttempt: Int = 0,
        messageAgeMs: Long = 0L,
        networkType: String = "UNKNOWN",
        errorCode: String? = null
    ) {
        if (!isEnabled) return

        val targetPrefix = CryptoUtils.toHex(target).take(8)
        val now = System.currentTimeMillis()

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
            success = success,
            republishAttempt = republishAttempt,
            messageAgeMs = messageAgeMs,
            networkType = networkType,
            errorCode = errorCode
        )

        // Increment live UI counters
        _eventsCount.value += 1
        when (role) {
            PacketRole.FIRST_SEND -> {
                _firstSendCount.value += 1
                inFlightRepublishes[targetPrefix] = InFlightTracker(targetPrefix, now)
                _activeSampler?.trackPacket(target, initialPutEpochMs = now, republishActive = true)
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

        // 1. Write to local CSV files
        appendPacketEventCsv(event)

        // 2. Queue for Firebase sync
        firebaseSync.queuePacketEvent(event)
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
        firebaseSync.queueRepublishSummary(summary)
    }

    private fun recordTtlSampleInternal(sample: TtlSampleEvent) {
        if (!isEnabled) return
        _ttlSamplesCount.value += 1
        appendTtlSampleCsv(sample)
        firebaseSync.queueTtlSample(sample)
    }

    private fun appendPacketEventCsv(event: PacketTelemetryEvent) {
        scope.launch {
            synchronized(csvLock) {
                try {
                    packetEventsCsvFile?.let { file ->
                        PrintWriter(FileWriter(file, true)).use { it.println(event.toCsvRow()) }
                    }
                    masterCsvFile?.let { file ->
                        PrintWriter(FileWriter(file, true)).use { it.println(event.toMasterCsvRow()) }
                    }
                } catch (_: Exception) {}
            }
        }
    }

    private fun appendTtlSampleCsv(sample: TtlSampleEvent) {
        scope.launch {
            synchronized(csvLock) {
                try {
                    ttlSamplesCsvFile?.let { file ->
                        PrintWriter(FileWriter(file, true)).use { it.println(sample.toCsvRow()) }
                    }
                    masterCsvFile?.let { file ->
                        PrintWriter(FileWriter(file, true)).use { it.println(sample.toMasterCsvRow()) }
                    }
                } catch (_: Exception) {}
            }
        }
    }

    private fun appendRepublishSummaryCsv(summary: RepublishAnalysisSummary) {
        scope.launch {
            synchronized(csvLock) {
                try {
                    republishSummaryCsvFile?.let { file ->
                        PrintWriter(FileWriter(file, true)).use { it.println(summary.toCsvRow()) }
                    }
                    masterCsvFile?.let { file ->
                        PrintWriter(FileWriter(file, true)).use { it.println(summary.toMasterCsvRow()) }
                    }
                } catch (_: Exception) {}
            }
        }
    }


    /**
     * Creates an Android Intent to share the generated research CSV with external apps (Drive, Gmail, USB, etc.).
     */
    fun createShareCsvIntent(context: Context): Intent? {
        val file = masterCsvFile ?: return null
        if (!file.exists() || file.length() == 0L) return null

        val uri = try {
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        } catch (_: Exception) {
            android.net.Uri.fromFile(file)
        }

        return Intent(Intent.ACTION_SEND).apply {
            type = "text/csv"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "PQChat Research Telemetry Master CSV ($sessionId)")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }

    /**
     * Manually triggers an immediate flush and upload of local CSV data to Google Firebase.
     */
    suspend fun forceFirebaseSync(): Boolean = withContext(Dispatchers.IO) {
        firebaseSync.flushPendingData()
        masterCsvFile?.let { file ->
            if (file.exists() && file.length() > 0) {
                firebaseSync.uploadCsvToStorage(sessionId, file, "research_telemetry_master.csv")
            }
        }
        packetEventsCsvFile?.let { file ->
            if (file.exists() && file.length() > 0) {
                firebaseSync.uploadCsvToStorage(sessionId, file, "research_packet_events.csv")
            }
        }
        ttlSamplesCsvFile?.let { file ->
            if (file.exists() && file.length() > 0) {
                firebaseSync.uploadCsvToStorage(sessionId, file, "research_ttl_samples.csv")
            }
        }
        republishSummaryCsvFile?.let { file ->
            if (file.exists() && file.length() > 0) {
                firebaseSync.uploadCsvToStorage(sessionId, file, "research_republish_analysis.csv")
            }
        }
        true
    }

    fun stop() {
        _activeSampler?.stop()
        firebaseSync.stop()
    }
}
