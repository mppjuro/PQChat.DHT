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
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
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
 * - Supports instant offline sharing via Android FileProvider / ACTION_SEND or cloud sync to Firebase Storage.
 * - Strictly zero plaintext, zero cryptographic keys, and default-off user privacy.
 */
class ResearchTelemetryManager(
    private val context: Context? = null,
    private val settingsManager: AppSettingsManager? = null,
    private val dhtClient: DhtClient? = null,
    val firebaseSync: FirebaseResearchSync = FirebaseResearchSync(context),
    val resourceProfiler: org.pqchat.dht.debug.AndroidResourceProfiler? = null,
    val baseDir: File? = null,
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

        // Periodic background auto-sync check (at most once every 6 hours and strictly on Wi-Fi)
        scope.launch {
            while (isActive) {
                delay(60 * 60 * 1000L) // check every 1 hour
                if (isEnabled && firebaseSync.isWifiConnected() && firebaseSync.isFirebaseConfigured()) {
                    try {
                        val bundle = buildCompressedResearchBundle()
                        val manifestFile = File(telemetryDir, "session_manifest.json")
                        val manifestMap = generateManifestData().toMap()
                        firebaseSync.syncResearchBundle(sessionId, bundle, manifestMap, isManual = false)
                    } catch (_: Exception) {}
                }
            }
        }
    }

    val isEnabled: Boolean
        get() = settingsManager?.isAnonymousStatsEnabled?.value == true

    private fun initCsvFiles() {
        synchronized(csvLock) {
            if (!masterCsvFile.exists()) masterCsvFile.writeText(ResearchCsvSchema.MASTER_CSV_HEADER + "\n")
            if (!packetEventsCsvFile.exists()) packetEventsCsvFile.writeText(PacketTelemetryEvent.CSV_HEADER + "\n")
            if (!ttlSamplesCsvFile.exists()) ttlSamplesCsvFile.writeText(TtlSampleEvent.CSV_HEADER + "\n")
            if (!republishSummaryCsvFile.exists()) republishSummaryCsvFile.writeText(RepublishAnalysisSummary.CSV_HEADER + "\n")
            if (!resourceProfileCsvFile.exists()) {
                resourceProfileCsvFile.writeText(org.pqchat.dht.debug.AndroidResourceProfiler.ResourceSample.CSV_HEADER + "\n")
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

        // Append to local CSV files immediately
        appendPacketEventCsv(event)
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
    }

    private fun recordTtlSampleInternal(sample: TtlSampleEvent) {
        if (!isEnabled) return
        _ttlSamplesCount.value += 1
        appendTtlSampleCsv(sample)
    }

    private fun appendPacketEventCsv(event: PacketTelemetryEvent) {
        synchronized(csvLock) {
            try {
                PrintWriter(FileWriter(packetEventsCsvFile, true)).use { it.println(event.toCsvRow()) }
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
     * Packs all 4 primary CSV files (master, ttl_samples, republish_analysis, resource_profile)
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
     * Manually triggers an immediate bundle packaging and upload to Google Firebase (ZIP to Storage + Summary to Firestore).
     */
    suspend fun forceFirebaseSync(): Boolean = withContext(Dispatchers.IO) {
        val bundle = try {
            buildCompressedResearchBundle()
        } catch (_: Exception) {
            null
        } ?: run {
            return@withContext false
        }

        val manifestMap = generateManifestData().toMap()
        firebaseSync.syncResearchBundle(sessionId, bundle, manifestMap, isManual = true)
    }

    fun stop() {
        scope.cancel()
        _activeSampler?.stop()
        firebaseSync.stop()
    }
}
