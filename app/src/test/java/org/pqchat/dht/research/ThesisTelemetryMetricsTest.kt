package org.pqchat.dht.research

import android.content.Context
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.debug.AndroidResourceProfiler
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.util.Base64
import java.util.Random
import java.util.concurrent.atomic.AtomicLong
import java.util.zip.ZipFile
import kotlin.math.ln

/**
 * Comprehensive unit test suite verifying all Master's Thesis research telemetry metrics:
 * 1. Replica survival distribution (k_alive / K) across 15m..72h split by RepublishMode.
 * 2. Traffic-analysis resistance: empirical D_KL, Anderson-Darling A^2 / A*^2 / p-value, KS, and DHT target entropy.
 * 3. Group masking coefficient & absence of N-recipient correlation.
 * 4. Energy overhead (uAh per delivered real message).
 * 5. Automatic CSV rotation, chunked ZIP splitting (<= 550 KB), and multi-part Firestore rules compliance.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ThesisTelemetryMetricsTest {

    private lateinit var appContext: Context
    private lateinit var tempDir: File
    private lateinit var settingsManager: AppSettingsManager
    private lateinit var mockDhtClient: ResearchTelemetryManagerTest.MockDhtClient

    @Before
    fun setUp() {
        appContext = RuntimeEnvironment.getApplication()
        appContext.getSharedPreferences(FirebaseResearchSync.PREFS_NAME, Context.MODE_PRIVATE)
            .edit().clear().commit()
        tempDir = File(
            System.getProperty("java.io.tmpdir") ?: ".",
            "pqchat_thesis_metrics_test_${System.nanoTime()}"
        ).apply { mkdirs() }
        settingsManager = AppSettingsManager()
        mockDhtClient = ResearchTelemetryManagerTest.MockDhtClient()
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    @Test
    fun `test replica survival distribution k_alive over K across 15m to 72h by RepublishMode`() {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            context = appContext,
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        val horizonsHours = listOf(0.25, 1.0, 6.0, 12.0, 24.0, 48.0, 72.0)
        val noRepubResponders = listOf(8, 5, 0, 0, 0, 0, 0)
        val ownRepubResponders = listOf(8, 8, 7, 7, 6, 6, 5)
        val crowdRepubResponders = listOf(8, 8, 8, 7, 7, 7, 6)

        val initialPutMs = 1_750_000_000_000L
        for (i in horizonsHours.indices) {
            val h = horizonsHours[i]
            val ts = initialPutMs + (h * 3_600_000.0).toLong()

            manager.recordTtlSample(
                TtlSampleEvent(
                    sessionId = manager.sessionId,
                    timestampEpochMs = ts,
                    targetPrefix = "aa00000$i",
                    initialPutEpochMs = initialPutMs,
                    elapsedMinutes = h * 60.0,
                    elapsedHours = h,
                    republishActive = false,
                    isAlive = noRepubResponders[i] > 0,
                    nodesQueried = 20,
                    nodesResponded = noRepubResponders[i],
                    replicationK = 8,
                    republishMode = RepublishMode.NO_REPUBLISH
                )
            )
            manager.recordTtlSample(
                TtlSampleEvent(
                    sessionId = manager.sessionId,
                    timestampEpochMs = ts,
                    targetPrefix = "bb00000$i",
                    initialPutEpochMs = initialPutMs,
                    elapsedMinutes = h * 60.0,
                    elapsedHours = h,
                    republishActive = true,
                    isAlive = ownRepubResponders[i] > 0,
                    nodesQueried = 20,
                    nodesResponded = ownRepubResponders[i],
                    replicationK = 8,
                    republishMode = RepublishMode.OWN_REPUBLISH
                )
            )
            manager.recordTtlSample(
                TtlSampleEvent(
                    sessionId = manager.sessionId,
                    timestampEpochMs = ts,
                    targetPrefix = "cc00000$i",
                    initialPutEpochMs = initialPutMs,
                    elapsedMinutes = h * 60.0,
                    elapsedHours = h,
                    republishActive = true,
                    isAlive = crowdRepubResponders[i] > 0,
                    nodesQueried = 20,
                    nodesResponded = crowdRepubResponders[i],
                    replicationK = 8,
                    republishMode = RepublishMode.CROWD_REPUBLISH
                )
            )
        }

        val points = manager.computeReplicaSurvivalByMode()
        assertEquals("7 horizons x 3 modes = 21 points", 21, points.size)

        val no15m = points.first { it.horizonLabel == "15m" && it.republishMode == RepublishMode.NO_REPUBLISH }
        assertEquals(1, no15m.totalSamples)
        assertEquals(1.0, no15m.meanReplicaSurvivalRatio, 0.001)
        assertEquals(100.0, no15m.binarySurvivalRatePercent, 0.01)

        val no1h = points.first { it.horizonLabel == "1h" && it.republishMode == RepublishMode.NO_REPUBLISH }
        assertEquals(5.0 / 8.0, no1h.meanReplicaSurvivalRatio, 0.001)

        val no72h = points.first { it.horizonLabel == "72h" && it.republishMode == RepublishMode.NO_REPUBLISH }
        assertEquals(1, no72h.totalSamples) // 48h sample must NOT double-count into 72h
        assertEquals(0.0, no72h.meanReplicaSurvivalRatio, 0.001)

        val own72h = points.first { it.horizonLabel == "72h" && it.republishMode == RepublishMode.OWN_REPUBLISH }
        assertEquals(1, own72h.totalSamples)
        assertEquals(5.0 / 8.0, own72h.meanReplicaSurvivalRatio, 0.001)

        val crowd72h = points.first { it.horizonLabel == "72h" && it.republishMode == RepublishMode.CROWD_REPUBLISH }
        assertEquals(1, crowd72h.totalSamples)
        assertEquals(6.0 / 8.0, crowd72h.meanReplicaSurvivalRatio, 0.001)

        val conv = manager.computeDhtConvergenceStats()
        assertEquals(21, conv.replicaSurvivalByMode.size)
        assertTrue(conv.replicaSurvivalRateKAliveOverK in 0.5..0.9)

        manager.stop()
    }

    @Test
    fun `test KL divergence and Anderson-Darling distinguish Poisson Exp(lambda) from periodic traffic`() {
        settingsManager.setAnonymousStatsEnabled(true)

        // 1. True Exponential(lambda = 1/10s) packet arrivals
        val poissonClock = AtomicLong(1_750_000_000_000L)
        val poissonManager = ResearchTelemetryManager(
            context = appContext,
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = File(tempDir, "poisson"),
            clockProvider = { poissonClock.get() }
        )

        val rng = Random(42L)
        val lambda = 0.1 // mean 10 s
        repeat(400) { i ->
            val u = rng.nextDouble().coerceIn(1e-9, 1.0 - 1e-9)
            val dtMs = (-(1.0 / lambda) * ln(u) * 1000.0).toLong().coerceAtLeast(1L)
            poissonClock.addAndGet(dtMs)
            val target = ByteArray(20).also { rng.nextBytes(it) }
            poissonManager.recordPacketEvent(
                role = if (i % 4 == 0) PacketRole.FIRST_SEND else PacketRole.COVER_DUMMY_SENT,
                target = target,
                poissonLambda = lambda,
                timestampEpochMs = poissonClock.get()
            )
        }

        val poissonStats = poissonManager.computeTrafficShapingStats()
        assertTrue("Poisson D_KL should be small (< 0.15 nats), was ${poissonStats.klDivergenceNats}", poissonStats.klDivergenceNats < 0.15)
        assertTrue("Poisson A*^2 should stay below 5% critical 1.341, was ${poissonStats.andersonDarlingA2Star}", poissonStats.andersonDarlingA2Star < 1.341)
        assertTrue("Poisson AD p-value should be > 0.05, was ${poissonStats.andersonDarlingPValue}", poissonStats.andersonDarlingPValue > 0.05)
        assertTrue("Poisson KS p-value should be > 0.05, was ${poissonStats.kolmogorovSmirnovPValue}", poissonStats.kolmogorovSmirnovPValue > 0.05)
        assertTrue("Nibble entropy should be close to 4.0 bits, was ${poissonStats.targetNibbleEntropyBits}", poissonStats.targetNibbleEntropyBits > 3.85)
        assertEquals(400, poissonStats.uniqueTargetPrefixesCount)
        assertEquals(1.0, poissonStats.targetUniqueRatio, 0.001)

        // 2. Deterministic periodic traffic (constant 5000 ms spacing)
        val periodicClock = AtomicLong(1_750_000_000_000L)
        val periodicManager = ResearchTelemetryManager(
            context = appContext,
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = File(tempDir, "periodic"),
            clockProvider = { periodicClock.get() }
        )

        val fixedTarget = ByteArray(20) { 0xAB.toByte() }
        repeat(200) {
            periodicClock.addAndGet(5_000L)
            periodicManager.recordPacketEvent(
                role = PacketRole.FIRST_SEND,
                target = fixedTarget,
                poissonLambda = 0.2,
                timestampEpochMs = periodicClock.get()
            )
        }

        val periodicStats = periodicManager.computeTrafficShapingStats()
        assertTrue("Periodic D_KL must be high (> 1.5 nats), was ${periodicStats.klDivergenceNats}", periodicStats.klDivergenceNats > 1.5)
        assertTrue("Periodic A*^2 must reject exponentiality (>> 1.957), was ${periodicStats.andersonDarlingA2Star}", periodicStats.andersonDarlingA2Star > 5.0)
        assertTrue("Periodic AD p-value must be < 0.01, was ${periodicStats.andersonDarlingPValue}", periodicStats.andersonDarlingPValue < 0.01)
        assertEquals(1, periodicStats.uniqueTargetPrefixesCount)
        assertEquals(0.0, periodicStats.targetEntropyBits, 0.001)

        poissonManager.stop()
        periodicManager.stop()
    }

    @Test
    fun `test group masking coefficient and absence of N-recipient correlation`() {
        settingsManager.setAnonymousStatsEnabled(true)

        // Case A: Masked PQChat groups (per-recipient unique slots + constant 8-slot cover padding)
        val maskedManager = ResearchTelemetryManager(
            context = appContext,
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = File(tempDir, "grp_masked")
        )
        val groupId = CryptoUtils.secureRandomBytes(16)
        for (m in listOf(2, 4, 6, 8)) {
            maskedManager.recordGroupMessageDelivery(
                groupId = groupId,
                groupSizeM = m,
                latencyMs = 120L,
                fanOutSkewMs = 2500L,
                uniqueTargetCount = m,
                interleavedCoverCount = 8 - m
            )
        }
        val maskedStats = maskedManager.computeGroupChatStats()
        assertEquals(1.0, maskedStats.recipientDecorrelationScore, 0.001)
        assertTrue("Group masking coefficient must be > 0.85, was ${maskedStats.groupMaskingCoefficient}", maskedStats.groupMaskingCoefficient > 0.85)
        assertEquals("Constant padded window must eliminate N-recipient correlation (r ~ 0)", 0.0, maskedStats.recipientCountCorrelation, 0.001)

        // Case B: Unmasked shared-target naive group (1 shared target, 0 cover)
        val unmaskedManager = ResearchTelemetryManager(
            context = appContext,
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = File(tempDir, "grp_unmasked")
        )
        for (m in listOf(2, 4, 6, 8)) {
            unmaskedManager.recordGroupMessageDelivery(
                groupId = groupId,
                groupSizeM = m,
                latencyMs = 80L,
                fanOutSkewMs = 0L,
                uniqueTargetCount = 1,
                interleavedCoverCount = 0
            )
        }
        val unmaskedStats = unmaskedManager.computeGroupChatStats()
        assertEquals(0.0, unmaskedStats.recipientDecorrelationScore, 0.001)
        assertEquals(0.0, unmaskedStats.groupMaskingCoefficient, 0.001)
        assertEquals("Unpadded varying group size leaks N linearly (r = 1.0)", 1.0, unmaskedStats.recipientCountCorrelation, 0.001)

        maskedManager.stop()
        unmaskedManager.stop()
    }

    @Test
    fun `test energy overhead uAh per delivered real message`() {
        settingsManager.setAnonymousStatsEnabled(true)

        var currentChargeUah = 4_000_000L
        val profiler = AndroidResourceProfiler(
            context = null,
            dhtClient = mockDhtClient,
            pollingStateProvider = { "BACKGROUND_IDLE" },
            lambdaProvider = { 1.0 / 480.0 },
            batteryCurrentProvider = { 150_000L },
            batteryChargeCounterProvider = { currentChargeUah },
            batteryLevelProvider = { 90 }
        )

        val manager = ResearchTelemetryManager(
            context = appContext,
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            resourceProfiler = profiler,
            baseDir = tempDir
        )

        profiler.takeSnapshot("session_energy")
        Thread.sleep(20L)
        currentChargeUah = 3_998_500L // 1500 uAh consumed
        profiler.takeSnapshot("session_energy")

        // 5 delivered real messages (3 via FIRST_SEND + ACK, 2 via direct recordMessageDelivered)
        repeat(3) {
            val target = CryptoUtils.secureRandomBytes(20)
            manager.recordPacketEvent(PacketRole.FIRST_SEND, target)
            manager.recordDeliveryAck(target)
        }
        repeat(2) {
            val target = CryptoUtils.secureRandomBytes(20)
            manager.recordMessageDelivered(target, latencyMs = 350L, lifecycleState = "BACKGROUND_IDLE", networkType = "WIFI")
        }

        val hwStats = manager.computeHardwareStats()
        assertEquals(1500.0, hwStats.totalEnergyDrainUah, 0.01)
        assertEquals(5, hwStats.deliveredRealMessagesCount)
        assertEquals(300.0, hwStats.energyOverheadUahPerDeliveredMsg, 0.01)
        assertEquals(500.0, hwStats.energyOverheadUahPerRealSentMsg, 0.01)

        manager.stop()
    }

    @Test
    fun `test automatic CSV rotation, chunked ZIP splitting under 550 KB, and Firestore multi-part sync`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)

        val syncedDocIds = mutableListOf<String>()
        val syncedPayloads = mutableListOf<Map<String, Any>>()
        val fakeClock = AtomicLong(1_760_000_000_000L)

        val customSync = FirebaseResearchSync(
            context = appContext,
            customAuthChecker = { true },
            customDocumentWriter = { docId, docData ->
                val (valid, err) = FirebaseResearchSync.validatePayloadWithReason(docData)
                assertTrue("Chunk document $docId must satisfy firestore.rules: $err", valid)
                syncedDocIds.add(docId)
                syncedPayloads.add(docData)
                true
            },
            wifiChecker = { true },
            clockProvider = { fakeClock.get() }
        )

        // Small rotation threshold (6 KB) & chunk limit (16 KB) to verify exact splitting & reassembly
        val chunkLimitBytes = 16_000L
        val manager = ResearchTelemetryManager(
            context = appContext,
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            firebaseSync = customSync,
            baseDir = tempDir,
            maxCsvFileBytes = 6_000L,
            maxChunkZipBytes = chunkLimitBytes,
            clockProvider = { fakeClock.get() }
        )

        val rng = Random(99L)
        repeat(220) { idx ->
            fakeClock.addAndGet(500L)
            val target = ByteArray(20).also { rng.nextBytes(it) }
            manager.recordPacketEvent(
                role = if (idx % 3 == 0) PacketRole.FIRST_SEND else PacketRole.COVER_DUMMY_SENT,
                target = target,
                seqNum = idx.toLong(),
                rttMs = 30L + (idx % 40),
                errorCode = "ERR_${CryptoUtils.toHex(target).take(12)}",
                timestampEpochMs = fakeClock.get()
            )
        }

        // 1. Verify automatic CSV rotation created rotated segments
        val rotated = manager.getRotatedCsvFiles()
        assertTrue("Expected rotated CSV files when maxCsvFileBytes=6000, found ${rotated.size}", rotated.isNotEmpty())
        val manifest = manager.generateManifestData()
        assertTrue(
            "Manifest checksums must include rotated files",
            rotated.all { manifest.fileChecksums.containsKey(it.name) }
        )

        // 2. Build chunked ZIP bundles strictly <= chunkLimitBytes
        val chunkZips = manager.buildChunkedResearchBundles(maxChunkBytes = chunkLimitBytes)
        assertTrue("Expected multiple ZIP chunks (>1), got ${chunkZips.size}", chunkZips.size > 1)

        var sawSessionManifest = false
        var sawChunkManifestCount = 0
        val reconstructedPacketRows = mutableListOf<String>()
        for (zipFile in chunkZips) {
            assertTrue("Chunk ${zipFile.name} (${zipFile.length()} B) must not exceed $chunkLimitBytes B", zipFile.length() <= chunkLimitBytes)
            ZipFile(zipFile).use { zf ->
                val entries = zf.entries().toList()
                val names = entries.map { it.name }.toSet()
                if ("session_manifest.json" in names) sawSessionManifest = true
                assertTrue("Every chunk must include chunk_manifest.json", "chunk_manifest.json" in names)
                sawChunkManifestCount++

                for (entry in entries) {
                    if (entry.name.contains("packet_events") && entry.name.endsWith(".csv")) {
                        val lines = zf.getInputStream(entry).bufferedReader().readLines()
                        assertEquals("Every CSV slice must repeat the exact CSV header", PacketTelemetryEvent.CSV_HEADER, lines.first())
                        reconstructedPacketRows.addAll(lines.drop(1))
                    }
                }
            }
        }
        assertTrue("session_manifest.json must be present in chunk bundle", sawSessionManifest)
        assertEquals(chunkZips.size, sawChunkManifestCount)
        assertEquals("All 220 packet events must survive rotation and chunking without loss", 220, reconstructedPacketRows.size)

        // 3. Verify computeChunkedSessionPayloads never returns OMITTED_EXCEEDS_600KB and syncs all parts
        val payloads = manager.computeChunkedSessionPayloads(maxChunkBytes = chunkLimitBytes)
        assertEquals(chunkZips.size, payloads.size)
        for ((idx, pair) in payloads.withIndex()) {
            val metrics = pair.second
            assertEquals("CHUNKED_ZIP_BASE64", metrics["bundleZipStatus"])
            assertNotEquals("OMITTED_EXCEEDS_600KB", metrics["bundleZipBase64"])
            assertEquals(idx + 1, metrics["bundleChunkIndex"])
            assertEquals(payloads.size, metrics["bundleTotalChunks"])
            val decoded = Base64.getDecoder().decode(metrics["bundleZipBase64"] as String)
            assertTrue(decoded.size.toLong() <= chunkLimitBytes)
        }

        // Verify forceFirebaseSync uploads all chunk parts cleanly
        val syncOk = customSync.syncResearchSessionChunks(manager.sessionId, payloads, isManual = true)
        assertTrue("Multi-chunk Firestore sync must succeed", syncOk)
        assertEquals(payloads.size, syncedDocIds.size)
        assertEquals(manager.sessionId, syncedDocIds[0])
        assertTrue(syncedDocIds[1].endsWith("_part2_of_${payloads.size}"))

        manager.stop()
    }

    @Test
    fun `test 550 KB default chunk cap splits real oversized bundle for Firestore`() {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            context = appContext,
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        // Create a high-entropy (>550 KB compressed) packet CSV directly in telemetry dir to test default 550 KB ceiling
        val rng = Random(1234L)
        val sb = StringBuilder()
        sb.append(PacketTelemetryEvent.CSV_HEADER).append("\n")
        val rowCount = 12_000
        repeat(rowCount) { idx ->
            val buf1 = ByteArray(72)
            val buf2 = ByteArray(48)
            rng.nextBytes(buf1)
            rng.nextBytes(buf2)
            val token1 = Base64.getUrlEncoder().withoutPadding().encodeToString(buf1)
            val token2 = Base64.getUrlEncoder().withoutPadding().encodeToString(buf2)
            val prefixHex = CryptoUtils.toHex(buf2).take(8)
            sb.append("${token2}_${idx},${manager.sessionId},${1750000000000L + idx * 1000L},2026-11-17T00:00:00.000Z,COVER_DUMMY_SENT,\"Dummy\",$prefixHex,$idx,900,${30 + (idx % 100)},24,8,3,true,0,0,WIFI,BACKGROUND_IDLE,8,0.002083,120000,90,\"$token1\"\n")
        }
        manager.packetEventsCsvFile.writeText(sb.toString(), Charsets.UTF_8)

        val chunks = manager.buildChunkedResearchBundles()
        assertTrue("High-entropy multi-day CSV (>550 KB compressed) must split into >= 2 chunks, got ${chunks.size}", chunks.size >= 2)
        for (chunk in chunks) {
            assertTrue(
                "Every default chunk (${chunk.length()} B) must fit <= 550 KB (${ResearchTelemetryManager.DEFAULT_MAX_CHUNK_ZIP_BYTES} B)",
                chunk.length() <= ResearchTelemetryManager.DEFAULT_MAX_CHUNK_ZIP_BYTES
            )
        }

        val payloads = manager.computeChunkedSessionPayloads()
        assertEquals(chunks.size, payloads.size)
        for ((_, metrics) in payloads) {
            val doc = mapOf(
                "sessionId" to manager.sessionId,
                "timestamp" to 1_750_000_000_001L,
                "deviceInfo" to payloads[0].first,
                "metrics" to metrics,
                "schemaVersion" to FirebaseResearchSync.EXPECTED_SCHEMA_VERSION
            )
            val (valid, err) = FirebaseResearchSync.validatePayloadWithReason(doc)
            assertTrue("550 KB chunk payload must satisfy firestore.rules: $err", valid)
            assertNotEquals("OMITTED_EXCEEDS_600KB", metrics["bundleZipBase64"])
        }

        manager.stop()
    }
}
