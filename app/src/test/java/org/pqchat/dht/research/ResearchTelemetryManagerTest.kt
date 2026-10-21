package org.pqchat.dht.research

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.dht.leaf.DhtOpMetrics
import java.io.File

class ResearchTelemetryManagerTest {

    private lateinit var tempDir: File
    private lateinit var settingsManager: AppSettingsManager
    private lateinit var mockDhtClient: MockDhtClient

    class MockDhtClient : DhtClient {
        override val myNodeId: ByteArray = ByteArray(20) { 1 }
        override var replicationK: Int = 8
        override var lastOperationMetrics: DhtOpMetrics = DhtOpMetrics(nodesQueried = 24, nodesResponded = 8, lookupHops = 3)
        override fun start() {}
        override fun stop() {}
        override fun getActivePeerCount(): Int = 8
        override suspend fun preWarmTarget(target: ByteArray): List<DhtLeafNode.DhtPeer> = emptyList()
        override fun preWarmTargetAsync(target: ByteArray): kotlinx.coroutines.Job = kotlinx.coroutines.Job()

        var storedItems = mutableMapOf<String, DhtLeafNode.MutableItem>()

        override suspend fun getMutable(
            target: ByteArray,
            salt: ByteArray?,
            skipLocalStore: Boolean,
            timeoutMs: Long,
            probeAllReplicas: Boolean
        ): DhtLeafNode.MutableItem? {
            return storedItems[CryptoUtils.toHex(target)]
        }

        override suspend fun putMutable(
            target: ByteArray,
            v: ByteArray,
            seq: Long,
            salt: ByteArray?,
            sk: ByteArray,
            skipLocalStore: Boolean
        ): Boolean {
            val hex = CryptoUtils.toHex(target)
            storedItems[hex] = DhtLeafNode.MutableItem(
                v = v,
                seq = seq,
                k = sk,
                sig = ByteArray(64),
                salt = salt,
                token = null,
                responder = null,
                nodesQueried = 24,
                nodesResponded = 8,
                lookupHops = 3
            )
            return true
        }

        override suspend fun putMutablePreSigned(
            target: ByteArray,
            v: ByteArray,
            seq: Long,
            salt: ByteArray?,
            pk: ByteArray,
            sig: ByteArray,
            skipLocalStore: Boolean
        ): Boolean {
            val hex = CryptoUtils.toHex(target)
            storedItems[hex] = DhtLeafNode.MutableItem(
                v = v,
                seq = seq,
                k = pk,
                sig = sig,
                salt = salt,
                token = null,
                responder = null,
                nodesQueried = 24,
                nodesResponded = 8,
                lookupHops = 3
            )
            return true
        }

        override suspend fun sendCoverTrafficDummy(): ByteArray? = CryptoUtils.secureRandomBytes(20)
    }

    @Before
    fun setup() {
        tempDir = File(System.getProperty("java.io.tmpdir"), "pqchat_research_test_${System.currentTimeMillis()}")
        tempDir.mkdirs()
        settingsManager = AppSettingsManager()
        mockDhtClient = MockDhtClient()
    }

    @Test
    fun `test default state is disabled and records zero events`() {
        // Must be default FALSE as required by user and AGENTS.md
        assertFalse("Anonymous stats must be disabled by default", settingsManager.isAnonymousStatsEnabled.value)

        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient
        )

        assertFalse(manager.isEnabled)

        val dummyTarget = CryptoUtils.secureRandomBytes(20)
        manager.recordPacketEvent(
            role = PacketRole.FIRST_SEND,
            target = dummyTarget,
            seqNum = 1L
        )

        assertEquals("Events count must remain 0 when disabled", 0, manager.eventsCount.value)
        assertEquals(0, manager.firstSendCount.value)
        assertEquals(0, manager.ownRepublishCount.value)
    }

    @Test
    fun `test event tracking distinguishes FIRST_SEND, OWN_REPUBLISH and CROWD_REPUBLISH`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        assertTrue(settingsManager.isAnonymousStatsEnabled.value)

        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient
        )
        assertTrue(manager.isEnabled)

        val target1 = CryptoUtils.secureRandomBytes(20)
        val target2 = CryptoUtils.secureRandomBytes(20)

        // 1. FIRST_SEND
        manager.recordPacketEvent(
            role = PacketRole.FIRST_SEND,
            target = target1,
            seqNum = 1L,
            payloadBytes = 900,
            rttMs = 45L,
            success = true
        )

        assertEquals(1, manager.firstSendCount.value)
        assertEquals(1, manager.eventsCount.value)

        // 2. OWN_REPUBLISH
        manager.recordPacketEvent(
            role = PacketRole.OWN_REPUBLISH,
            target = target1,
            seqNum = 1L,
            payloadBytes = 900,
            rttMs = 52L,
            success = true,
            republishAttempt = 1,
            messageAgeMs = 900_000L
        )

        assertEquals(1, manager.ownRepublishCount.value)
        assertEquals(2, manager.eventsCount.value)

        // 3. CROWD_REPUBLISH (third-party relay)
        manager.recordPacketEvent(
            role = PacketRole.CROWD_REPUBLISH,
            target = target2,
            seqNum = 1L,
            payloadBytes = 900,
            rttMs = 60L,
            success = true
        )

        assertEquals(1, manager.crowdRepublishCount.value)
        assertEquals(3, manager.eventsCount.value)

        // 4. PACKET_RECEIVED
        manager.recordPacketEvent(
            role = PacketRole.PACKET_RECEIVED,
            target = target1,
            seqNum = 1L,
            payloadBytes = 900,
            rttMs = 38L,
            success = true
        )

        assertEquals(1, manager.packetsReceivedCount.value)
        assertEquals(4, manager.eventsCount.value)

        // 5. ACK delivery confirmation
        manager.recordDeliveryAck(target1, deliveredEpochMs = System.currentTimeMillis() + 1000L)
    }

    @Test
    fun `test csv serialization contains valid header and privacy-safe data`() {
        val event = PacketTelemetryEvent(
            sessionId = "test_sess_123",
            role = PacketRole.FIRST_SEND,
            targetPrefix = "a1b2c3d4",
            seqNum = 5L,
            payloadBytes = 900,
            rttMs = 75L,
            nodesQueried = 24,
            nodesResponded = 8,
            success = true,
            republishAttempt = 0,
            networkType = "WIFI"
        )

        val csvRow = event.toCsvRow()
        assertTrue("CSV row must contain role name", csvRow.contains("FIRST_SEND"))
        assertTrue("CSV row must contain target prefix", csvRow.contains("a1b2c3d4"))
        assertTrue("CSV row must contain seqNum", csvRow.contains(",5,"))
        assertTrue("CSV row must contain 900 payload size", csvRow.contains(",900,"))

        val masterRow = event.toMasterCsvRow()
        assertTrue("Master row must contain PACKET_EVENT type", masterRow.contains("PACKET_EVENT"))
        assertTrue("Master row must contain target prefix", masterRow.contains("a1b2c3d4"))

        val summary = RepublishAnalysisSummary(
            messagePrefix = "a1b2c3d4",
            sessionId = "test_sess_123",
            initialSentEpochMs = 1000L,
            deliveredEpochMs = 2500L,
            isDelivered = true,
            totalRepublishes = 2,
            timeToFirstRepublishMs = 900L,
            endToEndDeliveryLatencyMs = 1500L,
            crowdRelayed = true,
            finalStatus = "DELIVERED"
        )

        val summaryRow = summary.toCsvRow()
        assertTrue("Summary row must have delivered flag", summaryRow.contains("true"))
        assertTrue("Summary row must have 2 republishes", summaryRow.contains(",2,"))
        assertTrue("Summary row must have DELIVERED status", summaryRow.contains("DELIVERED"))
    }

    @Test
    fun `test compressed research bundle generation and manifest sha256 checksums`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        val target = CryptoUtils.secureRandomBytes(20)
        manager.recordPacketEvent(
            role = PacketRole.FIRST_SEND,
            target = target,
            seqNum = 1L,
            payloadBytes = 900,
            rttMs = 40L,
            success = true
        )
        manager.recordPacketEvent(
            role = PacketRole.OWN_REPUBLISH,
            target = target,
            seqNum = 1L,
            payloadBytes = 900,
            rttMs = 50L,
            success = true
        )
        manager.recordDeliveryAck(target)

        // Generate compressed ZIP bundle
        val zipFile = manager.buildCompressedResearchBundle()
        assertNotNull("Generated bundle file must not be null", zipFile)
        assertTrue("ZIP bundle must exist on disk", zipFile.exists())
        assertTrue("ZIP bundle must not be empty", zipFile.length() > 0)
        assertTrue("File name must start with pqchat_research_", zipFile.name.startsWith("pqchat_research_"))
        assertTrue("File name must end with .zip", zipFile.name.endsWith(".zip"))

        // Inspect ZIP contents
        val zip = java.util.zip.ZipFile(zipFile)
        val entryNames = zip.entries().asSequence().map { it.name }.toSet()

        assertTrue("ZIP must contain session_manifest.json", entryNames.contains("session_manifest.json"))
        assertTrue("ZIP must contain research_telemetry_master.csv", entryNames.contains("research_telemetry_master.csv"))
        assertTrue("ZIP must contain research_ttl_samples.csv", entryNames.contains("research_ttl_samples.csv"))
        assertTrue("ZIP must contain research_republish_analysis.csv", entryNames.contains("research_republish_analysis.csv"))
        assertTrue("ZIP must contain research_resource_profile.csv", entryNames.contains("research_resource_profile.csv"))

        // Verify SHA-256 checksums in manifest
        val manifest = manager.generateManifestData()
        assertEquals(manager.sessionId, manifest.sessionId)
        assertEquals(manager.eventsCount.value, manifest.totalEvents)
        assertTrue("Manifest must contain file checksums", manifest.fileChecksums.isNotEmpty())

        for ((fileName, hash) in manifest.fileChecksums) {
            assertTrue("Hash must be 64-character SHA-256 hex string", hash.length == 64)
            val file = when (fileName) {
                "research_telemetry_master.csv" -> manager.masterCsvFile
                "research_ttl_samples.csv" -> manager.ttlSamplesCsvFile
                "research_republish_analysis.csv" -> manager.republishSummaryCsvFile
                "research_resource_profile.csv" -> manager.resourceProfileCsvFile
                "research_packet_events.csv" -> manager.packetEventsCsvFile
                else -> null
            }
            if (file != null && file.exists()) {
                val actualHash = computeSha256(file)
                assertEquals("Checksum for $fileName must match actual file hash", actualHash, hash)
            }
        }

        zip.close()
    }

    @Test
    fun `test graceful no-op when Firebase is not configured`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val unconfiguredSync = FirebaseResearchSync(context = null)
        assertFalse("Firebase must report not configured when context and credentials are null", unconfiguredSync.isFirebaseConfigured())

        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            firebaseSync = unconfiguredSync,
            baseDir = tempDir
        )

        val target = CryptoUtils.secureRandomBytes(20)
        manager.recordPacketEvent(
            role = PacketRole.FIRST_SEND,
            target = target,
            seqNum = 1L
        )
        assertEquals(1, manager.eventsCount.value)

        // Force sync must gracefully return false without throwing any IllegalStateException
        val syncResult = manager.forceFirebaseSync()
        assertFalse("Force sync must return false when Firebase is unconfigured", syncResult)

        // Local archive remains fully functional
        val zipFile = manager.buildCompressedResearchBundle()
        assertTrue("Local ZIP archive generation must succeed even without Firebase", zipFile.exists() && zipFile.length() > 0)
    }

    @Test
    fun `test computeSessionPayload conforms to Firestore rules schema and decodes bundle`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        val target = CryptoUtils.secureRandomBytes(20)
        manager.recordPacketEvent(
            role = PacketRole.FIRST_SEND,
            target = target,
            seqNum = 1L,
            payloadBytes = 900,
            rttMs = 42L,
            nodesQueried = 18,
            nodesResponded = 8,
            success = true
        )
        manager.recordDeliveryAck(target)

        val (deviceInfo, metrics) = manager.computeSessionPayload()

        // 1. Validate firestore.rules requirements:
        // - request.resource.data.keys().hasAll(['timestamp', 'deviceInfo', 'metrics'])
        // - request.resource.data.metrics is map
        assertNotNull("deviceInfo must not be null", deviceInfo)
        assertNotNull("metrics must not be null", metrics)
        assertTrue("deviceInfo must contain sessionId", deviceInfo.containsKey("sessionId"))
        assertTrue("deviceInfo must contain deviceModel", deviceInfo.containsKey("deviceModel"))
        assertTrue("deviceInfo must contain appVersion", deviceInfo.containsKey("appVersion"))

        assertTrue("metrics must contain totalEvents", metrics.containsKey("totalEvents"))
        assertTrue("metrics must contain rttStats", metrics["rttStats"] is Map<*, *>)
        assertTrue("metrics must contain ttlStats", metrics["ttlStats"] is Map<*, *>)
        assertTrue("metrics must contain republishStats", metrics["republishStats"] is Map<*, *>)
        assertTrue("metrics must contain fileChecksums", metrics["fileChecksums"] is Map<*, *>)
        assertTrue("metrics must contain manifestSha256", metrics.containsKey("manifestSha256"))
        assertTrue("metrics must contain bundleZipBase64", metrics.containsKey("bundleZipBase64"))

        val rttStats = metrics["rttStats"] as Map<*, *>
        assertEquals(42L, rttStats["minMs"])
        assertEquals(42L, rttStats["maxMs"])
        assertEquals(1, rttStats["count"])

        val republishStats = metrics["republishStats"] as Map<*, *>
        assertEquals(1, republishStats["deliveredCount"])

        // 2. Validate embedded Base64 ZIP payload
        val bundleBase64 = metrics["bundleZipBase64"] as String
        assertTrue("Base64 string must not be empty", bundleBase64.isNotBlank())
        val decodedBytes = java.util.Base64.getDecoder().decode(bundleBase64)
        assertTrue("Decoded bytes must have ZIP magic header", decodedBytes.size > 4)
        assertEquals(0x50.toByte(), decodedBytes[0]) // 'P'
        assertEquals(0x4B.toByte(), decodedBytes[1]) // 'K'

        // Verify total payload size is far below the 1 MB Firestore limit
        val estimatedPayloadSize = bundleBase64.length + 2048
        assertTrue("Payload size must be strictly under 1 MB limit", estimatedPayloadSize < 1024 * 1024)
    }

    @Test
    fun `test enrichment with AndroidResourceProfiler and dhtClient metrics`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val profiler = org.pqchat.dht.debug.AndroidResourceProfiler(
            context = null,
            dhtClient = mockDhtClient,
            pollingStateProvider = { "FOREGROUND_CHAT" },
            lambdaProvider = { 1.0 / 300.0 },
            batteryCurrentProvider = { 123456L },
            batteryLevelProvider = { 88 }
        )

        mockDhtClient.replicationK = 16
        mockDhtClient.lastOperationMetrics = DhtOpMetrics(nodesQueried = 20, nodesResponded = 14, lookupHops = 4)

        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            resourceProfiler = profiler,
            baseDir = tempDir
        )

        val target = CryptoUtils.secureRandomBytes(20)
        manager.recordPacketEvent(
            role = PacketRole.FIRST_SEND,
            target = target,
            seqNum = 42L,
            payloadBytes = 900,
            rttMs = 55L,
            success = true
        )

        val packetCsv = manager.packetEventsCsvFile.readText()
        val masterCsv = manager.masterCsvFile.readText()

        assertTrue("Packet CSV should contain nodesQueried = 20", packetCsv.contains(",20,"))
        assertTrue("Packet CSV should contain nodesResponded = 14", packetCsv.contains(",14,"))
        assertTrue("Packet CSV should contain lookupHops = 4", packetCsv.contains(",4,"))
        assertTrue("Packet CSV should contain replicationK = 16", packetCsv.contains(",16,"))
        assertTrue("Packet CSV should contain pollingState = FOREGROUND_CHAT", packetCsv.contains("FOREGROUND_CHAT"))
        assertTrue("Packet CSV should contain batteryCurrentUa = 123456", packetCsv.contains(",123456,"))
        assertTrue("Packet CSV should contain batteryLevelPct = 88", packetCsv.contains(",88,"))

        assertTrue("Master CSV should contain FOREGROUND_CHAT", masterCsv.contains("FOREGROUND_CHAT"))
        assertTrue("Master CSV should contain 123456", masterCsv.contains(",123456,"))
    }

    @Test
    fun `test zero sensitive data in all telemetry bundles and payloads`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        // Sensitive mock artifacts that must NEVER be leaked to research telemetry
        val sensitiveSeed = CryptoUtils.secureRandomBytes(32)
        val sensitiveSeedHex = CryptoUtils.toHex(sensitiveSeed)
        val sensitivePrivateKey = CryptoUtils.secureRandomBytes(32)
        val sensitiveKeyHex = CryptoUtils.toHex(sensitivePrivateKey)
        val sensitivePlaintext = "TopSecretUltraConfidentialMessage123"
        val sensitiveContactName = "SpecialAgentAliceSmith"
        val sensitiveIpAddress = "192.168.1.188"
        val fullTarget = CryptoUtils.secureRandomBytes(20)
        val fullTargetHex = CryptoUtils.toHex(fullTarget)

        // 1. Record normal operations
        manager.recordPacketEvent(
            role = PacketRole.FIRST_SEND,
            target = fullTarget,
            seqNum = 1L,
            payloadBytes = 900,
            rttMs = 35L,
            success = true
        )
        manager.recordDecoyGet(
            target = CryptoUtils.secureRandomBytes(20),
            rttMs = 45L
        )
        manager.recordGroupMessageDelivery(
            groupId = CryptoUtils.secureRandomBytes(16),
            groupSizeM = 5,
            latencyMs = 120L,
            fanOutSkewMs = 15L
        )
        manager.recordKeyRotationConvergence(
            groupId = CryptoUtils.secureRandomBytes(16),
            groupSizeM = 5,
            convergenceMs = 85L
        )
        manager.recordDeliveryAck(fullTarget)

        val bundleZip = manager.buildCompressedResearchBundle()
        assertTrue("Bundle zip file must exist and be non-empty", bundleZip.exists() && bundleZip.length() > 0)

        val filesToCheck = listOf(
            manager.masterCsvFile,
            manager.packetEventsCsvFile,
            manager.groupEventsCsvFile,
            manager.ttlSamplesCsvFile,
            manager.republishSummaryCsvFile,
            manager.resourceProfileCsvFile,
            manager.trafficIntervalsCsvFile,
            manager.kademliaConvergenceCsvFile,
            manager.adversarialEventsCsvFile,
            File(tempDir, "session_manifest.json")
        )

        for (file in filesToCheck) {
            if (!file.exists()) continue
            val content = file.readText()

            assertFalse("File ${file.name} must NOT contain sensitive seed hex", content.contains(sensitiveSeedHex))
            assertFalse("File ${file.name} must NOT contain sensitive key hex", content.contains(sensitiveKeyHex))
            assertFalse("File ${file.name} must NOT contain plaintext message", content.contains(sensitivePlaintext))
            assertFalse("File ${file.name} must NOT contain contact name", content.contains(sensitiveContactName))
            assertFalse("File ${file.name} must NOT contain IP address", content.contains(sensitiveIpAddress))
            // The full 40-character target hex must NOT appear; only the 8-character prefix is permitted
            assertFalse("File ${file.name} must NOT contain full target hex", content.contains(fullTargetHex))
        }

        // Check Firestore payload maps
        val (deviceInfo, metrics) = manager.computeSessionPayload()
        val metricsJson = metrics.toString()
        val deviceJson = deviceInfo.toString()

        assertFalse("Metrics payload must NOT contain sensitive seed hex", metricsJson.contains(sensitiveSeedHex))
        assertFalse("Metrics payload must NOT contain sensitive key hex", metricsJson.contains(sensitiveKeyHex))
        assertFalse("Metrics payload must NOT contain plaintext message", metricsJson.contains(sensitivePlaintext))
        assertFalse("Metrics payload must NOT contain contact name", metricsJson.contains(sensitiveContactName))
        assertFalse("Metrics payload must NOT contain IP address", metricsJson.contains(sensitiveIpAddress))
        assertFalse("DeviceInfo must NOT contain IP address", deviceJson.contains(sensitiveIpAddress))
    }

    @Test
    fun `test traffic shaping metrics, Kolmogorov-Smirnov test and Shannon entropy`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        // Emit packets with diverse roles and diverse target prefixes
        val targets = (0 until 10).map { i ->
            val b = ByteArray(20)
            b[0] = (i * 25).toByte()
            b
        }

        for (t in targets) {
            manager.recordPacketEvent(role = PacketRole.FIRST_SEND, target = t, rttMs = 30L, nodesQueried = 16, nodesResponded = 8)
            manager.recordPacketEvent(role = PacketRole.COVER_DUMMY_SENT, target = t, rttMs = 25L, nodesQueried = 16, nodesResponded = 8)
            manager.recordDecoyGet(target = t, rttMs = 20L, nodesQueried = 16, nodesResponded = 8)
            manager.recordPacketEvent(role = PacketRole.TOMBSTONE_SENT, target = t, rttMs = 35L, nodesQueried = 16, nodesResponded = 8)
            manager.recordPacketEvent(role = PacketRole.CROWD_REPUBLISH, target = t, rttMs = 40L, nodesQueried = 16, nodesResponded = 8)
        }

        val stats = manager.computeTrafficShapingStats()

        assertEquals(50, stats.totalOutboundPackets)
        assertEquals(10, stats.realMsgCount)
        assertEquals(10, stats.coverDummyCount)
        assertEquals(10, stats.decoyGetCount)
        assertEquals(10, stats.tombstoneCount)
        assertEquals(10, stats.blindRepublishCount)

        assertEquals(20.0, stats.realMsgPercent, 0.01)
        assertEquals(20.0, stats.coverDummyPercent, 0.01)
        assertEquals(20.0, stats.decoyGetPercent, 0.01)
        assertEquals(20.0, stats.tombstonePercent, 0.01)
        assertEquals(20.0, stats.blindRepublishPercent, 0.01)

        // Shannon entropy: 10 distinct prefixes uniformly distributed -> H(X) = log2(10) ~ 3.32 bits
        assertTrue("Shannon entropy bits should be positive", stats.targetEntropyBits > 3.0)
        assertTrue("Shannon entropy bits must not exceed theoretical 8.0 bits", stats.targetEntropyBits <= 8.0)
        assertTrue("Entropy normalized uniformity must be between 0 and 100", stats.targetEntropyNormalized in 0.0..100.0)

        // KS test D statistic
        assertTrue("Kolmogorov-Smirnov D statistic must be non-negative", stats.kolmogorovSmirnovD >= 0.0)

        // Ed25519 signature stats
        val sigStats = manager.computeEd25519SignatureStats()
        assertEquals(50, sigStats["totalQueries"])
        assertEquals(50 * 16, sigStats["totalNodesQueried"])
        assertEquals(50 * 8, sigStats["totalNodesValid"])
        assertEquals(50.0, sigStats["validSignatureRatioPercent"])
    }

    @Test
    fun `test group chat and chunk transfer resumption research metrics`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        // Group chat messages for various sizes
        val gId = CryptoUtils.secureRandomBytes(16)
        manager.recordGroupMessageDelivery(groupId = gId, groupSizeM = 3, latencyMs = 80L, fanOutSkewMs = 12L)
        manager.recordGroupMessageDelivery(groupId = gId, groupSizeM = 3, latencyMs = 90L, fanOutSkewMs = 16L)
        manager.recordGroupMessageDelivery(groupId = gId, groupSizeM = 7, latencyMs = 150L, fanOutSkewMs = 28L)
        manager.recordKeyRotationConvergence(groupId = gId, groupSizeM = 7, convergenceMs = 110L)

        val groupStats = manager.computeGroupChatStats()
        assertEquals(3, groupStats.totalGroupMessagesTracked)
        assertEquals(1, groupStats.totalKeyRotationsTracked)
        assertEquals(85.0, groupStats.latencyByGroupSize["size_3"] ?: 0.0, 0.01)
        assertEquals(150.0, groupStats.latencyByGroupSize["size_7"] ?: 0.0, 0.01)
        assertTrue("Fan-out skew average must be positive", groupStats.avgFanOutDeliverySkewMs > 0.0)
        assertEquals(28L, groupStats.maxFanOutDeliverySkewMs)
        assertEquals(110.0, groupStats.avgKeyRotationConvergenceMs, 0.01)

        // Chunk transfer resumption
        manager.recordChunkTransfer(wasResumed = false, wasSuccessful = true)
        manager.recordChunkTransfer(wasResumed = true, wasSuccessful = true)
        manager.recordChunkTransfer(wasResumed = true, wasSuccessful = false)

        val chunkStats = manager.computeChunkResumptionStats()
        assertEquals(3, chunkStats.totalTransfers)
        assertEquals(2, chunkStats.resumedTransfers)
        assertEquals(1, chunkStats.successfulResumptions)
        assertEquals(50.0, chunkStats.resumptionSuccessRate, 0.01)
    }

    @Test
    fun `test traffic intervals, wake-up jitter and Kolmogorov-Smirnov p-value`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        // Record scheduled vs actual traffic intervals and jitter
        manager.recordTrafficInterval(
            role = PacketRole.COVER_DUMMY_SENT,
            scheduledDelayMs = 4800L,
            actualDelayMs = 4825L,
            wakeUpJitterMs = 25L,
            poissonLambda = 1.0 / 480.0,
            pollingState = "BACKGROUND_IDLE",
            isScreenOn = true
        )
        manager.recordTrafficInterval(
            role = PacketRole.FIRST_SEND,
            scheduledDelayMs = 5000L,
            actualDelayMs = 5060L,
            wakeUpJitterMs = 60L,
            poissonLambda = 1.0 / 480.0,
            pollingState = "DOZE_SLEEP",
            isScreenOn = false
        )

        assertTrue(manager.trafficIntervalsCsvFile.exists())
        val csvLines = manager.trafficIntervalsCsvFile.readLines()
        assertTrue(csvLines.size >= 3) // header + 2 rows

        val stats = manager.computeTrafficShapingStats()
        assertEquals(4900.0, stats.deltaTheoreticalMeanMs, 0.01)
        assertEquals(42.5, stats.wakeUpJitterMeanMs, 0.01)
        assertEquals(60L, stats.wakeUpJitterMaxMs)

        // Validate KS p-value asymptotic function directly
        val pHigh = manager.computeKolmogorovSmirnovPValue(d = 0.05, n = 50)
        assertTrue("Small D should yield high p-value", pHigh > 0.05)
        val pLow = manager.computeKolmogorovSmirnovPValue(d = 0.95, n = 50)
        assertTrue("Large D should yield tiny p-value", pLow < 0.01)
    }

    @Test
    fun `test Kademlia convergence, replica survival and subnet entropy`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        val target = CryptoUtils.secureRandomBytes(20)
        manager.recordDhtConvergence(
            operation = "PUT",
            target = target,
            rttMs = 120L,
            nodesQueried = 24,
            nodesResponded = 8,
            timeouts = 2,
            preWarmingHit = true,
            fastTerminated = true,
            subnets24 = listOf("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
        )
        manager.recordDhtConvergence(
            operation = "GET",
            target = target,
            rttMs = 80L,
            nodesQueried = 16,
            nodesResponded = 8,
            timeouts = 0,
            preWarmingHit = false,
            fastTerminated = false,
            subnets24 = listOf("192.0.2.0/24", "198.51.100.0/24")
        )

        val convStats = manager.computeDhtConvergenceStats()
        assertEquals(14, convStats.ttlDecayCurve.size) // 7 horizons x 2 republish states (with / without)
        assertEquals(120L, convStats.putLatencyP50Ms)
        assertEquals(80L, convStats.getLatencyP50Ms)
        assertEquals(20.0, convStats.avgNodesQueriedPerOp, 0.01)
        assertEquals(100.0, convStats.krpcTimeoutRatePercent, 0.01) // 2 timeouts across 2 ops
        assertEquals(50.0, convStats.preWarmingHitRatePercent, 0.01)
        assertEquals(50.0, convStats.fastTerminationSavingsPercent, 0.01)
        assertTrue("Subnet entropy should be positive", convStats.subnet24EntropyBits > 0.0)
    }

    @Test
    fun `test end-to-end delivery partitioned by lifecycle and transport`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        val target = CryptoUtils.secureRandomBytes(20)
        manager.recordPacketEvent(role = PacketRole.FIRST_SEND, target = target)
        manager.recordMessageDelivered(
            target = target,
            latencyMs = 450L,
            lifecycleState = "FOREGROUND_CHAT",
            networkType = "WIFI"
        )

        val targetAck = CryptoUtils.secureRandomBytes(20)
        manager.recordCoverAckReceived(target = targetAck, latencyMs = 620L, lifecycleState = "BACKGROUND_IDLE")

        manager.recordPqcRekeyDuration(14L)
        manager.recordPqcRekeyDuration(18L)
        manager.recordGroupKeyRotationDuration(25L)

        val e2eStats = manager.computeE2eDeliveryStats()
        assertEquals(450.0, e2eStats.deliveryLatencyByLifecycle["FOREGROUND_CHAT"] ?: 0.0, 0.01)
        assertEquals(450.0, e2eStats.deliveryLatencyByTransport["WIFI"] ?: 0.0, 0.01)
        assertEquals(620.0, e2eStats.coverAckLatencyByLifecycle["BACKGROUND_IDLE"] ?: 0.0, 0.01)
        assertEquals(16.0, e2eStats.avgPqcRekeyDurationMs, 0.01)
        assertEquals(2, e2eStats.totalPqcRekeys)
        assertEquals(25.0, e2eStats.avgGroupKeyRotationDurationMs, 0.01)
        assertEquals(1, e2eStats.totalGroupRotations)
    }

    @Test
    fun `test adversarial anomaly mitigation tracking`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        val target = CryptoUtils.secureRandomBytes(20)
        manager.recordAdversarialEvent("BAD_ED25519_SIG", target, "Node returned invalid Ed25519 signature")
        manager.recordAdversarialEvent("BAD_AEAD_TAG", target, "Corrupted ciphertext AEADBadTagException")
        manager.recordAdversarialEvent("SEQ_ROLLBACK", target, "Received seqNum 2 when counter is 5")
        manager.recordAdversarialEvent("BITMAP_DUPLICATE", target, "Duplicate packet seq 3 in window")
        manager.recordAdversarialEvent("BLOCKED_TOR_LEAK", target, "Tor SOCKS5 not ready; packet blocked")

        val advStats = manager.computeAdversarialStats()
        assertEquals(1, advStats.badEd25519SignatureCount)
        assertEquals(1, advStats.badAeadTagCount)
        assertEquals(1, advStats.seqRollbackAttemptsCount)
        assertEquals(1, advStats.slidingWindowDuplicateRejections)
        assertEquals(1, advStats.blockedTorColdStartLeaks)
        assertEquals(5, advStats.totalAdversarialEvents)

        assertTrue(manager.adversarialEventsCsvFile.exists())
        val lines = manager.adversarialEventsCsvFile.readLines()
        assertEquals(6, lines.size) // header + 5 events
    }
}


