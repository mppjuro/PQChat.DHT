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
import java.io.File

class ResearchTelemetryManagerTest {

    private lateinit var tempDir: File
    private lateinit var settingsManager: AppSettingsManager
    private lateinit var mockDhtClient: MockDhtClient

    class MockDhtClient : DhtClient {
        override val myNodeId: ByteArray = ByteArray(20) { 1 }
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
            timeoutMs: Long
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
            storedItems[hex] = DhtLeafNode.MutableItem(v, seq, sk, ByteArray(64), salt, null, null)
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
            storedItems[hex] = DhtLeafNode.MutableItem(v, seq, pk, sig, salt, null, null)
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
}
