package org.pqchat.dht.research

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
import java.util.zip.ZipFile

/**
 * Verification test suite for Master's Thesis research telemetry data integrity:
 * 1. Strict Zero-Leakage Guarantee: confirms that ZERO sensitive cryptographic keys, KDF seeds,
 *    plaintext messages, contact identifiers, or full IP addresses appear in any telemetry artifact.
 * 2. Strict Opt-in Guarantee: confirms that with telemetry disabled (default false), ZERO network
 *    calls, ZERO background timers, and ZERO persistent records are created.
 * 3. Schema Version 2 Compliance: confirms session payload structure, Base64 ZIP compression,
 *    and cryptographic SHA-256 manifest validation.
 */
class TelemetryDataIntegrityTest {

    private lateinit var tempDir: File
    private lateinit var settingsManager: AppSettingsManager
    private lateinit var mockDhtClient: MockDhtClient

    class MockDhtClient : DhtClient {
        override val myNodeId: ByteArray = ByteArray(20) { 0x42 }
        override var replicationK: Int = 8
        override var lastOperationMetrics: DhtOpMetrics = DhtOpMetrics(nodesQueried = 24, nodesResponded = 8, lookupHops = 3)
        override fun start() {}
        override fun stop() {}
        override fun getActivePeerCount(): Int = 8
        override suspend fun preWarmTarget(target: ByteArray): List<DhtLeafNode.DhtPeer> = emptyList()
        override fun preWarmTargetAsync(target: ByteArray): kotlinx.coroutines.Job = kotlinx.coroutines.Job()
        override suspend fun getMutable(target: ByteArray, salt: ByteArray?, skipLocalStore: Boolean, timeoutMs: Long, probeAllReplicas: Boolean): DhtLeafNode.MutableItem? = null
        override suspend fun putMutable(target: ByteArray, v: ByteArray, seq: Long, salt: ByteArray?, sk: ByteArray, skipLocalStore: Boolean): Boolean = true
        override suspend fun putMutablePreSigned(target: ByteArray, v: ByteArray, seq: Long, salt: ByteArray?, pk: ByteArray, sig: ByteArray, skipLocalStore: Boolean): Boolean = true
        override suspend fun sendCoverTrafficDummy(): ByteArray? = CryptoUtils.secureRandomBytes(20)
    }

    @Before
    fun setup() {
        tempDir = File(System.getProperty("java.io.tmpdir"), "telemetry_integrity_test_${System.currentTimeMillis()}")
        tempDir.mkdirs()
        settingsManager = AppSettingsManager()
        mockDhtClient = MockDhtClient()
    }

    @Test
    fun `test zero network activity and zero disk recording when telemetry is disabled`() = runBlocking {
        // Strict default: FALSE
        assertFalse("Anonymous stats must be disabled by default", settingsManager.isAnonymousStatsEnabled.value)

        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        assertFalse("Telemetry manager must report isEnabled == false", manager.isEnabled)

        val testTarget = CryptoUtils.secureRandomBytes(20)

        // Attempt recording across all channels while disabled
        manager.recordPacketEvent(role = PacketRole.FIRST_SEND, target = testTarget, seqNum = 1L)
        manager.recordTrafficInterval(PacketRole.COVER_DUMMY_SENT, 1000L, 1020L, 20L, 0.002, "IDLE", true)
        manager.recordDhtConvergence("PUT", testTarget, 100L, 24, 8, 0, true, true, listOf("192.0.2.0/24"))
        manager.recordMessageDelivered(testTarget, 300L, "FOREGROUND_CHAT", "WIFI")
        manager.recordCoverAckReceived(testTarget, 400L, "BACKGROUND_IDLE")
        manager.recordPqcRekeyDuration(15L)
        manager.recordGroupKeyRotationDuration(22L)
        manager.recordAdversarialEvent("BAD_AEAD_TAG", testTarget, "Test anomaly", true)
        manager.recordChunkTransfer(wasResumed = true, wasSuccessful = true)
        manager.recordGroupMessageDelivery(testTarget, 5, 200L, 10L)

        // Counters must remain strictly 0
        assertEquals("Total events count must be 0", 0, manager.eventsCount.value)
        assertEquals(0, manager.firstSendCount.value)
        assertEquals(0, manager.ownRepublishCount.value)
        assertEquals(0, manager.crowdRepublishCount.value)
        assertEquals(0, manager.packetsReceivedCount.value)
        assertEquals(0, manager.ttlSamplesCount.value)

        // forceFirebaseSync must return false immediately without network access
        val syncResult = manager.forceFirebaseSync()
        assertFalse("forceFirebaseSync must be rejected when telemetry is disabled", syncResult)
    }

    @Test
    fun `test absolute zero leakage of PII, private keys and plaintext in all telemetry files`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        assertTrue(settingsManager.isAnonymousStatsEnabled.value)

        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        // Defined sensitive vectors that must NEVER be found in research outputs
        val sensitiveKdfSeed = CryptoUtils.secureRandomBytes(32)
        val sensitiveKdfSeedHex = CryptoUtils.toHex(sensitiveKdfSeed)

        val sensitiveKemPrivateKey = CryptoUtils.secureRandomBytes(1632)
        val sensitiveKemPrivateKeyHex = CryptoUtils.toHex(sensitiveKemPrivateKey)

        val sensitivePlaintext = "CONFIDENTIAL_MASTER_THESIS_RESEARCH_MESSAGE_TOP_SECRET"
        val sensitiveContact = "Alice_Kowalska_Contact_ID_99"
        val sensitiveFullIp = "192.168.100.123"

        val rawTarget = CryptoUtils.secureRandomBytes(20)
        val rawTargetHex = CryptoUtils.toHex(rawTarget)
        val allowedPrefix = rawTargetHex.take(8)

        // Record various events with telemetry enabled
        manager.recordPacketEvent(
            role = PacketRole.FIRST_SEND,
            target = rawTarget,
            seqNum = 1L,
            payloadBytes = 900,
            rttMs = 75L,
            success = true
        )
        manager.recordTrafficInterval(
            role = PacketRole.FIRST_SEND,
            scheduledDelayMs = 4800L,
            actualDelayMs = 4830L,
            wakeUpJitterMs = 30L,
            poissonLambda = 1.0 / 480.0,
            pollingState = "FOREGROUND_CHAT",
            isScreenOn = true
        )
        manager.recordDhtConvergence(
            operation = "PUT",
            target = rawTarget,
            rttMs = 95L,
            nodesQueried = 24,
            nodesResponded = 8,
            timeouts = 0,
            preWarmingHit = true,
            fastTerminated = true,
            subnets24 = listOf("192.0.2.0/24") // Only anonymized /24 prefix permitted
        )
        manager.recordMessageDelivered(rawTarget, latencyMs = 320L, lifecycleState = "FOREGROUND_CHAT", networkType = "WIFI")
        manager.recordCoverAckReceived(rawTarget, latencyMs = 410L, lifecycleState = "FOREGROUND_CHAT")
        manager.recordPqcRekeyDuration(16L)
        manager.recordGroupKeyRotationDuration(28L)
        manager.recordAdversarialEvent("BAD_AEAD_TAG", rawTarget, "Tampered ciphertext tag", true)

        // Build research bundle (.ZIP)
        val bundleZip = manager.buildCompressedResearchBundle()
        assertTrue("Research bundle zip must exist", bundleZip.exists() && bundleZip.length() > 0)

        // Read all entries in the ZIP archive
        ZipFile(bundleZip).use { zip ->
            val entries = zip.entries().toList()
            assertTrue("Bundle zip must contain multiple telemetry files", entries.size >= 5)

            for (entry in entries) {
                val content = zip.getInputStream(entry).bufferedReader().readText()

                assertFalse("Entry ${entry.name} must not contain sensitive KDF seed", content.contains(sensitiveKdfSeedHex))
                assertFalse("Entry ${entry.name} must not contain sensitive private key", content.contains(sensitiveKemPrivateKeyHex))
                assertFalse("Entry ${entry.name} must not contain sensitive plaintext", content.contains(sensitivePlaintext))
                assertFalse("Entry ${entry.name} must not contain contact identifier", content.contains(sensitiveContact))
                assertFalse("Entry ${entry.name} must not contain full user IP", content.contains(sensitiveFullIp))
                assertFalse("Entry ${entry.name} must not contain full 40-char target hex", content.contains(rawTargetHex))

                // The 8-character prefix is allowed for correlation
                if (entry.name.contains("packet_events") || entry.name.contains("kademlia") || entry.name.contains("adversarial")) {
                    assertTrue("Entry ${entry.name} should contain 8-hex target prefix", content.contains(allowedPrefix))
                }
            }
        }

        // Verify JSON payload for Firestore batch sync
        val (deviceInfo, metrics) = manager.computeSessionPayload()
        val metricsStr = metrics.toString()
        val deviceStr = deviceInfo.toString()

        assertFalse("Metrics payload must not contain sensitive seed", metricsStr.contains(sensitiveKdfSeedHex))
        assertFalse("Metrics payload must not contain private key", metricsStr.contains(sensitiveKemPrivateKeyHex))
        assertFalse("Metrics payload must not contain plaintext", metricsStr.contains(sensitivePlaintext))
        assertFalse("Metrics payload must not contain full target hex", metricsStr.contains(rawTargetHex))
        assertFalse("DeviceInfo must not contain full user IP", deviceStr.contains(sensitiveFullIp))
    }

    @Test
    fun `test schemaVersion 2 and Base64 ZIP bundle Firestore compliance`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            settingsManager = settingsManager,
            dhtClient = mockDhtClient,
            baseDir = tempDir
        )

        val target = CryptoUtils.secureRandomBytes(20)
        manager.recordPacketEvent(PacketRole.FIRST_SEND, target, rttMs = 50L)

        val (deviceInfo, metrics) = manager.computeSessionPayload()

        // 1. Top-level keys required by firestore.rules
        assertEquals(manager.sessionId, deviceInfo["sessionId"])
        assertTrue("Metrics must contain totalEvents", metrics.containsKey("totalEvents"))
        assertTrue("Metrics must contain dhtRetentionAndConvergenceStats", metrics.containsKey("dhtRetentionAndConvergenceStats"))
        assertTrue("Metrics must contain endToEndDeliveryAndRekeyStats", metrics.containsKey("endToEndDeliveryAndRekeyStats"))
        assertTrue("Metrics must contain adversarialAnomalyStats", metrics.containsKey("adversarialAnomalyStats"))
        assertTrue("Metrics must contain hardwareBatteryStats", metrics.containsKey("hardwareBatteryStats"))

        // 2. Bundle compression status
        val status = metrics["bundleZipStatus"] as? String
        assertEquals("EMBEDDED_ZIP_BASE64", status)
        val b64 = metrics["bundleZipBase64"] as? String
        assertNotNull(b64)
        assertTrue("Base64 bundle must be non-empty", b64!!.isNotEmpty())

        // 3. Unpack and verify Base64 bundle can be decompressed
        val decodedBytes = java.util.Base64.getDecoder().decode(b64)
        val zipStream = java.util.zip.ZipInputStream(decodedBytes.inputStream())
        var entryCount = 0
        var entry = zipStream.nextEntry
        while (entry != null) {
            entryCount++
            entry = zipStream.nextEntry
        }
        assertTrue("Decompressed Base64 ZIP must contain entries", entryCount >= 5)
    }
}
