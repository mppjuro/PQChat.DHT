package org.pqchat.dht.research

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode

class HistoricalTtlSamplerTest {

    private lateinit var mockDhtClient: ResearchTelemetryManagerTest.MockDhtClient
    private val recordedSamples = mutableListOf<TtlSampleEvent>()

    @Before
    fun setup() {
        mockDhtClient = ResearchTelemetryManagerTest.MockDhtClient()
        recordedSamples.clear()
    }

    @Test
    fun `test tracking packet and sampling retention lifecycle`() = runBlocking {
        val sampler = HistoricalTtlSampler(
            dhtClient = mockDhtClient,
            onSampleRecorded = { recordedSamples.add(it) }
        )

        val target = CryptoUtils.secureRandomBytes(20)
        val initialTime = 1_000_000L

        // Store item in mock DHT
        mockDhtClient.putMutable(target, ByteArray(900), 1L, null, ByteArray(32))

        // Track packet
        sampler.trackPacket(target, initialPutEpochMs = initialTime, republishActive = true)
        assertEquals(1, sampler.getTrackedCount())
        assertEquals(1, sampler.getActiveTrackingCount())

        // Pass 1: 15 minutes elapsed, item is alive in DHT
        val pass1Time = initialTime + 15 * 60 * 1000L
        val pass1Count = sampler.executeSamplingPass(pass1Time, "sess_1")
        assertEquals(1, pass1Count)
        assertEquals(1, recordedSamples.size)

        val sample1 = recordedSamples[0]
        assertTrue("Item should be detected alive on pass 1", sample1.isAlive)
        assertEquals(15.0, sample1.elapsedMinutes, 0.01)
        assertEquals(0.25, sample1.elapsedHours, 0.01)
        assertTrue(sample1.republishActive)
        assertNull("Confirmed lifespan is not set while still alive", sample1.confirmedLifespanMinutes)

        // Simulate item evicted / expired from DHT (e.g. node dropped cache)
        mockDhtClient.storedItems.remove(CryptoUtils.toHex(target))

        // Pass 2: 30 minutes elapsed, first miss
        val pass2Time = initialTime + 30 * 60 * 1000L
        sampler.executeSamplingPass(pass2Time, "sess_1")
        assertEquals(2, recordedSamples.size)
        val sample2 = recordedSamples[1]
        assertFalse("Item should be missed on pass 2", sample2.isAlive)

        // Pass 3: 45 minutes elapsed, second consecutive miss -> confirmed expired!
        val pass3Time = initialTime + 45 * 60 * 1000L
        sampler.executeSamplingPass(pass3Time, "sess_1")
        assertEquals(3, recordedSamples.size)
        val sample3 = recordedSamples[2]
        assertFalse("Item should be marked expired", sample3.isAlive)
        assertNotNull("Confirmed lifespan should be calculated", sample3.confirmedLifespanMinutes)
        assertEquals("Lifespan corresponds to last seen time (15 min)", 15.0, sample3.confirmedLifespanMinutes!!, 0.01)

        // Subsequent pass should ignore expired items
        val pass4Count = sampler.executeSamplingPass(initialTime + 60 * 60 * 1000L, "sess_1")
        assertEquals(0, pass4Count)
    }

    @Test
    fun `test calibration probe injection generates dual decay and republish targets`() = runBlocking {
        val sampler = HistoricalTtlSampler(
            dhtClient = mockDhtClient,
            onSampleRecorded = { recordedSamples.add(it) }
        )

        val success = sampler.injectCalibrationProbePair()
        assertTrue("Calibration probe injection should succeed", success)
        assertEquals("Should register 2 tracked calibration packets", 2, sampler.getTrackedCount())
    }

    @Test
    fun `test multipoint replica decay curve K to 0 and probeAllReplicas`() = runBlocking {
        var recordedProbeAllReplicas = false
        var currentRespondedCount = 8

        val client = object : DhtClient by mockDhtClient {
            override suspend fun getMutable(
                target: ByteArray,
                salt: ByteArray?,
                skipLocalStore: Boolean,
                timeoutMs: Long,
                probeAllReplicas: Boolean
            ): DhtLeafNode.MutableItem? {
                recordedProbeAllReplicas = probeAllReplicas
                if (currentRespondedCount <= 0) return null
                return DhtLeafNode.MutableItem(
                    v = ByteArray(900),
                    seq = 1L,
                    k = ByteArray(32),
                    sig = ByteArray(64),
                    salt = salt,
                    token = null,
                    responder = null,
                    nodesQueried = 24,
                    nodesResponded = currentRespondedCount,
                    lookupHops = 3
                )
            }
        }

        val sampler = HistoricalTtlSampler(
            dhtClient = client,
            onSampleRecorded = { recordedSamples.add(it) }
        )

        val target = CryptoUtils.secureRandomBytes(20)
        val initialTime = 10_000_000L
        sampler.trackPacket(target, initialPutEpochMs = initialTime, republishActive = false)

        // Window 1 (15m): 8 replicas responding
        currentRespondedCount = 8
        sampler.executeSamplingPass(initialTime + 15 * 60 * 1000L, "sess_decay")
        assertTrue("Sampler must set probeAllReplicas = true", recordedProbeAllReplicas)
        assertEquals(1, recordedSamples.size)
        assertEquals(8, recordedSamples[0].nodesResponded)
        assertTrue(recordedSamples[0].isAlive)

        // Window 2 (30m): 5 replicas responding
        currentRespondedCount = 5
        sampler.executeSamplingPass(initialTime + 30 * 60 * 1000L, "sess_decay")
        assertEquals(2, recordedSamples.size)
        assertEquals(5, recordedSamples[1].nodesResponded)
        assertTrue(recordedSamples[1].isAlive)

        // Window 3 (45m): 2 replicas responding
        currentRespondedCount = 2
        sampler.executeSamplingPass(initialTime + 45 * 60 * 1000L, "sess_decay")
        assertEquals(3, recordedSamples.size)
        assertEquals(2, recordedSamples[2].nodesResponded)
        assertTrue(recordedSamples[2].isAlive)

        // Window 4 (60m): 0 replicas responding (evicted/expired)
        currentRespondedCount = 0
        sampler.executeSamplingPass(initialTime + 60 * 60 * 1000L, "sess_decay")
        assertEquals(4, recordedSamples.size)
        assertEquals(0, recordedSamples[3].nodesResponded)
        assertFalse(recordedSamples[3].isAlive)
    }

    @Test
    fun `test dynamic probe interval flow updates timer`() = runBlocking {
        val intervalFlow = kotlinx.coroutines.flow.MutableStateFlow(15 * 60 * 1000L)
        val sampler = HistoricalTtlSampler(
            dhtClient = mockDhtClient,
            probeIntervalFlow = intervalFlow,
            onSampleRecorded = { recordedSamples.add(it) }
        )

        assertEquals(15 * 60 * 1000L, sampler.probeIntervalMs)

        // Update settings flow
        intervalFlow.value = 5 * 60 * 1000L
        sampler.start { "test_session" }
        kotlinx.coroutines.delay(100L)

        assertEquals(5 * 60 * 1000L, sampler.probeIntervalMs)
        sampler.stop()
    }

    @Test
    fun `test enrichment with AndroidResourceProfiler and network provider`() = runBlocking {
        val profiler = org.pqchat.dht.debug.AndroidResourceProfiler(
            context = null,
            dhtClient = mockDhtClient,
            pollingStateProvider = { "DOZE_SLEEP" },
            lambdaProvider = { 1.0 / 600.0 },
            batteryCurrentProvider = { 45000L },
            batteryLevelProvider = { 75 }
        )

        val sampler = HistoricalTtlSampler(
            dhtClient = mockDhtClient,
            resourceProfiler = profiler,
            networkTypeProvider = { "TOR_SOCKS5" },
            onSampleRecorded = { recordedSamples.add(it) }
        )

        val target = CryptoUtils.secureRandomBytes(20)
        mockDhtClient.putMutable(target, ByteArray(900), 1L, null, ByteArray(32))
        sampler.trackPacket(target, initialPutEpochMs = 1_000_000L, republishActive = false)

        sampler.executeSamplingPass(1_000_000L + 15 * 60 * 1000L, "sess_prof")
        assertEquals(1, recordedSamples.size)
        val sample = recordedSamples[0]

        assertEquals("TOR_SOCKS5", sample.networkType)
        assertEquals("DOZE_SLEEP", sample.pollingState)
        assertEquals(45000L, sample.batteryCurrentUa)
        assertEquals(75, sample.batteryLevelPct)
        assertEquals(1.0 / 600.0, sample.poissonLambda, 0.00001)
        assertEquals(8, sample.replicationK)
    }
}
