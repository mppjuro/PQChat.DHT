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
}
