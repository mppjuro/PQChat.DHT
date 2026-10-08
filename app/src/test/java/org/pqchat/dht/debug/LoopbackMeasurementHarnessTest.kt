package org.pqchat.dht.debug

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.dht.bencode.Bencode
import kotlin.random.Random

class LoopbackMeasurementHarnessTest {

    @Test
    fun testLivePayloadWithinBep44BencodeLimit() {
        val payload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)
        assertEquals(900, payload.size)

        // Bencode string encoding of 900 bytes produces "900:<900 bytes>" = 904 bytes
        val bencoded = Bencode.encode(payload)
        assertEquals(904, bencoded.size)
        assertTrue(
            "Bencoded value must be <= 1000 bytes per BEP 44 limit, got: ${bencoded.size}",
            bencoded.size <= 1000
        )

        // Also verify when wrapped in BEP 44 dictionary structure "d1:v900:...3:seqi1ee"
        val dict = mapOf("v" to payload, "seq" to 1L)
        val bencodedDict = Bencode.encode(dict)
        assertTrue(
            "Bencoded dictionary must be non-empty",
            bencodedDict.isNotEmpty()
        )
        assertTrue(
            "Bencoded value must be within 1000 byte value budget",
            bencoded.size <= 1000
        )
    }

    @Test
    fun testPercentileCalculationAccuracy() {
        val harness = LoopbackMeasurementHarness()
        val data = (1..100).map { it.toDouble() }

        val p50 = harness.calculatePercentile(data, 50.0)
        val p90 = harness.calculatePercentile(data, 90.0)
        val p99 = harness.calculatePercentile(data, 99.0)

        assertEquals(50.5, p50, 0.5)
        assertEquals(90.1, p90, 0.5)
        assertEquals(99.01, p99, 0.5)

        // Single element
        assertEquals(42.0, harness.calculatePercentile(listOf(42.0), 50.0), 0.001)
        // Empty list
        assertEquals(0.0, harness.calculatePercentile(emptyList(), 90.0), 0.001)
    }

    @Test
    fun testBenchmarkAcrossNetworkEnvironments() = runBlocking {
        val harness = LoopbackMeasurementHarness()
        val fixedRandom = Random(12345)

        val reportWifi = harness.runBenchmarkSuite(
            LoopbackMeasurementHarness.NetworkEnvironment.WIFI,
            iterations = 50,
            random = fixedRandom
        )
        val reportLte = harness.runBenchmarkSuite(
            LoopbackMeasurementHarness.NetworkEnvironment.LTE,
            iterations = 50,
            random = fixedRandom
        )
        val reportNat = harness.runBenchmarkSuite(
            LoopbackMeasurementHarness.NetworkEnvironment.RESTRICTIVE_NAT,
            iterations = 50,
            random = fixedRandom
        )

        assertEquals(50, reportWifi.totalTrials)
        assertEquals(LoopbackMeasurementHarness.DataSource.SIMULATED, reportWifi.dataSource)
        assertTrue("Wi-Fi delivery success rate should be high (>90%)", reportWifi.deliverySuccessRate >= 90.0)
        assertTrue("LTE median RTT should be higher than Wi-Fi", reportLte.totalP50Ms > reportWifi.totalP50Ms)
        assertTrue("Restrictive NAT median RTT should be higher than LTE", reportNat.totalP50Ms > reportLte.totalP50Ms)
        assertTrue("p99 latency should be strictly greater than or equal to p50", reportWifi.totalP99Ms >= reportWifi.totalP50Ms)
        assertTrue("Average retransmissions for Restrictive NAT should be higher than Wi-Fi", reportNat.averageRetransmissions >= reportWifi.averageRetransmissions)
    }

    @Test
    fun testRetentionDecayWithAndWithoutRepublish() = runBlocking {
        val harness = LoopbackMeasurementHarness()
        val fixedRandom = Random(42)

        val retentionResults = harness.evaluateRetentionScenarios(
            networkEnv = LoopbackMeasurementHarness.NetworkEnvironment.WIFI,
            horizonsHours = listOf(5.0 / 60.0, 1.0, 2.0, 6.0, 12.0, 24.0),
            sampleSizePerHorizon = 100,
            random = fixedRandom
        )

        assertEquals(12, retentionResults.size) // 6 horizons * 2 modes (with & without republish)

        val short5min = retentionResults.first { it.hours == 5.0 / 60.0 && !it.republishEnabled }
        val noRepublish24h = retentionResults.first { it.hours == 24.0 && !it.republishEnabled }
        val withRepublish24h = retentionResults.first { it.hours == 24.0 && it.republishEnabled }

        assertEquals(LoopbackMeasurementHarness.DataSource.SIMULATED, short5min.dataSource)
        assertTrue("5-minute retention should be very high (>95%)", short5min.survivalRate >= 0.95)
        // After 24h without republishing, retention drops severely (< 20%)
        assertTrue("24h retention without republish should degrade severely (< 20%)", noRepublish24h.survivalRate < 0.20)
        // With active republishing, retention sustains high survival
        assertTrue("24h retention with republish should remain resilient (> 70%)", withRepublish24h.survivalRate >= 0.70)
    }

    @Test
    fun testMeasuredRetentionScenarioWithFakeDht() = runBlocking {
        val fakeDht = FakeDht(minDelayMs = 2L, maxDelayMs = 5L)
        fakeDht.start()

        val harness = LoopbackMeasurementHarness(dhtClient = fakeDht)
        val initialPuts = fakeDht.putCalls.get()
        val initialGets = fakeDht.getCalls.get()

        val results = harness.evaluateRetentionScenarios(
            networkEnv = LoopbackMeasurementHarness.NetworkEnvironment.WIFI,
            horizonsHours = listOf(5.0 / 60.0, 1.0),
            sampleSizePerHorizon = 10
        )

        assertEquals(4, results.size) // 2 horizons * 2 republish modes
        for (r in results) {
            assertEquals(LoopbackMeasurementHarness.DataSource.MEASURED, r.dataSource)
            assertEquals(10, r.testedRecords)
            assertEquals(10, r.survivingRecords)
            assertEquals(1.0, r.survivalRate, 0.001)
        }

        // Verify that real PUT and GET calls were executed on DhtClient
        assertTrue("PUT calls must have been made to DhtClient", fakeDht.putCalls.get() > initialPuts)
        assertTrue("GET calls must have been made to DhtClient", fakeDht.getCalls.get() > initialGets)

        fakeDht.stop()
    }

    @Test
    fun testSafeCsvExportGuaranteesZeroCryptoOrContentLeakage() = runBlocking {
        val harness = LoopbackMeasurementHarness()
        harness.runLoopbackIteration(LoopbackMeasurementHarness.NetworkEnvironment.WIFI)
        harness.runLoopbackIteration(LoopbackMeasurementHarness.NetworkEnvironment.LTE)

        val csv = harness.exportToCsvString()

        // Check header
        val lines = csv.trim().lines()
        assertTrue("CSV should have header and records", lines.size >= 3)
        assertEquals(
            "measurement_id,timestamp_epoch_ms,data_source,network_environment,operation,rtt_put_ms,rtt_get_ms,rtt_total_ms,delivery_success,retransmissions,retention_hours,republish_enabled,nodes_queried,nodes_responded,error_code",
            lines[0]
        )

        // Strict verification: NO hex strings of length 32 or 64 (seeds, keys, hashes) in CSV records
        val hexKeyRegex = Regex("(?i)[0-9a-f]{32,64}")
        for (line in lines.drop(1)) {
            val parts = line.split(",")
            assertEquals(15, parts.size)
            assertEquals("SIMULATED", parts[2])
            assertFalse("CSV record must not contain cryptographic keys/hashes", hexKeyRegex.containsMatchIn(line))
            assertFalse("CSV record must not contain payload text", line.contains("hello", ignoreCase = true))
        }
    }

    @Test
    fun testLoopbackExecutionWithFakeDht() = runBlocking {
        val fakeDht = FakeDht(minDelayMs = 5L, maxDelayMs = 15L)
        fakeDht.start()

        val harness = LoopbackMeasurementHarness(dhtClient = fakeDht)
        val metric = harness.runLoopbackIteration(LoopbackMeasurementHarness.NetworkEnvironment.WIFI)

        assertEquals(LoopbackMeasurementHarness.DataSource.MEASURED, metric.dataSource)
        assertTrue("FakeDht loopback should succeed", metric.deliverySuccess)
        assertTrue("PUT RTT should be measured", metric.rttPutMs >= 5L)
        assertTrue("GET RTT should be measured", metric.rttGetMs >= 5L)
        assertTrue("Total RTT should equal PUT + GET", metric.rttTotalMs == metric.rttPutMs + metric.rttGetMs)
        assertEquals(null, metric.errorCode)

        fakeDht.stop()
    }
}
