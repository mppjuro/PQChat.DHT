package org.pqchat.dht.debug

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.dht.FakeDht
import kotlin.random.Random

class LoopbackMeasurementHarnessTest {

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
        assertTrue("Wi-Fi delivery success rate should be high (>90%)", reportWifi.deliverySuccessRate >= 90.0)
        assertTrue("LTE median RTT should be higher than Wi-Fi", reportLte.totalP50Ms > reportWifi.totalP50Ms)
        assertTrue("Restrictive NAT median RTT should be higher than LTE", reportNat.totalP50Ms > reportLte.totalP50Ms)
        assertTrue("p99 latency should be strictly greater than or equal to p50", reportWifi.totalP99Ms >= reportWifi.totalP50Ms)
        assertTrue("Average retransmissions for Restrictive NAT should be higher than Wi-Fi", reportNat.averageRetransmissions >= reportWifi.averageRetransmissions)
    }

    @Test
    fun testRetentionDecayWithAndWithoutRepublish() {
        val harness = LoopbackMeasurementHarness()
        val fixedRandom = Random(42)

        val retentionResults = harness.evaluateRetentionScenarios(
            networkEnv = LoopbackMeasurementHarness.NetworkEnvironment.WIFI,
            horizonsHours = listOf(1.0, 2.0, 6.0, 24.0),
            sampleSizePerHorizon = 100,
            random = fixedRandom
        )

        assertEquals(8, retentionResults.size) // 4 horizons * 2 modes (with & without republish)

        val noRepublish24h = retentionResults.first { it.hours == 24.0 && !it.republishEnabled }
        val withRepublish24h = retentionResults.first { it.hours == 24.0 && it.republishEnabled }

        // After 24h, without republishing nodes churn out and retention drops severely (< 15%)
        assertTrue("24h retention without republish should degrade severely (< 20%)", noRepublish24h.survivalRate < 0.20)
        // With active republishing, records are sustained (> 85%)
        assertTrue("24h retention with republish should remain high (> 80%)", withRepublish24h.survivalRate >= 0.80)
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
            "measurement_id,timestamp_epoch_ms,network_environment,operation,rtt_put_ms,rtt_get_ms,rtt_total_ms,delivery_success,retransmissions,retention_hours,republish_enabled,nodes_queried,nodes_responded,error_code",
            lines[0]
        )

        // Strict verification: NO hex strings of length 32 or 64 (seeds, keys, hashes) in CSV records
        val hexKeyRegex = Regex("(?i)[0-9a-f]{32,64}")
        for (line in lines.drop(1)) {
            val parts = line.split(",")
            assertEquals(14, parts.size)
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

        assertTrue("FakeDht loopback should succeed", metric.deliverySuccess)
        assertTrue("PUT RTT should be measured", metric.rttPutMs >= 5L)
        assertTrue("GET RTT should be measured", metric.rttGetMs >= 5L)
        assertTrue("Total RTT should equal PUT + GET", metric.rttTotalMs == metric.rttPutMs + metric.rttGetMs)
        assertEquals(null, metric.errorCode)

        fakeDht.stop()
    }
}
