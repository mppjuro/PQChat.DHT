package org.pqchat.dht.dht.integration

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.debug.LoopbackMeasurementHarness
import org.pqchat.dht.dht.leaf.DhtLeafNode
import java.security.Security

/**
 * Integration test verifying real BitTorrent Mainline DHT BEP 44 remote PUT and GET operations.
 *
 * Designed to be executed manually or on-demand via GitHub Actions `workflow_dispatch`.
 * Set environment variable `RUN_REAL_DHT_TESTS=true` or system property `-DrunRealDhtTests=true`
 * to execute against live public BitTorrent DHT bootstrap nodes.
 */
class RealBep44RemoteIntegrationTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }

        fun isRemoteDhtTestEnabled(): Boolean {
            return System.getenv("RUN_REAL_DHT_TESTS")?.equals("true", ignoreCase = true) == true ||
                    System.getProperty("runRealDhtTests")?.equals("true", ignoreCase = true) == true
        }
    }

    @Test
    fun testRealBep44RemotePutAndGetWith900BytesPayload() = runBlocking {
        assumeTrue(
            "Skipping real BEP 44 remote test. Enable with RUN_REAL_DHT_TESTS=true or -DrunRealDhtTests=true",
            isRemoteDhtTestEnabled()
        )

        val node = DhtLeafNode()
        node.start()
        try {
            val bootstrapNodes = node.resolveBootstrapNodes()
            println("[Live DHT] Bootstrap nodes resolved: $bootstrapNodes")
            node.bootstrap()

            // Allow bootstrap queries to populate active peer routing table
            delay(3500)
            val peerCount = node.getActivePeerCount()
            println("[Live DHT] Active peer count after bootstrap: $peerCount")
            assertTrue("Should connect to at least 1 active DHT peer", peerCount > 0)

            // Ephemeral key pair and 900-byte payload (MAX_FRAME_PAYLOAD_BYTES)
            val seed = CryptoUtils.secureRandomBytes(32)
            val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
            val target = Ed25519Engine.computeTarget(keyPair.publicKey)
            val payload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)
            assertEquals(900, payload.size)

            val targetHex = CryptoUtils.toHex(target)
            println("[Live DHT] Publishing 900-byte payload under target: $targetHex")

            val t0 = System.currentTimeMillis()
            val putResult = node.putMutable(
                target = target,
                v = payload,
                seq = 1L,
                salt = null,
                sk = seed,
                skipLocalStore = true
            )
            val putRttMs = System.currentTimeMillis() - t0
            println("[Live DHT] putMutable result: $putResult (RTT: ${putRttMs}ms)")
            assertTrue("putMutable to remote DHT peers must succeed", putResult)

            // Propagation window across Kademlia closest swarm
            delay(3000)

            // Clear local store to force remote KRPC get traversal
            node.localMutableStore.clear()
            println("[Live DHT] Local cache cleared. Querying remote peers via getMutable...")

            val t1 = System.currentTimeMillis()
            val retrieved = node.getMutable(
                target = target,
                salt = null,
                skipLocalStore = true,
                timeoutMs = DhtLeafNode.FAST_GET_TIMEOUT_MS
            )
            val getRttMs = System.currentTimeMillis() - t1

            assertNotNull("Record must be retrieved from remote DHT peers", retrieved)
            assertEquals("Retrieved payload must have size 900", 900, retrieved!!.v.size)
            assertArrayEquals("Retrieved payload must match original byte-for-byte", payload, retrieved.v)
            println("[Live DHT] Verification succeeded! getMutable RTT: ${getRttMs}ms, Total: ${putRttMs + getRttMs}ms")
        } finally {
            node.stop()
        }
    }

    @Test
    fun testRealBep44RemoteLoopbackHarnessMeasurements() = runBlocking {
        assumeTrue(
            "Skipping real BEP 44 remote test. Enable with RUN_REAL_DHT_TESTS=true or -DrunRealDhtTests=true",
            isRemoteDhtTestEnabled()
        )

        val node = DhtLeafNode()
        node.start()
        try {
            node.bootstrap()
            delay(3000)

            val harness = LoopbackMeasurementHarness(dhtClient = node)
            val trials = 3
            val results = mutableListOf<LoopbackMeasurementHarness.TelemetryMetric>()

            for (i in 1..trials) {
                println("[Live DHT] Executing Loopback Measurement trial $i/$trials...")
                val metric = harness.runLoopbackIteration(LoopbackMeasurementHarness.NetworkEnvironment.WIFI)
                results.add(metric)
                println(" -> Trial $i: Success=${metric.deliverySuccess}, Total RTT=${metric.rttTotalMs}ms, Source=${metric.dataSource}")
                assertTrue("Telemetry must be classified as MEASURED", metric.dataSource == LoopbackMeasurementHarness.DataSource.MEASURED)
                assertTrue("Live loopback iteration should succeed", metric.deliverySuccess)
                assertTrue("PUT RTT must be recorded", metric.rttPutMs > 0)
                assertTrue("GET RTT must be recorded", metric.rttGetMs > 0)
            }

            val csv = harness.exportToCsvString()
            assertTrue("CSV header must contain data_source", csv.contains("data_source"))
            assertTrue("CSV records must record MEASURED", csv.contains("MEASURED"))

            val report = harness.computeAggregateReport(
                networkEnv = LoopbackMeasurementHarness.NetworkEnvironment.WIFI,
                dataSource = LoopbackMeasurementHarness.DataSource.MEASURED,
                records = results
            )
            println("[Live DHT] Aggregate Report: SuccessRate=${report.deliverySuccessRate}%, p50=${report.totalP50Ms}ms")
            assertEquals(LoopbackMeasurementHarness.DataSource.MEASURED, report.dataSource)
            assertEquals(100.0, report.deliverySuccessRate, 0.001)
        } finally {
            node.stop()
        }
    }

    @Test
    fun testRealBep44RemoteRetentionProbeWithRepublish() = runBlocking {
        assumeTrue(
            "Skipping real BEP 44 remote test. Enable with RUN_REAL_DHT_TESTS=true or -DrunRealDhtTests=true",
            isRemoteDhtTestEnabled()
        )

        val node = DhtLeafNode()
        node.start()
        try {
            node.bootstrap()
            delay(3000)

            val harness = LoopbackMeasurementHarness(dhtClient = node)
            val results = harness.evaluateRetentionScenarios(
                networkEnv = LoopbackMeasurementHarness.NetworkEnvironment.WIFI,
                horizonsHours = listOf(5.0 / 60.0), // 5-minute horizon probe
                sampleSizePerHorizon = 2
            )

            assertEquals(2, results.size) // with republish and without republish
            for (res in results) {
                assertEquals(LoopbackMeasurementHarness.DataSource.MEASURED, res.dataSource)
                assertTrue("Tested records should equal 2", res.testedRecords == 2)
                println("[Live DHT] Retention Probe Result (hours=${res.hours}, republish=${res.republishEnabled}): survival=${res.survivalRate * 100}%")
            }
        } finally {
            node.stop()
        }
    }
}
