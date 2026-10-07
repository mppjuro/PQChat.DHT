package org.pqchat.dht.dht

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import java.security.Security

class FakeDhtTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @Test
    fun testBasicPutAndGet() = runBlocking {
        val fakeDht = FakeDht()
        fakeDht.start()

        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        val payload = "Hello Fake DHT".toByteArray(Charsets.UTF_8)

        val putSuccess = fakeDht.putMutable(target, payload, 1L, null, seed)
        assertTrue(putSuccess)
        assertEquals(1, fakeDht.putCalls.get())

        val retrieved = fakeDht.getMutable(target)
        assertNotNull(retrieved)
        assertArrayEquals(payload, retrieved!!.v)
        assertEquals(1L, retrieved.seq)
        assertEquals(1, fakeDht.getCalls.get())

        fakeDht.stop()
    }

    @Test
    fun testSimulatedDelay() = runBlocking {
        val fakeDht = FakeDht(minDelayMs = 50L, maxDelayMs = 80L)
        fakeDht.start()

        val seed = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.sha1(seed)
        val payload = ByteArray(100) { 0x11 }

        val startTime = System.currentTimeMillis()
        fakeDht.putMutable(target, payload, 1L, null, seed)
        val elapsed = System.currentTimeMillis() - startTime

        assertTrue("Expected delay >= 40ms, got ${elapsed}ms", elapsed >= 40L)
        fakeDht.stop()
    }

    @Test
    fun testSimulatedPacketLoss() = runBlocking {
        val fakeDht = FakeDht(dropProbability = 1.0) // 100% loss
        fakeDht.start()

        val seed = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.sha1(seed)
        val payload = ByteArray(100) { 0x22 }

        val putSuccess = fakeDht.putMutable(target, payload, 1L, null, seed)
        assertFalse(putSuccess)
        assertNull(fakeDht.getMutable(target))

        fakeDht.stop()
    }

    @Test
    fun testTtlExpiration() = runBlocking {
        val fakeDht = FakeDht(defaultTtlMs = 60L) // expires in 60ms
        fakeDht.start()

        val seed = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.sha1(seed)
        val payload = ByteArray(100) { 0x33 }

        fakeDht.putMutable(target, payload, 1L, null, seed)
        assertNotNull(fakeDht.getMutable(target))

        delay(80L) // Wait for TTL expiry
        assertNull(fakeDht.getMutable(target))

        fakeDht.stop()
    }

    @Test
    fun testReorderingSimulation() = runBlocking {
        // With varying delays, simulate concurrent put operations with seq updates
        val fakeDht = FakeDht(minDelayMs = 5L, maxDelayMs = 30L)
        fakeDht.start()

        val seed = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.sha1(seed)

        // Launch seq 1 and seq 2 concurrently
        val job1 = async {
            fakeDht.putMutable(target, "v1".toByteArray(), 1L, null, seed)
        }
        val job2 = async {
            delay(10L)
            fakeDht.putMutable(target, "v2".toByteArray(), 2L, null, seed)
        }
        awaitAll(job1, job2)

        val retrieved = fakeDht.getMutable(target)
        assertNotNull(retrieved)
        // Higher seq must prevail or be current
        assertEquals(2L, retrieved!!.seq)
        assertEquals("v2", String(retrieved.v, Charsets.UTF_8))

        fakeDht.stop()
    }
}
