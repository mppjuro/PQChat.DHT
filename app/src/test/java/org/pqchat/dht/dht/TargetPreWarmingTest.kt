package org.pqchat.dht.dht

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.dht.krpc.KrpcMessage
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.dht.leaf.PeerContact
import org.pqchat.dht.protocol.RatchetChain
import java.net.InetSocketAddress

class TargetPreWarmingTest {

    @Test
    fun testRatchetChainGetNextExpectedTarget() {
        val seed = CryptoUtils.secureRandomBytes(64)
        val counter0 = 0
        val counter1 = 1

        val target0 = RatchetChain.getNextExpectedTarget(seed, counter0)
        val target1 = RatchetChain.getNextExpectedTarget(seed, counter1)

        assertEquals("DHT target must be 20 bytes (SHA-1)", 20, target0.size)
        assertEquals("DHT target must be 20 bytes (SHA-1)", 20, target1.size)

        // Must exactly match the slot's derived target
        val slot0 = RatchetChain.deriveSlot(seed, counter0)
        assertArrayEquals("nextExpectedTarget must match deriveSlot target", slot0.target, target0)

        // Must match Ed25519 public key hash
        val expectedSha1 = Ed25519Engine.computeTarget(slot0.edPublicKey)
        assertArrayEquals(expectedSha1, target0)

        // Different counters must produce different targets
        assertFalse(target0.contentEquals(target1))

        // Deterministic: repeating derivation with same key and counter produces same target
        val repeatTarget0 = RatchetChain.getNextExpectedTarget(seed, counter0)
        assertArrayEquals(target0, repeatTarget0)
    }

    @Test
    fun testTargetRouteCacheContentBasedKeyEqualityAndMax8Nodes() {
        val cache = DhtLeafNode.TargetRouteCache(maxCapacity = 10)
        val targetBytes = CryptoUtils.sha1("test_target_bytes".toByteArray())

        // Create 12 distinct fake peer contacts
        val peers = (1..12).map { i ->
            DhtLeafNode.DhtPeer(
                nodeId = CryptoUtils.secureRandomBytes(20),
                address = InetSocketAddress("127.0.0.1", 10000 + i),
                rttMs = i * 10L
            )
        }

        // Put route with 12 peers
        cache.put(targetBytes, peers)

        // TargetRouteCache must cap to exactly 8 closest nodes
        val cached = cache.get(targetBytes)
        assertNotNull(cached)
        assertEquals(8, cached!!.size)

        // Must match content equality: new ByteArray instance with same bytes
        val identicalTargetCopy = targetBytes.copyOf()
        assertNotSame(targetBytes, identicalTargetCopy) // Ensure different object references
        val retrievedWithCopy = cache.get(identicalTargetCopy)
        assertNotNull("Must find entry using content-equal ByteArray instance", retrievedWithCopy)
        assertEquals(8, retrievedWithCopy!!.size)
    }

    @Test
    fun testTargetRouteCacheLruEvictionPreventsMemoryLeaks() {
        val capacity = 10
        val cache = DhtLeafNode.TargetRouteCache(maxCapacity = capacity)

        val targets = (1..25).map { i ->
            CryptoUtils.sha1("target_$i".toByteArray())
        }

        for (target in targets) {
            val peer = listOf(
                DhtLeafNode.DhtPeer(
                    nodeId = CryptoUtils.secureRandomBytes(20),
                    address = InetSocketAddress("10.0.0.1", 8000)
                )
            )
            cache.put(target, peer)
        }

        // Size must never exceed max capacity (bounded LRU, zero memory leak)
        assertTrue("Cache size must be capped to maxCapacity", cache.size <= capacity)
        assertEquals(capacity, cache.size)

        // Earliest targets (1..15) should have been evicted
        assertNull(cache.get(targets[0]))
        assertNull(cache.get(targets[5]))

        // Latest targets should still be present
        assertNotNull(cache.get(targets[24]))
        assertNotNull(cache.get(targets[23]))
    }

    @Test
    fun testTargetRouteCacheConcurrentAccessThreadSafety() = runBlocking {
        val cache = DhtLeafNode.TargetRouteCache(maxCapacity = 30)
        val numThreads = 10
        val operationsPerThread = 50

        val deferreds = (1..numThreads).map { threadId ->
            async {
                for (op in 1..operationsPerThread) {
                    val target = CryptoUtils.sha1("thread_${threadId}_op_${op}".toByteArray())
                    val peer = listOf(
                        DhtLeafNode.DhtPeer(
                            nodeId = CryptoUtils.secureRandomBytes(20),
                            address = InetSocketAddress("127.0.0.1", 5000 + op)
                        )
                    )
                    cache.put(target, peer)
                    val retrieved = cache.get(target)
                    assertNotNull(retrieved)
                }
            }
        }

        deferreds.awaitAll()
        assertTrue(cache.size <= 30)
    }

    @Test
    fun testGetMutableDirectHitViaPreWarmedRoute() = runBlocking {
        val nodeA = DhtLeafNode()
        val nodeB = DhtLeafNode()

        try {
            nodeA.initSocket()
            val socketB = nodeB.initSocket()
            nodeA.start()
            nodeB.start()

            // Prepare item in Node B's local store
            val seedB = CryptoUtils.secureRandomBytes(32)
            val keyPairB = Ed25519Engine.generateKeyPairFromSeed(seedB)
            val target = Ed25519Engine.computeTarget(keyPairB.publicKey)
            val payload = "PreWarmed_Fast_RTT_Message".toByteArray()

            nodeB.putMutable(
                target = target,
                v = payload,
                seq = 1L,
                salt = null,
                sk = seedB
            )

            // Verify Node A does NOT have it locally yet
            assertNull(nodeA.localMutableStore[CryptoUtils.toHex(target)])

            // Pre-warm Node A's TargetRouteCache with Node B's address
            val peerB: PeerContact = DhtLeafNode.DhtPeer(
                nodeId = nodeB.myNodeId,
                address = InetSocketAddress("127.0.0.1", socketB.localPort),
                rttMs = 15L
            )
            nodeA.targetRouteCache.put(target, listOf(peerB))

            assertTrue("Target must be in Node A route cache", nodeA.targetRouteCache.containsKey(target))

            // Now Node A performs getMutable - must hit pre-warmed cache in single RTT
            val startMs = System.currentTimeMillis()
            val result = nodeA.getMutable(target)
            val durationMs = System.currentTimeMillis() - startMs

            assertNotNull("getMutable must successfully retrieve item via pre-warmed route", result)
            assertArrayEquals(payload, result!!.v)
            assertEquals(1L, result.seq)

            // Duration should be very fast (local loopback single RTT < 2000 ms)
            assertTrue("Direct pre-warmed route must resolve rapidly", durationMs < 2000L)
        } finally {
            nodeA.stop()
            nodeB.stop()
        }
    }

    @Test
    fun testPreWarmTargetDiscoversAndCachesClosestPeers() = runBlocking {
        val node = DhtLeafNode()
        try {
            node.initSocket()
            val target = CryptoUtils.sha1("prewarm_discovery_test".toByteArray())

            // Add several known peers with varying distances to node's routing table
            (1..10).forEach { i ->
                val peerId = CryptoUtils.secureRandomBytes(20)
                val peerAddr = InetSocketAddress("127.0.0.1", 20000 + i)
                node.addPeer(peerId, peerAddr)
            }

            // Execute preWarmTarget
            val warmed = node.preWarmTarget(target)

            assertNotNull(warmed)
            assertTrue("Pre-warmed route must be populated", warmed.isNotEmpty())
            assertTrue("Pre-warmed route must contain at most 8 closest nodes", warmed.size <= 8)

            // targetRouteCache must now contain this target
            val cachedRoute = node.targetRouteCache[target]
            assertNotNull(cachedRoute)
            assertEquals(warmed.size, cachedRoute!!.size)
        } finally {
            node.stop()
        }
    }
}
