package org.pqchat.dht.dht

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.dht.leaf.DhtLeafNode
import java.net.InetSocketAddress

class FastTerminationTest {

    @Test
    fun testFastTerminationReturnsNullUnder600msWhenTop3NodesEmpty() = runBlocking {
        val nodeA = DhtLeafNode()
        val nodeB1 = DhtLeafNode()
        val nodeB2 = DhtLeafNode()
        val nodeB3 = DhtLeafNode()

        try {
            nodeA.initSocket()
            val socketB1 = nodeB1.initSocket()
            val socketB2 = nodeB2.initSocket()
            val socketB3 = nodeB3.initSocket()

            nodeA.start()
            nodeB1.start()
            nodeB2.start()
            nodeB3.start()

            val target = CryptoUtils.secureRandomBytes(20)

            // Setup peer contacts for B1, B2, B3
            val peerB1 = DhtLeafNode.DhtPeer(
                nodeId = nodeB1.myNodeId,
                address = InetSocketAddress("127.0.0.1", socketB1.localPort),
                rttMs = 10L
            )
            val peerB2 = DhtLeafNode.DhtPeer(
                nodeId = nodeB2.myNodeId,
                address = InetSocketAddress("127.0.0.1", socketB2.localPort),
                rttMs = 15L
            )
            val peerB3 = DhtLeafNode.DhtPeer(
                nodeId = nodeB3.myNodeId,
                address = InetSocketAddress("127.0.0.1", socketB3.localPort),
                rttMs = 20L
            )

            // Pre-warm Node A's TargetRouteCache with B1, B2, B3 (the 3 closest nodes)
            nodeA.targetRouteCache.put(target, listOf(peerB1, peerB2, peerB3))

            // None of B1, B2, B3 have the item for target.
            // When queried, all 3 respond with empty get response (no 'v' and no closer nodes).
            val startMs = System.currentTimeMillis()
            val result = nodeA.getMutable(target)
            val durationMs = System.currentTimeMillis() - startMs

            assertNull("getMutable must return null when top 3 nodes return no 'v'", result)
            assertTrue(
                "Fast Termination must abort quickly under 600 ms (was $durationMs ms)",
                durationMs < 600L
            )
            println("[Test] Fast termination completed in $durationMs ms (< 600 ms)")
        } finally {
            nodeA.stop()
            nodeB1.stop()
            nodeB2.stop()
            nodeB3.stop()
        }
    }

    @Test
    fun testGetMutableReturnsItemWhenPresentOnOneOfClosestNodes() = runBlocking {
        val nodeA = DhtLeafNode()
        val nodeB1 = DhtLeafNode()
        val nodeB2 = DhtLeafNode()
        val nodeB3 = DhtLeafNode()

        try {
            nodeA.initSocket()
            val socketB1 = nodeB1.initSocket()
            val socketB2 = nodeB2.initSocket()
            val socketB3 = nodeB3.initSocket()

            nodeA.start()
            nodeB1.start()
            nodeB2.start()
            nodeB3.start()

            // Prepare BEP 44 item stored on Node B2
            val seed = CryptoUtils.secureRandomBytes(32)
            val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
            val target = Ed25519Engine.computeTarget(keyPair.publicKey)
            val payload = "Hello Fast Termination with Item".toByteArray(Charsets.UTF_8)

            nodeB2.putMutable(
                target = target,
                v = payload,
                seq = 1L,
                sk = seed
            )

            val peerB1 = DhtLeafNode.DhtPeer(nodeB1.myNodeId, InetSocketAddress("127.0.0.1", socketB1.localPort), rttMs = 10L)
            val peerB2 = DhtLeafNode.DhtPeer(nodeB2.myNodeId, InetSocketAddress("127.0.0.1", socketB2.localPort), rttMs = 15L)
            val peerB3 = DhtLeafNode.DhtPeer(nodeB3.myNodeId, InetSocketAddress("127.0.0.1", socketB3.localPort), rttMs = 20L)

            nodeA.targetRouteCache.put(target, listOf(peerB1, peerB2, peerB3))

            val startMs = System.currentTimeMillis()
            val result = nodeA.getMutable(target)
            val durationMs = System.currentTimeMillis() - startMs

            assertNotNull("getMutable must return item when present on node B2", result)
            assertArrayEquals(payload, result!!.v)
            assertTrue("Resolution should take < 600 ms on loopback", durationMs < 600L)
        } finally {
            nodeA.stop()
            nodeB1.stop()
            nodeB2.stop()
            nodeB3.stop()
        }
    }
}
