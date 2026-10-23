package org.pqchat.dht.dht

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.dht.leaf.DhtLeafNode
import java.net.InetSocketAddress

class DhtLeafNodePutLookupTest {

    @Test
    fun testPutMutablePerformsIterativeLookupAndStoresOnClosestPeer() = runBlocking {
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        val payload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

        // Node B2's nodeId is set exactly to target (XOR distance = 0, closest peer)
        val nodeA = DhtLeafNode(autoBootstrap = false)
        val nodeB1 = DhtLeafNode(autoBootstrap = false)
        val nodeB2 = DhtLeafNode(myNodeId = target.copyOf(), autoBootstrap = false)

        try {
            val socketA = nodeA.initSocket()
            val socketB1 = nodeB1.initSocket()
            val socketB2 = nodeB2.initSocket()

            nodeA.start()
            nodeB1.start()
            nodeB2.start()

            // Topology:
            // Node A knows only Node B1
            // Node B1 knows Node B2
            // Node A has no initial awareness of Node B2
            nodeB1.addPeer(nodeB2.myNodeId, InetSocketAddress("127.0.0.1", socketB2.localPort))
            nodeA.addPeer(nodeB1.myNodeId, InetSocketAddress("127.0.0.1", socketB1.localPort))

            // 1. Verify iterativeFindClosestNodes discovers Node B2 via Node B1
            val closest = nodeA.iterativeFindClosestNodes(target, k = 8)
            assertTrue("Iterative lookup must discover peers", closest.isNotEmpty())
            val foundB2 = closest.any { it.address.port == socketB2.localPort }
            assertTrue("Iterative lookup must converge to Node B2 via find_node on Node B1", foundB2)

            // 2. Execute putMutable with skipLocalStore = true
            val putSuccess = nodeA.putMutable(
                target = target,
                v = payload,
                seq = 1L,
                salt = null,
                sk = seed,
                skipLocalStore = true
            )

            assertTrue("putMutable must return true when record is stored on closest peer", putSuccess)

            // 3. Verify Node B2 directly received and stored the record in its localMutableStore
            val targetHex = CryptoUtils.toHex(target)
            val storedItem = nodeB2.localMutableStore[targetHex]
            assertNotNull("Record must be physically present in Node B2's localMutableStore", storedItem)
            assertArrayEquals("Payload on Node B2 must match exactly", payload, storedItem!!.v)
            assertEquals(1L, storedItem.seq)
            assertArrayEquals(keyPair.publicKey, storedItem.k)

            // 4. Verify getMutable from Node A retrieves the item from Node B2
            val retrieved = nodeA.getMutable(
                target = target,
                salt = null,
                skipLocalStore = true,
                timeoutMs = 2000L
            )

            assertNotNull("getMutable must retrieve the item stored by iterative putMutable", retrieved)
            assertArrayEquals("Retrieved payload must match", payload, retrieved!!.v)
        } finally {
            nodeA.stop()
            nodeB1.stop()
            nodeB2.stop()
        }
    }

    @Test
    fun testPutMutableRespectsQuorumAndFailsWhenNoPeersAvailable() = runBlocking {
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        val payload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

        val isolatedNode = DhtLeafNode(autoBootstrap = false)
        try {
            isolatedNode.initSocket()
            isolatedNode.start()

            // No peers added to routing table
            val putResult = isolatedNode.putMutable(
                target = target,
                v = payload,
                seq = 1L,
                salt = null,
                sk = seed,
                skipLocalStore = true
            )

            assertFalse("putMutable must return false when no peers are reachable and skipLocalStore=true", putResult)
        } finally {
            isolatedNode.stop()
        }
    }
}
