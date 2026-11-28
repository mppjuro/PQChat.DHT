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

    private var prevLocalTestbedMode: Boolean = false

    @org.junit.Before
    fun setUpLocalTestbed() {
        prevLocalTestbedMode = DhtLeafNode.isLocalTestbedMode
        DhtLeafNode.isLocalTestbedMode = true
    }

    @org.junit.After
    fun tearDownLocalTestbed() {
        DhtLeafNode.isLocalTestbedMode = prevLocalTestbedMode
    }

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

    @Test
    fun testBep44PutQueryByteSerializationAndEd25519Compliance() {
        val myNodeId = CryptoUtils.secureRandomBytes(20)
        val token = "test_token_1234".toByteArray(Charsets.US_ASCII)
        val payload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES) // exactly 900 bytes
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val seq = 1L

        // Test with salt == null:
        val signDataNoSalt = org.pqchat.dht.dht.bencode.Bencode.encodeBep44SignData(payload, seq, salt = null)
        val sigNoSalt = Ed25519Engine.sign(seed, signDataNoSalt)

        val queryNoSalt = org.pqchat.dht.dht.krpc.KrpcMessage.createBep44PutQuery(
            myNodeId = myNodeId,
            token = token,
            v = payload,
            k = keyPair.publicKey,
            sig = sigNoSalt,
            seq = seq,
            salt = null,
            readOnly = false
        )

        val bencoded = queryNoSalt.toBencoded()
        val asciiStr = String(bencoded, Charsets.ISO_8859_1)

        // BEP 44 compliance assertions:
        // 1. salt MUST NOT be present when null
        assertFalse("Bencoded put query must not contain 'salt' key when salt is null", asciiStr.contains("4:salt"))
        // 2. Value payload v is 900 bytes, encoded as single string with '1:v900:' prefix
        assertTrue("Value key must have 900 bytes length prefix 1:v900:", asciiStr.contains("1:v900:"))
        // 3. No read-only flag 'ro' in put
        assertFalse("Put query must not include read-only flag 'ro'", asciiStr.contains("2:ro"))
        // 4. Ed25519 verification succeeds
        assertTrue("Ed25519 signature must verify over BEP 44 sign data", Ed25519Engine.verify(keyPair.publicKey, signDataNoSalt, sigNoSalt))

        // 5. Test with salt present:
        val salt = "custom_salt".toByteArray(Charsets.US_ASCII)
        val signDataWithSalt = org.pqchat.dht.dht.bencode.Bencode.encodeBep44SignData(payload, seq, salt = salt)
        val sigWithSalt = Ed25519Engine.sign(seed, signDataWithSalt)

        val queryWithSalt = org.pqchat.dht.dht.krpc.KrpcMessage.createBep44PutQuery(
            myNodeId = myNodeId,
            token = token,
            v = payload,
            k = keyPair.publicKey,
            sig = sigWithSalt,
            seq = seq,
            salt = salt,
            readOnly = false
        )
        val bencodedWithSalt = queryWithSalt.toBencoded()
        val asciiStrWithSalt = String(bencodedWithSalt, Charsets.ISO_8859_1)
        assertTrue("Bencoded put query must contain '4:salt' when salt is present", asciiStrWithSalt.contains("4:salt"))
        assertTrue("Ed25519 signature with salt must verify", Ed25519Engine.verify(keyPair.publicKey, signDataWithSalt, sigWithSalt))
    }

    @Test
    fun testPutMutableFiltersTokenBearingNodesInMixedNetwork() = runBlocking {
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        val payload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

        val nodeA = DhtLeafNode(autoBootstrap = false)

        // Create 2 token-bearing nodes
        val tokenNode1 = DhtLeafNode(autoBootstrap = false)
        val tokenNode2 = DhtLeafNode(autoBootstrap = false)

        // Create 3 mock nodes that respond WITHOUT token (simulating BEP 5 / non-BEP-44 routers)
        val mockSockets = mutableListOf<java.net.DatagramSocket>()
        val mockThreads = mutableListOf<Thread>()
        val mockAddresses = mutableListOf<InetSocketAddress>()

        try {
            val sockA = nodeA.initSocket()
            val sockT1 = tokenNode1.initSocket()
            val sockT2 = tokenNode2.initSocket()

            nodeA.start()
            tokenNode1.start()
            tokenNode2.start()

            for (i in 1..3) {
                val s = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
                mockSockets.add(s)
                val mockAddr = InetSocketAddress("127.0.0.1", s.localPort)
                mockAddresses.add(mockAddr)
                val mockId = CryptoUtils.secureRandomBytes(20)

                val t = Thread {
                    val buf = ByteArray(2048)
                    while (!s.isClosed) {
                        try {
                            val p = java.net.DatagramPacket(buf, buf.size)
                            s.receive(p)
                            val msg = org.pqchat.dht.dht.krpc.KrpcMessage.parse(p.data.copyOf(p.length))
                            if (msg is org.pqchat.dht.dht.krpc.KrpcMessage.Query) {
                                // Response with NO token field
                                val resp = org.pqchat.dht.dht.krpc.KrpcMessage.Response(
                                    transactionId = msg.transactionId,
                                    responseData = mapOf("id" to mockId, "nodes" to ByteArray(0))
                                )
                                val b = resp.toBencoded()
                                s.send(java.net.DatagramPacket(b, b.size, p.socketAddress))
                            }
                        } catch (_: Exception) {}
                    }
                }
                mockThreads.add(t)
                t.start()

                // Add mock node to Node A's routing table
                nodeA.addPeer(mockId, mockAddr)
            }

            // Also add the two token-bearing nodes to Node A's routing table
            nodeA.addPeer(tokenNode1.myNodeId, InetSocketAddress("127.0.0.1", sockT1.localPort))
            nodeA.addPeer(tokenNode2.myNodeId, InetSocketAddress("127.0.0.1", sockT2.localPort))

            val putSuccess = nodeA.putMutable(
                target = target,
                v = payload,
                seq = 1L,
                salt = null,
                sk = seed,
                skipLocalStore = true
            )

            assertTrue("putMutable must succeed in mixed network by targeting token-bearing nodes", putSuccess)
            assertTrue("Must have received tokens from the token-bearing nodes", nodeA.lastTokensReceived >= 2)
            assertTrue("Must have successfully stored on at least 1 token-bearing node", nodeA.lastPutNodesSucceeded >= 1)
        } finally {
            nodeA.stop()
            tokenNode1.stop()
            tokenNode2.stop()
            mockSockets.forEach { try { it.close() } catch (_: Exception) {} }
            mockThreads.forEach { it.interrupt() }
        }
    }

    @Test
    fun testHandshakeTarget0MatchesSha1OfEd25519PublicKey() {
        val aliceInit = org.pqchat.dht.protocol.HandshakeManager.aliceCreateHandshake()
        val bobResult = org.pqchat.dht.protocol.HandshakeManager.bobProcessQr(aliceInit.qrBytes)

        val bobEdPk = Ed25519Engine.generateKeyPairFromSeed(bobResult.edPrivateKeySeed).publicKey
        val expectedTarget = Ed25519Engine.computeTarget(bobEdPk)

        assertArrayEquals("Bob's target0 must strictly match SHA-1(k)", expectedTarget, bobResult.target0)
        assertArrayEquals("Alice's target0 must strictly match Bob's target0", aliceInit.target0, bobResult.target0)
    }

    @Test
    fun testMinHealthyRoutingTableSizeConstant() {
        assertEquals("MIN_HEALTHY_ROUTING_TABLE_SIZE must be at least 16 to prevent node cache starvation",
            16, DhtLeafNode.MIN_HEALTHY_ROUTING_TABLE_SIZE)
    }

    @Test
    fun testRebootstrapReturnsTrueWhenHealthy() = runBlocking {
        val node = DhtLeafNode(autoBootstrap = false)
        try {
            node.initSocket()
            node.start()
            for (i in 0 until 16) {
                node.addPeer(CryptoUtils.secureRandomBytes(20), java.net.InetSocketAddress("127.0.0.1", 50000 + i))
            }
            val result = node.rebootstrap(force = false)
            assertTrue("rebootstrap must succeed when routing table has sufficient peers", result)
        } finally {
            node.stop()
        }
    }

    @Test
    fun testPutMutableContinuesDiscoveryBeyondHop3EvenAfterCollectingManyTokens() = runBlocking {
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        val payload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)
        val targetHex = CryptoUtils.toHex(target)

        // Build target-monotonic XOR chain: B1 -> B2 -> B3 -> B4 (distance 0 = target)
        fun flippedId(vararg bitIndicesFromEnd: Int): ByteArray {
            val id = target.copyOf()
            for (idx in bitIndicesFromEnd) {
                val bytePos = 19 - (idx / 8)
                val bitPos = idx % 8
                id[bytePos] = (id[bytePos].toInt() xor (1 shl bitPos)).toByte()
            }
            return id
        }

        val nodeA = DhtLeafNode(autoBootstrap = false)
        val nodeB1 = DhtLeafNode(myNodeId = flippedId(3), autoBootstrap = false)
        val nodeB2 = DhtLeafNode(myNodeId = flippedId(2), autoBootstrap = false)
        val nodeB3 = DhtLeafNode(myNodeId = flippedId(1), autoBootstrap = false)
        val nodeB4 = DhtLeafNode(myNodeId = target.copyOf(), autoBootstrap = false)

        // 13 farther distractor nodes known in hop 1 so tokenMap.size >= 12 by hop 2
        val distractors = (0 until 13).map { i ->
            val farId = target.copyOf()
            farId[0] = (farId[0].toInt() xor (0x80 or (i shl 2))).toByte()
            DhtLeafNode(myNodeId = farId, autoBootstrap = false)
        }

        val allNodes = listOf(nodeA, nodeB1, nodeB2, nodeB3, nodeB4) + distractors
        try {
            val ports = allNodes.associateWith { it.initSocket().localPort }
            allNodes.forEach { it.start() }

            // Wire chain: A knows B1 + all distractors; B1 -> B2 -> B3 -> B4
            nodeA.addPeer(nodeB1.myNodeId, InetSocketAddress("127.0.0.1", ports.getValue(nodeB1)))
            distractors.forEach { d ->
                nodeA.addPeer(d.myNodeId, InetSocketAddress("127.0.0.1", ports.getValue(d)))
            }
            nodeB1.addPeer(nodeB2.myNodeId, InetSocketAddress("127.0.0.1", ports.getValue(nodeB2)))
            nodeB2.addPeer(nodeB3.myNodeId, InetSocketAddress("127.0.0.1", ports.getValue(nodeB3)))
            nodeB3.addPeer(nodeB4.myNodeId, InetSocketAddress("127.0.0.1", ports.getValue(nodeB4)))

            val putSuccess = nodeA.putMutable(
                target = target,
                v = payload,
                seq = 1L,
                salt = null,
                sk = seed,
                skipLocalStore = true
            )

            assertTrue("Multi-hop putMutable must succeed", putSuccess)
            val storedOnB4 = nodeB4.localMutableStore[targetHex]
            assertNotNull(
                "Closest peer B4 at hop 4 must receive PUT even when >= 12 tokens were collected earlier",
                storedOnB4
            )
            assertArrayEquals("Payload stored on B4 must match", payload, storedOnB4!!.v)
        } finally {
            allNodes.forEach { try { it.stop() } catch (_: Exception) {} }
        }
    }

    @Test
    fun testGetMutableFastSingleHopHitPreservesRoutingTableAndReturnsItem() = runBlocking {
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        val payload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

        val nodeA = DhtLeafNode(autoBootstrap = false)
        val nodeB = DhtLeafNode(myNodeId = target.copyOf(), autoBootstrap = false)

        try {
            nodeA.initSocket()
            val portB = nodeB.initSocket().localPort
            nodeA.start()
            nodeB.start()

            assertTrue(nodeB.putMutable(target = target, v = payload, seq = 1L, salt = null, sk = seed, skipLocalStore = false))
            nodeA.addPeer(nodeB.myNodeId, InetSocketAddress("127.0.0.1", portB))

            val retrieved = nodeA.getMutable(target = target, salt = null, skipLocalStore = true, timeoutMs = 1500L)
            assertNotNull("Single-hop getMutable hit must return stored mutable item", retrieved)
            assertArrayEquals("Retrieved payload must match", payload, retrieved!!.v)
            assertTrue("Routing table must retain verified responder", nodeA.getActivePeerCount() >= 1)
        } finally {
            nodeA.stop()
            nodeB.stop()
        }
    }
}
