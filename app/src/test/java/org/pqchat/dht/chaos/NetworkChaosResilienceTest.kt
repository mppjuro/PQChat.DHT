package org.pqchat.dht.chaos

import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.dht.krpc.KrpcMessage
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.dht.leaf.DhtOpMetrics
import org.pqchat.dht.dht.leaf.TorProxyConfig
import org.pqchat.dht.dht.leaf.TorTransportMode
import org.pqchat.dht.protocol.ChunkingEngine
import org.pqchat.dht.test.BaseFakeChunkDao
import org.pqchat.dht.test.BaseFakeMessageDao
import org.pqchat.dht.traffic.OutboundPoissonFrame
import org.pqchat.dht.traffic.OutboundPoissonQueue
import org.pqchat.dht.traffic.PendingAck
import org.pqchat.dht.traffic.PendingAckQueue
import org.pqchat.dht.traffic.PoissonTrafficGenerator
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.Security
import java.util.Random
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Deterministic network chaos & resilience test suite validating PQChat.DHT recovery under:
 * 1. High UDP packet loss (10%..40%) + mid-transfer network partition during 0x05 chunk transfers.
 * 2. UDP loss + temporary network partition during 50-message PQC rekey (0x03/0x04) & outbox draining.
 * 3. Carrier CGNAT IP/port rebinding (both ChaosDhtClient + live DhtLeafNode socket rebind).
 * 4. Tor SOCKS5 circuit crash/restart verifying zero clearnet UDP leaks (fail-closed) and recovery.
 */
class NetworkChaosResilienceTest {

    companion object {
        @JvmStatic
        @BeforeAll
        fun setupSecurity() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    /**
     * Deterministic chaos proxy over [FakeDht] that injects configurable UDP loss (10%..40%),
     * temporary complete network partitions, and CGNAT IP/port rebind events.
     */
    private class ChaosDhtClient(
        private val delegate: FakeDht,
        seed: Long = 20261128L
    ) : DhtClient {
        private val prng = Random(seed)

        @Volatile
        var udpLossRate: Double = 0.0

        @Volatile
        var isNetworkPartitioned: Boolean = false

        val droppedPuts = AtomicInteger(0)
        val droppedGets = AtomicInteger(0)
        val cgnatRebinds = AtomicInteger(0)
        val rebootstrapCalls = AtomicInteger(0)

        override var myNodeId: ByteArray = delegate.myNodeId.copyOf()
            private set

        override var replicationK: Int
            get() = delegate.replicationK
            set(value) {
                delegate.replicationK = value
            }

        override fun setAdaptiveK(isMobileOrCgnat: Boolean) {
            delegate.setAdaptiveK(isMobileOrCgnat)
        }

        override val lastOperationMetrics: DhtOpMetrics
            get() = if (isNetworkPartitioned) {
                DhtOpMetrics(nodesQueried = replicationK, nodesResponded = 0, dhtError = "NETWORK_PARTITION")
            } else {
                delegate.lastOperationMetrics
            }

        override val totalGetCalls: Long get() = delegate.totalGetCalls
        override val totalPutCalls: Long get() = delegate.totalPutCalls
        override val totalBytesSent: Long get() = delegate.totalBytesSent
        override val totalBytesReceived: Long get() = delegate.totalBytesReceived

        override fun start() = delegate.start()
        override fun stop() = delegate.stop()
        override fun getActivePeerCount(): Int = if (isNetworkPartitioned) 0 else delegate.getActivePeerCount()

        override suspend fun rebootstrap(force: Boolean): Boolean {
            if (isNetworkPartitioned) return false
            rebootstrapCalls.incrementAndGet()
            return true
        }

        override suspend fun sendKeepalivePing(): Boolean {
            if (isNetworkPartitioned) return false
            return delegate.sendKeepalivePing()
        }

        fun simulateCgnatPortRebind() {
            cgnatRebinds.incrementAndGet()
            // Rotate ephemeral node ID / socket binding footprint to emulate carrier NAT remapping
            val nextId = ByteArray(20)
            synchronized(prng) { prng.nextBytes(nextId) }
            myNodeId = nextId
        }

        private fun shouldDrop(): Boolean {
            val rate = udpLossRate
            if (rate <= 0.0) return false
            return synchronized(prng) { prng.nextDouble() < rate }
        }

        override suspend fun preWarmTarget(target: ByteArray): List<DhtLeafNode.DhtPeer> {
            if (isNetworkPartitioned) return emptyList()
            return delegate.preWarmTarget(target)
        }

        override fun preWarmTargetAsync(target: ByteArray): Job = delegate.preWarmTargetAsync(target)

        override suspend fun getMutable(
            target: ByteArray,
            salt: ByteArray?,
            skipLocalStore: Boolean,
            timeoutMs: Long,
            probeAllReplicas: Boolean,
            minSeq: Long
        ): DhtLeafNode.MutableItem? {
            if (isNetworkPartitioned || shouldDrop()) {
                droppedGets.incrementAndGet()
                return null
            }
            return delegate.getMutable(target, salt, skipLocalStore, timeoutMs, probeAllReplicas, minSeq)
        }

        override suspend fun putMutable(
            target: ByteArray,
            v: ByteArray,
            seq: Long,
            salt: ByteArray?,
            sk: ByteArray,
            skipLocalStore: Boolean
        ): Boolean {
            if (isNetworkPartitioned || shouldDrop()) {
                droppedPuts.incrementAndGet()
                return false
            }
            return delegate.putMutable(target, v, seq, salt, sk, skipLocalStore)
        }

        override suspend fun putMutablePreSigned(
            target: ByteArray,
            v: ByteArray,
            seq: Long,
            salt: ByteArray?,
            pk: ByteArray,
            sig: ByteArray,
            skipLocalStore: Boolean
        ): Boolean {
            if (isNetworkPartitioned || shouldDrop()) {
                droppedPuts.incrementAndGet()
                return false
            }
            return delegate.putMutablePreSigned(target, v, seq, salt, pk, sig, skipLocalStore)
        }

        override suspend fun sendCoverTrafficDummy(): ByteArray? {
            if (isNetworkPartitioned || shouldDrop()) return null
            return delegate.sendCoverTrafficDummy()
        }
    }

    private class ChaosContactDao : ContactDao {
        val contacts = ConcurrentHashMap<String, ContactEntity>()
        val flow = MutableStateFlow<List<ContactEntity>>(emptyList())

        override fun getAllContactsFlow(): Flow<List<ContactEntity>> = flow
        override suspend fun getContactById(id: String): ContactEntity? = contacts[id]

        override suspend fun insertOrUpdate(contact: ContactEntity) {
            contacts[contact.id] = contact
            flow.value = contacts.values.toList()
        }

        override suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: EncryptedBlob) {
            contacts.computeIfPresent(id) { _, c -> c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut) }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: EncryptedBlob, rekeyEpoch: Long) {
            contacts.computeIfPresent(id) { _, c -> c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut, rekeyEpoch = rekeyEpoch) }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {
            contacts.computeIfPresent(id) { _, c -> c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn) }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long) {
            contacts.computeIfPresent(id) { _, c -> c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch) }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {
            contacts.computeIfPresent(id) { _, c -> c.copy(rekeyEpoch = rekeyEpoch) }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateVerifiedStatus(id: String, isVerified: Boolean) {
            contacts.computeIfPresent(id) { _, c -> c.copy(isVerified = isVerified) }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateContactName(id: String, name: EncryptedText) {
            contacts.computeIfPresent(id) { _, c -> c.copy(name = name) }
            flow.value = contacts.values.toList()
        }

        override suspend fun deleteContact(id: String) {
            contacts.remove(id)
            flow.value = contacts.values.toList()
        }
    }

    private class ChaosMessageDao : BaseFakeMessageDao()
    private class ChaosChunkDao : BaseFakeChunkDao()

    private class ChaosPendingRekeyDao : PendingRekeyOfferDao {
        val offers = ConcurrentHashMap<String, PendingRekeyOfferEntity>()
        val offersFlow = MutableStateFlow<Map<String, PendingRekeyOfferEntity>>(emptyMap())

        override suspend fun getPendingOffer(contactId: String): PendingRekeyOfferEntity? = offers[contactId]
        override fun getPendingOfferFlow(contactId: String): Flow<PendingRekeyOfferEntity?> = offersFlow.map { it[contactId] }
        override fun isRekeyPendingFlow(contactId: String): Flow<Boolean> = offersFlow.map { it.containsKey(contactId) }

        override suspend fun insertOrUpdate(offer: PendingRekeyOfferEntity) {
            offers[offer.contactId] = offer
            offersFlow.value = HashMap(offers)
        }

        override suspend fun deletePendingOffer(contactId: String) {
            offers.remove(contactId)
            offersFlow.value = HashMap(offers)
        }
    }

    private fun configureFastRepo(repo: ChatRepository) {
        repo.isFastTestMode = true
        repo.delayedPutMaxMs = 0L
        repo.decoyPutSlotsCount = 0
        repo.enableDecoyGets = false
        repo.intraBatchJitterMinMs = 0L
        repo.intraBatchJitterMaxMs = 0L
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    fun testMultiChunkTransferSurvivesPacketLossAndTemporaryPartition() = runBlocking {
        val sharedDht = FakeDht(minDelayMs = 0, maxDelayMs = 0).apply { start() }
        val senderChaos = ChaosDhtClient(sharedDht, seed = 101L)
        val receiverChaos = ChaosDhtClient(sharedDht, seed = 202L)

        val bobContactDao = ChaosContactDao()
        val bobMessageDao = ChaosMessageDao()
        val bobChunkDao = ChaosChunkDao()
        val bobRepo = ChatRepository(bobContactDao, bobMessageDao, bobChunkDao, null, receiverChaos).also(::configureFastRepo)

        // 4800-byte synthetic PNG (split into 6 x 0x05 chunks)
        val fakePng = ByteArray(4800).also { arr ->
            System.arraycopy(ChunkingEngine.PNG_MAGIC, 0, arr, 0, 4)
            for (i in 4 until arr.size) {
                arr[i] = ((i * 31 + 7) and 0xFF).toByte()
            }
        }

        val chainA2B = CryptoUtils.secureRandomBytes(64)
        bobContactDao.insertOrUpdate(
            ContactEntity(
                id = "alice",
                name = "Alice",
                chainKeyOut = CryptoUtils.secureRandomBytes(64),
                counterOut = 0,
                chainKeyIn = chainA2B,
                counterIn = 0,
                isInitiator = false
            )
        )

        val slot0 = org.pqchat.dht.protocol.RatchetChain.deriveSlot(chainA2B, 0)
        val chunks = ChunkingEngine.splitData(
            data = fakePng,
            currentEdSeed = slot0.edPrivateKeySeed,
            currentMsgKey = slot0.msgKey,
            seqNum = 0,
            ackNum = 0,
            direction = "AliceToBob"
        )
        assertEquals(6, chunks.size)

        // Phase 1: Upload chunks 1, 3, 5 under 35% UDP packet loss with retry
        senderChaos.udpLossRate = 0.35
        for (idx in listOf(1, 3, 5)) {
            val target = ChunkingEngine.deriveChunkTarget(slot0.edPrivateKeySeed, idx)
            val sk = ChunkingEngine.deriveChunkEdSeed(slot0.edPrivateKeySeed, idx)
            var stored = false
            repeat(25) {
                if (!stored) {
                    stored = senderChaos.putMutable(target, chunks[idx].frame, sk = sk)
                }
            }
            assertTrue("Chunk $idx must be stored despite 35% UDP loss", stored)
        }
        assertTrue("Expected simulated UDP drops during initial upload", senderChaos.droppedPuts.get() > 0)

        // Bob polls partial chunks cleanly
        receiverChaos.udpLossRate = 0.0
        assertTrue(bobRepo.pollContactIncoming("alice"))
        val transferIdHex = CryptoUtils.toHex(chunks[0].transferId)
        val partialBeforePartition = bobChunkDao.getPendingTransfer(transferIdHex)
        assertNotNull("Partial transfer should be tracked before partition", partialBeforePartition)
        assertEquals("0,2,4", partialBeforePartition!!.rawMissingIndices)

        // Phase 2: Full network partition mid-transfer
        receiverChaos.isNetworkPartitioned = true
        bobRepo.pollContactIncoming("alice")
        val resumedDuringPartition = bobRepo.resumePendingChunkTransfers("alice")
        assertFalse("Resumption must fail cleanly while network is partitioned", resumedDuringPartition)
        assertNotNull(
            "Partial transfer state must survive network partition without data loss",
            bobChunkDao.getPendingTransfer(transferIdHex)
        )

        // Phase 3: Partition heals, remaining chunks uploaded & resumed under 25%..30% UDP loss
        receiverChaos.isNetworkPartitioned = false
        senderChaos.udpLossRate = 0.30
        for (idx in listOf(0, 2, 4)) {
            val target = ChunkingEngine.deriveChunkTarget(slot0.edPrivateKeySeed, idx)
            val sk = ChunkingEngine.deriveChunkEdSeed(slot0.edPrivateKeySeed, idx)
            var stored = false
            repeat(25) {
                if (!stored) {
                    stored = senderChaos.putMutable(target, chunks[idx].frame, sk = sk)
                }
            }
            assertTrue("Chunk $idx must be stored after partition heals", stored)
        }

        receiverChaos.udpLossRate = 0.25
        var reassembled = false
        repeat(30) {
            if (!reassembled) {
                reassembled = bobRepo.resumePendingChunkTransfers("alice")
            }
        }
        assertTrue("Chunk transfer must finish reassembly after partition recovery", reassembled)
        assertTrue("Expected simulated GET drops during recovery", receiverChaos.droppedGets.get() > 0)
        assertNull("Completed transfer record must be cleaned up", bobChunkDao.getPendingTransfer(transferIdHex))

        val deliveredImages = bobMessageDao.messages.filter { it.contactId == "alice" && it.imageBytes != null }
        assertEquals(1, deliveredImages.size)
        assertArrayEquals("Reassembled PNG must match original byte-for-byte", fakePng, deliveredImages.first().rawImageBytes)

        bobRepo.close()
        sharedDht.stop()
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    fun testPqcRekeySurvivesUdpLossAndNetworkPartition() = runBlocking {
        val sharedDht = FakeDht(minDelayMs = 0, maxDelayMs = 0).apply { start() }
        val aliceChaos = ChaosDhtClient(sharedDht, seed = 303L)
        val bobChaos = ChaosDhtClient(sharedDht, seed = 404L)

        val aliceContactDao = ChaosContactDao()
        val aliceMessageDao = ChaosMessageDao()
        val aliceChunkDao = ChaosChunkDao()
        val aliceRekeyDao = ChaosPendingRekeyDao()
        val aliceRepo = ChatRepository(aliceContactDao, aliceMessageDao, aliceChunkDao, aliceRekeyDao, aliceChaos).also(::configureFastRepo)

        val bobContactDao = ChaosContactDao()
        val bobMessageDao = ChaosMessageDao()
        val bobChunkDao = ChaosChunkDao()
        val bobRekeyDao = ChaosPendingRekeyDao()
        val bobRepo = ChatRepository(bobContactDao, bobMessageDao, bobChunkDao, bobRekeyDao, bobChaos).also(::configureFastRepo)

        val aliceToBobSeed = CryptoUtils.secureRandomBytes(64)
        val bobToAliceSeed = CryptoUtils.secureRandomBytes(64)

        aliceRepo.addContact(
            ContactEntity(
                id = "bob",
                name = "Bob",
                chainKeyOut = aliceToBobSeed,
                chainKeyIn = bobToAliceSeed,
                counterOut = 0,
                counterIn = 0,
                rekeyEpoch = 0,
                isInitiator = true
            )
        )
        bobRepo.addContact(
            ContactEntity(
                id = "alice",
                name = "Alice",
                chainKeyOut = bobToAliceSeed,
                chainKeyIn = aliceToBobSeed,
                counterOut = 0,
                counterIn = 0,
                rekeyEpoch = 0,
                isInitiator = false
            )
        )

        // Advance cleanly to counter 50 right before the PQC rekey boundary
        for (i in 0 until 50) {
            assertTrue(aliceRepo.sendTextMessage("bob", "Pre-rekey #$i"))
            assertTrue(bobRepo.pollContactIncoming("alice"))
        }
        assertEquals(50, aliceRepo.getContact("bob")!!.counterOut)

        // Phase 1: Initiate 0x03 Rekey Offer under 30% UDP loss + queue outbox messages
        aliceChaos.udpLossRate = 0.30
        aliceRepo.sendTextMessage("bob", "Msg #50-chaos")
        aliceRepo.sendTextMessage("bob", "Msg #51-chaos")
        aliceRepo.sendTextMessage("bob", "Msg #52-chaos")

        assertNotNull("Pending rekey offer must be persisted", aliceRekeyDao.getPendingOffer("bob"))
        assertEquals("Queued messages must wait in outbox until rekey completes", 3, aliceMessageDao.getQueuedMessagesForContact("bob").size)

        // Phase 2: Full network partition interrupts Bob receiving Offer / sending 0x04 Response
        aliceChaos.isNetworkPartitioned = true
        bobChaos.isNetworkPartitioned = true
        bobRepo.pollContactIncoming("alice")
        assertEquals("Epoch must remain 0 during network partition", 0L, bobRepo.getContact("alice")!!.rekeyEpoch)
        assertEquals(3, aliceMessageDao.getQueuedMessagesForContact("bob").size)

        // Phase 3: Partition heals with 20% ongoing UDP loss; Bob processes Offer (0x03) -> sends Response (0x04)
        aliceChaos.isNetworkPartitioned = false
        bobChaos.isNetworkPartitioned = false
        aliceChaos.udpLossRate = 0.20
        bobChaos.udpLossRate = 0.20

        var bobRekeyed = false
        repeat(20) {
            if (!bobRekeyed) {
                bobRepo.pollContactIncoming("alice")
                bobRekeyed = bobRepo.getContact("alice")!!.rekeyEpoch == 1L
            }
        }
        assertTrue("Bob must process 0x03 offer and advance to rekeyEpoch=1", bobRekeyed)

        // Alice receives 0x04 response under 15% loss and drains all 3 queued messages cleanly
        aliceChaos.udpLossRate = 0.0
        bobChaos.udpLossRate = 0.15
        var aliceRekeyed = false
        repeat(20) {
            if (!aliceRekeyed) {
                aliceRepo.pollContactIncoming("bob")
                aliceRekeyed = aliceRepo.getContact("bob")!!.rekeyEpoch == 1L
            }
        }
        assertTrue("Alice must process 0x04 response and advance to rekeyEpoch=1", aliceRekeyed)

        bobChaos.udpLossRate = 0.20
        repeat(10) {
            bobRepo.pollContactIncoming("alice")
        }

        val deliveredTexts = bobMessageDao.messages
            .filter { it.contactId == "alice" && !it.isOutgoing && it.status == "DELIVERED" }
            .mapNotNull { it.rawTextContent }
            .toSet()

        assertEquals(53, deliveredTexts.size)
        assertTrue(deliveredTexts.contains("Msg #50-chaos"))
        assertTrue(deliveredTexts.contains("Msg #51-chaos"))
        assertTrue(deliveredTexts.contains("Msg #52-chaos"))
        assertTrue(aliceMessageDao.getQueuedMessagesForContact("bob").isEmpty())

        // Verify post-rekey bidirectional communication stays synchronized
        aliceChaos.udpLossRate = 0.15
        bobChaos.udpLossRate = 0.15
        assertTrue(aliceRepo.sendTextMessage("bob", "Post-chaos-rekey Alice->Bob"))
        repeat(10) { bobRepo.pollContactIncoming("alice") }
        assertTrue(bobRepo.sendTextMessage("alice", "Post-chaos-rekey Bob->Alice"))
        repeat(10) { aliceRepo.pollContactIncoming("bob") }

        assertTrue(bobMessageDao.messages.any { it.rawTextContent == "Post-chaos-rekey Alice->Bob" })
        assertTrue(aliceMessageDao.messages.any { it.rawTextContent == "Post-chaos-rekey Bob->Alice" })

        aliceRepo.close()
        bobRepo.close()
        sharedDht.stop()
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    fun testCgnatPortRebindingRecoversWithAdaptiveReplicationAndLiveSocketRebind() = runBlocking {
        // Part A: ChaosDhtClient CGNAT port rebinds + adaptive K=16 + keepalive recovery under 25% UDP loss
        val sharedDht = FakeDht(minDelayMs = 0, maxDelayMs = 0).apply { start() }
        val aliceChaos = ChaosDhtClient(sharedDht, seed = 505L)
        val bobChaos = ChaosDhtClient(sharedDht, seed = 606L)

        val aliceContactDao = ChaosContactDao()
        val aliceMessageDao = ChaosMessageDao()
        val bobContactDao = ChaosContactDao()
        val bobMessageDao = ChaosMessageDao()
        val aliceRepo = ChatRepository(aliceContactDao, aliceMessageDao, ChaosChunkDao(), null, aliceChaos).also(::configureFastRepo)
        val bobRepo = ChatRepository(bobContactDao, bobMessageDao, ChaosChunkDao(), null, bobChaos).also(::configureFastRepo)

        val chainA2B = CryptoUtils.secureRandomBytes(64)
        val chainB2A = CryptoUtils.secureRandomBytes(64)
        aliceRepo.addContact(ContactEntity(id = "bob", name = "Bob", chainKeyOut = chainA2B, chainKeyIn = chainB2A, counterOut = 0, counterIn = 0, isInitiator = true))
        bobRepo.addContact(ContactEntity(id = "alice", name = "Alice", chainKeyOut = chainB2A, chainKeyIn = chainA2B, counterOut = 0, counterIn = 0, isInitiator = false))

        aliceChaos.setAdaptiveK(true)
        assertEquals(16, aliceChaos.replicationK)
        aliceChaos.udpLossRate = 0.25

        for (round in 1..4) {
            bobChaos.simulateCgnatPortRebind()
            assertTrue(bobChaos.rebootstrap(force = true))
            assertTrue(bobChaos.sendKeepalivePing())

            assertTrue(aliceRepo.sendTextMessage("bob", "CGNAT round $round"))
            repeat(10) { bobRepo.pollContactIncoming("alice") }
        }
        assertEquals(4, bobChaos.cgnatRebinds.get())
        assertEquals(4, bobMessageDao.messages.count { !it.isOutgoing && it.status == "DELIVERED" })

        aliceRepo.close()
        bobRepo.close()
        sharedDht.stop()

        // Part B: Real local DhtLeafNode UDP socket rebinding on loopback port change
        val prevLocalTestbed = DhtLeafNode.isLocalTestbedMode
        DhtLeafNode.isLocalTestbedMode = true
        val relayLeaf = DhtLeafNode(port = 0, autoBootstrap = false)
        val aliceLeaf = DhtLeafNode(port = 0, autoBootstrap = false)
        var bobLeaf = DhtLeafNode(port = 0, autoBootstrap = false)
        try {
            val relaySocket = relayLeaf.initSocket()
            val aliceSocket = aliceLeaf.initSocket()
            val bobSocket1 = bobLeaf.initSocket()
            relayLeaf.start()
            aliceLeaf.start()
            bobLeaf.start()

            val relayAddr = InetSocketAddress("127.0.0.1", relaySocket.localPort)
            val initialBobPort = bobSocket1.localPort
            aliceLeaf.addPeer(relayLeaf.myNodeId, relayAddr)
            bobLeaf.addPeer(relayLeaf.myNodeId, relayAddr)
            relayLeaf.addPeer(aliceLeaf.myNodeId, InetSocketAddress("127.0.0.1", aliceSocket.localPort))
            relayLeaf.addPeer(bobLeaf.myNodeId, InetSocketAddress("127.0.0.1", initialBobPort))

            val edSk1 = CryptoUtils.secureRandomBytes(32)
            val pk1 = org.pqchat.dht.crypto.Ed25519Engine.generateKeyPairFromSeed(edSk1).publicKey
            val target1 = org.pqchat.dht.crypto.Ed25519Engine.computeTarget(pk1)
            val frame1 = ByteArray(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES) { 0x41 }

            assertTrue(aliceLeaf.putMutable(target1, frame1, sk = edSk1, skipLocalStore = true))
            val got1 = bobLeaf.getMutable(target1, skipLocalStore = true)
            assertNotNull("Bob must retrieve record before CGNAT port rebind", got1)
            assertArrayEquals(frame1, got1!!.v)

            // Stop Bob and bind a brand-new ephemeral UDP port (emulating CGNAT source port rebinding)
            bobLeaf.stop()
            bobLeaf = DhtLeafNode(port = 0, autoBootstrap = false)
            val bobSocket2 = bobLeaf.initSocket()
            bobLeaf.start()
            val reboundBobPort = bobSocket2.localPort
            assertNotEquals("Rebound CGNAT port must differ from previous closed port", initialBobPort, reboundBobPort)

            bobLeaf.addPeer(relayLeaf.myNodeId, relayAddr)
            val gotAfterRebind = bobLeaf.getMutable(target1, skipLocalStore = true)
            assertNotNull("Bob must still retrieve stored record from its new rebound UDP port", gotAfterRebind)
            assertArrayEquals(frame1, gotAfterRebind!!.v)

            val edSk2 = CryptoUtils.secureRandomBytes(32)
            val pk2 = org.pqchat.dht.crypto.Ed25519Engine.generateKeyPairFromSeed(edSk2).publicKey
            val target2 = org.pqchat.dht.crypto.Ed25519Engine.computeTarget(pk2)
            val frame2 = ByteArray(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES) { 0x42 }

            // Bob writes from post-rebind socket, Alice reads back cleanly
            assertTrue(bobLeaf.putMutable(target2, frame2, sk = edSk2, skipLocalStore = true))
            val got2 = aliceLeaf.getMutable(target2, skipLocalStore = true)
            assertNotNull("Alice must retrieve record written from Bob's rebound UDP port", got2)
            assertArrayEquals(frame2, got2!!.v)
        } finally {
            aliceLeaf.stop()
            bobLeaf.stop()
            relayLeaf.stop()
            DhtLeafNode.isLocalTestbedMode = prevLocalTestbed
        }
    }

    @Test
    @Timeout(value = 25, unit = TimeUnit.SECONDS)
    fun testTorCircuitRestartEnforcesFailClosedAndResumesTransport() = runBlocking {
        val clearnetCatcher = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val catcherAddress = InetSocketAddress(clearnetCatcher.localAddress, clearnetCatcher.localPort)
        val leakedPackets = AtomicInteger(0)

        Thread {
            val buf = ByteArray(2048)
            while (!clearnetCatcher.isClosed) {
                try {
                    clearnetCatcher.receive(DatagramPacket(buf, buf.size))
                    leakedPackets.incrementAndGet()
                } catch (_: Exception) {
                    break
                }
            }
        }.apply { isDaemon = true; start() }

        val node = DhtLeafNode(port = 0, autoBootstrap = false)
        node.start()

        val pendingAckQueue = PendingAckQueue()
        val outboundPoissonQueue = OutboundPoissonQueue()
        val trafficGenerator = PoissonTrafficGenerator(
            dhtLeafNode = node,
            pendingAckQueue = pendingAckQueue,
            outboundPoissonQueue = outboundPoissonQueue
        )

        var proxy1: ServerSocket? = null
        var proxy2: ServerSocket? = null
        try {
            // 1. Healthy SOCKS5 proxy (TCP tunnel mode, rejecting UDP ASSOCIATE with 0x07)
            proxy1 = startMockSocks5TcpOnlyProxy()
            node.setTorProxy(TorProxyConfig(enabled = true, socksHost = "127.0.0.1", socksPort = proxy1.localPort, timeoutMs = 1000))
            assertEquals(TorTransportMode.SOCKS5_TCP, node.torTransportMode)
            assertTrue(node.isTorRoutingActive)

            // 2. Simulate sudden Tor daemon/circuit crash
            proxy1.close()
            node.setTorProxy(TorProxyConfig(enabled = true, socksHost = "127.0.0.1", socksPort = findClosedPort(), timeoutMs = 200))
            assertEquals(TorTransportMode.BLOCKED_ERROR, node.torTransportMode)
            assertFalse(node.isTorRoutingActive)

            // Enqueue real frame + ACK and run traffic generator during outage
            outboundPoissonQueue.enqueue(
                OutboundPoissonFrame(
                    target = CryptoUtils.secureRandomBytes(20),
                    payload = ByteArray(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES),
                    sk = CryptoUtils.secureRandomBytes(32),
                    seqNum = 1,
                    messageId = 99L
                )
            )
            pendingAckQueue.enqueue(
                PendingAck(
                    contactId = "alice",
                    messageId = "msg-chaos-tor",
                    ratchetKey = CryptoUtils.secureRandomBytes(32),
                    seqNum = 1
                )
            )

            trafficGenerator.processCoverTrafficTick()
            assertNull(node.sendQuery(catcherAddress, KrpcMessage.createPingQuery(node.myNodeId), timeoutMs = 200L))
            assertNull(node.sendCoverTrafficDummy())
            delay(100)

            assertEquals("Fail-closed must leak zero clearnet UDP packets during Tor restart", 0, leakedPackets.get())
            assertEquals("Outbound queue must be preserved during Tor outage", 1, outboundPoissonQueue.size)
            assertEquals("Pending ACK queue must be preserved during Tor outage", 1, pendingAckQueue.size)

            // 3. Tor circuit recovers on fresh SOCKS5 port
            proxy2 = startMockSocks5TcpOnlyProxy()
            node.setTorProxy(TorProxyConfig(enabled = true, socksHost = "127.0.0.1", socksPort = proxy2.localPort, timeoutMs = 1000))
            assertEquals(TorTransportMode.SOCKS5_TCP, node.torTransportMode)
            assertTrue("Tor routing must recover cleanly once circuit restarts", node.isTorRoutingActive)
            assertEquals("Zero clearnet UDP packets allowed across entire lifecycle", 0, leakedPackets.get())
        } finally {
            trafficGenerator.stop()
            node.stop()
            clearnetCatcher.close()
            try { proxy1?.close() } catch (_: Exception) {}
            try { proxy2?.close() } catch (_: Exception) {}
        }
    }

    private fun startMockSocks5TcpOnlyProxy(): ServerSocket {
        val server = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
        Thread {
            while (!server.isClosed) {
                try {
                    val client = server.accept()
                    val inp = DataInputStream(client.getInputStream())
                    val out = DataOutputStream(client.getOutputStream())
                    inp.readUnsignedByte()
                    val nMethods = inp.readUnsignedByte()
                    inp.readFully(ByteArray(nMethods))
                    out.write(byteArrayOf(0x05, 0x00))
                    out.flush()

                    inp.readUnsignedByte()
                    inp.readUnsignedByte()
                    inp.readUnsignedByte()
                    val atyp = inp.readUnsignedByte()
                    when (atyp) {
                        0x01 -> inp.skipBytes(4)
                        0x03 -> inp.skipBytes(inp.readUnsignedByte())
                        0x04 -> inp.skipBytes(16)
                    }
                    inp.readUnsignedShort()
                    // Reject UDP ASSOCIATE (0x07), forcing DhtLeafNode into Tor SOCKS5_TCP mode
                    out.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    out.flush()
                    client.close()
                } catch (_: Exception) {
                    if (server.isClosed) break
                }
            }
        }.apply { isDaemon = true; start() }
        return server
    }

    private fun findClosedPort(): Int {
        val ss = ServerSocket(0)
        val p = ss.localPort
        ss.close()
        return p
    }
}
