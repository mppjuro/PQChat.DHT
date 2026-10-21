package org.pqchat.dht.traffic

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.dht.leaf.DhtClient
import java.security.Security
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.sqrt

class StrictPoissonTrafficShapingTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupBouncyCastle() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private lateinit var fakeDht: FakeDht

    @Before
    fun setUp() {
        fakeDht = FakeDht()
        fakeDht.start()
        PollingWorker.clearRepublishTasks()
        BlindRepublishPool.defaultInstance.clear()
        DecoyTargetPool.defaultInstance.clear()
    }

    @After
    fun tearDown() {
        fakeDht.stop()
        PollingWorker.clearRepublishTasks()
        BlindRepublishPool.defaultInstance.clear()
        DecoyTargetPool.defaultInstance.clear()
    }

    @Test
    fun testOutboundPoissonQueue_FifoAndRemoval() {
        val queue = OutboundPoissonQueue()
        assertTrue(queue.isEmpty())
        assertEquals(0, queue.size)
        assertNull(queue.poll())
        assertNull(queue.peek())

        val frame1 = OutboundPoissonFrame(
            target = ByteArray(20) { 1 },
            payload = ByteArray(900) { 1 },
            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
            salt = null,
            sk = ByteArray(32) { 1 },
            seqNum = 0,
            messageId = 101L,
            contactId = "alice"
        )
        val frame2 = OutboundPoissonFrame(
            target = ByteArray(20) { 2 },
            payload = ByteArray(900) { 2 },
            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
            salt = null,
            sk = ByteArray(32) { 2 },
            seqNum = 1,
            messageId = 102L,
            contactId = "alice"
        )

        queue.enqueue(frame1)
        queue.enqueue(frame2)
        assertEquals(2, queue.size)
        assertFalse(queue.isEmpty())
        assertEquals(101L, queue.peek()?.messageId)

        // Remove by messageId
        queue.removeForMessage(101L)
        assertEquals(1, queue.size)
        assertEquals(102L, queue.peek()?.messageId)

        val polled = queue.poll()
        assertNotNull(polled)
        assertEquals(102L, polled?.messageId)
        assertTrue(queue.isEmpty())
    }

    @Test
    fun testProcessCoverTrafficTick_StrictEmissionPriority() = runBlocking {
        val outboundQueue = OutboundPoissonQueue()
        val ackQueue = PendingAckQueue()
        val republishPool = BlindRepublishPool()

        val generator = PoissonTrafficGenerator(
            dhtLeafNode = fakeDht,
            pendingAckQueue = ackQueue,
            blindRepublishPool = republishPool,
            outboundPoissonQueue = outboundQueue,
            crowdsourcedRepublishEnabledProvider = { true }
        )

        // Tier 4: All queues empty -> sends Dummy Cover Traffic
        val eventDummy = generator.processCoverTrafficTick()
        assertNotNull("Dummy event must be returned", eventDummy)
        assertFalse("Dummy is not first send", eventDummy.isFirstSend)
        assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, eventDummy.payloadSize)

        // Populate all tiers simultaneously to verify strict priority:
        // Tier 1: User message in OutboundPoissonQueue
        val userSentFired = AtomicBoolean(false)
        val userTarget = CryptoUtils.secureRandomBytes(20)
        outboundQueue.enqueue(
            OutboundPoissonFrame(
                target = userTarget,
                payload = ByteArray(900) { 0x42 },
                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                salt = null,
                sk = CryptoUtils.secureRandomBytes(32),
                seqNum = 0,
                messageId = 1L,
                contactId = "alice",
                onSent = { success -> userSentFired.set(success) }
            )
        )

        // Tier 2: Pending ACK in PendingAckQueue
        ackQueue.enqueue(PendingAck("alice", "0", CryptoUtils.secureRandomBytes(32), 0))

        // Tier 3: Crowd republish task in BlindRepublishPool
        val kp = org.pqchat.dht.crypto.Ed25519Engine.generateEphemeralKeyPair()
        val v = ByteArray(900) { 0x77 }
        val seq = DhtClient.DEFAULT_MUTABLE_SEQ
        val signData = org.pqchat.dht.dht.bencode.Bencode.encodeBep44SignData(v, seq, null)
        val sig = org.pqchat.dht.crypto.Ed25519Engine.sign(kp.seed, signData)
        val republishTarget = CryptoUtils.sha1(kp.publicKey)
        republishPool.verifyAndAdd(republishTarget, kp.publicKey, seq, v, sig, null)

        // Tick 1: MUST emit Tier 1 (Outbound user frame)
        val eventTier1 = generator.processCoverTrafficTick()
        assertNotNull(eventTier1)
        assertTrue("Tier 1 must be marked as isFirstSend", eventTier1.isFirstSend)
        assertTrue("Callback onSent must be invoked", userSentFired.get())
        assertEquals(CryptoUtils.toHex(userTarget), eventTier1.targetHex)
        assertEquals(0, outboundQueue.size)

        // Tick 2: MUST emit Tier 2 (Pending Cover ACK)
        val eventTier2 = generator.processCoverTrafficTick()
        assertNotNull(eventTier2)
        assertFalse("Tier 2 is not first send", eventTier2.isFirstSend)
        assertEquals(0, ackQueue.size)

        // Tick 3: MUST emit Tier 3 (Crowd Republish)
        val eventTier3 = generator.processCoverTrafficTick()
        assertNotNull(eventTier3)
        assertFalse("Tier 3 is not first send", eventTier3.isFirstSend)
        assertTrue("Tier 3 is blind republish", eventTier3.isBlindRepublish)
        assertEquals(CryptoUtils.toHex(republishTarget), eventTier3.targetHex)

        // Clear republish pool to test Tier 4 fallback
        republishPool.clear()

        // Tick 4: MUST fall back to Tier 4 (Dummy Chaff)
        val eventTier4 = generator.processCoverTrafficTick()
        assertNotNull(eventTier4)
        assertFalse("Tier 4 is dummy", eventTier4.isFirstSend)
        assertFalse("Tier 4 is not ACK", eventTier4.isAck)
        assertFalse("Tier 4 is not blind republish", eventTier4.isBlindRepublish)
    }

    @Test
    fun testChatRepository_StrictPoissonShaping_Flow() = runBlocking {
        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()
        val ackQueue = PendingAckQueue()
        val outboundQueue = OutboundPoissonQueue()

        val repo = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = chunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = ackQueue,
            outboundPoissonQueue = outboundQueue,
            isStrictPoissonShapingEnabled = true
        )

        val generator = PoissonTrafficGenerator(
            dhtLeafNode = fakeDht,
            pendingAckQueue = ackQueue,
            blindRepublishPool = repo.blindRepublishPool,
            outboundPoissonQueue = outboundQueue
        )

        val contactId = "bob"
        val seed = CryptoUtils.secureRandomBytes(64)
        repo.addContact(
            ContactEntity(
                id = contactId,
                name = "Bob",
                chainKeyOut = seed,
                chainKeyIn = seed,
                counterOut = 0,
                counterIn = 0
            )
        )

        // 1. Send text message with strict Poisson shaping enabled
        val sentOk = repo.sendTextMessage(contactId, "Strict Poisson Secret Message")
        assertTrue("sendTextMessage should succeed immediately by queueing", sentOk)

        // Message should be in database with status "QUEUED_POISSON"
        val messages = messageDao.messages
        assertEquals(1, messages.size)
        val msg = messages.first()
        assertEquals("QUEUED_POISSON", msg.status)
        assertEquals(0, msg.seqNum)

        // Contact's outgoing counter must have advanced immediately so next message gets next ratcheted slot
        val updatedContact = contactDao.getContactById(contactId)
        assertNotNull(updatedContact)
        assertEquals(1, updatedContact!!.counterOut)

        // Outbound queue has 1 frame
        assertEquals(1, outboundQueue.size)

        // Frame must NOT yet be in DHT before the Poisson tick fires!
        val target = requireNotNull(msg.slotTarget) { "slotTarget must not be null" }
        val dhtBefore = fakeDht.getMutable(target)
        assertNull("Payload must not be published to DHT before Poisson tick", dhtBefore)

        // 2. Poisson tick fires
        val event = generator.processCoverTrafficTick()
        assertNotNull("Poisson tick should emit the queued frame", event)
        assertTrue("Event should be FIRST_SEND", event.isFirstSend)
        assertEquals(0, outboundQueue.size)

        // Now frame is published in DHT
        val dhtAfter = requireNotNull(fakeDht.getMutable(target)) { "Payload must now be present in DHT" }
        assertEquals(900, dhtAfter.v.size)

        // Message status in database transitions to "PENDING_DELIVERY"
        val updatedMsg = messageDao.getMessageById(msg.id)
        assertNotNull(updatedMsg)
        assertEquals("PENDING_DELIVERY", updatedMsg!!.status)

        // Republish task is registered
        assertTrue(PollingWorker.isRepublishTaskRegistered(msg.id))
    }

    @Test
    fun testStrictPoisson_MultiChunkImage_KolmogorovSmirnov() = runBlocking {
        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()
        val ackQueue = PendingAckQueue()
        val outboundQueue = OutboundPoissonQueue()

        val repo = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = chunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = ackQueue,
            outboundPoissonQueue = outboundQueue,
            isStrictPoissonShapingEnabled = true
        )

        val lambda = 1.0 / 60.0
        val generator = PoissonTrafficGenerator(
            dhtLeafNode = fakeDht,
            lambda = lambda,
            pendingAckQueue = ackQueue,
            blindRepublishPool = repo.blindRepublishPool,
            outboundPoissonQueue = outboundQueue,
            random = java.util.Random(101L)
        )

        val contactId = "bob"
        val seed = CryptoUtils.secureRandomBytes(64)
        repo.addContact(
            ContactEntity(
                id = contactId,
                name = "Bob",
                chainKeyOut = seed,
                chainKeyIn = seed,
                counterOut = 0,
                counterIn = 0
            )
        )

        val n = 200
        val intervalsBaseline = DoubleArray(n) { generator.computeNextIntervalMs(lambda).toDouble() }

        // Send multi-chunk image (8 KB -> ~10 chunks)
        val imageBytes = CryptoUtils.secureRandomBytes(8192)
        val sendResult = repo.sendImagePayload(contactId, imageBytes)
        assertTrue("Image sending should be queued immediately", sendResult)

        // Verify that all chunks are held in OutboundPoissonQueue (NO burst on DHT)
        val chunkCount = outboundQueue.size
        assertTrue("Multi-chunk image must enqueue multiple chunks (> 5), got $chunkCount", chunkCount >= 5)

        // Process ticks: emit chunks followed by idle chaffing
        val intervalsActive = DoubleArray(n)
        for (i in 0 until n) {
            intervalsActive[i] = generator.computeNextIntervalMs(lambda).toDouble()
            val event = generator.processCoverTrafficTick(delayMs = intervalsActive[i].toLong())
            assertNotNull(event)
            assertEquals("Every packet must strictly be 900 bytes", BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, event.payloadSize)
        }

        // Two-sample Kolmogorov-Smirnov test against baseline Poisson process
        val dTwoSample = computeTwoSampleKsStatistic(intervalsActive, intervalsBaseline)
        val dTwoCrit = 1.36 * sqrt((2.0 * n) / (n.toDouble() * n))
        assertTrue(
            "Two-sample KS statistic D ($dTwoSample) must be < D_crit ($dTwoCrit) at alpha=0.05 (p > 0.05), proving multi-chunk image does not alter timing",
            dTwoSample < dTwoCrit
        )

        // One-sample Kolmogorov-Smirnov test against theoretical exponential distribution
        val dOneSample = computeOneSampleKsStatistic(intervalsActive, lambda)
        val dOneCrit = 1.36 / sqrt(n.toDouble())
        assertTrue(
            "One-sample KS statistic D ($dOneSample) must be < D_crit ($dOneCrit) at alpha=0.05 (p > 0.05) against Poisson process",
            dOneSample < dOneCrit
        )
    }

    @Test
    fun testStrictPoisson_5PersonGroupInvite_KolmogorovSmirnov() = runBlocking {
        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()
        val groupDao = FakeGroupDao()
        val groupMemberDao = FakeGroupMemberDao()
        val ackQueue = PendingAckQueue()
        val outboundQueue = OutboundPoissonQueue()

        val repo = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = chunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = ackQueue,
            outboundPoissonQueue = outboundQueue,
            isStrictPoissonShapingEnabled = true,
            groupDao = groupDao,
            groupMemberDao = groupMemberDao
        )

        val lambda = 1.0 / 60.0
        val generator = PoissonTrafficGenerator(
            dhtLeafNode = fakeDht,
            lambda = lambda,
            pendingAckQueue = ackQueue,
            blindRepublishPool = repo.blindRepublishPool,
            outboundPoissonQueue = outboundQueue,
            random = java.util.Random(202L)
        )

        // Setup 4 contacts for a 5-person group (Self + 4 contacts)
        val contacts = listOf("bob", "charlie", "dave", "eve")
        for (c in contacts) {
            repo.addContact(
                ContactEntity(
                    id = c,
                    name = c.replaceFirstChar { it.uppercase() },
                    chainKeyOut = CryptoUtils.secureRandomBytes(64),
                    chainKeyIn = CryptoUtils.secureRandomBytes(64),
                    counterOut = 0,
                    counterIn = 0,
                    isVerified = true
                )
            )
        }

        val n = 200
        val intervalsBaseline = DoubleArray(n) { generator.computeNextIntervalMs(lambda).toDouble() }

        // Create 5-person group: sends 4 INVITE packets
        val group = repo.createGroup("Cryptographers Core", contacts)
        assertNotNull(group)

        // Verify that 4 invites are enqueued in OutboundPoissonQueue, NOT blasted directly to DHT
        assertEquals("4 invite packets must be queued in OutboundPoissonQueue", 4, outboundQueue.size)

        // Process emission ticks
        val intervalsActive = DoubleArray(n)
        for (i in 0 until n) {
            intervalsActive[i] = generator.computeNextIntervalMs(lambda).toDouble()
            val event = generator.processCoverTrafficTick(delayMs = intervalsActive[i].toLong())
            assertNotNull(event)
            assertEquals("Every packet must strictly be 900 bytes", BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, event.payloadSize)
        }

        // Two-sample KS test
        val dTwoSample = computeTwoSampleKsStatistic(intervalsActive, intervalsBaseline)
        val dTwoCrit = 1.36 * sqrt((2.0 * n) / (n.toDouble() * n))
        assertTrue(
            "Two-sample KS statistic D ($dTwoSample) must be < D_crit ($dTwoCrit) at alpha=0.05 (p > 0.05), proving 5-person group invite does not alter timing",
            dTwoSample < dTwoCrit
        )

        // One-sample KS test against theoretical exponential distribution
        val dOneSample = computeOneSampleKsStatistic(intervalsActive, lambda)
        val dOneCrit = 1.36 / sqrt(n.toDouble())
        assertTrue(
            "One-sample KS statistic D ($dOneSample) must be < D_crit ($dOneCrit) at alpha=0.05 (p > 0.05)",
            dOneSample < dOneCrit
        )
    }

    @Test
    fun testStrictPoisson_GroupMessage_KolmogorovSmirnov() = runBlocking {
        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()
        val groupDao = FakeGroupDao()
        val groupMemberDao = FakeGroupMemberDao()
        val ackQueue = PendingAckQueue()
        val outboundQueue = OutboundPoissonQueue()

        val repo = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = chunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = ackQueue,
            outboundPoissonQueue = outboundQueue,
            isStrictPoissonShapingEnabled = true,
            groupDao = groupDao,
            groupMemberDao = groupMemberDao
        )

        val lambda = 1.0 / 60.0
        val generator = PoissonTrafficGenerator(
            dhtLeafNode = fakeDht,
            lambda = lambda,
            pendingAckQueue = ackQueue,
            blindRepublishPool = repo.blindRepublishPool,
            outboundPoissonQueue = outboundQueue,
            random = java.util.Random(303L)
        )

        // Setup 4 contacts and group
        val contacts = listOf("bob", "charlie", "dave", "eve")
        for (c in contacts) {
            repo.addContact(
                ContactEntity(
                    id = c,
                    name = c.replaceFirstChar { it.uppercase() },
                    chainKeyOut = CryptoUtils.secureRandomBytes(64),
                    chainKeyIn = CryptoUtils.secureRandomBytes(64),
                    counterOut = 0,
                    counterIn = 0,
                    isVerified = true
                )
            )
        }
        val group = repo.createGroup("Cryptographers Core", contacts)
        // Drain group invites first
        while (!outboundQueue.isEmpty()) {
            generator.processCoverTrafficTick()
        }

        val n = 200
        val intervalsBaseline = DoubleArray(n) { generator.computeNextIntervalMs(lambda).toDouble() }

        // Send group message: derives individual slots for all 4 recipients
        val sentOk = repo.sendGroupMessage(group.groupId, "Quantum-resistant broadcast message")
        assertTrue(sentOk)

        // Verify that 4 individual recipient message frames are enqueued in OutboundPoissonQueue
        assertEquals("4 individual recipient message frames must be queued", 4, outboundQueue.size)

        // Process emission ticks
        val intervalsActive = DoubleArray(n)
        for (i in 0 until n) {
            intervalsActive[i] = generator.computeNextIntervalMs(lambda).toDouble()
            val event = generator.processCoverTrafficTick(delayMs = intervalsActive[i].toLong())
            assertNotNull(event)
            assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, event.payloadSize)
        }

        val dTwoSample = computeTwoSampleKsStatistic(intervalsActive, intervalsBaseline)
        val dTwoCrit = 1.36 * sqrt((2.0 * n) / (n.toDouble() * n))
        assertTrue(
            "Two-sample KS statistic D ($dTwoSample) must be < D_crit ($dTwoCrit) at alpha=0.05 (p > 0.05), proving group message does not alter timing",
            dTwoSample < dTwoCrit
        )

        val dOneSample = computeOneSampleKsStatistic(intervalsActive, lambda)
        val dOneCrit = 1.36 / sqrt(n.toDouble())
        assertTrue(
            "One-sample KS statistic D ($dOneSample) must be < D_crit ($dOneCrit) at alpha=0.05 (p > 0.05)",
            dOneSample < dOneCrit
        )
    }

    @Test
    fun testStrictPoisson_CombinedBurst_KolmogorovSmirnov() = runBlocking {
        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()
        val groupDao = FakeGroupDao()
        val groupMemberDao = FakeGroupMemberDao()
        val ackQueue = PendingAckQueue()
        val outboundQueue = OutboundPoissonQueue()

        val repo = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = chunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = ackQueue,
            outboundPoissonQueue = outboundQueue,
            isStrictPoissonShapingEnabled = true,
            groupDao = groupDao,
            groupMemberDao = groupMemberDao
        )

        val lambda = 1.0 / 60.0
        val generator = PoissonTrafficGenerator(
            dhtLeafNode = fakeDht,
            lambda = lambda,
            pendingAckQueue = ackQueue,
            blindRepublishPool = repo.blindRepublishPool,
            outboundPoissonQueue = outboundQueue,
            random = java.util.Random(404L)
        )

        val contacts = listOf("bob", "charlie", "dave", "eve")
        for (c in contacts) {
            repo.addContact(
                ContactEntity(
                    id = c,
                    name = c.replaceFirstChar { it.uppercase() },
                    chainKeyOut = CryptoUtils.secureRandomBytes(64),
                    chainKeyIn = CryptoUtils.secureRandomBytes(64),
                    counterOut = 0,
                    counterIn = 0,
                    isVerified = true
                )
            )
        }

        val n = 200
        val intervalsBaseline = DoubleArray(n) { generator.computeNextIntervalMs(lambda).toDouble() }

        // Combined burst: 5-person group invite (4) + 6KB image (~8 chunks) + group message (4)
        val group = repo.createGroup("Cryptographers Core", contacts)
        repo.sendImagePayload("bob", CryptoUtils.secureRandomBytes(6000))
        repo.sendGroupMessage(group.groupId, "Simultaneous quantum message burst")

        // Total queue size should be at least 15 frames
        assertTrue("Queue must absorb combined burst (> 12 frames), got ${outboundQueue.size}", outboundQueue.size >= 12)

        // Process emission ticks
        val intervalsActive = DoubleArray(n)
        for (i in 0 until n) {
            intervalsActive[i] = generator.computeNextIntervalMs(lambda).toDouble()
            val event = generator.processCoverTrafficTick(delayMs = intervalsActive[i].toLong())
            assertNotNull(event)
            assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, event.payloadSize)
        }

        val dTwoSample = computeTwoSampleKsStatistic(intervalsActive, intervalsBaseline)
        val dTwoCrit = 1.36 * sqrt((2.0 * n) / (n.toDouble() * n))
        assertTrue(
            "Two-sample KS statistic D ($dTwoSample) must be < D_crit ($dTwoCrit) at alpha=0.05 (p > 0.05), proving combined burst does not alter timing",
            dTwoSample < dTwoCrit
        )

        val dOneSample = computeOneSampleKsStatistic(intervalsActive, lambda)
        val dOneCrit = 1.36 / sqrt(n.toDouble())
        assertTrue(
            "One-sample KS statistic D ($dOneSample) must be < D_crit ($dOneCrit) at alpha=0.05 (p > 0.05)",
            dOneSample < dOneCrit
        )
    }

    // --- Minimal In-Memory DAOs for isolation ---

    private class FakeContactDao : ContactDao {
        val contacts = mutableMapOf<String, ContactEntity>()
        val flow = MutableStateFlow<List<ContactEntity>>(emptyList())

        override fun getAllContactsFlow(): Flow<List<ContactEntity>> = flow
        override suspend fun getContactById(id: String): ContactEntity? = contacts[id]

        override suspend fun insertOrUpdate(contact: ContactEntity) {
            contacts[contact.id] = contact
            flow.value = contacts.values.toList()
        }

        override suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: EncryptedBlob) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateOutgoingStateAndEpoch(
            id: String,
            counterOut: Int,
            chainKeyOut: EncryptedBlob,
            rekeyEpoch: Long
        ) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut, rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpoch(
            id: String,
            counterIn: Int,
            chainKeyIn: EncryptedBlob,
            rekeyEpoch: Long
        ) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateWithBitmap(
            id: String,
            counterIn: Int,
            chainKeyIn: EncryptedBlob,
            bitmapBase: Int,
            bitmap: ByteArray
        ) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(
                counterIn = counterIn,
                chainKeyIn = chainKeyIn,
                receivedBitmapBase = bitmapBase,
                receivedBitmap = bitmap
            )
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpochWithBitmap(
            id: String,
            counterIn: Int,
            chainKeyIn: EncryptedBlob,
            rekeyEpoch: Long,
            bitmapBase: Int,
            bitmap: ByteArray
        ) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(
                counterIn = counterIn,
                chainKeyIn = chainKeyIn,
                rekeyEpoch = rekeyEpoch,
                receivedBitmapBase = bitmapBase,
                receivedBitmap = bitmap
            )
            flow.value = contacts.values.toList()
        }

        override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateVerifiedStatus(id: String, isVerified: Boolean) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(isVerified = isVerified)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateContactName(id: String, name: EncryptedText) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(name = name)
            flow.value = contacts.values.toList()
        }

        override suspend fun deleteContact(id: String) {
            contacts.remove(id)
            flow.value = contacts.values.toList()
        }
    }

    private class FakeMessageDao : org.pqchat.dht.test.BaseFakeMessageDao()

    private class FakeChunkDao : org.pqchat.dht.test.BaseFakeChunkDao()

    private class FakeGroupDao : GroupDao {
        val groups = mutableMapOf<String, GroupEntity>()
        val flow = MutableStateFlow<List<GroupEntity>>(emptyList())

        override fun getAllGroupsFlow(): Flow<List<GroupEntity>> = flow
        override suspend fun getAllActiveGroups(): List<GroupEntity> = groups.values.filter { it.isActive }
        override suspend fun getGroupById(groupId: String): GroupEntity? = groups[groupId]
        override suspend fun insertOrUpdate(group: GroupEntity) {
            groups[group.groupId] = group
            flow.value = groups.values.toList()
        }
        override suspend fun updateOutgoingState(groupId: String, counterOut: Int, chainKeyOut: EncryptedBlob, lastActive: Long) {
            val g = groups[groupId] ?: return
            groups[groupId] = g.copy(myCounterOut = counterOut, myChainKeyOut = chainKeyOut, lastActive = lastActive)
            flow.value = groups.values.toList()
        }
        override suspend fun updateRekeyedState(groupId: String, epoch: Long, counterOut: Int, chainKeyOut: EncryptedBlob, lastActive: Long) {
            val g = groups[groupId] ?: return
            groups[groupId] = g.copy(myCounterOut = counterOut, myChainKeyOut = chainKeyOut, groupEpoch = epoch, lastActive = lastActive)
            flow.value = groups.values.toList()
        }
        override suspend fun updateActiveStatus(groupId: String, isActive: Boolean) {
            val g = groups[groupId] ?: return
            groups[groupId] = g.copy(isActive = isActive)
            flow.value = groups.values.toList()
        }
        override suspend fun deleteGroup(groupId: String) {
            groups.remove(groupId)
            flow.value = groups.values.toList()
        }
    }

    private class FakeGroupMemberDao : GroupMemberDao {
        val members = mutableMapOf<String, MutableMap<String, GroupMemberEntity>>()
        val flows = mutableMapOf<String, MutableStateFlow<List<GroupMemberEntity>>>()

        private fun getFlow(groupId: String): MutableStateFlow<List<GroupMemberEntity>> {
            return flows.getOrPut(groupId) {
                MutableStateFlow(members[groupId]?.values?.filter { it.isActive } ?: emptyList())
            }
        }

        override fun getMembersForGroupFlow(groupId: String): Flow<List<GroupMemberEntity>> = getFlow(groupId)
        override suspend fun getMembersForGroup(groupId: String): List<GroupMemberEntity> = members[groupId]?.values?.filter { it.isActive } ?: emptyList()
        override suspend fun getMember(groupId: String, memberId: String): GroupMemberEntity? = members[groupId]?.get(memberId)
        override suspend fun insertOrUpdate(member: GroupMemberEntity) {
            val groupMap = members.getOrPut(member.groupId) { mutableMapOf() }
            groupMap[member.memberId] = member
            getFlow(member.groupId).value = groupMap.values.filter { it.isActive }
        }
        override suspend fun insertOrUpdateAll(members: List<GroupMemberEntity>) {
            for (m in members) {
                insertOrUpdate(m)
            }
        }
        override suspend fun updateMemberIncomingStateWithBitmap(
            groupId: String,
            memberId: String,
            counterIn: Int,
            chainKeyIn: EncryptedBlob,
            bitmapBase: Int,
            bitmap: ByteArray
        ) {
            val m = members[groupId]?.get(memberId) ?: return
            val updated = m.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            members[groupId]!![memberId] = updated
            getFlow(groupId).value = members[groupId]!!.values.filter { it.isActive }
        }
        override suspend fun markMemberInactive(groupId: String, memberId: String) {
            val m = members[groupId]?.get(memberId) ?: return
            members[groupId]!![memberId] = m.copy(isActive = false)
            getFlow(groupId).value = members[groupId]!!.values.filter { it.isActive }
        }
        override suspend fun deleteMember(groupId: String, memberId: String) {
            members[groupId]?.remove(memberId)
            getFlow(groupId).value = members[groupId]?.values?.filter { it.isActive } ?: emptyList()
        }
        override suspend fun deleteMembersForGroup(groupId: String) {
            members.remove(groupId)
            getFlow(groupId).value = emptyList()
        }
    }

    private fun computeTwoSampleKsStatistic(sample1: DoubleArray, sample2: DoubleArray): Double {
        val n1 = sample1.size
        val n2 = sample2.size
        val sorted1 = sample1.sortedArray()
        val sorted2 = sample2.sortedArray()

        var i1 = 0
        var i2 = 0
        var maxDiff = 0.0

        while (i1 < n1 && i2 < n2) {
            val v1 = sorted1[i1]
            val v2 = sorted2[i2]
            val v = if (v1 <= v2) v1 else v2

            while (i1 < n1 && sorted1[i1] <= v) i1++
            while (i2 < n2 && sorted2[i2] <= v) i2++

            val cdf1 = i1.toDouble() / n1
            val cdf2 = i2.toDouble() / n2
            val diff = abs(cdf1 - cdf2)
            if (diff > maxDiff) {
                maxDiff = diff
            }
        }
        return maxDiff
    }

    private fun computeOneSampleKsStatistic(sample: DoubleArray, lambda: Double): Double {
        val n = sample.size
        val sorted = sample.sortedArray()
        var maxDiff = 0.0
        for (i in 0 until n) {
            val x = sorted[i]
            val theoreticalCdf = 1.0 - exp(-lambda * (x / 1000.0))
            val empiricalPlus = (i + 1).toDouble() / n
            val empiricalMinus = i.toDouble() / n
            val diffPlus = abs(empiricalPlus - theoreticalCdf)
            val diffMinus = abs(theoreticalCdf - empiricalMinus)
            if (diffPlus > maxDiff) maxDiff = diffPlus
            if (diffMinus > maxDiff) maxDiff = diffMinus
        }
        return maxDiff
    }
}
