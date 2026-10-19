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
import java.util.concurrent.atomic.AtomicBoolean

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

        override suspend fun updateContactName(id: String, name: String) {
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
}
