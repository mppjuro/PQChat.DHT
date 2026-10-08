package org.pqchat.dht.traffic

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.protocol.CoverAckProtocol
import org.pqchat.dht.data.repository.ChatRepository
import java.security.Security

class CoverTrafficAckTest {

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
    }

    @After
    fun tearDown() {
        fakeDht.stop()
        PollingWorker.clearRepublishTasks()
    }

    // --- Fake DAOs for ChatRepository tests ---

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

        override suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: EncryptedBlob, rekeyEpoch: Long) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut, rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun deleteContact(id: String) {
            contacts.remove(id)
            flow.value = contacts.values.toList()
        }
    }

    private class FakeMessageDao : MessageDao {
        val messages = mutableListOf<MessageEntity>()
        private var idCounter = 1L

        override fun getMessagesForContactFlow(contactId: String): Flow<List<MessageEntity>> =
            MutableStateFlow(messages.filter { it.contactId == contactId })

        override suspend fun insertMessage(message: MessageEntity): Long {
            val id = idCounter++
            messages.add(message.copy(id = id))
            return id
        }

        override suspend fun updateStatus(id: Long, status: String) {
            val idx = messages.indexOfFirst { it.id == id }
            if (idx >= 0) messages[idx] = messages[idx].copy(status = status)
        }

        override suspend fun updateMessageStatusAndSeq(id: Long, status: String, seqNum: Int) {
            val idx = messages.indexOfFirst { it.id == id }
            if (idx >= 0) messages[idx] = messages[idx].copy(status = status, seqNum = seqNum)
        }

        override suspend fun updateMessageRetry(id: Long, status: String, retryCount: Int, timestamp: Long) {
            val idx = messages.indexOfFirst { it.id == id }
            if (idx >= 0) messages[idx] = messages[idx].copy(status = status, retryCount = retryCount, lastAttemptTimestamp = timestamp)
        }

        override suspend fun getQueuedMessagesForContact(contactId: String): List<MessageEntity> =
            messages.filter { it.contactId == contactId && it.isOutgoing && it.status == "QUEUED" }.sortedBy { it.id }

        override suspend fun getAllQueuedMessages(): List<MessageEntity> =
            messages.filter { it.isOutgoing && it.status == "QUEUED" }.sortedBy { it.id }

        override suspend fun updateStatusForSeq(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String) {
            val idx = messages.indexOfFirst { it.contactId == contactId && it.seqNum == seqNum && it.isOutgoing == isOutgoing }
            if (idx >= 0) messages[idx] = messages[idx].copy(status = status)
        }

        override suspend fun updateMessageStatusAndDirection(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String) {
            val idx = messages.indexOfFirst { it.contactId == contactId && it.seqNum == seqNum }
            if (idx >= 0) messages[idx] = messages[idx].copy(status = status, isOutgoing = isOutgoing)
        }

        override suspend fun normalizeConfirmedSelfNotes(contactId: String) {}

        override suspend fun deleteMessagesForContact(contactId: String) {
            messages.removeAll { it.contactId == contactId }
        }

        override suspend fun existsMessageWithEpoch(contactId: String, seqEpoch: Int, seqNum: Int, isOutgoing: Boolean): Boolean =
            messages.any { it.contactId == contactId && it.seqEpoch == seqEpoch && it.seqNum == seqNum && it.isOutgoing == isOutgoing }

        override suspend fun existsMessage(contactId: String, seqNum: Int, isOutgoing: Boolean): Boolean =
            messages.any { it.contactId == contactId && it.seqNum == seqNum && it.isOutgoing == isOutgoing }

        override suspend fun getPendingDeliveryMessagesForContact(contactId: String): List<MessageEntity> =
            messages.filter { it.contactId == contactId && it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }.sortedBy { it.id }

        override suspend fun getAllPendingDeliveryMessages(): List<MessageEntity> =
            messages.filter { it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }.sortedBy { it.id }
    }

    private class FakeChunkDao : ChunkDao {
        override suspend fun insertChunk(chunk: ChunkEntity) {}
        override suspend fun getChunksForTransfer(transferId: String): List<ChunkEntity> = emptyList()
        override suspend fun countChunks(transferId: String): Int = 0
        override suspend fun deleteChunks(transferId: String) {}
    }

    @Test
    fun testCoverAckProtocol_PayloadCreationAndVerification() {
        val ratchetKey = CryptoUtils.secureRandomBytes(32)
        val messageId = "msg_42"
        val seqNum = 42

        val ackTarget = CoverAckProtocol.computeAckTarget(ratchetKey, messageId)
        assertNotNull(ackTarget)
        assertEquals(20, ackTarget.size)

        val payload = CoverAckProtocol.createAckPayload(ratchetKey, messageId, seqNum)
        assertEquals("Payload must be exactly MAX_FRAME_PAYLOAD_BYTES (900 bytes)",
            BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, payload.size)

        // Valid verification
        val isValid = CoverAckProtocol.verifyAckPayload(ratchetKey, payload, messageId, seqNum)
        assertTrue("Valid ACK payload must verify successfully", isValid)

        // Verification with wrong ratchet key
        val wrongKey = CryptoUtils.secureRandomBytes(32)
        val isWrongKeyValid = CoverAckProtocol.verifyAckPayload(wrongKey, payload, messageId, seqNum)
        assertFalse("Wrong ratchet key must fail verification", isWrongKeyValid)

        // Verification with wrong message ID
        val isWrongMsgValid = CoverAckProtocol.verifyAckPayload(ratchetKey, payload, "msg_999", seqNum)
        assertFalse("Wrong message ID must fail verification", isWrongMsgValid)

        // Verification with wrong sequence number
        val isWrongSeqValid = CoverAckProtocol.verifyAckPayload(ratchetKey, payload, messageId, 999)
        assertFalse("Wrong sequence number must fail verification", isWrongSeqValid)

        // Tampered payload
        val tampered = payload.copyOf()
        tampered[30] = (tampered[30].toInt() xor 0xFF).toByte()
        val isTamperedValid = CoverAckProtocol.verifyAckPayload(ratchetKey, tampered, messageId, seqNum)
        assertFalse("Tampered payload must fail AEAD authentication tag check", isTamperedValid)
    }

    @Test
    fun testPendingAckQueue_EnqueuePollAndRemoveForContact() {
        val queue = PendingAckQueue()
        val key = CryptoUtils.secureRandomBytes(32)

        queue.enqueue(PendingAck("alice", "1", key, 1))
        queue.enqueue(PendingAck("alice", "2", key, 2))
        queue.enqueue(PendingAck("bob", "10", key, 10))

        assertEquals(3, queue.size)

        // Piggybacked ACK removes Alice's ACKs up to seq 1
        queue.removeForContact("alice", upToSeqNum = 1)
        assertEquals(2, queue.size)

        val first = queue.poll()
        assertNotNull(first)
        assertEquals("alice", first!!.contactId)
        assertEquals("2", first.messageId)

        val second = queue.poll()
        assertNotNull(second)
        assertEquals("bob", second!!.contactId)
        assertEquals("10", second.messageId)

        assertNull(queue.poll())
    }

    @Test
    fun testPoissonTrafficGenerator_ReplacesDummyWithAckToken() = runBlocking {
        val queue = PendingAckQueue()
        val generator = PoissonTrafficGenerator(
            dhtLeafNode = fakeDht,
            pendingAckQueue = queue
        )

        // 1. Tick when queue is empty -> sends dummy packet
        val dummyEvent = generator.processCoverTrafficTick(delayMs = 5000L)
        assertFalse("Tick with empty queue must NOT be an ACK", dummyEvent.isAck)
        assertEquals(1, fakeDht.coverTrafficCalls.get())
        assertEquals(0, fakeDht.putCalls.get())

        // 2. Enqueue an ACK token
        val ratchetKey = CryptoUtils.secureRandomBytes(32)
        val pendingAck = PendingAck(
            contactId = "alice",
            messageId = "100",
            ratchetKey = ratchetKey,
            seqNum = 100
        )
        queue.enqueue(pendingAck)

        // 3. Tick with pending ACK -> sends encrypted ACK token replacing dummy
        val ackEvent = generator.processCoverTrafficTick(delayMs = 6000L)
        assertTrue("Tick with pending item must be an ACK", ackEvent.isAck)
        assertEquals(1, fakeDht.putCalls.get())
        assertEquals(0, queue.size)

        val expectedTarget = CoverAckProtocol.computeAckTarget(ratchetKey, "100")
        assertEquals(CryptoUtils.toHex(expectedTarget), ackEvent.targetHex)

        // The stored payload in DHT must be valid CoverAckProtocol payload
        val stored = fakeDht.getMutable(expectedTarget)
        assertNotNull("ACK payload must be stored in fake DHT under Target_ACK", stored)
        val verified = CoverAckProtocol.verifyAckPayload(
            ratchetKey = ratchetKey,
            frame = stored!!.v,
            expectedMessageId = "100",
            expectedSeqNum = 100
        )
        assertTrue("Payload stored by Poisson generator must verify as valid ACK", verified)
    }

    @Test
    fun testRepublishLoopTermination_OnCoverAckDetection() = runBlocking {
        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()
        val queue = PendingAckQueue()

        val repo = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = chunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = queue
        )

        val seed = CryptoUtils.secureRandomBytes(64)
        val contactId = "bob"
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

        // 1. Send message to Bob
        val sent = repo.sendTextMessage(contactId, "Hello Bob with Cover ACK!")
        assertTrue("sendTextMessage should succeed", sent)

        val pendingMsgs = messageDao.getPendingDeliveryMessagesForContact(contactId)
        assertEquals(1, pendingMsgs.size)
        val sentMsg = pendingMsgs[0]
        assertEquals("PENDING_DELIVERY", sentMsg.status)
        assertNotNull("ackTarget must be computed", sentMsg.ackTarget)
        assertNotNull("ackRatchetKey must be stored", sentMsg.ackRatchetKey)

        // Verify republish task registered in PollingWorker / DhtWorker
        assertTrue("Republish task must be registered", PollingWorker.isRepublishTaskRegistered(sentMsg.id))

        // Start republish loop with fast interval
        val republishTask = PollingWorker.RepublishTask(
            messageId = sentMsg.id,
            contactId = contactId,
            target = sentMsg.slotTarget!!,
            payload = ByteArray(900),
            edPrivateKeySeed = sentMsg.slotEdSeed!!.raw,
            intervalMs = 50L,
            maxRetries = 10
        )
        val loopJob = repo.startRepublishLoopForMessage(republishTask)

        // 2. Simulate receiver publishing Cover-Traffic ACK into Target_ACK
        val ackSeed = CoverAckProtocol.deriveAckSeed(sentMsg.ackRatchetKey!!.raw, "${sentMsg.seqNum}")
        val ackPayload = CoverAckProtocol.createAckPayload(sentMsg.ackRatchetKey!!.raw, "${sentMsg.seqNum}", sentMsg.seqNum)
        fakeDht.putMutable(
            target = sentMsg.ackTarget!!,
            v = ackPayload,
            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
            salt = null,
            sk = ackSeed
        )

        // 3. Sender performs checkPendingAcks (as during routine polling)
        val acksFound = repo.checkPendingAcks(contactId)
        assertEquals(1, acksFound)

        // 4. Verify message status updated to DELIVERED
        val updatedMsg = messageDao.messages.first { it.id == sentMsg.id }
        assertEquals("DELIVERED", updatedMsg.status)

        // 5. Verify republish task was unregistered and loop terminates
        assertFalse("Republish task must be unregistered after ACK detection",
            PollingWorker.isRepublishTaskRegistered(sentMsg.id))

        // Wait briefly to confirm loop finishes
        delay(100L)
        assertFalse("Republish loop job should be completed or cancelled", loopJob.isActive)

        // 6. Verify tombstone was placed on slotTarget (length 0 payload)
        val tombstone = fakeDht.getMutable(sentMsg.slotTarget!!)
        assertNotNull("Tombstone must be published on slotTarget", tombstone)
        assertEquals("Tombstone payload must be empty (BEP 44 empty record)", 0, tombstone!!.v.size)
    }

    @Test
    fun testPiggybackedAck_Integration() = runBlocking {
        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()
        val queue = PendingAckQueue()

        val repo = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = chunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = queue
        )

        val seed = CryptoUtils.secureRandomBytes(64)
        val contactId = "charlie"
        repo.addContact(
            ContactEntity(
                id = contactId,
                name = "Charlie",
                chainKeyOut = seed,
                chainKeyIn = seed,
                counterOut = 5,
                counterIn = 3
            )
        )

        // Pre-insert an outgoing message waiting for ACK (seqNum = 2)
        val msgId = messageDao.insertMessage(
            MessageEntity(
                contactId = contactId,
                isOutgoing = true,
                seqEpoch = 0,
                seqNum = 2,
                ackNum = 0,
                timestamp = System.currentTimeMillis(),
                textContent = "Outgoing msg awaiting ACK",
                status = "PENDING_DELIVERY",
                slotTarget = CryptoUtils.secureRandomBytes(20),
                slotEdSeed = CryptoUtils.secureRandomBytes(32)
            )
        )
        PollingWorker.registerRepublishTask(
            PollingWorker.RepublishTask(
                messageId = msgId,
                contactId = contactId,
                target = ByteArray(20),
                payload = ByteArray(900),
                edPrivateKeySeed = ByteArray(32)
            )
        )
        assertTrue(PollingWorker.isRepublishTaskRegistered(msgId))

        // Enqueue an ACK in the receiver queue to test clearing on outgoing reply
        queue.enqueue(PendingAck(contactId, "2", CryptoUtils.secureRandomBytes(32), 2))
        assertEquals(1, queue.size)

        // When sending an outgoing message, receiver's pendingAckQueue is cleared for that contact
        repo.sendTextMessage(contactId, "Reply from us")
        assertEquals("Outgoing message must clear pending ACK queue for that contact", 0, queue.size)

        // When a frame with piggybacked last_received_seq (e.g. 3) arrives from Charlie,
        // any pending messages with seqNum < 3 are acknowledged!
        repo.processPiggybackedAck(contactId, lastReceivedSeq = 3)

        val msgAfterAck = messageDao.messages.first { it.id == msgId }
        assertEquals("Message must transition to DELIVERED via piggybacked ACK", "DELIVERED", msgAfterAck.status)
        assertFalse("Republish task must be unregistered on piggybacked ACK",
            PollingWorker.isRepublishTaskRegistered(msgId))
    }
}
