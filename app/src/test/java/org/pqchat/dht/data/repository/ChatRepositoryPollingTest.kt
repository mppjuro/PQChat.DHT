package org.pqchat.dht.data.repository

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.RatchetChain
import java.security.Security

class ChatRepositoryPollingTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

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

        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch)
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

        override suspend fun getQueuedMessagesForContact(contactId: String): List<MessageEntity> {
            return messages.filter { it.contactId == contactId && it.isOutgoing && it.status == "QUEUED" }.sortedBy { it.id }
        }

        override suspend fun getAllQueuedMessages(): List<MessageEntity> {
            return messages.filter { it.isOutgoing && it.status == "QUEUED" }.sortedBy { it.id }
        }

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

        override suspend fun existsMessageWithEpoch(contactId: String, seqEpoch: Int, seqNum: Int, isOutgoing: Boolean): Boolean {
            return messages.any { it.contactId == contactId && it.seqEpoch == seqEpoch && it.seqNum == seqNum && it.isOutgoing == isOutgoing }
        }

        override suspend fun existsMessage(contactId: String, seqNum: Int, isOutgoing: Boolean): Boolean {
            return messages.any { it.contactId == contactId && it.seqNum == seqNum && it.isOutgoing == isOutgoing }
        }

        override suspend fun getPendingDeliveryMessagesForContact(contactId: String): List<MessageEntity> {
            return messages.filter { it.contactId == contactId && it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }.sortedBy { it.id }
        }

        override suspend fun getAllPendingDeliveryMessages(): List<MessageEntity> {
            return messages.filter { it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }.sortedBy { it.id }
        }
    }

    private class FakeChunkDao : ChunkDao {
        val chunks = mutableListOf<ChunkEntity>()

        override suspend fun insertChunk(chunk: ChunkEntity) {
            chunks.add(chunk)
        }

        override suspend fun getChunksForTransfer(transferId: String): List<ChunkEntity> =
            chunks.filter { it.transferId == transferId }

        override suspend fun countChunks(transferId: String): Int =
            chunks.count { it.transferId == transferId }

        override suspend fun deleteChunks(transferId: String) {
            chunks.removeAll { it.transferId == transferId }
        }
    }

    @Test
    fun testRoutineCheckQueriesOnlyCounterInWhenEmpty() = runBlocking {
        val fakeContactDao = FakeContactDao()
        val fakeMessageDao = FakeMessageDao()
        val fakeChunkDao = FakeChunkDao()
        val dhtNode = DhtLeafNode()
        val repository = ChatRepository(fakeContactDao, fakeMessageDao, fakeChunkDao, dhtNode)

        val seed = CryptoUtils.secureRandomBytes(64)
        val contact = ContactEntity(
            id = "alice",
            name = "Alice",
            chainKeyOut = seed,
            counterOut = 0,
            chainKeyIn = seed,
            counterIn = 0
        )
        fakeContactDao.insertOrUpdate(contact)

        // Slot 0 is EMPTY in DHT.
        // But slot 1 HAS a message stored in DHT.
        val slot1 = RatchetChain.computeLookaheadSlots(seed, 0, windowSize = 2)[1]
        val plaintext1 = BinaryFrameCodec.encodeTextMessage(1, 0, System.currentTimeMillis(), "Ahead Msg")
        val frame1 = BinaryFrameCodec.packAeadFrame(slot1.msgKey, plaintext1, slot1.target, contact.inboundDirection)
        dhtNode.putMutable(slot1.target, frame1, 2L, null, slot1.edPrivateKeySeed)

        // Routine check: pollContactIncoming
        val received = repository.pollContactIncoming(contact.id)

        // Must return false because current slot (counterIn = 0) is empty.
        // It must NOT poll n+1..n+4 when slot 0 is empty!
        assertFalse("Routine poll must return false when counterIn is empty", received)

        val c = fakeContactDao.getContactById(contact.id)
        assertEquals("counterIn must remain 0 when current slot is empty", 0, c!!.counterIn)
        assertTrue("No messages should be delivered yet", fakeMessageDao.messages.isEmpty())

        dhtNode.stop()
    }

    @Test
    fun testReceivingMessageAtCounterInTriggersLookaheadWindow() = runBlocking {
        val fakeContactDao = FakeContactDao()
        val fakeMessageDao = FakeMessageDao()
        val fakeChunkDao = FakeChunkDao()
        val dhtNode = DhtLeafNode()
        val repository = ChatRepository(fakeContactDao, fakeMessageDao, fakeChunkDao, dhtNode)

        val seed = CryptoUtils.secureRandomBytes(64)
        val contact = ContactEntity(
            id = "bob",
            name = "Bob",
            chainKeyOut = seed,
            counterOut = 0,
            chainKeyIn = seed,
            counterIn = 0
        )
        fakeContactDao.insertOrUpdate(contact)

        // Slot 0 has Message 0
        val slot0 = RatchetChain.deriveSlot(seed, 0)
        val plaintext0 = BinaryFrameCodec.encodeTextMessage(0, 0, System.currentTimeMillis(), "Message 0")
        val frame0 = BinaryFrameCodec.packAeadFrame(slot0.msgKey, plaintext0, slot0.target, contact.inboundDirection)
        dhtNode.putMutable(slot0.target, frame0, 1L, null, slot0.edPrivateKeySeed)

        // Slot 1 has Message 1 (in lookahead window)
        val slot1 = RatchetChain.deriveSlot(slot0.nextChainKey, 1)
        val plaintext1 = BinaryFrameCodec.encodeTextMessage(1, 0, System.currentTimeMillis(), "Message 1")
        val frame1 = BinaryFrameCodec.packAeadFrame(slot1.msgKey, plaintext1, slot1.target, contact.inboundDirection)
        dhtNode.putMutable(slot1.target, frame1, 2L, null, slot1.edPrivateKeySeed)

        // Routine poll: message 0 is received at counterIn = 0
        val received = repository.pollContactIncoming(contact.id)
        assertTrue("Message 0 should be received successfully", received)

        // Directly execute or await checkLookaheadWindow to verify lookahead window processing
        repository.checkLookaheadWindow(contact.id)

        val updated = fakeContactDao.getContactById(contact.id)
        assertNotNull(updated)
        assertEquals("counterIn should have advanced to 2 after consuming both messages", 2, updated!!.counterIn)

        val msgs = fakeMessageDao.messages
        assertEquals(2, msgs.size)
        assertEquals("Message 0", msgs[0].rawTextContent)
        assertEquals("Message 1", msgs[1].rawTextContent)

        dhtNode.stop()
    }

    @Test
    fun testPollAllContactsIncomingQueriesConcurrently() = runBlocking {
        val fakeContactDao = FakeContactDao()
        val fakeMessageDao = FakeMessageDao()
        val fakeChunkDao = FakeChunkDao()
        val dhtNode = DhtLeafNode()
        val repository = ChatRepository(fakeContactDao, fakeMessageDao, fakeChunkDao, dhtNode)

        val seed1 = CryptoUtils.secureRandomBytes(64)
        val seed2 = CryptoUtils.secureRandomBytes(64)
        val seed3 = CryptoUtils.secureRandomBytes(64)

        val c1 = ContactEntity(id = "c1", name = "Contact 1", chainKeyOut = seed1, chainKeyIn = seed1, counterOut = 0, counterIn = 0)
        val c2 = ContactEntity(id = "c2", name = "Contact 2", chainKeyOut = seed2, chainKeyIn = seed2, counterOut = 0, counterIn = 0)
        val c3 = ContactEntity(id = "c3", name = "Contact 3", chainKeyOut = seed3, chainKeyIn = seed3, counterOut = 0, counterIn = 0)

        fakeContactDao.insertOrUpdate(c1)
        fakeContactDao.insertOrUpdate(c2)
        fakeContactDao.insertOrUpdate(c3)

        // Put message for c1 and c3, leave c2 empty
        val slotC1 = RatchetChain.deriveSlot(seed1, 0)
        val frameC1 = BinaryFrameCodec.packAeadFrame(
            slotC1.msgKey,
            BinaryFrameCodec.encodeTextMessage(0, 0, System.currentTimeMillis(), "Hi C1"),
            slotC1.target,
            c1.inboundDirection
        )
        dhtNode.putMutable(slotC1.target, frameC1, 1L, null, slotC1.edPrivateKeySeed)

        val slotC3 = RatchetChain.deriveSlot(seed3, 0)
        val frameC3 = BinaryFrameCodec.packAeadFrame(
            slotC3.msgKey,
            BinaryFrameCodec.encodeTextMessage(0, 0, System.currentTimeMillis(), "Hi C3"),
            slotC3.target,
            c3.inboundDirection
        )
        dhtNode.putMutable(slotC3.target, frameC3, 1L, null, slotC3.edPrivateKeySeed)

        // Poll all contacts concurrently via coroutineScope and async/awaitAll
        val results = repository.pollAllContactsIncoming()
        assertEquals(3, results.size)

        val updatedC1 = fakeContactDao.getContactById("c1")
        val updatedC2 = fakeContactDao.getContactById("c2")
        val updatedC3 = fakeContactDao.getContactById("c3")

        assertEquals(1, updatedC1!!.counterIn)
        assertEquals(0, updatedC2!!.counterIn)
        assertEquals(1, updatedC3!!.counterIn)

        dhtNode.stop()
    }
}
