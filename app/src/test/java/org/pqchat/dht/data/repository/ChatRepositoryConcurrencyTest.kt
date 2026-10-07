package org.pqchat.dht.data.repository

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.dht.FakeDht
import java.security.Security
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

class ChatRepositoryConcurrencyTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private class ThreadSafeContactDao : ContactDao {
        val contacts = ConcurrentHashMap<String, ContactEntity>()
        val flow = MutableStateFlow<List<ContactEntity>>(emptyList())

        override fun getAllContactsFlow(): Flow<List<ContactEntity>> = flow

        override suspend fun getContactById(id: String): ContactEntity? = contacts[id]

        override suspend fun insertOrUpdate(contact: ContactEntity) {
            contacts[contact.id] = contact
            flow.value = contacts.values.toList()
        }

        override suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: ByteArray) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: ByteArray, rekeyEpoch: Long) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut, rekeyEpoch = rekeyEpoch)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: ByteArray) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: ByteArray, rekeyEpoch: Long) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(rekeyEpoch = rekeyEpoch)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun deleteContact(id: String) {
            contacts.remove(id)
            flow.value = contacts.values.toList()
        }
    }

    private class ThreadSafeMessageDao : MessageDao {
        val messages = CopyOnWriteArrayList<MessageEntity>()
        private var idCounter = java.util.concurrent.atomic.AtomicLong(1L)

        override fun getMessagesForContactFlow(contactId: String): Flow<List<MessageEntity>> =
            MutableStateFlow(messages.filter { it.contactId == contactId })

        override suspend fun insertMessage(message: MessageEntity): Long {
            val id = idCounter.getAndIncrement()
            val m = message.copy(id = id)
            messages.add(m)
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
            if (idx >= 0) messages[idx] = messages[idx].copy(
                status = status,
                retryCount = retryCount,
                lastAttemptTimestamp = timestamp
            )
        }

        override suspend fun getQueuedMessagesForContact(contactId: String): List<MessageEntity> {
            return messages.filter { it.contactId == contactId && it.isOutgoing && it.status == "QUEUED" }
                .sortedBy { it.id }
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
            messages.removeIf { it.contactId == contactId }
        }

        override suspend fun existsMessage(contactId: String, seqNum: Int, isOutgoing: Boolean): Boolean {
            return messages.any { it.contactId == contactId && it.seqNum == seqNum && it.isOutgoing == isOutgoing }
        }
    }

    private class ThreadSafeChunkDao : ChunkDao {
        val chunks = CopyOnWriteArrayList<ChunkEntity>()

        override suspend fun insertChunk(chunk: ChunkEntity) {
            chunks.add(chunk)
        }

        override suspend fun getChunksForTransfer(transferId: String): List<ChunkEntity> =
            chunks.filter { it.transferId == transferId }.sortedBy { it.chunkIndex }

        override suspend fun countChunks(transferId: String): Int =
            chunks.count { it.transferId == transferId }

        override suspend fun deleteChunks(transferId: String) {
            chunks.removeIf { it.transferId == transferId }
        }
    }

    private class ThreadSafePendingRekeyOfferDao : PendingRekeyOfferDao {
        val offers = ConcurrentHashMap<String, PendingRekeyOfferEntity>()

        override suspend fun getPendingOffer(contactId: String): PendingRekeyOfferEntity? =
            offers[contactId]

        override suspend fun insertOrUpdate(offer: PendingRekeyOfferEntity) {
            offers[offer.contactId] = offer
        }

        override suspend fun deletePendingOffer(contactId: String) {
            offers.remove(contactId)
        }
    }

    @Test
    fun testConcurrentSendsSerializeAndProduceDistinctSlots() = runBlocking {
        val contactDao = ThreadSafeContactDao()
        val messageDao = ThreadSafeMessageDao()
        val chunkDao = ThreadSafeChunkDao()
        val rekeyDao = ThreadSafePendingRekeyOfferDao()
        val fakeDht = FakeDht(minDelayMs = 2, maxDelayMs = 10)
        fakeDht.start()

        val repo = ChatRepository(contactDao, messageDao, chunkDao, rekeyDao, fakeDht)
        val seed = CryptoUtils.secureRandomBytes(64)
        val contactId = "bob"
        repo.addContact(
            ContactEntity(
                id = contactId,
                name = "Bob",
                chainKeyOut = seed,
                chainKeyIn = seed,
                counterOut = 0,
                counterIn = 0,
                rekeyEpoch = 0
            )
        )

        // Launch 10 concurrent send requests
        val messageCount = 10
        val results = coroutineScope {
            (0 until messageCount).map { i ->
                async(Dispatchers.Default) {
                    repo.sendTextMessage(contactId, "Concurrent Message $i")
                }
            }.awaitAll()
        }

        assertTrue("All sends should succeed", results.all { it })

        val contact = repo.getContact(contactId)
        assertNotNull(contact)
        assertEquals("counterOut should equal messageCount", messageCount, contact!!.counterOut)

        val sentMessages = messageDao.messages.filter { it.contactId == contactId && it.status == "SENT_DHT" }
        assertEquals(messageCount, sentMessages.size)

        // Verify sequential unique sequence numbers
        val seqNums = sentMessages.map { it.seqNum }.sorted()
        assertEquals((0 until messageCount).toList(), seqNums)

        fakeDht.stop()
    }

    @Test
    fun testConcurrentPollsDoNotCorruptIncomingState() = runBlocking {
        val sharedDht = FakeDht(minDelayMs = 1, maxDelayMs = 5)
        sharedDht.start()

        val aliceContactDao = ThreadSafeContactDao()
        val aliceMessageDao = ThreadSafeMessageDao()
        val aliceChunkDao = ThreadSafeChunkDao()
        val aliceRekeyDao = ThreadSafePendingRekeyOfferDao()
        val aliceRepo = ChatRepository(aliceContactDao, aliceMessageDao, aliceChunkDao, aliceRekeyDao, sharedDht)

        val bobContactDao = ThreadSafeContactDao()
        val bobMessageDao = ThreadSafeMessageDao()
        val bobChunkDao = ThreadSafeChunkDao()
        val bobRekeyDao = ThreadSafePendingRekeyOfferDao()
        val bobRepo = ChatRepository(bobContactDao, bobMessageDao, bobChunkDao, bobRekeyDao, sharedDht)

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
                rekeyEpoch = 0
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
                rekeyEpoch = 0
            )
        )

        // Alice sends 5 messages to Bob
        for (i in 0 until 5) {
            val ok = aliceRepo.sendTextMessage("bob", "Hello $i")
            assertTrue(ok)
        }

        // Bob runs 5 concurrent polls
        coroutineScope {
            (0 until 5).map {
                async(Dispatchers.Default) {
                    bobRepo.pollContactIncoming("alice")
                }
            }.awaitAll()
        }

        val bobContact = bobRepo.getContact("alice")
        assertNotNull(bobContact)
        assertEquals("Bob's counterIn should advance to 5 without race conditions", 5, bobContact!!.counterIn)

        val deliveredToBob = bobMessageDao.messages.filter { it.contactId == "alice" && !it.isOutgoing && it.status == "DELIVERED" }
        assertEquals(5, deliveredToBob.size)
        val deliveredTexts = deliveredToBob.map { it.textContent }.toSet()
        for (i in 0 until 5) {
            assertTrue(deliveredTexts.contains("Hello $i"))
        }

        sharedDht.stop()
    }

    @Test
    fun testFailedPutQueuesMessageWithoutAdvancingCounterAndRetriesWithBackoff() = runBlocking {
        val fakeDht = FakeDht()
        fakeDht.start()
        // Simulate total network drop
        fakeDht.dropProbability = 1.0

        val contactDao = ThreadSafeContactDao()
        val messageDao = ThreadSafeMessageDao()
        val chunkDao = ThreadSafeChunkDao()
        val rekeyDao = ThreadSafePendingRekeyOfferDao()
        val repo = ChatRepository(contactDao, messageDao, chunkDao, rekeyDao, fakeDht)

        val seed = CryptoUtils.secureRandomBytes(64)
        val contactId = "charlie"
        repo.addContact(
            ContactEntity(
                id = contactId,
                name = "Charlie",
                chainKeyOut = seed,
                chainKeyIn = seed,
                counterOut = 0,
                counterIn = 0,
                rekeyEpoch = 0
            )
        )

        // Sending while network fails
        val sent = repo.sendTextMessage(contactId, "Failing offline message")
        assertFalse("Send should fail when network drops", sent)

        // Verify message was stored as QUEUED
        val queuedMessages = messageDao.getQueuedMessagesForContact(contactId)
        assertEquals(1, queuedMessages.size)
        val queuedMsg = queuedMessages[0]
        assertEquals("QUEUED", queuedMsg.status)
        assertEquals(1, queuedMsg.retryCount)

        // Crucial requirement: counterOut MUST NOT advance when put fails!
        val contactAfterFailure = repo.getContact(contactId)
        assertEquals("counterOut must NOT advance after failed put", 0, contactAfterFailure!!.counterOut)

        // Network recovers
        fakeDht.dropProbability = 0.0

        // Drain outbox with force=true
        val sentCount = repo.drainOutbox(contactId, force = true)
        assertEquals(1, sentCount)

        val contactAfterRetry = repo.getContact(contactId)
        assertEquals("counterOut must advance to 1 after successful retry", 1, contactAfterRetry!!.counterOut)

        val updatedMsg = messageDao.messages.first { it.id == queuedMsg.id }
        assertEquals("SENT_DHT", updatedMsg.status)
        assertEquals(0, updatedMsg.seqNum)

        fakeDht.stop()
    }
}
