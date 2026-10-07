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

class ChatRepositoryRekeyIntegrationTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private class TestContactDao : ContactDao {
        val contacts = ConcurrentHashMap<String, ContactEntity>()
        val flow = MutableStateFlow<List<ContactEntity>>(emptyList())

        override fun getAllContactsFlow(): Flow<List<ContactEntity>> = flow

        override suspend fun getContactById(id: String): ContactEntity? = contacts[id]

        override suspend fun insertOrUpdate(contact: ContactEntity) {
            contacts[contact.id] = contact
            flow.value = contacts.values.toList()
        }

        override suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: EncryptedBlob) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: EncryptedBlob, rekeyEpoch: Long) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut, rekeyEpoch = rekeyEpoch)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
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

    private class TestMessageDao : MessageDao {
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

        override suspend fun existsMessageWithEpoch(contactId: String, seqEpoch: Int, seqNum: Int, isOutgoing: Boolean): Boolean {
            return messages.any { it.contactId == contactId && it.seqEpoch == seqEpoch && it.seqNum == seqNum && it.isOutgoing == isOutgoing }
        }

        override suspend fun existsMessage(contactId: String, seqNum: Int, isOutgoing: Boolean): Boolean {
            return messages.any { it.contactId == contactId && it.seqNum == seqNum && it.isOutgoing == isOutgoing }
        }
    }

    private class TestChunkDao : ChunkDao {
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

    private class TestPendingRekeyOfferDao : PendingRekeyOfferDao {
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
    fun testTwoRepositoriesExchange200MessagesBidirectionallyWithPqcRekeys() = runBlocking {
        val sharedDht = FakeDht(minDelayMs = 0, maxDelayMs = 0)
        sharedDht.start()

        val aliceContactDao = TestContactDao()
        val aliceMessageDao = TestMessageDao()
        val aliceChunkDao = TestChunkDao()
        val aliceRekeyDao = TestPendingRekeyOfferDao()
        val aliceRepo = ChatRepository(aliceContactDao, aliceMessageDao, aliceChunkDao, aliceRekeyDao, sharedDht)

        val bobContactDao = TestContactDao()
        val bobMessageDao = TestMessageDao()
        val bobChunkDao = TestChunkDao()
        val bobRekeyDao = TestPendingRekeyOfferDao()
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

        val totalRounds = 200

        for (i in 0 until totalRounds) {
            // 1. Alice sends to Bob
            val aliceText = "Alice to Bob #$i"
            aliceRepo.sendTextMessage("bob", aliceText)

            // Bob polls for Alice's message or rekey offer
            bobRepo.pollContactIncoming("alice")
            // Alice polls in case Bob replied with rekey response
            aliceRepo.pollContactIncoming("bob")
            // Bob polls again in case Alice drained outbox after rekey
            bobRepo.pollContactIncoming("alice")

            // 2. Bob sends to Alice
            val bobText = "Bob to Alice #$i"
            bobRepo.sendTextMessage("alice", bobText)

            // Alice polls for Bob's message or rekey offer
            aliceRepo.pollContactIncoming("bob")
            // Bob polls in case Alice replied with rekey response
            bobRepo.pollContactIncoming("alice")
            // Alice polls again in case Bob drained outbox after rekey
            aliceRepo.pollContactIncoming("bob")
        }

        // Final poll synchronization
        bobRepo.pollContactIncoming("alice")
        aliceRepo.pollContactIncoming("bob")
        bobRepo.pollContactIncoming("alice")
        aliceRepo.pollContactIncoming("bob")

        // Assert all 200 messages delivered from Alice to Bob
        val bobDelivered = bobMessageDao.messages.filter { it.contactId == "alice" && !it.isOutgoing && it.status == "DELIVERED" }
        assertEquals("Bob should receive all 200 messages from Alice", totalRounds, bobDelivered.size)
        val bobReceivedTexts = bobDelivered.map { it.rawTextContent }.toSet()
        for (i in 0 until totalRounds) {
            assertTrue("Bob missing message #$i", bobReceivedTexts.contains("Alice to Bob #$i"))
        }

        // Assert all 200 messages delivered from Bob to Alice
        val aliceDelivered = aliceMessageDao.messages.filter { it.contactId == "bob" && !it.isOutgoing && it.status == "DELIVERED" }
        assertEquals("Alice should receive all 200 messages from Bob", totalRounds, aliceDelivered.size)
        val aliceReceivedTexts = aliceDelivered.map { it.rawTextContent }.toSet()
        for (i in 0 until totalRounds) {
            assertTrue("Alice missing message #$i", aliceReceivedTexts.contains("Bob to Alice #$i"))
        }

        // Verify Rekey Epochs: with 200 messages and rekey every 50, at least 4 epochs must have occurred
        val finalAliceContact = aliceRepo.getContact("bob")!!
        val finalBobContact = bobRepo.getContact("alice")!!

        assertTrue("Alice should have performed at least 4 PQC rekey epochs (got ${finalAliceContact.rekeyEpoch})", finalAliceContact.rekeyEpoch >= 4)
        assertTrue("Bob should have performed at least 4 PQC rekey epochs (got ${finalBobContact.rekeyEpoch})", finalBobContact.rekeyEpoch >= 4)
        assertEquals("Both parties must have identical rekeyEpoch", finalAliceContact.rekeyEpoch, finalBobContact.rekeyEpoch)

        // Verify no pending rekey offers or queued messages remain
        assertNull("Alice should have no pending rekey offer", aliceRekeyDao.getPendingOffer("bob"))
        assertNull("Bob should have no pending rekey offer", bobRekeyDao.getPendingOffer("alice"))
        assertTrue("Alice should have empty outbox", aliceMessageDao.getQueuedMessagesForContact("bob").isEmpty())
        assertTrue("Bob should have empty outbox", bobMessageDao.getQueuedMessagesForContact("alice").isEmpty())

        sharedDht.stop()
    }
}
