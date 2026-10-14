package org.pqchat.dht.data.repository

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.dht.leaf.DhtLeafNode
import java.net.InetSocketAddress
import java.security.Security
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

@Tag("slow")
class ChatRepositoryRekeyIntegrationTest {

    companion object {
        @JvmStatic
        @BeforeAll
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

        override suspend fun updateVerifiedStatus(id: String, isVerified: Boolean) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(isVerified = isVerified)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateContactName(id: String, name: String) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(name = name)
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

        override suspend fun getPendingDeliveryMessagesForContact(contactId: String): List<MessageEntity> {
            return messages.filter { it.contactId == contactId && it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }.sortedBy { it.id }
        }

        override suspend fun getAllPendingDeliveryMessages(): List<MessageEntity> {
            return messages.filter { it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }.sortedBy { it.id }
        }
    }

    private class TestChunkDao : org.pqchat.dht.test.BaseFakeChunkDao()

    private class TestPendingRekeyOfferDao : PendingRekeyOfferDao {
        val offers = ConcurrentHashMap<String, PendingRekeyOfferEntity>()
        val offersFlow = MutableStateFlow<Map<String, PendingRekeyOfferEntity>>(emptyMap())

        override suspend fun getPendingOffer(contactId: String): PendingRekeyOfferEntity? =
            offers[contactId]

        override fun getPendingOfferFlow(contactId: String): Flow<PendingRekeyOfferEntity?> =
            offersFlow.map { it[contactId] }

        override fun isRekeyPendingFlow(contactId: String): Flow<Boolean> =
            offersFlow.map { it.containsKey(contactId) }

        override suspend fun insertOrUpdate(offer: PendingRekeyOfferEntity) {
            offers[offer.contactId] = offer
            offersFlow.value = HashMap(offers)
        }

        override suspend fun deletePendingOffer(contactId: String) {
            offers.remove(contactId)
            offersFlow.value = HashMap(offers)
        }
    }

    private fun isNightly(): Boolean {
        return System.getProperty("runNightlyTests") == "true" ||
               System.getenv("RUN_NIGHTLY_TESTS") == "true"
    }

    @Test
    fun testTwoRepositoriesExchangeMessagesBidirectionallyWithPqcRekeys() = runBlocking {
        val sharedDht = FakeDht(minDelayMs = 0, maxDelayMs = 0)
        sharedDht.start()

        val aliceContactDao = TestContactDao()
        val aliceMessageDao = TestMessageDao()
        val aliceChunkDao = TestChunkDao()
        val aliceRekeyDao = TestPendingRekeyOfferDao()
        val aliceRepo = ChatRepository(aliceContactDao, aliceMessageDao, aliceChunkDao, aliceRekeyDao, sharedDht)
        aliceRepo.delayedPutMaxMs = 0L
        aliceRepo.decoyPutSlotsCount = 0
        aliceRepo.enableDecoyGets = false

        val bobContactDao = TestContactDao()
        val bobMessageDao = TestMessageDao()
        val bobChunkDao = TestChunkDao()
        val bobRekeyDao = TestPendingRekeyOfferDao()
        val bobRepo = ChatRepository(bobContactDao, bobMessageDao, bobChunkDao, bobRekeyDao, sharedDht)
        bobRepo.delayedPutMaxMs = 0L
        bobRepo.decoyPutSlotsCount = 0
        bobRepo.enableDecoyGets = false

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

        val totalRounds = if (isNightly()) 200 else 60
        val minEpochs = if (isNightly()) 4L else 1L

        for (i in 0 until totalRounds) {
            // 1. Alice sends to Bob
            val aliceText = "Alice to Bob #$i"
            aliceRepo.sendTextMessage("bob", aliceText)

            // Bob polls for Alice's message or rekey offer
            bobRepo.pollContactIncoming("alice")
            if (aliceRekeyDao.getPendingOffer("bob") != null) {
                // Alice polls for Bob's rekey response
                aliceRepo.pollContactIncoming("bob")
                // Bob polls for Alice's drained outbox message
                bobRepo.pollContactIncoming("alice")
            }

            // 2. Bob sends to Alice
            val bobText = "Bob to Alice #$i"
            bobRepo.sendTextMessage("alice", bobText)

            // Alice polls for Bob's message or rekey offer
            aliceRepo.pollContactIncoming("bob")
            if (bobRekeyDao.getPendingOffer("alice") != null) {
                // Bob polls for Alice's rekey response
                bobRepo.pollContactIncoming("alice")
                // Alice polls for Bob's drained outbox message
                aliceRepo.pollContactIncoming("bob")
            }
        }

        if (aliceRekeyDao.getPendingOffer("bob") != null) {
            aliceRepo.pollContactIncoming("bob")
            bobRepo.pollContactIncoming("alice")
        }
        if (bobRekeyDao.getPendingOffer("alice") != null) {
            bobRepo.pollContactIncoming("alice")
            aliceRepo.pollContactIncoming("bob")
        }

        // Assert all messages delivered from Alice to Bob
        val bobDelivered = bobMessageDao.messages.filter { it.contactId == "alice" && !it.isOutgoing && it.status == "DELIVERED" }
        assertEquals("Bob should receive all $totalRounds messages from Alice", totalRounds, bobDelivered.size)
        val bobReceivedTexts = bobDelivered.map { it.rawTextContent }.toSet()
        for (i in 0 until totalRounds) {
            assertTrue("Bob missing message #$i", bobReceivedTexts.contains("Alice to Bob #$i"))
        }

        // Assert all messages delivered from Bob to Alice
        val aliceDelivered = aliceMessageDao.messages.filter { it.contactId == "bob" && !it.isOutgoing && it.status == "DELIVERED" }
        assertEquals("Alice should receive all $totalRounds messages from Bob", totalRounds, aliceDelivered.size)
        val aliceReceivedTexts = aliceDelivered.map { it.rawTextContent }.toSet()
        for (i in 0 until totalRounds) {
            assertTrue("Alice missing message #$i", aliceReceivedTexts.contains("Bob to Alice #$i"))
        }

        // Verify Rekey Epochs: with 200 messages at least 4 epochs; with 60 messages at least 1 epoch
        val finalAliceContact = aliceRepo.getContact("bob")!!
        val finalBobContact = bobRepo.getContact("alice")!!

        assertTrue("Alice should have performed at least $minEpochs PQC rekey epochs (got ${finalAliceContact.rekeyEpoch})", finalAliceContact.rekeyEpoch >= minEpochs)
        assertTrue("Bob should have performed at least $minEpochs PQC rekey epochs (got ${finalBobContact.rekeyEpoch})", finalBobContact.rekeyEpoch >= minEpochs)
        assertEquals("Both parties must have identical rekeyEpoch", finalAliceContact.rekeyEpoch, finalBobContact.rekeyEpoch)

        // Verify no pending rekey offers or queued messages remain
        assertNull("Alice should have no pending rekey offer", aliceRekeyDao.getPendingOffer("bob"))
        assertNull("Bob should have no pending rekey offer", bobRekeyDao.getPendingOffer("alice"))
        assertTrue("Alice should have empty outbox", aliceMessageDao.getQueuedMessagesForContact("bob").isEmpty())
        assertTrue("Bob should have empty outbox", bobMessageDao.getQueuedMessagesForContact("alice").isEmpty())

        sharedDht.stop()
    }

    @Test
    fun testMessagesSentDuringRekeyAreQueuedAndDeliveredWithoutLoss() = runBlocking {
        val sharedDht = FakeDht(minDelayMs = 0, maxDelayMs = 0)
        sharedDht.start()

        val aliceContactDao = TestContactDao()
        val aliceMessageDao = TestMessageDao()
        val aliceChunkDao = TestChunkDao()
        val aliceRekeyDao = TestPendingRekeyOfferDao()
        val aliceRepo = ChatRepository(aliceContactDao, aliceMessageDao, aliceChunkDao, aliceRekeyDao, sharedDht)
        aliceRepo.delayedPutMaxMs = 0L
        aliceRepo.decoyPutSlotsCount = 0
        aliceRepo.enableDecoyGets = false

        val bobContactDao = TestContactDao()
        val bobMessageDao = TestMessageDao()
        val bobChunkDao = TestChunkDao()
        val bobRekeyDao = TestPendingRekeyOfferDao()
        val bobRepo = ChatRepository(bobContactDao, bobMessageDao, bobChunkDao, bobRekeyDao, sharedDht)
        bobRepo.delayedPutMaxMs = 0L
        bobRepo.decoyPutSlotsCount = 0
        bobRepo.enableDecoyGets = false

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

        // Send 49 regular messages from Alice to Bob
        for (i in 0 until 49) {
            aliceRepo.sendTextMessage("bob", "Msg #$i")
            bobRepo.pollContactIncoming("alice")
        }

        val bobInitialReceived = bobMessageDao.messages.filter { it.contactId == "alice" && !it.isOutgoing && it.status == "DELIVERED" }
        assertEquals(49, bobInitialReceived.size)

        // Message #49: counterOut reaches 49, message 49 sent, next counterOut is 50
        val aliceContactBefore50 = aliceRepo.getContact("bob")!!
        assertEquals(49, aliceContactBefore50.counterOut)

        aliceRepo.sendTextMessage("bob", "Msg #49-trigger")
        bobRepo.pollContactIncoming("alice")
        assertEquals(50, aliceRepo.getContact("bob")!!.counterOut)

        // Now counterOut is 50 (50 % 50 == 0). Sending next message triggers createRekeyOffer
        // and queues the message.
        aliceRepo.sendTextMessage("bob", "Msg #50-during-rekey")
        // Also queue additional messages while rekey offer is pending
        aliceRepo.sendTextMessage("bob", "Msg #51-during-rekey")
        aliceRepo.sendTextMessage("bob", "Msg #52-during-rekey")

        // Assert offer is pending and messages are queued in outbox
        assertNotNull("Rekey offer must be pending", aliceRekeyDao.getPendingOffer("bob"))
        val queuedMessages = aliceMessageDao.getQueuedMessagesForContact("bob")
        assertEquals(3, queuedMessages.size)

        // Bob polls incoming: Bob receives Type 0x03 offer, encapsulates SS_rekey, ratchets chainKeyIn, sends Type 0x04 response
        val bobProcessedOffer = bobRepo.pollContactIncoming("alice")
        assertTrue("Bob should process rekey offer", bobProcessedOffer)
        assertEquals(1L, bobRepo.getContact("alice")!!.rekeyEpoch)

        // Alice polls incoming: Alice receives Type 0x04 response, decapsulates SS_rekey, ratchets chainKeyOut, updates epoch to 1,
        // and automatically drains the outbox sending queued messages #50, #51, #52!
        val aliceProcessedResp = aliceRepo.pollContactIncoming("bob")
        assertTrue("Alice should process rekey response", aliceProcessedResp)
        assertEquals(1L, aliceRepo.getContact("bob")!!.rekeyEpoch)
        assertNull("Pending rekey offer should be removed", aliceRekeyDao.getPendingOffer("bob"))

        // Bob polls incoming: receives drained messages
        bobRepo.pollContactIncoming("alice")

        // Assert all messages delivered without loss
        val allBobDelivered = bobMessageDao.messages.filter { it.contactId == "alice" && !it.isOutgoing && it.status == "DELIVERED" }
        assertEquals(53, allBobDelivered.size)
        val bobTexts = allBobDelivered.map { it.rawTextContent }.toSet()
        assertTrue("Msg #50 must be delivered", bobTexts.contains("Msg #50-during-rekey"))
        assertTrue("Msg #51 must be delivered", bobTexts.contains("Msg #51-during-rekey"))
        assertTrue("Msg #52 must be delivered", bobTexts.contains("Msg #52-during-rekey"))

        sharedDht.stop()
    }

    @Test
    fun testTwoRepositoriesExchangeMessagesWithPqcRekeyOnLiveDhtLeafNodes() = runBlocking {
        val aliceDht = DhtLeafNode(autoBootstrap = false)
        val bobDht = DhtLeafNode(autoBootstrap = false)
        aliceDht.start()
        bobDht.start()

        try {
            // Pair the two nodes over local UDP ports
            val aliceAddr = InetSocketAddress("127.0.0.1", aliceDht.localPort)
            val bobAddr = InetSocketAddress("127.0.0.1", bobDht.localPort)
            aliceDht.addPeer(bobDht.myNodeId, bobAddr)
            bobDht.addPeer(aliceDht.myNodeId, aliceAddr)

            val aliceContactDao = TestContactDao()
            val aliceMessageDao = TestMessageDao()
            val aliceChunkDao = TestChunkDao()
            val aliceRekeyDao = TestPendingRekeyOfferDao()
            val aliceRepo = ChatRepository(aliceContactDao, aliceMessageDao, aliceChunkDao, aliceRekeyDao, aliceDht)
            aliceRepo.delayedPutMaxMs = 0L
            aliceRepo.decoyPutSlotsCount = 0
            aliceRepo.enableDecoyGets = false

            val bobContactDao = TestContactDao()
            val bobMessageDao = TestMessageDao()
            val bobChunkDao = TestChunkDao()
            val bobRekeyDao = TestPendingRekeyOfferDao()
            val bobRepo = ChatRepository(bobContactDao, bobMessageDao, bobChunkDao, bobRekeyDao, bobDht)
            bobRepo.delayedPutMaxMs = 0L
            bobRepo.decoyPutSlotsCount = 0
            bobRepo.enableDecoyGets = false

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

            val totalRounds = if (isNightly()) 200 else 55
            val minEpochs = if (isNightly()) 4L else 1L

            for (i in 0 until totalRounds) {
                // 1. Alice sends to Bob
                val aliceText = "Live DHT Alice to Bob #$i"
                aliceRepo.sendTextMessage("bob", aliceText)

                // Bob polls for Alice's message or rekey offer
                bobRepo.pollContactIncoming("alice")
                if (aliceRekeyDao.getPendingOffer("bob") != null) {
                    // Alice polls for Bob's rekey response
                    aliceRepo.pollContactIncoming("bob")
                    // Bob polls for Alice's drained outbox message
                    bobRepo.pollContactIncoming("alice")
                }

                // 2. Bob sends to Alice
                val bobText = "Live DHT Bob to Alice #$i"
                bobRepo.sendTextMessage("alice", bobText)

                // Alice polls for Bob's message or rekey offer
                aliceRepo.pollContactIncoming("bob")
                if (bobRekeyDao.getPendingOffer("alice") != null) {
                    // Bob polls for Alice's rekey response
                    bobRepo.pollContactIncoming("alice")
                    // Alice polls for Bob's drained outbox message
                    aliceRepo.pollContactIncoming("bob")
                }
            }

            if (aliceRekeyDao.getPendingOffer("bob") != null) {
                aliceRepo.pollContactIncoming("bob")
                bobRepo.pollContactIncoming("alice")
            }
            if (bobRekeyDao.getPendingOffer("alice") != null) {
                bobRepo.pollContactIncoming("alice")
                aliceRepo.pollContactIncoming("bob")
            }

            // Assert all messages delivered from Alice to Bob
            val bobDelivered = bobMessageDao.messages.filter { it.contactId == "alice" && !it.isOutgoing && it.status == "DELIVERED" }
            assertEquals("Bob should receive all $totalRounds messages from Alice on live DHT", totalRounds, bobDelivered.size)

            // Assert all messages delivered from Bob to Alice
            val aliceDelivered = aliceMessageDao.messages.filter { it.contactId == "bob" && !it.isOutgoing && it.status == "DELIVERED" }
            assertEquals("Alice should receive all $totalRounds messages from Bob on live DHT", totalRounds, aliceDelivered.size)

            val finalAliceContact = aliceRepo.getContact("bob")!!
            val finalBobContact = bobRepo.getContact("alice")!!

            assertTrue("Alice should have performed at least $minEpochs PQC rekey epochs on live DHT (got ${finalAliceContact.rekeyEpoch})", finalAliceContact.rekeyEpoch >= minEpochs)
            assertTrue("Bob should have performed at least $minEpochs PQC rekey epochs on live DHT (got ${finalBobContact.rekeyEpoch})", finalBobContact.rekeyEpoch >= minEpochs)
            assertEquals("Both parties must have identical rekeyEpoch on live DHT", finalAliceContact.rekeyEpoch, finalBobContact.rekeyEpoch)

            assertNull("Alice should have no pending rekey offer", aliceRekeyDao.getPendingOffer("bob"))
            assertNull("Bob should have no pending rekey offer", bobRekeyDao.getPendingOffer("alice"))
            assertTrue("Alice should have empty outbox", aliceMessageDao.getQueuedMessagesForContact("bob").isEmpty())
            assertTrue("Bob should have empty outbox", bobMessageDao.getQueuedMessagesForContact("alice").isEmpty())
        } finally {
            aliceDht.stop()
            bobDht.stop()
        }
    }
}
