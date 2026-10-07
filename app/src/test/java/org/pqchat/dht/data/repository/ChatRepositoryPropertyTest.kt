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
import org.pqchat.dht.protocol.SlidingWindowBitmap
import java.security.Security
import java.util.Random
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

class ChatRepositoryPropertyTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private class PropertyContactDao : ContactDao {
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

        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: ByteArray, bitmapBase: Int, bitmap: ByteArray) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: ByteArray, rekeyEpoch: Long) {
            contacts.computeIfPresent(id) { _, c ->
                c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch)
            }
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: ByteArray, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {
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

    private class PropertyMessageDao : MessageDao {
        val messages = CopyOnWriteArrayList<MessageEntity>()
        private var idCounter = java.util.concurrent.atomic.AtomicLong(1L)

        override fun getMessagesForContactFlow(contactId: String): Flow<List<MessageEntity>> =
            MutableStateFlow(messages.filter { it.contactId == contactId })

        override suspend fun insertMessage(message: MessageEntity): Long {
            val id = if (message.id == 0L) idCounter.getAndIncrement() else message.id
            val toSave = message.copy(id = id)
            messages.add(toSave)
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

    private class PropertyChunkDao : ChunkDao {
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

    private class PropertyPendingRekeyOfferDao : PendingRekeyOfferDao {
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

    private class PropertySkippedKeyDao : SkippedKeyDao {
        val keys = ConcurrentHashMap<String, SkippedKeyEntity>()

        private fun key(contactId: String, slotIndex: Int) = "$contactId:$slotIndex"

        override suspend fun insertOrUpdate(skippedKey: SkippedKeyEntity) {
            keys[key(skippedKey.contactId, skippedKey.slotIndex)] = skippedKey
        }

        override suspend fun getSkippedKeysForContact(contactId: String): List<SkippedKeyEntity> {
            return keys.values.filter { it.contactId == contactId }.sortedBy { it.slotIndex }
        }

        override suspend fun getSkippedKey(contactId: String, slotIndex: Int): SkippedKeyEntity? {
            return keys[key(contactId, slotIndex)]
        }

        override suspend fun deleteSkippedKey(contactId: String, slotIndex: Int) {
            keys.remove(key(contactId, slotIndex))
        }

        override suspend fun deleteExpiredKeys(now: Long) {
            keys.entries.removeIf { it.value.expiresAt < now }
        }

        override suspend fun countSkippedKeys(contactId: String): Int {
            return keys.values.count { it.contactId == contactId }
        }

        override suspend fun deleteOldestSkippedKeys(contactId: String, count: Int) {
            val contactKeys = keys.values.filter { it.contactId == contactId }.sortedBy { it.createdAt }
            val toRemove = contactKeys.take(count)
            for (k in toRemove) {
                keys.remove(key(k.contactId, k.slotIndex))
            }
        }
    }

    @Test
    fun testSlidingWindowBitmapProperties() {
        val random = Random(42)
        val bitmap = SlidingWindowBitmap(windowBase = 100)

        // 1. Mark in random order within [100, 200]
        val indices = (100..200).shuffled(random)
        for (idx in indices) {
            assertTrue("Should accept $idx inside window", bitmap.markReceived(idx))
            assertTrue("Index $idx should now be marked received", bitmap.isReceived(idx))
            // Duplicate mark returns false
            assertFalse("Duplicate $idx should not be accepted again", bitmap.markReceived(idx))
        }

        // 2. Out of window below base
        assertTrue("Index below base is considered already received", bitmap.isReceived(99))
        assertFalse("Cannot mark below base", bitmap.markReceived(99))

        // 3. Round-trip serialization invariant
        val bytes = bitmap.toByteArray()
        val restored = SlidingWindowBitmap(windowBase = bitmap.windowBase, byteArray = bytes)
        for (i in 100..200) {
            assertTrue("Restored bitmap must retain bit/state for $i", restored.isReceived(i))
        }
        assertFalse("Restored bitmap must not have bit for 201", restored.isReceived(201))
    }

    @Test
    fun testSeqEpochSeparation() = runBlocking {
        val messageDao = PropertyMessageDao()
        val contactId = "contact-epoch-test"

        // Msg 0 in Epoch 0 (seqNum = 0)
        val msgEpoch0 = MessageEntity(
            contactId = contactId,
            isOutgoing = false,
            seqEpoch = 0,
            seqNum = 0,
            ackNum = 0,
            timestamp = System.currentTimeMillis(),
            textContent = "Hello epoch 0",
            status = "CONFIRMED_DHT"
        )
        messageDao.insertMessage(msgEpoch0)

        // Msg 65536 is seqNum 0 in Epoch 1
        val msgEpoch1 = MessageEntity(
            contactId = contactId,
            isOutgoing = false,
            seqEpoch = 1,
            seqNum = 0,
            ackNum = 0,
            timestamp = System.currentTimeMillis(),
            textContent = "Hello epoch 1",
            status = "CONFIRMED_DHT"
        )

        // Old existsMessage(0) would have collided and returned true!
        assertTrue("Old existsMessage should see seqNum 0 exists", messageDao.existsMessage(contactId, 0, false))

        // But existsMessageWithEpoch correctly differentiates:
        assertTrue("Epoch 0 seq 0 exists", messageDao.existsMessageWithEpoch(contactId, 0, 0, false))
        assertFalse("Epoch 1 seq 0 DOES NOT exist yet", messageDao.existsMessageWithEpoch(contactId, 1, 0, false))

        // Insert epoch 1
        messageDao.insertMessage(msgEpoch1)
        assertTrue("Epoch 1 seq 0 now exists", messageDao.existsMessageWithEpoch(contactId, 1, 0, false))
    }

    @Test
    fun testOutOfOrderArrivalAndSkippedKeyRetention() = runBlocking {
        val sharedDht = FakeDht()
        sharedDht.start()

        val aliceContactDao = PropertyContactDao()
        val aliceMessageDao = PropertyMessageDao()
        val aliceChunkDao = PropertyChunkDao()
        val alicePendingRekeyOfferDao = PropertyPendingRekeyOfferDao()
        val aliceSkippedKeyDao = PropertySkippedKeyDao()

        val bobContactDao = PropertyContactDao()
        val bobMessageDao = PropertyMessageDao()
        val bobChunkDao = PropertyChunkDao()
        val bobPendingRekeyOfferDao = PropertyPendingRekeyOfferDao()
        val bobSkippedKeyDao = PropertySkippedKeyDao()

        val aliceRepo = ChatRepository(aliceContactDao, aliceMessageDao, aliceChunkDao, alicePendingRekeyOfferDao, aliceSkippedKeyDao, sharedDht)
        val bobRepo = ChatRepository(bobContactDao, bobMessageDao, bobChunkDao, bobPendingRekeyOfferDao, bobSkippedKeyDao, sharedDht)

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

        // Alice sends 5 messages: m0, m1, m2, m3, m4
        for (i in 0 until 5) {
            val sent = aliceRepo.sendTextMessage("bob", "Message #$i")
            assertTrue("Message $i sent successfully", sent)
        }

        // Bob's incoming chainKey is aliceToBobSeed to derive slots 0, 1, 2, 3, 4
        val slot0 = org.pqchat.dht.protocol.RatchetChain.deriveSlot(aliceToBobSeed, 0)
        val slot1 = org.pqchat.dht.protocol.RatchetChain.deriveSlot(slot0.nextChainKey, 1)
        val slot2 = org.pqchat.dht.protocol.RatchetChain.deriveSlot(slot1.nextChainKey, 2)

        val target0Hex = CryptoUtils.toHex(slot0.target)
        val target1Hex = CryptoUtils.toHex(slot1.target)
        val target2Hex = CryptoUtils.toHex(slot2.target)

        val backup0 = sharedDht.storage.remove(target0Hex)
        val backup1 = sharedDht.storage.remove(target1Hex)
        val backup2 = sharedDht.storage.remove(target2Hex)
        assertNotNull("Slot 0 should have been stored in DHT", backup0)
        assertNotNull("Slot 1 should have been stored in DHT", backup1)
        assertNotNull("Slot 2 should have been stored in DHT", backup2)

        // Bob polls lookahead: slots 0,1,2 missing, but lookahead window finds slot 3 (k=3)!
        // Bob must retain skipped keys for slots 0, 1, 2 in SkippedKeyDao and process slot 3
        bobRepo.checkLookaheadWindow("alice")

        // Check that skipped keys 0, 1, 2 are in Bob's SkippedKeyDao
        val skippedKeys = bobSkippedKeyDao.getSkippedKeysForContact("alice")
        assertEquals("Should retain 3 skipped keys (0, 1, 2)", 3, skippedKeys.size)
        assertEquals(listOf(0, 1, 2), skippedKeys.map { it.slotIndex })

        // Bob has received messages #3 and #4 (both in lookahead window)
        val bobMsgsAfterLookahead = bobMessageDao.messages.filter { !it.isOutgoing }.sortedBy { it.seqNum }
        assertEquals(2, bobMsgsAfterLookahead.size)
        assertEquals("Message #3", bobMsgsAfterLookahead[0].textContent)
        assertEquals(3, bobMsgsAfterLookahead[0].seqNum)
        assertEquals("Message #4", bobMsgsAfterLookahead[1].textContent)
        assertEquals(4, bobMsgsAfterLookahead[1].seqNum)

        // Now restore slot 0, 1, 2 into DHT
        sharedDht.storage[target0Hex] = backup0!!
        sharedDht.storage[target1Hex] = backup1!!
        sharedDht.storage[target2Hex] = backup2!!

        // Bob recovers skipped keys:
        val recovered = bobRepo.pollPendingSkippedKeys("alice")
        assertTrue("Should have recovered skipped keys", recovered)

        // All skipped keys should be cleared from DB
        val remainingSkipped = bobSkippedKeyDao.getSkippedKeysForContact("alice")
        assertTrue("Skipped keys should now be empty", remainingSkipped.isEmpty())

        // All 5 messages received!
        val allReceived = bobMessageDao.messages.filter { !it.isOutgoing }.sortedBy { it.seqNum }
        assertEquals(5, allReceived.size)
        for (i in 0 until 5) {
            assertEquals("Message #$i", allReceived[i].textContent)
            assertEquals(i, allReceived[i].seqNum)
        }

        sharedDht.stop()
    }

    @Test
    fun testRandomizedLossAndReorderingProperty() = runBlocking {
        val sharedDht = FakeDht()
        sharedDht.start()

        val aliceContactDao = PropertyContactDao()
        val aliceMessageDao = PropertyMessageDao()
        val aliceChunkDao = PropertyChunkDao()
        val alicePendingRekeyOfferDao = PropertyPendingRekeyOfferDao()
        val aliceSkippedKeyDao = PropertySkippedKeyDao()

        val bobContactDao = PropertyContactDao()
        val bobMessageDao = PropertyMessageDao()
        val bobChunkDao = PropertyChunkDao()
        val bobPendingRekeyOfferDao = PropertyPendingRekeyOfferDao()
        val bobSkippedKeyDao = PropertySkippedKeyDao()

        val aliceRepo = ChatRepository(aliceContactDao, aliceMessageDao, aliceChunkDao, alicePendingRekeyOfferDao, aliceSkippedKeyDao, sharedDht)
        val bobRepo = ChatRepository(bobContactDao, bobMessageDao, bobChunkDao, bobPendingRekeyOfferDao, bobSkippedKeyDao, sharedDht)

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

        val totalMessages = 20
        for (i in 0 until totalMessages) {
            assertTrue("Send $i", aliceRepo.sendTextMessage("bob", "Randomized msg $i"))
        }

        // Simulate random intermittent packet loss (30% drop probability)
        sharedDht.dropProbability = 0.3
        var rounds = 0
        while (bobMessageDao.messages.count { !it.isOutgoing } < totalMessages && rounds < 25) {
            rounds++
            bobRepo.pollContactIncoming("alice")
            bobRepo.checkLookaheadWindow("alice")
            bobRepo.pollPendingSkippedKeys("alice")
        }

        // Turn off drop probability to ensure all remaining skipped/pending messages are recovered
        sharedDht.dropProbability = 0.0
        while (bobMessageDao.messages.count { !it.isOutgoing } < totalMessages && rounds < 50) {
            rounds++
            bobRepo.pollContactIncoming("alice")
            bobRepo.checkLookaheadWindow("alice")
            bobRepo.pollPendingSkippedKeys("alice")
        }

        val received = bobMessageDao.messages.filter { !it.isOutgoing }.sortedBy { it.seqNum }
        assertEquals("All $totalMessages messages must be received", totalMessages, received.size)
        for (i in 0 until totalMessages) {
            assertEquals("Randomized msg $i", received[i].textContent)
            assertEquals(i, received[i].seqNum)
        }

        // Verify bitmap has recorded all indices
        val updatedBobContact = bobContactDao.getContactById("alice")!!
        val bitmap = SlidingWindowBitmap(windowBase = updatedBobContact.receivedBitmapBase, byteArray = updatedBobContact.receivedBitmap)
        for (i in 0 until totalMessages) {
            assertTrue("Bitmap should record sequence $i", bitmap.isReceived(i))
        }

        sharedDht.stop()
    }
}
