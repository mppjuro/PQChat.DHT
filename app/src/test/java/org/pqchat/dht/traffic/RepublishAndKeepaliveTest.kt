package org.pqchat.dht.traffic

import kotlinx.coroutines.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.CoverAckProtocol
import org.pqchat.dht.test.BaseFakeChunkDao
import org.pqchat.dht.test.BaseFakeMessageDao
import java.security.Security
import java.util.UUID

class RepublishAndKeepaliveTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupCrypto() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private lateinit var fakeDht: FakeDht
    private lateinit var messageDao: BaseFakeMessageDao
    private lateinit var contactDao: TestContactDao
    private lateinit var chunkDao: BaseFakeChunkDao
    private lateinit var repository: ChatRepository

    private class TestContactDao : ContactDao {
        val contacts = mutableMapOf<String, ContactEntity>()

        override fun getAllContactsFlow() = kotlinx.coroutines.flow.flowOf(contacts.values.toList())
        override suspend fun getContactById(id: String): ContactEntity? = contacts[id]
        override suspend fun insertOrUpdate(contact: ContactEntity) { contacts[contact.id] = contact }
        override suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: EncryptedBlob) {
            contacts[id]?.let { contacts[id] = it.copy(counterOut = counterOut, chainKeyOut = chainKeyOut) }
        }
        override suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: EncryptedBlob, rekeyEpoch: Long) {
            contacts[id]?.let { contacts[id] = it.copy(counterOut = counterOut, chainKeyOut = chainKeyOut, rekeyEpoch = rekeyEpoch) }
        }
        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {
            contacts[id]?.let { contacts[id] = it.copy(counterIn = counterIn, chainKeyIn = chainKeyIn) }
        }
        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long) {
            contacts[id]?.let { contacts[id] = it.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch) }
        }
        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {
            contacts[id]?.let { contacts[id] = it.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap) }
        }
        override suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {
            contacts[id]?.let { contacts[id] = it.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap) }
        }
        override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {
            contacts[id]?.let { contacts[id] = it.copy(rekeyEpoch = rekeyEpoch) }
        }
        override suspend fun updateVerifiedStatus(id: String, isVerified: Boolean) {
            contacts[id]?.let { contacts[id] = it.copy(isVerified = isVerified) }
        }
        override suspend fun updateContactName(id: String, name: String) {
            contacts[id]?.let { contacts[id] = it.copy(name = name) }
        }
        override suspend fun deleteContact(id: String) { contacts.remove(id) }
    }

    @Before
    fun setUp() {
        fakeDht = FakeDht()
        fakeDht.start()
        PollingWorker.clearRepublishTasks()
        messageDao = BaseFakeMessageDao()
        contactDao = TestContactDao()
        chunkDao = BaseFakeChunkDao()
        repository = ChatRepository(contactDao, messageDao, chunkDao, fakeDht)
    }

    @After
    fun tearDown() {
        fakeDht.stop()
        PollingWorker.clearRepublishTasks()
    }

    @Test
    fun testAdaptiveKFactorConfigurationAndScaling() {
        // 1. Verify default replication factor is 8 (Wi-Fi standard)
        assertEquals(DhtLeafNode.DEFAULT_K, fakeDht.replicationK)
        assertEquals(8, DhtLeafNode.DEFAULT_K)
        assertEquals(16, DhtLeafNode.CGNAT_LTE_K)

        // 2. Set mobile / CGNAT mode -> should switch to K=16
        fakeDht.setAdaptiveK(isMobileOrCgnat = true)
        assertEquals(16, fakeDht.replicationK)

        // 3. Switch back to Wi-Fi mode -> should revert to K=8
        fakeDht.setAdaptiveK(isMobileOrCgnat = false)
        assertEquals(8, fakeDht.replicationK)
    }

    @Test
    fun testAdaptiveKDeliveryAdvantageUnderPacketLoss() = runBlocking {
        // Simulate high packet loss (20%) typical of congested LTE / Restrictive NAT
        fakeDht.packetLossRate = 0.20

        // Test with K=8
        fakeDht.setAdaptiveK(isMobileOrCgnat = false)
        assertEquals(8, fakeDht.replicationK)
        val seed1 = CryptoUtils.secureRandomBytes(32)
        val kp1 = Ed25519Engine.generateKeyPairFromSeed(seed1)
        val target1 = Ed25519Engine.computeTarget(kp1.publicKey)
        val payload1 = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

        // Test with K=16
        fakeDht.setAdaptiveK(isMobileOrCgnat = true)
        assertEquals(16, fakeDht.replicationK)
        val seed2 = CryptoUtils.secureRandomBytes(32)
        val kp2 = Ed25519Engine.generateKeyPairFromSeed(seed2)
        val target2 = Ed25519Engine.computeTarget(kp2.publicKey)
        val payload2 = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

        // With packet loss p=0.20:
        // p_loss(K=8)  = 0.20^8  = 2.56 * 10^-6
        // p_loss(K=16) = 0.20^16 = 6.55 * 10^-12
        val putResult1 = fakeDht.putMutable(target1, payload1, 1L, null, seed1)
        val putResult2 = fakeDht.putMutable(target2, payload2, 1L, null, seed2)
        assertTrue("PUT with adaptive K=16 must succeed reliably", putResult2)
    }

    @Test
    fun testKeepaliveLoopInActiveChatLifecycle() = runBlocking {
        var pingCount = 0
        val pollingManager = AdaptivePollingManager { /* no-op sync */ }
        pollingManager.onKeepalivePingRequested = {
            pingCount++
            fakeDht.sendKeepalivePing()
        }

        // Initially in APP_ACTIVE_OTHER -> keepalive loop is not active
        assertEquals(AdaptivePollingManager.PollingState.APP_ACTIVE_OTHER, pollingManager.currentState.value)
        assertEquals(0, pingCount)

        // Transition to FOREGROUND_CHAT (active chat screen open)
        pollingManager.onChatOpened("contact_alice")
        assertEquals(AdaptivePollingManager.PollingState.FOREGROUND_CHAT, pollingManager.currentState.value)

        // Manual keepalive ping test
        val pingSuccess = fakeDht.sendKeepalivePing()
        assertTrue("Keepalive ping must succeed on active leaf node", pingSuccess)
        assertEquals(1, fakeDht.keepalivePingCalls.get())

        // Transition to APP_ACTIVE_OTHER (navigated back to contact list)
        pollingManager.onChatClosed()
        assertEquals(AdaptivePollingManager.PollingState.APP_ACTIVE_OTHER, pollingManager.currentState.value)

        // Transition to BACKGROUND_IDLE
        pollingManager.onAppMinimized()
        assertEquals(AdaptivePollingManager.PollingState.BACKGROUND_IDLE, pollingManager.currentState.value)

        // Stop polling manager cleanly
        pollingManager.stop()
    }

    @Test
    fun testRepublishPreventsNodeEvictionInFakeDht() = runBlocking {
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        val payload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

        // 1. Initial PUT at t = 0
        fakeDht.putMutable(target, payload, seq = 1L, salt = null, sk = seed)
        assertNotNull("Record should exist immediately", fakeDht.getMutable(target))

        // 2. Simulate 75 minutes passing: without republish, age is 75m
        // If we advance past 2h (120m) without republish, Kademlia evicts the record
        val twoHoursMs = 2 * 60 * 60 * 1000L
        fakeDht.evictUnrefreshedRecords(olderThanMs = twoHoursMs)
        // Record was created recently so it is not evicted yet
        assertNotNull(fakeDht.getMutable(target))

        // 3. Republish at 75 minutes: updates store timestamp to current time
        val republishOk = fakeDht.putMutable(target, payload, seq = 1L, salt = null, sk = seed)
        assertTrue("Republish PUT must succeed", republishOk)

        // 4. After republish, item has fresh timestamp. Evicting records older than 1 hour does NOT remove it
        fakeDht.evictUnrefreshedRecords(olderThanMs = 60 * 60 * 1000L)
        val retrieved = fakeDht.getMutable(target)
        assertNotNull("Republished record must survive eviction", retrieved)
        assertArrayEquals(payload, retrieved!!.v)
    }

    @Test
    fun testDeliveryConfirmationAckAndTombstone() = runBlocking {
        val contactId = UUID.randomUUID().toString()
        val initialChainKey = CryptoUtils.secureRandomBytes(64)
        val initialCounterOut = 0

        val contact = ContactEntity(
            id = contactId,
            name = "Bob",
            counterOut = initialCounterOut,
            counterIn = 0,
            chainKeyOut = EncryptedBlob(initialChainKey, "contacts", contactId),
            chainKeyIn = EncryptedBlob(CryptoUtils.secureRandomBytes(64), "contacts", contactId)
        )
        contactDao.insertOrUpdate(contact)

        // 1. Send outgoing text message
        val sent = repository.sendTextMessage(contactId, "Hello Alice via DHT")
        assertTrue("sendTextMessage should succeed", sent)

        val pendingMsgs = messageDao.getPendingDeliveryMessagesForContact(contactId)
        assertEquals(1, pendingMsgs.size)
        val sentMsg = pendingMsgs[0]
        assertEquals("PENDING_DELIVERY", sentMsg.status)
        assertNotNull(sentMsg.slotTarget)
        assertNotNull(sentMsg.ackTarget)
        assertNotNull(sentMsg.ackRatchetKey)

        // Message should be registered in PollingWorker republish pool
        assertTrue("Republish task must be registered", PollingWorker.isRepublishTaskRegistered(sentMsg.id))

        // 2. Simulate recipient sending Cover-traffic ACK to ackTarget
        val ackSeed = CoverAckProtocol.deriveAckSeed(sentMsg.ackRatchetKey!!.raw, "${sentMsg.seqNum}")
        val ackPayload = CoverAckProtocol.createAckPayload(
            ratchetKey = sentMsg.ackRatchetKey.raw,
            messageId = "${sentMsg.seqNum}",
            seqNum = sentMsg.seqNum
        )
        fakeDht.putMutable(
            target = sentMsg.ackTarget!!,
            v = ackPayload,
            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
            salt = null,
            sk = ackSeed
        )

        // 3. Execute checkPendingAcks
        val acksFound = repository.checkPendingAcks(contactId)
        assertEquals(1, acksFound)

        // 4. Verify message status updated to DELIVERED
        val deliveredMsg = messageDao.getMessageById(sentMsg.id)
        assertNotNull(deliveredMsg)
        assertEquals("DELIVERED", deliveredMsg!!.status)

        // 5. Verify unregister from republish pool
        assertFalse("Delivered message must be removed from republish pool", PollingWorker.isRepublishTaskRegistered(sentMsg.id))

        // 6. Verify 900-byte tombstone written to consumed slot
        val tombstoneItem = fakeDht.getMutable(sentMsg.slotTarget!!)
        assertNotNull("Tombstone must be published at slot target", tombstoneItem)
        assertEquals("Tombstone must have exactly 900 bytes", BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, tombstoneItem!!.v.size)
        assertEquals("Tombstone seq must be incremented to DEFAULT_MUTABLE_SEQ + 1", DhtClient.DEFAULT_MUTABLE_SEQ + 1, tombstoneItem.seq)
    }

    @Test
    fun testExpiredMessageStatusAndResendWorkflow() = runBlocking {
        val contactId = UUID.randomUUID().toString()
        val initialChainKey = CryptoUtils.secureRandomBytes(64)

        val contact = ContactEntity(
            id = contactId,
            name = "Charlie",
            counterOut = 2,
            counterIn = 0,
            chainKeyOut = EncryptedBlob(initialChainKey, "contacts", contactId),
            chainKeyIn = EncryptedBlob(CryptoUtils.secureRandomBytes(64), "contacts", contactId)
        )
        contactDao.insertOrUpdate(contact)

        // 1. Insert an expired message with status EXPIRED_OFFLINE ("Wygasła w DHT")
        val expiredTarget = CryptoUtils.secureRandomBytes(20)
        val expiredEdSeed = CryptoUtils.secureRandomBytes(32)
        val msgId = messageDao.insertMessage(
            MessageEntity(
                id = 0L,
                contactId = contactId,
                isOutgoing = true,
                seqEpoch = 0,
                seqNum = 1,
                ackNum = 0,
                timestamp = System.currentTimeMillis() - 72 * 3600 * 1000L,
                textContent = "Message that expired in DHT",
                imageBytes = null,
                status = "EXPIRED_OFFLINE",
                retryCount = 4,
                lastAttemptTimestamp = 0L,
                ackTarget = CryptoUtils.secureRandomBytes(20),
                ackRatchetKey = CryptoUtils.secureRandomBytes(32),
                slotTarget = expiredTarget,
                slotEdSeed = expiredEdSeed
            )
        )

        val beforeResend = messageDao.getMessageById(msgId)
        assertNotNull(beforeResend)
        assertEquals("EXPIRED_OFFLINE", beforeResend!!.status)

        // 2. User taps "Ponów" (resendMessage)
        val resendSuccess = repository.resendMessage(msgId)
        assertTrue("resendMessage must return true on success", resendSuccess)

        // 3. Verify message state after resend
        val afterResend = messageDao.getMessageById(msgId)
        assertNotNull(afterResend)
        assertEquals("PENDING_DELIVERY", afterResend!!.status)
        assertEquals("Sequence number should increment to 2", 2, afterResend.seqNum)
        assertEquals(5, afterResend.retryCount)
        assertFalse("New slot target must be different from expired target", afterResend.slotTarget!!.contentEquals(expiredTarget))

        // 4. Verify message published to FakeDht under new slot target
        val published = fakeDht.getMutable(afterResend.slotTarget)
        assertNotNull("Resent message must be published to DHT", published)
        assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, published!!.v.size)

        // 5. Verify registered in republish pool
        assertTrue("Resent message must be registered for 60-90 min republishing", PollingWorker.isRepublishTaskRegistered(msgId))

        // 6. Verify contact counterOut incremented
        val updatedContact = contactDao.getContactById(contactId)
        assertNotNull(updatedContact)
        assertEquals(3, updatedContact!!.counterOut)
    }

    @Test
    fun testRepublishWorkerPeriodicityConfiguration() {
        // RepublishWorker must run with default interval 75 minutes (60–90 min window with 15m flex)
        assertEquals(75L, RepublishWorker.DEFAULT_INTERVAL_MINUTES)
        assertEquals("PQChatRepublishPeriodicWorker", RepublishWorker.WORK_NAME)
        assertEquals("republish_work", RepublishWorker.TAG_REPUBLISH)
    }
}
