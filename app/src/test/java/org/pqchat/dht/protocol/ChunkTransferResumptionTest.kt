package org.pqchat.dht.protocol

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.test.BaseFakeChunkDao
import java.security.Security

class ChunkTransferResumptionTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private class TestContactDao : ContactDao {
        val contacts = mutableMapOf<String, ContactEntity>()
        val flow = MutableStateFlow<List<ContactEntity>>(emptyList())

        override fun getAllContactsFlow(): Flow<List<ContactEntity>> = flow
        override suspend fun getContactById(id: String): ContactEntity? = contacts[id]

        override suspend fun insertOrUpdate(contact: ContactEntity) {
            contacts[contact.id] = contact
            flow.value = contacts.values.toList()
        }

        override suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: EncryptedBlob) {}
        override suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: EncryptedBlob, rekeyEpoch: Long) {}
        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn)
            flow.value = contacts.values.toList()
        }
        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {}
        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long) {}
        override suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {}
        override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {}
        override suspend fun updateVerifiedStatus(id: String, isVerified: Boolean) {}
        override suspend fun updateContactName(id: String, name: EncryptedText) {}
        override suspend fun deleteContact(id: String) {
            contacts.remove(id)
            flow.value = contacts.values.toList()
        }
    }

    private class TestMessageDao : org.pqchat.dht.test.BaseFakeMessageDao()

    @Test
    fun testChunk0KeySeparationAndDeterministicTargetDerivation() {
        val baseEdSeed = CryptoUtils.secureRandomBytes(32)
        val baseMsgKey = CryptoUtils.secureRandomBytes(32)

        // 1. Chunk 0 must have domain-separated seed and key, never reusing base keys directly
        val subSeed0 = ChunkingEngine.deriveChunkEdSeed(baseEdSeed, 0)
        assertFalse("chunk 0 edSeed must NOT equal baseEdSeed", subSeed0.contentEquals(baseEdSeed))

        val subKey0 = ChunkingEngine.deriveChunkMsgKey(baseMsgKey, 0)
        assertFalse("chunk 0 msgKey must NOT equal baseMsgKey", subKey0.contentEquals(baseMsgKey))

        // 2. Each chunk index must produce distinct seeds and keys
        val subSeed1 = ChunkingEngine.deriveChunkEdSeed(baseEdSeed, 1)
        val subSeed2 = ChunkingEngine.deriveChunkEdSeed(baseEdSeed, 2)
        assertFalse("subSeed0 must not equal subSeed1", subSeed0.contentEquals(subSeed1))
        assertFalse("subSeed1 must not equal subSeed2", subSeed1.contentEquals(subSeed2))

        val subKey1 = ChunkingEngine.deriveChunkMsgKey(baseMsgKey, 1)
        assertFalse("subKey0 must not equal subKey1", subKey0.contentEquals(subKey1))

        // 3. Target derivation must match SHA-1 of Ed25519 public key derived from subSeed
        val target0 = ChunkingEngine.deriveChunkTarget(baseEdSeed, 0)
        val expectedTarget0 = CryptoUtils.sha1(Ed25519Engine.generateKeyPairFromSeed(subSeed0).publicKey)
        assertArrayEquals("deriveChunkTarget must equal sha1(pk) of subSeed", expectedTarget0, target0)

        // 4. Derivation depends purely on baseEdSeed and chunkIndex (transferId is not required)
        val target0Again = ChunkingEngine.deriveChunkTarget(baseEdSeed, 0)
        assertArrayEquals("deriveChunkTarget must be completely deterministic", target0, target0Again)
    }

    @Test
    fun testOutOfOrderChunkArrivalAndResumption() = runBlocking {
        val contactDao = TestContactDao()
        val messageDao = TestMessageDao()
        val chunkDao = BaseFakeChunkDao()
        val fakeDht = FakeDht()
        fakeDht.start()

        val repository = ChatRepository(contactDao, messageDao, chunkDao, fakeDht)

        // Create 2400 byte fake PNG (will be split into 3 chunks: 800 * 3 = 2400 B)
        val fakePng = ByteArray(2400)
        System.arraycopy(ChunkingEngine.PNG_MAGIC, 0, fakePng, 0, 4)
        for (i in 4 until 2400) {
            fakePng[i] = (i % 251).toByte()
        }
        assertTrue(ChunkingEngine.isPngImage(fakePng))

        val initialChain = CryptoUtils.secureRandomBytes(64)
        val contact = ContactEntity(
            id = "alice",
            name = "Alice",
            chainKeyOut = initialChain,
            counterOut = 0,
            chainKeyIn = initialChain,
            counterIn = 0,
            isInitiator = false
        )
        contactDao.insertOrUpdate(contact)

        val slot0 = RatchetChain.deriveSlot(initialChain, 0)
        val chunks = ChunkingEngine.splitData(
            data = fakePng,
            currentEdSeed = slot0.edPrivateKeySeed,
            currentMsgKey = slot0.msgKey,
            seqNum = 0,
            ackNum = 0,
            direction = contact.inboundDirection
        )
        assertEquals(3, chunks.size)

        // Initially, ONLY chunk 1 is available in DHT (out-of-order arrival, chunks 0 and 2 missing)
        val chunk1Target = ChunkingEngine.deriveChunkTarget(slot0.edPrivateKeySeed, 1)
        val chunk1Seed = ChunkingEngine.deriveChunkEdSeed(slot0.edPrivateKeySeed, 1)
        fakeDht.putMutable(chunk1Target, chunks[1].frame, sk = chunk1Seed)

        // First poll: Bob probes chunk 0 (absent), probes chunk 1 (present!) and receives chunk 1
        val pollSuccess = repository.pollContactIncoming("alice")
        assertTrue("Should poll successfully", pollSuccess)

        // Verify partial transfer is recorded
        val transferIdHex = CryptoUtils.toHex(chunks[0].transferId)
        val pending = chunkDao.getPendingTransfer(transferIdHex)
        assertNotNull("Pending transfer must be stored in DB", pending)
        assertEquals("Missing indices should be 0 and 2", "0,2", pending?.rawMissingIndices)

        // Verify image download progress is reported (1 of 3)
        val progressMap = repository.imageDownloadProgress.value
        assertTrue("Download progress should contain transfer", progressMap.containsKey(transferIdHex))
        val progress = progressMap[transferIdHex]
        assertEquals(1, progress?.receivedChunks)
        assertEquals(3, progress?.totalChunks)

        // Now chunk 0 and chunk 2 arrive in DHT
        val chunk0Target = ChunkingEngine.deriveChunkTarget(slot0.edPrivateKeySeed, 0)
        val chunk0Seed = ChunkingEngine.deriveChunkEdSeed(slot0.edPrivateKeySeed, 0)
        fakeDht.putMutable(chunk0Target, chunks[0].frame, sk = chunk0Seed)

        val chunk2Target = ChunkingEngine.deriveChunkTarget(slot0.edPrivateKeySeed, 2)
        val chunk2Seed = ChunkingEngine.deriveChunkEdSeed(slot0.edPrivateKeySeed, 2)
        fakeDht.putMutable(chunk2Target, chunks[2].frame, sk = chunk2Seed)

        // Now resume pending chunk transfers (e.g. in next polling cycle or explicit resume)
        val resumed = repository.resumePendingChunkTransfers("alice")
        assertTrue("Resumed transfer should succeed and assemble all chunks", resumed)

        // Verify pending transfer has been cleaned up after full reassembly
        val pendingAfter = chunkDao.getPendingTransfer(transferIdHex)
        assertNull("Pending transfer must be deleted once complete", pendingAfter)

        // Verify message is assembled and saved in database
        val savedMessages = messageDao.messages
        assertEquals(1, savedMessages.size)
        val msg = savedMessages[0]
        assertEquals("alice", msg.contactId)
        assertNotNull("imageBytes should be present", msg.imageBytes)
        assertArrayEquals("Reassembled image must match fakePng byte-for-byte", fakePng, msg.rawImageBytes)

        // Verify progress is cleared
        val progressAfter = repository.imageDownloadProgress.value
        assertFalse("Download progress should be cleared after completion", progressAfter.containsKey(transferIdHex))

        fakeDht.stop()
    }

    @Test
    fun testPurgeExpiredTransfers72HoursTtl() = runBlocking {
        val chunkDao = BaseFakeChunkDao()
        val now = System.currentTimeMillis()
        val hourMs = 3600 * 1000L

        // Expired transfer (created 73 hours ago)
        val expiredTransfer = PendingChunkTransferEntity(
            transferId = "expired-uuid",
            contactId = "alice",
            seqNum = 1,
            totalChunks = 3,
            missingIndices = "0,2",
            baseEdSeed = EncryptedBlob(ByteArray(32), "pending_chunk_transfers", "expired-uuid_seed"),
            baseMsgKey = EncryptedBlob(ByteArray(32), "pending_chunk_transfers", "expired-uuid_key"),
            direction = "AliceToBob",
            isSelf = false,
            ackNum = 0,
            timestampUTC = now - (73 * hourMs),
            createdAt = now - (73 * hourMs),
            expiresAt = now - hourMs // Expired 1 hour ago
        )
        chunkDao.insertPendingTransfer(expiredTransfer)
        chunkDao.insertChunk(ChunkEntity("expired-uuid", 1, 3, ByteArray(100)))

        // Fresh transfer (created 2 hours ago, expires in 70 hours)
        val freshTransfer = PendingChunkTransferEntity(
            transferId = "fresh-uuid",
            contactId = "alice",
            seqNum = 2,
            totalChunks = 2,
            missingIndices = "0",
            baseEdSeed = EncryptedBlob(ByteArray(32), "pending_chunk_transfers", "fresh-uuid_seed"),
            baseMsgKey = EncryptedBlob(ByteArray(32), "pending_chunk_transfers", "fresh-uuid_key"),
            direction = "AliceToBob",
            isSelf = false,
            ackNum = 0,
            timestampUTC = now - (2 * hourMs),
            createdAt = now - (2 * hourMs),
            expiresAt = now + (70 * hourMs)
        )
        chunkDao.insertPendingTransfer(freshTransfer)
        chunkDao.insertChunk(ChunkEntity("fresh-uuid", 1, 2, ByteArray(100)))

        // Verify initial state
        assertEquals(2, chunkDao.getAllPendingTransfers().size)
        assertEquals(1, chunkDao.getChunksForTransfer("expired-uuid").size)
        assertEquals(1, chunkDao.getChunksForTransfer("fresh-uuid").size)

        // Purge expired transfers
        chunkDao.purgeExpiredTransfers(now)

        // Verify expired transfer and its chunks are removed
        assertNull("Expired transfer must be purged", chunkDao.getPendingTransfer("expired-uuid"))
        assertTrue("Expired chunks must be purged", chunkDao.getChunksForTransfer("expired-uuid").isEmpty())

        // Verify fresh transfer and its chunks remain untouched
        assertNotNull("Fresh transfer must remain intact", chunkDao.getPendingTransfer("fresh-uuid"))
        assertEquals(1, chunkDao.getChunksForTransfer("fresh-uuid").size)
    }
}
