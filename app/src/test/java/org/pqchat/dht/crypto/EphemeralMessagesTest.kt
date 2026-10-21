package org.pqchat.dht.crypto

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.CoverAckProtocol
import org.pqchat.dht.protocol.RatchetChain
import org.pqchat.dht.test.BaseFakeContactDao
import org.pqchat.dht.test.BaseFakeMessageDao
import java.util.concurrent.CopyOnWriteArrayList
import javax.crypto.spec.SecretKeySpec

class EphemeralMessagesTest {

    private val masterKey = SecretKeySpec(ByteArray(32) { (it * 7 + 3).toByte() }, "AES")

    @Before
    fun setUp() {
        KeystoreCrypto.setTestSecretKey(masterKey)
    }

    @Test
    fun testFrameEncodingAndDecodingWithEphemeralTtl() {
        val key = ByteArray(32) { (it + 1).toByte() }
        val target = ByteArray(20) { 0xAA.toByte() }
        val direction = "AliceToBob"

        val ttls = listOf(0L, 60L, 900L, 3600L, 86400L)

        for (ttl in ttls) {
            val plaintext = BinaryFrameCodec.encodeTextMessage(
                seqNum = 42,
                ackNum = 17,
                timestampUTC = 1700000000000L,
                text = "Secret disappearing message with TTL=$ttl",
                ephemeralTtlSeconds = ttl
            )

            // Plaintext size inside AEAD payload
            assertEquals(872, plaintext.size)

            val packedFrame = BinaryFrameCodec.packAeadFrame(
                key = key,
                plaintext = plaintext,
                target = target,
                direction = direction
            )

            // Wire frame size MUST be strictly 900 bytes per BEP 44 budget
            assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, packedFrame.size)
            assertEquals(900, packedFrame.size)

            val decoded = BinaryFrameCodec.unpackAeadFrame(
                key = key,
                frame = packedFrame,
                target = target,
                direction = direction
            )

            assertEquals(BinaryFrameCodec.TYPE_TEXT_MESSAGE, decoded.msgType)
            assertEquals(42, decoded.seqNum)
            assertEquals(17, decoded.ackNum)
            assertEquals(1700000000000L, decoded.timestampUTC)

            val payload = decoded.payload as BinaryFrameCodec.DecodedPayload.TextMessage
            assertEquals("Secret disappearing message with TTL=$ttl", payload.text)
            assertEquals("TTL mismatch for ttl=$ttl", ttl, payload.ephemeralTtlSeconds)
        }
    }

    @Test
    fun testBackwardCompatibilityWithOldFramesWithoutEphemeralMagic() {
        val key = ByteArray(32) { 0x44.toByte() }
        val target = ByteArray(20) { 0x55.toByte() }
        val direction = "BobToAlice"

        // Manually construct an old-style plaintext payload filled with random CSPRNG noise
        // without the MAGIC_EPHEMERAL header
        val textBytes = "Old style legacy message".toByteArray(Charsets.UTF_8)
        val plaintext = ByteArray(872)
        val buffer = java.nio.ByteBuffer.wrap(plaintext).order(java.nio.ByteOrder.BIG_ENDIAN)
        buffer.put(BinaryFrameCodec.TYPE_TEXT_MESSAGE)
        buffer.putShort(10.toShort())
        buffer.putShort(5.toShort())
        buffer.putLong(1700000000000L)
        buffer.putShort(textBytes.size.toShort())
        buffer.put(textBytes)
        // Fill remainder with random CSPRNG noise without magic
        val noise = CryptoUtils.secureRandomBytes(plaintext.size - buffer.position())
        buffer.put(noise)

        val frame = BinaryFrameCodec.packAeadFrame(key, plaintext, target, direction)
        assertEquals(900, frame.size)

        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        val payload = decoded.payload as BinaryFrameCodec.DecodedPayload.TextMessage
        assertEquals("Old style legacy message", payload.text)
        assertEquals("Legacy message must fall back safely to 0L TTL", 0L, payload.ephemeralTtlSeconds)
    }

    @Test
    fun testChunkEncodingAndDecodingWithEphemeralTtl() {
        val key = ByteArray(32) { 0x77.toByte() }
        val target = ByteArray(20) { 0x88.toByte() }
        val transferId = ByteArray(16) { 0x99.toByte() }
        val chunkData = ByteArray(500) { (it % 256).toByte() }
        val direction = "AliceToBob"

        val plaintext = BinaryFrameCodec.encodeChunkData(
            seqNum = 1,
            ackNum = 0,
            timestampUTC = 1700000000000L,
            transferId = transferId,
            chunkIndex = 0,
            totalChunks = 1,
            chunkData = chunkData,
            ephemeralTtlSeconds = 900L
        )

        assertEquals(872, plaintext.size)
        val frame = BinaryFrameCodec.packAeadFrame(key, plaintext, target, direction)
        assertEquals(900, frame.size)

        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        assertEquals(BinaryFrameCodec.TYPE_CHUNK_DATA, decoded.msgType)
        val payload = decoded.payload as BinaryFrameCodec.DecodedPayload.ChunkData
        assertArrayEquals(chunkData, payload.data)
        assertEquals(900L, payload.ephemeralTtlSeconds)
    }

    private class RecordingFakeDhtClient(val delegate: org.pqchat.dht.dht.FakeDht = org.pqchat.dht.dht.FakeDht()) : DhtClient by delegate {
        data class PutCall(
            val target: ByteArray,
            val v: ByteArray,
            val seq: Long,
            val sk: ByteArray
        )

        val puts = CopyOnWriteArrayList<PutCall>()

        override suspend fun putMutable(
            target: ByteArray,
            v: ByteArray,
            seq: Long,
            salt: ByteArray?,
            sk: ByteArray,
            skipLocalStore: Boolean
        ): Boolean {
            puts.add(PutCall(target.copyOf(), v.copyOf(), seq, sk.copyOf()))
            return delegate.putMutable(target, v, seq, salt, sk, skipLocalStore)
        }
    }

    @Test
    fun testMarkIncomingMessagesAsReadTriggersExpirationTimer() = runBlocking {
        val messageDao = BaseFakeMessageDao()
        val contactDao = BaseFakeContactDao()
        val dhtClient = RecordingFakeDhtClient()

        val repository = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = org.pqchat.dht.test.BaseFakeChunkDao(),
            dhtLeafNode = dhtClient
        )

        val contactId = "contact_bob"
        val msg1 = MessageEntity(
            contactId = contactId,
            isOutgoing = false,
            seqNum = 1,
            textContent = "Hello ephemeral 1",
            ephemeralTtlSeconds = 60L,
            expiresAtTimestamp = null
        )
        val msg2 = MessageEntity(
            contactId = contactId,
            isOutgoing = false,
            seqNum = 2,
            textContent = "Regular persistent message",
            ephemeralTtlSeconds = 0L,
            expiresAtTimestamp = null
        )
        val msg3 = MessageEntity(
            contactId = contactId,
            isOutgoing = true,
            seqNum = 3,
            textContent = "Outgoing ephemeral message",
            ephemeralTtlSeconds = 60L,
            expiresAtTimestamp = 1000L + 60_000L
        )

        val id1 = messageDao.insertMessage(msg1)
        val id2 = messageDao.insertMessage(msg2)
        val id3 = messageDao.insertMessage(msg3)

        // Before mark as read: unread ephemeral has expiresAtTimestamp == null
        val stored1Before = messageDao.getMessageById(id1)
        assertNull(stored1Before?.expiresAtTimestamp)

        // Mark incoming messages as read
        val t0 = 1700000000000L
        repository.markIncomingMessagesAsRead(contactId)

        val stored1After = messageDao.getMessageById(id1)
        assertNotNull(stored1After?.expiresAtTimestamp)
        assertTrue(stored1After!!.expiresAtTimestamp!! >= System.currentTimeMillis())

        // Regular message remains null
        val stored2 = messageDao.getMessageById(id2)
        assertNull(stored2?.expiresAtTimestamp)

        // Outgoing message timestamp was already set and unchanged
        val stored3 = messageDao.getMessageById(id3)
        assertEquals(1000L + 60_000L, stored3?.rawExpiresAtTimestamp)
    }

    @Test
    fun testPurgeExpiredMessagesWipesSqliteAndEmitsDouble900ByteDhtTombstones() = runBlocking {
        val messageDao = BaseFakeMessageDao()
        val contactDao = BaseFakeContactDao()
        val dhtClient = RecordingFakeDhtClient()

        val repository = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = org.pqchat.dht.test.BaseFakeChunkDao(),
            dhtLeafNode = dhtClient
        )

        val contactId = "contact_alice"
        val slotTarget = ByteArray(20) { 0x12.toByte() }
        val slotEdSeed = ByteArray(32) { 0x34.toByte() }
        val ackRatchetKey = ByteArray(32) { 0x56.toByte() }
        val ackTarget = CoverAckProtocol.computeAckTarget(ackRatchetKey, "1")

        val now = 1700000000000L
        val expiredMsg = MessageEntity(
            contactId = contactId,
            isOutgoing = false,
            seqEpoch = 0,
            seqNum = 1,
            textContent = "Top Secret Plaintext",
            imageBytes = byteArrayOf(1, 2, 3, 4),
            slotTarget = slotTarget,
            slotEdSeed = slotEdSeed,
            ackTarget = ackTarget,
            ackRatchetKey = ackRatchetKey,
            ephemeralTtlSeconds = 60L,
            expiresAtTimestamp = now - 1000L // expired 1s ago
        )
        val activeMsg = MessageEntity(
            contactId = contactId,
            isOutgoing = false,
            seqEpoch = 0,
            seqNum = 2,
            textContent = "Active message",
            ephemeralTtlSeconds = 60L,
            expiresAtTimestamp = now + 50_000L // expires in future
        )

        val idExpired = messageDao.insertMessage(expiredMsg)
        val idActive = messageDao.insertMessage(activeMsg)

        // Before purge: both exist in DAO
        assertEquals(2, messageDao.messages.size)
        val expiredList = messageDao.getExpiredMessages(now)
        assertEquals(1, expiredList.size)
        assertEquals(idExpired, expiredList[0].id)

        // Execute purge
        val purgedCount = repository.purgeExpiredMessages(now)
        assertEquals(1, purgedCount)

        // SQLite verification:
        // 1. Expired message removed from database
        assertNull("Expired message must be deleted from SQLite", messageDao.getMessageById(idExpired))
        // 2. Active message remains intact
        assertNotNull("Active message must not be deleted", messageDao.getMessageById(idActive))

        // DHT Tombstones verification:
        // Must emit exactly 2 putMutable calls:
        // 1. For slotTarget (message slot)
        // 2. For ackTarget (ACK slot)
        assertEquals(2, dhtClient.puts.size)

        val slotPut = dhtClient.puts.firstOrNull { it.target.contentEquals(slotTarget) }
        assertNotNull("Tombstone must be sent to message slotTarget", slotPut)
        assertEquals(DhtClient.DEFAULT_MUTABLE_SEQ + 1L, slotPut!!.seq)
        assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, slotPut.v.size)
        assertEquals(900, slotPut.v.size)
        assertArrayEquals(slotEdSeed, slotPut.sk)

        val ackPut = dhtClient.puts.firstOrNull { it.target.contentEquals(ackTarget) }
        assertNotNull("Tombstone must be sent to ackTarget", ackPut)
        assertEquals(DhtClient.DEFAULT_MUTABLE_SEQ + 1L, ackPut!!.seq)
        assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, ackPut.v.size)
        assertEquals(900, ackPut.v.size)
        val expectedAckSeed = CoverAckProtocol.deriveAckSeed(ackRatchetKey, "1")
        assertArrayEquals(expectedAckSeed, ackPut.sk)
    }

    @Test
    fun testWipeMessageContentOverwritesEncryptedBlobsWithNoise() = runBlocking {
        val messageDao = BaseFakeMessageDao()
        val rowId = MessageEntity.computeMessageRowId("c1", 0, 5, true)

        val msg = MessageEntity(
            contactId = "c1",
            isOutgoing = true,
            seqEpoch = 0,
            seqNum = 5,
            textContent = "Confidential Banking Info",
            imageBytes = ByteArray(100) { 0xFF.toByte() }
        )
        val id = messageDao.insertMessage(msg)

        val before = messageDao.getMessageById(id)!!
        assertEquals("Confidential Banking Info", before.rawTextContent)
        assertEquals(100, before.rawImageBytes?.size)

        val noiseText = CryptoUtils.toHex(CryptoUtils.secureRandomBytes(32))
        val noiseBytes = CryptoUtils.secureRandomBytes(64)
        val wipedEncText = EncryptedText(noiseText, "messages", rowId, "textContent")
        val wipedEncBlob = EncryptedBlob(noiseBytes, "messages", rowId, "imageBytes")

        messageDao.wipeMessageContent(id, wipedEncText, wipedEncBlob)

        val after = messageDao.getMessageById(id)!!
        assertNotEquals("Confidential Banking Info", after.rawTextContent)
        assertFalse(after.rawTextContent!!.contains("Confidential"))
        assertEquals(noiseText, after.rawTextContent)
        assertEquals(64, after.rawImageBytes?.size)
        assertArrayEquals(noiseBytes, after.rawImageBytes)
    }
}
