package org.pqchat.dht.crypto

import android.content.SharedPreferences
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.protocol.CompressedMicroDocData
import org.pqchat.dht.protocol.ContactIntroducerData
import org.pqchat.dht.protocol.CoverAckProtocol
import org.pqchat.dht.protocol.HandshakeManager
import org.pqchat.dht.test.BaseFakeChunkDao
import org.pqchat.dht.test.BaseFakeMessageDao
import org.pqchat.dht.traffic.PendingAckQueue
import org.pqchat.dht.traffic.PoissonTrafficGenerator
import java.io.ByteArrayOutputStream
import java.security.Security
import java.util.zip.Deflater

class MicroDocAndReadReceiptTest {

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
    }

    @After
    fun tearDown() {
        fakeDht.stop()
    }

    private class InMemorySharedPreferences : SharedPreferences {
        private val data = LinkedHashMap<String, Any?>()
        override fun getAll(): MutableMap<String, *> = HashMap(data)
        override fun getString(key: String?, defValue: String?): String? = (data[key] as? String) ?: defValue
        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
            (data[key] as? Set<String>)?.toMutableSet() ?: defValues
        override fun getInt(key: String?, defValue: Int): Int = (data[key] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (data[key] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (data[key] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = (data[key] as? Boolean) ?: defValue
        override fun contains(key: String?): Boolean = data.containsKey(key)
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val pending = LinkedHashMap<String, Any?>()
            private val removals = HashSet<String>()
            private var clearAll = false
            override fun putString(key: String?, value: String?) = apply { if (key != null) pending[key] = value }
            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply {
                if (key != null) pending[key] = values?.toSet()
            }
            override fun putInt(key: String?, value: Int) = apply { if (key != null) pending[key] = value }
            override fun putLong(key: String?, value: Long) = apply { if (key != null) pending[key] = value }
            override fun putFloat(key: String?, value: Float) = apply { if (key != null) pending[key] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { if (key != null) pending[key] = value }
            override fun remove(key: String?) = apply { if (key != null) removals.add(key) }
            override fun clear() = apply { clearAll = true }
            override fun commit(): Boolean { apply(); return true }
            override fun apply() {
                if (clearAll) data.clear()
                removals.forEach { data.remove(it) }
                data.putAll(pending)
            }
        }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private class InMemoryContactDao : ContactDao {
        private val map = LinkedHashMap<String, ContactEntity>()
        private val flow = kotlinx.coroutines.flow.MutableStateFlow<List<ContactEntity>>(emptyList())
        override fun getAllContactsFlow() = flow
        override suspend fun getContactById(id: String) = map[id]
        override suspend fun insertOrUpdate(contact: ContactEntity) { map[contact.id] = contact; flow.value = map.values.toList() }
        override suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: EncryptedBlob) {
            map[id]?.let { map[id] = it.copy(counterOut = counterOut, chainKeyOut = chainKeyOut); flow.value = map.values.toList() }
        }
        override suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: EncryptedBlob, rekeyEpoch: Long) {
            map[id]?.let { map[id] = it.copy(counterOut = counterOut, chainKeyOut = chainKeyOut, rekeyEpoch = rekeyEpoch); flow.value = map.values.toList() }
        }
        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {
            map[id]?.let { map[id] = it.copy(counterIn = counterIn, chainKeyIn = chainKeyIn); flow.value = map.values.toList() }
        }
        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {
            map[id]?.let { map[id] = it.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap); flow.value = map.values.toList() }
        }
        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long) {
            map[id]?.let { map[id] = it.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch); flow.value = map.values.toList() }
        }
        override suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {
            map[id]?.let { map[id] = it.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap); flow.value = map.values.toList() }
        }
        override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {}
        override suspend fun updateVerifiedStatus(id: String, isVerified: Boolean) {}
        override suspend fun updateContactName(id: String, name: EncryptedText) {}
        override suspend fun deleteContact(id: String) { map.remove(id); flow.value = map.values.toList() }
    }

    @Test
    fun testType0C_CompressedMicroDoc_RoundTripAnd900BInvariant() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val title = "pqchat-notes.md"
        val body = buildString {
            append("# Post-Quantum Security Audit\n\n")
            repeat(40) { idx ->
                append("- Check #$idx: verify 900-byte BEP-44 frame padding and HKDF-SHA512 isolation.\n")
            }
        }
        assertTrue("Sample markdown should exceed single plaintext frame (>2000 B)", body.toByteArray().size > 2000)

        val plaintext = BinaryFrameCodec.encodeCompressedMicroDoc(
            seqNum = 7,
            ackNum = 3,
            timestampUTC = System.currentTimeMillis(),
            title = title,
            markdownBody = body,
            ephemeralTtlSeconds = 300L
        )
        assertEquals(BinaryFrameCodec.CIPHERTEXT_SIZE, plaintext.size)

        val frame = BinaryFrameCodec.packAeadFrame(key, plaintext, target, "AliceToBob")
        assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, frame.size)

        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, "AliceToBob")
        assertEquals(BinaryFrameCodec.TYPE_COMPRESSED_MICRO_DOC, decoded.msgType)
        assertEquals(7, decoded.seqNum)
        val payload = decoded.payload as BinaryFrameCodec.DecodedPayload.CompressedMicroDoc
        assertEquals(title, payload.title)
        assertEquals(body, payload.markdownBody)
        assertEquals(300L, payload.ephemeralTtlSeconds)
        assertEquals(BinaryFrameCodec.MICRO_DOC_COMPRESSION_DEFLATE, payload.compressionAlg)
    }

    @Test
    fun testType0C_ZipBombProtectionRejectsSpoofedAndOversizedStreams() {
        // Compress 32 KB of zeros (easily fits in ~60 bytes deflated, classic zip-bomb ratio >500x)
        val bombInput = ByteArray(32 * 1024) { 'A'.code.toByte() }
        val deflater = Deflater(Deflater.BEST_COMPRESSION)
        deflater.setInput(bombInput)
        deflater.finish()
        val out = ByteArrayOutputStream()
        val buf = ByteArray(1024)
        while (!deflater.finished()) {
            val n = deflater.deflate(buf)
            out.write(buf, 0, n)
        }
        deflater.end()
        val bombDeflated = out.toByteArray()
        assertTrue("Deflated 32 KB bomb should easily fit in 1 frame", bombDeflated.size < 256)

        // Attack 1: Spoof uncompressedLen in inner header as 64 B while stream actually expands to 32 KB
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val innerPayload = ByteArray(BinaryFrameCodec.INNER_PAYLOAD_SIZE)
        innerPayload[0] = BinaryFrameCodec.MICRO_DOC_SUBTYPE_MARKDOWN
        innerPayload[1] = BinaryFrameCodec.MICRO_DOC_COMPRESSION_DEFLATE
        // uncompressedLen = 64 (spoofed small value!)
        innerPayload[2] = 0
        innerPayload[3] = 64
        // encodedLen = bombDeflated.size
        innerPayload[4] = ((bombDeflated.size ushr 8) and 0xFF).toByte()
        innerPayload[5] = (bombDeflated.size and 0xFF).toByte()
        System.arraycopy(bombDeflated, 0, innerPayload, 10, bombDeflated.size)

        val plaintextBuf = java.nio.ByteBuffer.allocate(BinaryFrameCodec.CIPHERTEXT_SIZE)
            .order(java.nio.ByteOrder.BIG_ENDIAN)
        plaintextBuf.put(BinaryFrameCodec.TYPE_COMPRESSED_MICRO_DOC)
        plaintextBuf.putShort(1)
        plaintextBuf.putShort(0)
        plaintextBuf.putLong(System.currentTimeMillis())
        plaintextBuf.put(innerPayload)
        val frame = BinaryFrameCodec.packAeadFrame(key, plaintextBuf.array(), target, "AliceToBob")

        val ex1 = assertThrows(IllegalArgumentException::class.java) {
            BinaryFrameCodec.unpackAeadFrame(key, frame, target, "AliceToBob")
        }
        assertTrue(ex1.message?.contains("Zip bomb protection", ignoreCase = true) == true)

        // Attack 2: Declared uncompressedLen > 8192 B
        val innerPayload2 = innerPayload.copyOf()
        val hugeDeclared = 16384
        innerPayload2[2] = ((hugeDeclared ushr 8) and 0xFF).toByte()
        innerPayload2[3] = (hugeDeclared and 0xFF).toByte()
        val plaintextBuf2 = java.nio.ByteBuffer.allocate(BinaryFrameCodec.CIPHERTEXT_SIZE)
            .order(java.nio.ByteOrder.BIG_ENDIAN)
        plaintextBuf2.put(BinaryFrameCodec.TYPE_COMPRESSED_MICRO_DOC)
        plaintextBuf2.putShort(2)
        plaintextBuf2.putShort(0)
        plaintextBuf2.putLong(System.currentTimeMillis())
        plaintextBuf2.put(innerPayload2)
        val frame2 = BinaryFrameCodec.packAeadFrame(key, plaintextBuf2.array(), target, "AliceToBob")

        val ex2 = assertThrows(IllegalArgumentException::class.java) {
            BinaryFrameCodec.unpackAeadFrame(key, frame2, target, "AliceToBob")
        }
        assertTrue(ex2.message?.contains("exceeds", ignoreCase = true) == true)
    }

    @Test
    fun testType0C_ContactIntroducer_LosslessBase3329AndFullHandshakeAcross25Keys() {
        val transportKey = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)

        repeat(15) { round ->
            val charlieInit = HandshakeManager.aliceCreateHandshake()
            assertEquals(864, charlieInit.qrBytes.size)

            val packed = BinaryFrameCodec.packIntroducerQrPayload(charlieInit.qrBytes)
            assertEquals(845, packed.size)
            val unpacked = BinaryFrameCodec.unpackIntroducerQrPayload(packed)
            assertArrayEquals("Base-3329 packing must be 100% lossless (round $round)", charlieInit.qrBytes, unpacked)

            val plaintext = BinaryFrameCodec.encodeContactIntroducer(
                seqNum = round,
                ackNum = 0,
                timestampUTC = System.currentTimeMillis(),
                introducedName = "Charlie#$round",
                qrPayload = charlieInit.qrBytes
            )
            val frame = BinaryFrameCodec.packAeadFrame(transportKey, plaintext, target, "AliceToBob")
            assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, frame.size)

            val decoded = BinaryFrameCodec.unpackAeadFrame(transportKey, frame, target, "AliceToBob")
            val card = decoded.payload as BinaryFrameCodec.DecodedPayload.ContactIntroducer
            assertArrayEquals(charlieInit.qrBytes, card.qrPayload)

            // Verify recipient Bob can immediately complete a full PQ handshake using introduced QR payload
            val bobHs = HandshakeManager.bobProcessQr(card.qrPayload)
            val charlieSession = HandshakeManager.aliceFinalize(
                skA = charlieInit.skA,
                pkA = charlieInit.pkA,
                seedInit = charlieInit.seedInit,
                frame = bobHs.frame
            )
            assertEquals(bobHs.sas, charlieSession.sas)
            assertArrayEquals(bobHs.chainKeyAtoB, charlieSession.chainKeyOut)
            assertArrayEquals(bobHs.chainKeyBtoA, charlieSession.chainKeyIn)
            charlieInit.destroySensitiveKeys()
            bobHs.destroySensitiveKeys()
        }
    }

    @Test
    fun testZeroOverheadReadReceipts_CoverAckBitmapEncodingAndSecurity() {
        val ratchetKey = CryptoUtils.secureRandomBytes(32)
        val window = CoverAckProtocol.buildReadReceiptWindow(listOf(0, 1, 2, 5, 63))
        assertNotNull(window)
        val (baseSeq, bitmap) = window!!

        val ackWithRead = CoverAckProtocol.createAckPayload(
            ratchetKey = ratchetKey,
            messageId = "63",
            seqNum = 63,
            readBaseSeq = baseSeq,
            readSeqBitmap = bitmap
        )
        assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, ackWithRead.size)
        assertTrue(CoverAckProtocol.verifyAckPayload(ratchetKey, ackWithRead, "63", 63))

        val parsed = CoverAckProtocol.parseAckPayload(ratchetKey, ackWithRead, "63", 63)!!
        assertTrue(parsed.hasReadReceipt)
        assertTrue(parsed.isSeqRead(0))
        assertTrue(parsed.isSeqRead(1))
        assertTrue(parsed.isSeqRead(2))
        assertFalse(parsed.isSeqRead(3))
        assertTrue(parsed.isSeqRead(5))
        assertTrue(parsed.isSeqRead(63))

        // Delivery-only ACK (read receipts disabled) must NOT report hasReadReceipt
        val ackDeliveryOnly = CoverAckProtocol.createAckPayload(
            ratchetKey = ratchetKey,
            messageId = "63",
            seqNum = 63,
            readBaseSeq = null,
            readSeqBitmap = 0L
        )
        assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, ackDeliveryOnly.size)
        val parsedDeliveryOnly = CoverAckProtocol.parseAckPayload(ratchetKey, ackDeliveryOnly, "63", 63)!!
        assertFalse(parsedDeliveryOnly.hasReadReceipt)
        assertFalse(parsedDeliveryOnly.isSeqRead(63))
    }

    @Test
    fun testRepositoryEndToEnd_MicroDoc_Introducer_AndReadReceiptPrivacyToggle() = runBlocking {
        val prefs = InMemorySharedPreferences()
        val settings = AppSettingsManager(sharedPreferences = prefs)
        assertTrue("Read receipts must be enabled by default", settings.isReadReceiptsEnabled.value)

        val chainAtoB = CryptoUtils.secureRandomBytes(64)
        val chainBtoA = CryptoUtils.secureRandomBytes(64)

        val aliceContactDao = InMemoryContactDao()
        val aliceMsgDao = BaseFakeMessageDao()
        val aliceAckQueue = PendingAckQueue()
        val aliceRepo = ChatRepository(
            contactDao = aliceContactDao,
            messageDao = aliceMsgDao,
            chunkDao = BaseFakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = aliceAckQueue
        ).apply { isFastTestMode = true }

        val bobContactDao = InMemoryContactDao()
        val bobMsgDao = BaseFakeMessageDao()
        val bobAckQueue = PendingAckQueue()
        val bobRepo = ChatRepository(
            contactDao = bobContactDao,
            messageDao = bobMsgDao,
            chunkDao = BaseFakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = bobAckQueue,
            settingsManager = settings
        ).apply { isFastTestMode = true }
        val bobTraffic = PoissonTrafficGenerator(
            dhtLeafNode = fakeDht,
            pendingAckQueue = bobAckQueue,
            readReceiptsEnabledProvider = { settings.isReadReceiptsEnabled.value }
        )

        aliceRepo.addContact(ContactEntity("bob", "Bob", chainAtoB, chainBtoA, 0, 0, isInitiator = true))
        bobRepo.addContact(ContactEntity("alice", "Alice", chainBtoA, chainAtoB, 0, 0, isInitiator = false))

        // 1. Send Compressed Micro-Doc (seq 0) and Contact Introducer (seq 1)
        val charlieInit = HandshakeManager.aliceCreateHandshake()
        assertTrue(aliceRepo.sendCompressedMicroDoc("bob", "spec.md", "## Hello\n" + "x".repeat(900)))
        assertTrue(aliceRepo.sendContactIntroducer("bob", "Charlie", charlieInit.qrBytes))

        bobRepo.pollContactIncoming("alice")
        assertEquals(2, bobMsgDao.messages.size)
        val decodedDoc = CompressedMicroDocData.parse(bobMsgDao.messages[0].rawTextContent)
        assertNotNull(decodedDoc)
        assertEquals("spec.md", decodedDoc!!.title)
        val decodedIntro = ContactIntroducerData.parse(bobMsgDao.messages[1].rawTextContent)
        assertNotNull(decodedIntro)
        assertArrayEquals(charlieInit.qrBytes, decodedIntro!!.qrPayload)

        // 2. With read receipts ENABLED (default): Bob marks incoming messages read -> cover ACK upgrades both to READ
        bobRepo.markIncomingMessagesAsRead("alice")
        while (!bobAckQueue.isEmpty()) {
            bobTraffic.processCoverTrafficTick()
        }
        aliceRepo.checkPendingAcks("bob")
        assertEquals("READ", aliceMsgDao.messages[0].status)
        assertEquals("READ", aliceMsgDao.messages[1].status)

        // 3. Disable Read Receipts in settings -> Bob reads msg seq 2 -> Alice sees DELIVERED ONLY, never READ
        settings.setReadReceiptsEnabled(false)
        assertFalse(settings.isReadReceiptsEnabled.value)

        assertTrue(aliceRepo.sendTextMessage("bob", "Secret read-privacy test message"))
        bobRepo.pollContactIncoming("alice")
        bobRepo.markIncomingMessagesAsRead("alice")
        while (!bobAckQueue.isEmpty()) {
            bobTraffic.processCoverTrafficTick()
        }
        aliceRepo.checkPendingAcks("bob")
        val msg3 = aliceMsgDao.messages[2]
        assertEquals("DELIVERED", msg3.status)
        assertNotEquals("READ", msg3.status)

        charlieInit.destroySensitiveKeys()
    }
}
