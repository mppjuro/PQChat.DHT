package org.pqchat.dht.protocol

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import java.security.Security

class ProtocolEngineTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @Test
    fun testAliceBobHandshakeFlow() {
        // 1. Alice creates handshake (displays QR)
        val aliceInit = HandshakeManager.aliceCreateHandshake()
        assertEquals(832, aliceInit.qrBytes.size)

        // 2. Bob scans QR and creates Type 0x01 frame for DHT
        val bobHandshake = HandshakeManager.bobProcessQr(aliceInit.qrBytes)
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, bobHandshake.frame1000.size)
        assertArrayEquals(aliceInit.target0, bobHandshake.target0)

        // 3. Alice receives frame from DHT Target_0 and finalizes
        val aliceSession = HandshakeManager.aliceFinalize(
            skA = aliceInit.skA,
            seedInit = aliceInit.seedInit,
            frame1000 = bobHandshake.frame1000
        )

        // 4. Verify working chains match:
        // Tor A->B: Alice Out == Bob In
        assertArrayEquals(aliceSession.chainKeyOut, bobHandshake.chainKeyAtoB)
        // Tor B->A: Bob Out == Alice In
        assertArrayEquals(aliceSession.chainKeyIn, bobHandshake.chainKeyBtoA)
    }

    @Test
    fun testDualRatchetMessagingAndLookahead() {
        // Setup initial chains
        val initialKey = CryptoUtils.secureRandomBytes(64)
        var senderChain = initialKey
        val receiverChain = initialKey

        // Sender sends 3 messages
        val messages = listOf("Hello Bob!", "How are you?", "Post-quantum secure on DHT!")
        val sentFrames = ArrayList<Pair<RatchetChain.SlotParameters, ByteArray>>()

        for (i in messages.indices) {
            val slot = RatchetChain.deriveSlot(senderChain, i)
            val plaintext = BinaryFrameCodec.encodeTextMessage(i, 0, System.currentTimeMillis(), messages[i])
            val frame1000 = BinaryFrameCodec.packAeadFrame(slot.msgKey, plaintext)
            sentFrames.add(Pair(slot, frame1000))
            senderChain = slot.nextChainKey
        }

        // Receiver uses lookahead window [0..4]
        val lookaheadSlots = RatchetChain.computeLookaheadSlots(receiverChain, 0, windowSize = 4)
        assertEquals(5, lookaheadSlots.size)

        // Verify receiver can decrypt each sent frame using the corresponding slot
        for (i in messages.indices) {
            val slot = lookaheadSlots[i]
            val frame = sentFrames[i].second
            val decoded = BinaryFrameCodec.unpackAeadFrame(slot.msgKey, frame)
            val textPayload = decoded.payload as BinaryFrameCodec.DecodedPayload.TextMessage
            assertEquals(messages[i], textPayload.text)
        }
    }

    @Test
    fun testPqcRekeyingCycle() {
        val initialChain = CryptoUtils.secureRandomBytes(64)
        var aliceChain = initialChain
        var bobChain = initialChain

        // Fast-forward to step 50
        var aliceCounter = 50
        assertTrue(RekeyCoordinator.shouldOfferRekey(aliceCounter))

        val slot50 = RatchetChain.deriveSlot(aliceChain, aliceCounter)

        // 1. Alice creates Rekey Offer (Type 0x03)
        val (pendingOffer, offerFrame) = RekeyCoordinator.createRekeyOffer(
            epoch = 1L,
            seqNum = aliceCounter,
            ackNum = 0,
            msgKey = slot50.msgKey
        )
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, offerFrame.size)

        // 2. Bob receives Offer, decodes, and creates Response (Type 0x04) in his reverse channel
        val bobDecodedOfferMsg = BinaryFrameCodec.unpackAeadFrame(slot50.msgKey, offerFrame)
        val offerPayload = bobDecodedOfferMsg.payload as BinaryFrameCodec.DecodedPayload.RekeyOffer

        val bobReverseSlot = RatchetChain.deriveSlot(bobChain, 10)
        val (bobRekeySecret, responseFrame) = RekeyCoordinator.processOfferAndCreateResponse(
            offer = offerPayload,
            reverseSeqNum = 10,
            reverseAckNum = 50,
            reverseMsgKey = bobReverseSlot.msgKey
        )
        assertEquals(32, bobRekeySecret.size)
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, responseFrame.size)

        // 3. Alice receives Response in reverse channel, extracts SS_rekey
        val aliceDecodedRespMsg = BinaryFrameCodec.unpackAeadFrame(bobReverseSlot.msgKey, responseFrame)
        val respPayload = aliceDecodedRespMsg.payload as BinaryFrameCodec.DecodedPayload.RekeyResponse

        val aliceRekeySecret = RekeyCoordinator.processResponse(respPayload, pendingOffer)
        assertEquals(32, aliceRekeySecret.size)
        assertArrayEquals("Rekey shared secrets must match", bobRekeySecret, aliceRekeySecret)

        // 4. Both inject SS_rekey into their chains
        aliceChain = RatchetChain.injectRekeySecret(slot50.nextChainKey, aliceRekeySecret)
        bobChain = RatchetChain.injectRekeySecret(slot50.nextChainKey, bobRekeySecret)
        assertArrayEquals("Chains must remain synchronized after rekey", aliceChain, bobChain)
    }

    @Test
    fun testChunkingAndPngReassembly() {
        // Create 36 KB fake PNG file
        val fakePng = ByteArray(36000)
        System.arraycopy(ChunkingEngine.PNG_MAGIC, 0, fakePng, 0, 4)
        for (i in 4 until 36000) {
            fakePng[i] = (i % 251).toByte()
        }
        assertTrue(ChunkingEngine.isPngImage(fakePng))

        val edSeed = CryptoUtils.secureRandomBytes(32)
        val msgKey = CryptoUtils.secureRandomBytes(32)

        // Split into chunks of 800 bytes
        val chunks = ChunkingEngine.splitData(
            data = fakePng,
            currentEdSeed = edSeed,
            currentMsgKey = msgKey,
            seqNum = 5,
            ackNum = 1
        )
        assertEquals(45, chunks.size) // 36000 / 800 = 45 chunks

        // Decrypt each chunk and verify
        val decodedChunks = ArrayList<BinaryFrameCodec.DecodedPayload.ChunkData>()
        for (chunkItem in chunks) {
            assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, chunkItem.frame1000.size)
            val subKey = ChunkingEngine.deriveChunkMsgKey(msgKey, chunkItem.chunkIndex)
            val decodedMsg = BinaryFrameCodec.unpackAeadFrame(subKey, chunkItem.frame1000)
            assertEquals(BinaryFrameCodec.TYPE_CHUNK_DATA, decodedMsg.msgType)
            decodedChunks.add(decodedMsg.payload as BinaryFrameCodec.DecodedPayload.ChunkData)
        }

        // Reassemble
        val reassembled = ChunkingEngine.assembleChunks(decodedChunks)
        assertArrayEquals("Reassembled image must match original 36KB file byte-for-byte", fakePng, reassembled)
        assertTrue(ChunkingEngine.isPngImage(reassembled))
    }
}
