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
        assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, bobHandshake.frame.size)
        assertArrayEquals(aliceInit.target0, bobHandshake.target0)

        // 3. Alice receives frame from DHT Target_0 and finalizes
        val aliceSession = HandshakeManager.aliceFinalize(
            skA = aliceInit.skA,
            seedInit = aliceInit.seedInit,
            frame = bobHandshake.frame
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
            val frame = BinaryFrameCodec.packAeadFrame(slot.msgKey, plaintext, slot.target, "AliceToBob")
            sentFrames.add(Pair(slot, frame))
            senderChain = slot.nextChainKey
        }

        // Receiver uses lookahead window [0..4]
        val lookaheadSlots = RatchetChain.computeLookaheadSlots(receiverChain, 0, windowSize = 4)
        assertEquals(5, lookaheadSlots.size)

        // Verify receiver can decrypt each sent frame using the corresponding slot
        for (i in messages.indices) {
            val slot = lookaheadSlots[i]
            val frame = sentFrames[i].second
            val decoded = BinaryFrameCodec.unpackAeadFrame(slot.msgKey, frame, slot.target, "AliceToBob")
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
            msgKey = slot50.msgKey,
            target = slot50.target,
            direction = "AliceToBob"
        )
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, offerFrame.size)

        // 2. Bob receives Offer, decodes, and creates Response (Type 0x04) in his reverse channel
        val bobDecodedOfferMsg = BinaryFrameCodec.unpackAeadFrame(slot50.msgKey, offerFrame, slot50.target, "AliceToBob")
        val offerPayload = bobDecodedOfferMsg.payload as BinaryFrameCodec.DecodedPayload.RekeyOffer

        val bobReverseSlot = RatchetChain.deriveSlot(bobChain, 10)
        val (bobRekeySecret, responseFrame) = RekeyCoordinator.processOfferAndCreateResponse(
            offer = offerPayload,
            reverseSeqNum = 10,
            reverseAckNum = 50,
            reverseMsgKey = bobReverseSlot.msgKey,
            reverseTarget = bobReverseSlot.target,
            direction = "BobToAlice"
        )
        assertEquals(32, bobRekeySecret.size)
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, responseFrame.size)

        // 3. Alice receives Response in reverse channel, extracts SS_rekey
        val aliceDecodedRespMsg = BinaryFrameCodec.unpackAeadFrame(bobReverseSlot.msgKey, responseFrame, bobReverseSlot.target, "BobToAlice")
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
            ackNum = 1,
            direction = "AliceToBob"
        )
        assertEquals(45, chunks.size) // 36000 / 800 = 45 chunks

        // Decrypt each chunk and verify
        val decodedChunks = ArrayList<BinaryFrameCodec.DecodedPayload.ChunkData>()
        for (chunkItem in chunks) {
            assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, chunkItem.frame.size)
            val subKey = ChunkingEngine.deriveChunkMsgKey(msgKey, chunkItem.chunkIndex)
            val decodedMsg = BinaryFrameCodec.unpackAeadFrame(subKey, chunkItem.frame, chunkItem.target, "AliceToBob")
            assertEquals(BinaryFrameCodec.TYPE_CHUNK_DATA, decodedMsg.msgType)
            decodedChunks.add(decodedMsg.payload as BinaryFrameCodec.DecodedPayload.ChunkData)
        }

        // Reassemble
        val reassembled = ChunkingEngine.assembleChunks(decodedChunks)
        assertArrayEquals("Reassembled image must match original 36KB file byte-for-byte", fakePng, reassembled)
        assertTrue(ChunkingEngine.isPngImage(reassembled))
    }

    @Test
    fun testAliceBobHandshakeWithKeyConfirmationAndSas() {
        val aliceInit = HandshakeManager.aliceCreateHandshake()
        val bobHandshake = HandshakeManager.bobProcessQr(aliceInit.qrBytes)

        assertTrue(bobHandshake.sas.isNotEmpty())
        assertEquals(6, bobHandshake.sas.length)
        assertTrue(bobHandshake.fingerprint.isNotEmpty())

        val skACopy = aliceInit.skA.copyOf()
        val aliceSession = HandshakeManager.aliceFinalize(
            skA = aliceInit.skA,
            pkA = aliceInit.pkA,
            seedInit = aliceInit.seedInit,
            frame = bobHandshake.frame
        )

        // Chains must match
        assertArrayEquals(aliceSession.chainKeyOut, bobHandshake.chainKeyAtoB)
        assertArrayEquals(aliceSession.chainKeyIn, bobHandshake.chainKeyBtoA)

        // SAS and fingerprint must match
        assertEquals("SAS must match between Alice and Bob", bobHandshake.sas, aliceSession.sas)
        assertEquals("Fingerprint must match between Alice and Bob", bobHandshake.fingerprint, aliceSession.fingerprint)

        // skA must be securely zeroized after verified confirmation
        assertTrue("skA must be wiped with zeroes after confirmation", aliceInit.skA.all { it == 0.toByte() })
        assertFalse("Original skA was not all zeroes", skACopy.all { it == 0.toByte() })
    }

    @Test
    fun testHandshakeKeyConfirmationRejectsImplicitRejectionDesyncWithoutWipingSkA() {
        val aliceInit = HandshakeManager.aliceCreateHandshake()
        val pkA = aliceInit.pkA
        val seedInit = aliceInit.seedInit
        val target0 = aliceInit.target0

        // Bob performs legitimate encapsulation
        val bobHandshake = HandshakeManager.bobProcessQr(aliceInit.qrBytes)

        // Attacker tampers with the ML-KEM ciphertext:
        // In ML-KEM, modifying ciphertext doesn't throw on decapsulate (implicit rejection),
        // but results in a different pseudorandom shared secret!
        val forgedCt = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T1_CIPHERTEXT_SIZE)
        val salt = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T1_SALT_SIZE)
        val kHs = org.pqchat.dht.crypto.HkdfSha512.derive(null, seedInit, "hs_enc".toByteArray(Charsets.UTF_8), 32)

        // Attacker creates a frame with forged ct and invalid confirmation tag
        val forgedConfirmationTag = CryptoUtils.secureRandomBytes(32)
        val forgedPlaintext = BinaryFrameCodec.encodeHandshakeFinalize(
            seqNum = 0,
            ackNum = 0,
            timestampUTC = System.currentTimeMillis(),
            mlKemCiphertext = forgedCt,
            saltParameter = salt,
            confirmationTag = forgedConfirmationTag
        )
        val forgedFrame = BinaryFrameCodec.packAeadFrame(
            key = kHs,
            plaintext = forgedPlaintext,
            target = target0,
            direction = "BobToAlice"
        )

        val skABackup = aliceInit.skA.copyOf()

        // Alice attempts to finalize with forged frame: key confirmation MUST throw SecurityException
        try {
            HandshakeManager.aliceFinalize(
                skA = aliceInit.skA,
                pkA = pkA,
                seedInit = seedInit,
                frame = forgedFrame
            )
            fail("Expected SecurityException due to key confirmation failure on forged ciphertext")
        } catch (e: SecurityException) {
            assertTrue(e.message?.contains("key confirmation failed") == true)
        }

        // Alice's skA MUST NOT be wiped on failure, allowing retry on legitimate frame!
        assertArrayEquals("skA must remain intact on key confirmation failure", skABackup, aliceInit.skA)

        // Alice can now finalize with Bob's legitimate frame!
        val session = HandshakeManager.aliceFinalize(
            skA = aliceInit.skA,
            pkA = pkA,
            seedInit = seedInit,
            frame = bobHandshake.frame
        )
        assertEquals(bobHandshake.sas, session.sas)
        assertTrue("skA is wiped only after successful confirmation", aliceInit.skA.all { it == 0.toByte() })
    }

    @Test
    fun testAesGcmAadTargetAndDirectionIntegrity() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val otherTarget = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"
        val wrongDirection = "BobToAlice"

        val plaintext = BinaryFrameCodec.encodeTextMessage(0, 0, System.currentTimeMillis(), "Secret authenticated payload")
        val frame = BinaryFrameCodec.packAeadFrame(key, plaintext, target, direction)

        // 1. Correct AAD: decrypts successfully
        val msg = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        assertEquals("Secret authenticated payload", (msg.payload as BinaryFrameCodec.DecodedPayload.TextMessage).text)

        // 2. Tampered target: must fail AEAD verification
        try {
            BinaryFrameCodec.unpackAeadFrame(key, frame, otherTarget, direction)
            fail("Expected decryption failure with wrong target in AAD")
        } catch (_: Exception) {
            // expected
        }

        // 3. Tampered direction: must fail AEAD verification
        try {
            BinaryFrameCodec.unpackAeadFrame(key, frame, target, wrongDirection)
            fail("Expected decryption failure with wrong direction in AAD")
        } catch (_: Exception) {
            // expected
        }

        // 4. Tampered AAD bytes directly
        try {
            val tamperedAad = BinaryFrameCodec.buildAad(target, direction).apply { this[0] = (this[0].toInt() xor 0xFF).toByte() }
            BinaryFrameCodec.unpackAeadFrame(key, frame, tamperedAad)
            fail("Expected decryption failure with tampered raw AAD")
        } catch (_: Exception) {
            // expected
        }
    }
}
