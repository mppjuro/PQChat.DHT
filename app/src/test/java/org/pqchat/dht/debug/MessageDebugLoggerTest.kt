package org.pqchat.dht.debug

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.protocol.HandshakeManager
import org.pqchat.dht.protocol.RatchetChain
import org.pqchat.dht.protocol.RekeyCoordinator
import java.security.Security

class MessageDebugLoggerTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupCrypto() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @Test
    fun testJsonStringFormatting() {
        val testMap = linkedMapOf<String, Any?>(
            "status" to "OK",
            "count" to 42,
            "isActive" to true,
            "nested" to linkedMapOf(
                "key" to "value"
            ),
            "list" to listOf("a", "b")
        )
        val json = MessageDebugLogger.toJsonString(testMap)
        assertTrue(json.contains("\"status\": \"OK\""))
        assertTrue(json.contains("\"count\": 42"))
        assertTrue(json.contains("\"isActive\": true"))
        assertTrue(json.contains("\"key\": \"value\""))
        assertTrue(json.contains("\"list\": ["))
    }

    @Test
    fun testOutgoingAndIncomingTextMessageLogging() {
        val seed = CryptoUtils.secureRandomBytes(64)
        val slot = RatchetChain.deriveSlot(seed, counter = 0)
        val sampleText = "Witaj, to jest testowa wiadomość szyfrowana PQC+AES!"

        val plaintext972 = BinaryFrameCodec.encodeTextMessage(
            seqNum = 0,
            ackNum = 0,
            timestampUTC = System.currentTimeMillis(),
            text = sampleText
        )
        assertEquals(872, plaintext972.size)

        val frame1000 = BinaryFrameCodec.packAeadFrame(slot.msgKey, plaintext972)
        assertEquals(900, frame1000.size)

        // Test outgoing log doesn't throw and formats properly
        MessageDebugLogger.logOutgoingTextMessage(
            contactId = "test-contact-1",
            text = sampleText,
            slot = slot,
            seqNum = 0,
            ackNum = 0,
            plaintext972 = plaintext972,
            frame900 = frame1000
        )

        // Decrypt incoming
        val unpacked = BinaryFrameCodec.unpackAeadFrame(slot.msgKey, frame1000)
        assertEquals(BinaryFrameCodec.TYPE_TEXT_MESSAGE, unpacked.msgType)
        val decodedText = (unpacked.payload as BinaryFrameCodec.DecodedPayload.TextMessage).text
        assertEquals(sampleText, decodedText)

        // Test incoming log
        MessageDebugLogger.logIncomingMessage(
            contactId = "test-contact-1",
            target = slot.target,
            seq = 1L,
            senderEdPublicKey = slot.edPublicKey,
            senderSignature = CryptoUtils.secureRandomBytes(64),
            frame900 = frame1000,
            frameMsg = unpacked,
            slotMsgKey = slot.msgKey
        )
    }

    @Test
    fun testHandshakeFinalizePqcLogging() {
        // Step 1: Alice creates handshake
        val aliceInit = HandshakeManager.aliceCreateHandshake()

        // Step 2: Bob processes QR and creates Handshake Finalize frame
        val bobResult = HandshakeManager.bobProcessQr(aliceInit.qrBytes)
        assertEquals(900, bobResult.frame1000.size)

        // Test Outgoing Bob Handshake log
        MessageDebugLogger.logOutgoingBobHandshake(
            target = bobResult.target0,
            seq = 1L,
            edPrivateKeySeed = bobResult.edPrivateKeySeed,
            frame900 = bobResult.frame1000
        )

        // Step 3: Alice finalizes
        val session = HandshakeManager.aliceFinalize(
            skA = aliceInit.skA,
            seedInit = aliceInit.seedInit,
            frame1000 = bobResult.frame1000
        )
        assertNotNull(session)

        // Test Incoming Alice Handshake log
        MessageDebugLogger.logIncomingAliceHandshakeFinalize(
            target = aliceInit.target0,
            seq = 1L,
            senderEdPublicKey = CryptoUtils.secureRandomBytes(32),
            senderSignature = CryptoUtils.secureRandomBytes(64),
            frame900 = bobResult.frame1000,
            seedInit = aliceInit.seedInit,
            decapsulationSuccess = true
        )
    }

    @Test
    fun testRekeyOfferAndResponseLogging() {
        val seed = CryptoUtils.secureRandomBytes(64)
        val slot = RatchetChain.deriveSlot(seed, counter = 50)

        // Create Rekey Offer
        val (pendingOffer, offerFrame) = RekeyCoordinator.createRekeyOffer(
            epoch = 1L,
            seqNum = 50,
            ackNum = 10,
            msgKey = slot.msgKey
        )
        assertEquals(900, offerFrame.size)

        MessageDebugLogger.logOutgoingRekeyOffer(
            contactId = "test-contact-rekey",
            epoch = 1L,
            slot = slot,
            seqNum = 50,
            ackNum = 10,
            mlKemPublicKey = pendingOffer.pkNew,
            frame900 = offerFrame
        )

        // Decrypt offer on receiver side
        val offerMsg = BinaryFrameCodec.unpackAeadFrame(slot.msgKey, offerFrame)
        assertEquals(BinaryFrameCodec.TYPE_REKEY_OFFER, offerMsg.msgType)
        val offerPayload = offerMsg.payload as BinaryFrameCodec.DecodedPayload.RekeyOffer

        // Create Rekey Response
        val (ssRekey, respFrame) = RekeyCoordinator.processOfferAndCreateResponse(
            offer = offerPayload,
            reverseSeqNum = 20,
            reverseAckNum = 50,
            reverseMsgKey = slot.msgKey
        )
        assertEquals(32, ssRekey.size)
        assertEquals(900, respFrame.size)

        MessageDebugLogger.logOutgoingRekeyResponse(
            contactId = "test-contact-rekey",
            epoch = 1L,
            slot = slot,
            seqNum = 20,
            ackNum = 50,
            frame900 = respFrame
        )
    }

    @Test
    fun testChunkDataLogging() {
        val transferId = CryptoUtils.secureRandomBytes(16)
        val chunkData = "Fragment pliku PNG".toByteArray(Charsets.UTF_8)
        val seed = CryptoUtils.secureRandomBytes(64)
        val slot = RatchetChain.deriveSlot(seed, counter = 2)

        val plaintext = BinaryFrameCodec.encodeChunkData(
            seqNum = 2,
            ackNum = 1,
            timestampUTC = System.currentTimeMillis(),
            transferId = transferId,
            chunkIndex = 0,
            totalChunks = 3,
            chunkData = chunkData
        )
        val frame = BinaryFrameCodec.packAeadFrame(slot.msgKey, plaintext)

        MessageDebugLogger.logOutgoingChunkData(
            contactId = "test-contact-chunk",
            transferId = transferId,
            chunkIndex = 0,
            totalChunks = 3,
            target = slot.target,
            seq = 1L,
            slotMsgKey = slot.msgKey,
            frame900 = frame
        )

        val unpacked = BinaryFrameCodec.unpackAeadFrame(slot.msgKey, frame)
        MessageDebugLogger.logIncomingMessage(
            contactId = "test-contact-chunk",
            target = slot.target,
            seq = 1L,
            senderEdPublicKey = slot.edPublicKey,
            senderSignature = CryptoUtils.secureRandomBytes(64),
            frame900 = frame,
            frameMsg = unpacked,
            slotMsgKey = slot.msgKey
        )
    }
}
