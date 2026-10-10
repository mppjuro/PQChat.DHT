package org.pqchat.dht.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.dht.bencode.Bencode
import java.security.Security

class CryptoEngineTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupProviders() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @Test
    fun testMLKem512KeyGenAndEncapsDecaps() {
        // Alice generates ML-KEM-512 key pair
        val aliceKeys = MLKemEngine.generateKeyPair()
        assertEquals(MLKemEngine.PUBLIC_KEY_SIZE, aliceKeys.publicKey.size) // 800 bytes

        // Bob encapsulates shared secret using Alice's public key
        val bobEncaps = MLKemEngine.encapsulate(aliceKeys.publicKey)
        assertEquals(MLKemEngine.SHARED_SECRET_SIZE, bobEncaps.sharedSecret.size) // 32 bytes
        assertEquals(MLKemEngine.CIPHERTEXT_SIZE, bobEncaps.ciphertext.size) // 768 bytes

        // Alice decapsulates Bob's ciphertext
        val aliceSharedSecret = MLKemEngine.decapsulate(aliceKeys.privateKey, bobEncaps.ciphertext)
        assertEquals(MLKemEngine.SHARED_SECRET_SIZE, aliceSharedSecret.size)

        // Verify shared secrets match exactly
        assertArrayEquals("Shared secrets must be identical", bobEncaps.sharedSecret, aliceSharedSecret)
    }

    @Test
    fun testAes256GcmEncryptionDecryption() {
        val key = CryptoUtils.secureRandomBytes(32)
        val iv = CryptoUtils.secureRandomBytes(12)
        val plaintext = "Secure Post-Quantum BitTorrent DHT Message".toByteArray(Charsets.UTF_8)

        val (tag, ciphertext) = AesGcmEngine.encrypt(key, iv, plaintext)
        assertEquals(16, tag.size)
        assertEquals(plaintext.size, ciphertext.size)

        val decrypted = AesGcmEngine.decrypt(key, iv, tag, ciphertext)
        assertArrayEquals(plaintext, decrypted)

        // Tamper test: modify ciphertext byte
        ciphertext[0] = (ciphertext[0].toInt() xor 0x01).toByte()
        try {
            AesGcmEngine.decrypt(key, iv, tag, ciphertext)
            fail("Decryption should fail when ciphertext is tampered")
        } catch (e: Exception) {
            // Expected AEAD authentication failure
        }
    }

    @Test
    fun testHkdfSha512ExtractAndExpand() {
        val ikm = "InputKeyMaterialForTesting".toByteArray(Charsets.UTF_8)
        val salt = "SaltForKDF".toByteArray(Charsets.UTF_8)
        val info = "ApplicationInfo".toByteArray(Charsets.UTF_8)

        val prk = HkdfSha512.extract(salt, ikm)
        assertEquals(64, prk.size) // SHA-512 gives 64 bytes

        val okm128 = HkdfSha512.expand(prk, info, 128)
        assertEquals(128, okm128.size)

        // Determinism test
        val okm128Repeat = HkdfSha512.expand(prk, info, 128)
        assertArrayEquals(okm128, okm128Repeat)
    }

    @Test
    fun testEd25519DeterministicKeyPairAndSigning() {
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair1 = Ed25519Engine.generateKeyPairFromSeed(seed)
        val keyPair2 = Ed25519Engine.generateKeyPairFromSeed(seed)

        assertEquals(32, keyPair1.publicKey.size)
        assertArrayEquals(keyPair1.publicKey, keyPair2.publicKey)

        val message = "BEP44 mutable item data to sign".toByteArray(Charsets.UTF_8)
        val signature = Ed25519Engine.sign(seed, message)
        assertEquals(64, signature.size)

        val valid = Ed25519Engine.verify(keyPair1.publicKey, message, signature)
        assertTrue("Signature should be valid", valid)

        // Target derivation test
        val target = Ed25519Engine.computeTarget(keyPair1.publicKey)
        assertEquals(20, target.size) // SHA-1 is 20 bytes
    }

    @Test
    fun testBinaryFrameCodecTextMessageExactPayloadSize() {
        val key = CryptoUtils.secureRandomBytes(32)
        val testText = "Zażółć gęślą jaźń! 🛡️ Post-quantum metadata-free chat."

        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"

        val encodedPlaintext = BinaryFrameCodec.encodeTextMessage(
            seqNum = 1,
            ackNum = 0,
            timestampUTC = System.currentTimeMillis(),
            text = testText
        )
        assertEquals(BinaryFrameCodec.CIPHERTEXT_SIZE, encodedPlaintext.size)

        val frame = BinaryFrameCodec.packAeadFrame(key, encodedPlaintext, target, direction)
        assertEquals("Total frame must be EXACTLY ${BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES} bytes", BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, frame.size)

        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        assertEquals(BinaryFrameCodec.TYPE_TEXT_MESSAGE, decoded.msgType)
        assertEquals(1, decoded.seqNum)
        assertEquals(0, decoded.ackNum)

        val textPayload = decoded.payload as BinaryFrameCodec.DecodedPayload.TextMessage
        assertEquals(testText, textPayload.text)
    }

    @Test
    fun testBinaryFrameCodecHandshakeFinalizeExactSize() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "BobToAlice"
        val ct = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T1_CIPHERTEXT_SIZE)
        val salt = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T1_SALT_SIZE)

        val encoded = BinaryFrameCodec.encodeHandshakeFinalize(
            seqNum = 0,
            ackNum = 0,
            timestampUTC = 1700000000000L,
            mlKemCiphertext = ct,
            saltParameter = salt
        )
        assertEquals(BinaryFrameCodec.CIPHERTEXT_SIZE, encoded.size)

        val frame = BinaryFrameCodec.packAeadFrame(key, encoded, target, direction)
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, frame.size)

        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        assertEquals(BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE, decoded.msgType)
        val payload = decoded.payload as BinaryFrameCodec.DecodedPayload.HandshakeFinalize
        assertArrayEquals(ct, payload.mlKemCiphertext)
        assertArrayEquals(salt, payload.saltParameter)
    }

    @Test
    fun testBinaryFrameCodecRekeyOfferAndResponse() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"
        val pk = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T3_PUBLIC_KEY_SIZE)

        // Type 0x03: Offer
        val encodedOffer = BinaryFrameCodec.encodeRekeyOffer(50, 49, 123456789L, 1L, pk)
        val frameOffer = BinaryFrameCodec.packAeadFrame(key, encodedOffer, target, direction)
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, frameOffer.size)

        val decodedOffer = BinaryFrameCodec.unpackAeadFrame(key, frameOffer, target, direction)
        assertEquals(BinaryFrameCodec.TYPE_REKEY_OFFER, decodedOffer.msgType)
        val offerPayload = decodedOffer.payload as BinaryFrameCodec.DecodedPayload.RekeyOffer
        assertEquals(1L, offerPayload.rekeyEpoch)
        assertArrayEquals(pk, offerPayload.mlKemPublicKey)

        // Type 0x04: Response
        val reverseTarget = CryptoUtils.secureRandomBytes(20)
        val reverseDirection = "BobToAlice"
        val ct = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T4_CIPHERTEXT_SIZE)
        val encodedResp = BinaryFrameCodec.encodeRekeyResponse(25, 50, 123456799L, 1L, ct)
        val frameResp = BinaryFrameCodec.packAeadFrame(key, encodedResp, reverseTarget, reverseDirection)
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, frameResp.size)

        val decodedResp = BinaryFrameCodec.unpackAeadFrame(key, frameResp, reverseTarget, reverseDirection)
        assertEquals(BinaryFrameCodec.TYPE_REKEY_RESPONSE, decodedResp.msgType)
        val respPayload = decodedResp.payload as BinaryFrameCodec.DecodedPayload.RekeyResponse
        assertEquals(1L, respPayload.rekeyEpoch)
        assertArrayEquals(ct, respPayload.mlKemCiphertext)
    }

    @Test
    fun testBinaryFrameCodecChunkData() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"
        val transferId = CryptoUtils.secureRandomBytes(16)
        val fakePngChunk = ByteArray(800) { (it % 256).toByte() }

        val encoded = BinaryFrameCodec.encodeChunkData(
            seqNum = 5,
            ackNum = 2,
            timestampUTC = 999999999L,
            transferId = transferId,
            chunkIndex = 3,
            totalChunks = 10,
            chunkData = fakePngChunk
        )
        val frame = BinaryFrameCodec.packAeadFrame(key, encoded, target, direction)
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, frame.size)

        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        assertEquals(BinaryFrameCodec.TYPE_CHUNK_DATA, decoded.msgType)
        val payload = decoded.payload as BinaryFrameCodec.DecodedPayload.ChunkData
        assertArrayEquals(transferId, payload.transferId)
        assertEquals(3, payload.chunkIndex)
        assertEquals(10, payload.totalChunks)
        assertArrayEquals(fakePngChunk, payload.data)
    }

    @Test
    fun testAllBinaryFrameCodecGeneratedFramesFitIn1000BytesAfterBencodeEncoding() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"

        // 1. Handshake Finalize (Type 0x01)
        val ct1 = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T1_CIPHERTEXT_SIZE)
        val salt1 = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T1_SALT_SIZE)
        val plain1 = BinaryFrameCodec.encodeHandshakeFinalize(0, 0, System.currentTimeMillis(), ct1, salt1)
        val frame1 = BinaryFrameCodec.packAeadFrame(key, plain1, target, direction)

        // 2. Text Message - short text (Type 0x02)
        val plain2 = BinaryFrameCodec.encodeTextMessage(1, 0, System.currentTimeMillis(), "Post-quantum DHT chat")
        val frame2 = BinaryFrameCodec.packAeadFrame(key, plain2, target, direction)

        // 3. Text Message - maximum allowable text size (Type 0x02)
        val maxText = "X".repeat(BinaryFrameCodec.T2_MAX_TEXT_SIZE)
        val plain3 = BinaryFrameCodec.encodeTextMessage(2, 1, System.currentTimeMillis(), maxText)
        val frame3 = BinaryFrameCodec.packAeadFrame(key, plain3, target, direction)

        // 4. Rekey Offer (Type 0x03)
        val pk3 = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T3_PUBLIC_KEY_SIZE)
        val plain4 = BinaryFrameCodec.encodeRekeyOffer(50, 49, System.currentTimeMillis(), 1L, pk3)
        val frame4 = BinaryFrameCodec.packAeadFrame(key, plain4, target, direction)

        // 5. Rekey Response (Type 0x04)
        val ct4 = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T4_CIPHERTEXT_SIZE)
        val plain5 = BinaryFrameCodec.encodeRekeyResponse(25, 50, System.currentTimeMillis(), 1L, ct4)
        val frame5 = BinaryFrameCodec.packAeadFrame(key, plain5, target, direction)

        // 6. Chunk Data - max chunk size (Type 0x05)
        val transferId = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T5_TRANSFER_ID_SIZE)
        val maxChunk = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T5_MAX_CHUNK_SIZE)
        val plain6 = BinaryFrameCodec.encodeChunkData(5, 2, System.currentTimeMillis(), transferId, 0, 1, maxChunk)
        val frame6 = BinaryFrameCodec.packAeadFrame(key, plain6, target, direction)

        val generatedFrames = listOf(
            "HandshakeFinalize" to frame1,
            "TextMessageShort" to frame2,
            "TextMessageMax" to frame3,
            "RekeyOffer" to frame4,
            "RekeyResponse" to frame5,
            "ChunkDataMax" to frame6
        )

        for ((name, frame) in generatedFrames) {
            // Raw frame payload must match MAX_FRAME_PAYLOAD_BYTES (900 bytes)
            assertEquals("$name: Raw frame payload must be MAX_FRAME_PAYLOAD_BYTES",
                BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, frame.size)

            // Bencode encoding of byte string: "<len>:<data>" -> "900:" (4B) + 900B = 904B
            val bencodedValue = Bencode.encode(frame)
            assertTrue(
                "$name: Bencoded value size (${bencodedValue.size} bytes) must NOT exceed MAX_DHT_VALUE_BYTES (${BinaryFrameCodec.MAX_DHT_VALUE_BYTES} bytes)",
                bencodedValue.size <= BinaryFrameCodec.MAX_DHT_VALUE_BYTES
            )
            assertEquals(
                "$name: Bencoded byte string size for 900B payload should be exactly 904 bytes",
                904,
                bencodedValue.size
            )
        }
    }
}
