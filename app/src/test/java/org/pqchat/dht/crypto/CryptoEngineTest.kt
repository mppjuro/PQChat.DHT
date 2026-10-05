package org.pqchat.dht.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
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
    fun testBinaryFrameCodecTextMessageExact1000Bytes() {
        val key = CryptoUtils.secureRandomBytes(32)
        val testText = "Zażółć gęślą jaźń! 🛡️ Post-quantum metadata-free chat."

        val encodedPlaintext = BinaryFrameCodec.encodeTextMessage(
            seqNum = 1,
            ackNum = 0,
            timestampUTC = System.currentTimeMillis(),
            text = testText
        )
        assertEquals(972, encodedPlaintext.size)

        val frame1000 = BinaryFrameCodec.packAeadFrame(key, encodedPlaintext)
        assertEquals("Total frame must be EXACTLY 1000 bytes", 1000, frame1000.size)

        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame1000)
        assertEquals(BinaryFrameCodec.TYPE_TEXT_MESSAGE, decoded.msgType)
        assertEquals(1, decoded.seqNum)
        assertEquals(0, decoded.ackNum)

        val textPayload = decoded.payload as BinaryFrameCodec.DecodedPayload.TextMessage
        assertEquals(testText, textPayload.text)
    }

    @Test
    fun testBinaryFrameCodecHandshakeFinalizeExact1000Bytes() {
        val key = CryptoUtils.secureRandomBytes(32)
        val ct = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T1_CIPHERTEXT_SIZE)
        val salt = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T1_SALT_SIZE)

        val encoded = BinaryFrameCodec.encodeHandshakeFinalize(
            seqNum = 0,
            ackNum = 0,
            timestampUTC = 1700000000000L,
            mlKemCiphertext = ct,
            saltParameter = salt
        )
        assertEquals(972, encoded.size)

        val frame1000 = BinaryFrameCodec.packAeadFrame(key, encoded)
        assertEquals(1000, frame1000.size)

        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame1000)
        assertEquals(BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE, decoded.msgType)
        val payload = decoded.payload as BinaryFrameCodec.DecodedPayload.HandshakeFinalize
        assertArrayEquals(ct, payload.mlKemCiphertext)
        assertArrayEquals(salt, payload.saltParameter)
    }

    @Test
    fun testBinaryFrameCodecRekeyOfferAndResponse() {
        val key = CryptoUtils.secureRandomBytes(32)
        val pk = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T3_PUBLIC_KEY_SIZE)

        // Type 0x03: Offer
        val encodedOffer = BinaryFrameCodec.encodeRekeyOffer(50, 49, 123456789L, 1L, pk)
        val frameOffer = BinaryFrameCodec.packAeadFrame(key, encodedOffer)
        assertEquals(1000, frameOffer.size)

        val decodedOffer = BinaryFrameCodec.unpackAeadFrame(key, frameOffer)
        assertEquals(BinaryFrameCodec.TYPE_REKEY_OFFER, decodedOffer.msgType)
        val offerPayload = decodedOffer.payload as BinaryFrameCodec.DecodedPayload.RekeyOffer
        assertEquals(1L, offerPayload.rekeyEpoch)
        assertArrayEquals(pk, offerPayload.mlKemPublicKey)

        // Type 0x04: Response
        val ct = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T4_CIPHERTEXT_SIZE)
        val encodedResp = BinaryFrameCodec.encodeRekeyResponse(25, 50, 123456799L, 1L, ct)
        val frameResp = BinaryFrameCodec.packAeadFrame(key, encodedResp)
        assertEquals(1000, frameResp.size)

        val decodedResp = BinaryFrameCodec.unpackAeadFrame(key, frameResp)
        assertEquals(BinaryFrameCodec.TYPE_REKEY_RESPONSE, decodedResp.msgType)
        val respPayload = decodedResp.payload as BinaryFrameCodec.DecodedPayload.RekeyResponse
        assertEquals(1L, respPayload.rekeyEpoch)
        assertArrayEquals(ct, respPayload.mlKemCiphertext)
    }

    @Test
    fun testBinaryFrameCodecChunkData() {
        val key = CryptoUtils.secureRandomBytes(32)
        val transferId = CryptoUtils.secureRandomBytes(16)
        val fakePngChunk = ByteArray(900) { (it % 256).toByte() }

        val encoded = BinaryFrameCodec.encodeChunkData(
            seqNum = 5,
            ackNum = 2,
            timestampUTC = 999999999L,
            transferId = transferId,
            chunkIndex = 3,
            totalChunks = 10,
            chunkData = fakePngChunk
        )
        val frame1000 = BinaryFrameCodec.packAeadFrame(key, encoded)
        assertEquals(1000, frame1000.size)

        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame1000)
        assertEquals(BinaryFrameCodec.TYPE_CHUNK_DATA, decoded.msgType)
        val payload = decoded.payload as BinaryFrameCodec.DecodedPayload.ChunkData
        assertArrayEquals(transferId, payload.transferId)
        assertEquals(3, payload.chunkIndex)
        assertEquals(10, payload.totalChunks)
        assertArrayEquals(fakePngChunk, payload.data)
    }
}
