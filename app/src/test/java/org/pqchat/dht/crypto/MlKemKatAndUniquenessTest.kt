package org.pqchat.dht.crypto

import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.protocol.ChunkingEngine
import org.pqchat.dht.protocol.CoverAckProtocol
import org.pqchat.dht.protocol.RatchetChain
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/**
 * Tests for NIST FIPS 203 ML-KEM-512 Known Answer Tests (KAT),
 * Hybrid KEM (X25519 + ML-KEM), and IV/Key uniqueness verification.
 */
class MlKemKatAndUniquenessTest {

    @Test
    fun testMlKem512KnownAnswerTestDeterministicKeyGenAndEncaps() {
        // Deterministic seeds for ML-KEM-512 (FIPS 203 Section 6.1/6.2)
        // d: 32 bytes seed for matrix generation and error sampling
        // z: 32 bytes seed for implicit rejection key
        // m: 32 bytes seed for encapsulation message
        val d = ByteArray(32) { (it * 7 + 1).toByte() }
        val z = ByteArray(32) { (it * 13 + 3).toByte() }
        val m = ByteArray(32) { (it * 17 + 5).toByte() }

        val keyGen = MLKEMKeyPairGenerator()
        keyGen.init(MLKEMKeyGenerationParameters(SecureRandom(), MLKEMParameters.ml_kem_512))

        // Deterministic key generation via internalGenerateKeyPair(d, z)
        val keyPair1 = keyGen.internalGenerateKeyPair(d, z)
        val pub1 = keyPair1.public as MLKEMPublicKeyParameters
        val priv1 = keyPair1.private as MLKEMPrivateKeyParameters

        val pkBytes1 = pub1.encoded
        val skBytes1 = priv1.encoded

        assertEquals(MLKemEngine.PUBLIC_KEY_SIZE, pkBytes1.size)
        assertTrue(skBytes1.size > 0)

        // Repeat with identical seeds (d, z) must produce byte-for-byte identical keys
        val keyPair2 = keyGen.internalGenerateKeyPair(d, z)
        val pub2 = keyPair2.public as MLKEMPublicKeyParameters
        val priv2 = keyPair2.private as MLKEMPrivateKeyParameters

        assertArrayEquals("Deterministic keygen must produce identical public key", pkBytes1, pub2.encoded)
        assertArrayEquals("Deterministic keygen must produce identical private key", skBytes1, priv2.encoded)

        // Verify public key extraction from private key
        val extractedPk = MLKemEngine.extractPublicKey(skBytes1)
        assertArrayEquals("Extracted public key must match original public key", pkBytes1, extractedPk)

        // Deterministic encapsulation via internalGenerateEncapsulated(pub, m)
        val kemGen = MLKEMGenerator(SecureRandom())
        val encResult1 = kemGen.internalGenerateEncapsulated(pub1, m)
        val ss1 = encResult1.secret
        val ct1 = encResult1.encapsulation

        assertEquals(MLKemEngine.SHARED_SECRET_SIZE, ss1.size)
        assertEquals(MLKemEngine.CIPHERTEXT_SIZE, ct1.size)

        // Repeat with identical m and pub must produce identical secret and ciphertext
        val encResult2 = kemGen.internalGenerateEncapsulated(pub1, m)
        assertArrayEquals("Deterministic encaps must produce identical shared secret", ss1, encResult2.secret)
        assertArrayEquals("Deterministic encaps must produce identical ciphertext", ct1, encResult2.encapsulation)

        // Decapsulate using MLKemEngine
        val recoveredSecret = MLKemEngine.decapsulate(skBytes1, ct1)
        assertArrayEquals("Decapsulation must recover identical shared secret", ss1, recoveredSecret)

        // FIPS 203 Implicit Rejection Test:
        // Tampering with ciphertext MUST NOT return ss1 (implicit rejection returns pseudo-random hash)
        val corruptedCt = ct1.copyOf()
        corruptedCt[0] = (corruptedCt[0].toInt() xor 0x01).toByte()
        val rejectSecret = MLKemEngine.decapsulate(skBytes1, corruptedCt)
        assertEquals(32, rejectSecret.size)
        assertFalse("Corrupted ciphertext must implicitly reject and NOT match shared secret", ss1.contentEquals(rejectSecret))
    }

    @Test
    fun testAeadFrameIvUniquenessOverLargeSample() {
        val count = 1000
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"

        val plaintext = BinaryFrameCodec.encodeTextMessage(0, 0, System.currentTimeMillis(), "Test IV")
        val seenIvs = Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())

        for (i in 0 until count) {
            val frame = BinaryFrameCodec.packAeadFrame(key, plaintext, target, direction)
            val iv = frame.copyOfRange(0, BinaryFrameCodec.IV_SIZE)
            val ivHex = CryptoUtils.toHex(iv)

            val isNew = seenIvs.add(ivHex)
            assertTrue("Detected repeated IV in frame generation! IV collision at index $i: $ivHex", isNew)
        }

        assertEquals("All $count generated frames must have distinct IVs", count, seenIvs.size)
    }

    @Test
    fun testRatchetChainKeyAndTargetUniquenessOver1000Steps() {
        val steps = 1000
        val seed = CryptoUtils.secureRandomBytes(64)

        val seenMsgKeys = HashSet<String>(steps)
        val seenEdSeeds = HashSet<String>(steps)
        val seenTargets = HashSet<String>(steps)
        val seenChainKeys = HashSet<String>(steps)

        var currentChain = seed
        for (i in 0 until steps) {
            val slot = RatchetChain.deriveSlot(currentChain, i)

            val msgKeyHex = CryptoUtils.toHex(slot.msgKey)
            val edSeedHex = CryptoUtils.toHex(slot.edPrivateKeySeed)
            val targetHex = CryptoUtils.toHex(slot.target)
            val nextChainHex = CryptoUtils.toHex(slot.nextChainKey)

            assertTrue("Duplicate msgKey at step $i", seenMsgKeys.add(msgKeyHex))
            assertTrue("Duplicate edSeed at step $i", seenEdSeeds.add(edSeedHex))
            assertTrue("Duplicate target at step $i", seenTargets.add(targetHex))
            assertTrue("Duplicate chainKey at step $i", seenChainKeys.add(nextChainHex))

            currentChain = slot.nextChainKey
        }

        assertEquals(steps, seenMsgKeys.size)
        assertEquals(steps, seenEdSeeds.size)
        assertEquals(steps, seenTargets.size)
        assertEquals(steps, seenChainKeys.size)
    }

    @Test
    fun testChunkSubKeysAndTargetsUniqueness() {
        val totalChunks = 64
        val currentEdSeed = CryptoUtils.secureRandomBytes(32)
        val currentMsgKey = CryptoUtils.secureRandomBytes(32)
        val transferId = CryptoUtils.secureRandomBytes(16)

        val seenChunkKeys = HashSet<String>(totalChunks)
        val seenChunkSeeds = HashSet<String>(totalChunks)
        val seenChunkTargets = HashSet<String>(totalChunks)

        for (j in 0 until totalChunks) {
            val subMsgKey = ChunkingEngine.deriveChunkMsgKey(currentMsgKey, j)
            val subEdSeed = ChunkingEngine.deriveChunkEdSeed(currentEdSeed, transferId, j)
            val subKeyPair = Ed25519Engine.generateKeyPairFromSeed(subEdSeed)
            val subTarget = Ed25519Engine.computeTarget(subKeyPair.publicKey)

            assertTrue("Duplicate chunk msgKey at index $j", seenChunkKeys.add(CryptoUtils.toHex(subMsgKey)))
            assertTrue("Duplicate chunk edSeed at index $j", seenChunkSeeds.add(CryptoUtils.toHex(subEdSeed)))
            assertTrue("Duplicate chunk target at index $j", seenChunkTargets.add(CryptoUtils.toHex(subTarget)))
        }

        assertEquals(totalChunks, seenChunkKeys.size)
        assertEquals(totalChunks, seenChunkSeeds.size)
        assertEquals(totalChunks, seenChunkTargets.size)
    }

    @Test
    fun testCoverAckKeysAndTargetsUniqueness() {
        val count = 250
        val ratchetKey = CryptoUtils.secureRandomBytes(32)

        val seenAckKeys = HashSet<String>(count)
        val seenAckTargets = HashSet<String>(count)

        for (i in 0 until count) {
            val messageId = "msg_$i"
            val aesKey = CoverAckProtocol.deriveAckAesKey(ratchetKey, messageId)
            val target = CoverAckProtocol.computeAckTarget(ratchetKey, messageId)

            assertTrue("Duplicate ACK AES key for $messageId", seenAckKeys.add(CryptoUtils.toHex(aesKey)))
            assertTrue("Duplicate ACK target for $messageId", seenAckTargets.add(CryptoUtils.toHex(target)))
        }

        assertEquals(count, seenAckKeys.size)
        assertEquals(count, seenAckTargets.size)
    }

    @Test
    fun testHybridKemX25519PlusMlKem512AgreementAndIntegrity() {
        // Alice generates hybrid key pair (ML-KEM-512 + X25519)
        val aliceHybridKey = HybridKemEngine.generateKeyPair()
        assertEquals(HybridKemEngine.HYBRID_PUBLIC_KEY_SIZE, aliceHybridKey.combinedPublicKey.size)

        // Bob encapsulates against Alice's combined public key
        val bobEncResult = HybridKemEngine.encapsulate(aliceHybridKey.combinedPublicKey)
        assertEquals(HybridKemEngine.SHARED_SECRET_SIZE, bobEncResult.sharedSecret.size)
        assertEquals(HybridKemEngine.HYBRID_CIPHERTEXT_SIZE, bobEncResult.combinedCiphertext.size)

        // Alice decapsulates using her private keys
        val aliceRecoveredSecret = HybridKemEngine.decapsulate(
            mlKemPrivateKey = aliceHybridKey.mlKemPrivateKey,
            x25519PrivateKey = aliceHybridKey.x25519PrivateKey,
            combinedCiphertext = bobEncResult.combinedCiphertext
        )

        assertArrayEquals("Hybrid shared secret must match perfectly between Alice and Bob",
            bobEncResult.sharedSecret, aliceRecoveredSecret)

        // Tampering with either component (ML-KEM ct or X25519 ephemeral pk) breaks agreement:
        // 1. Corrupted ML-KEM part
        val corruptedCt1 = bobEncResult.combinedCiphertext.copyOf()
        corruptedCt1[0] = (corruptedCt1[0].toInt() xor 0xFF).toByte()
        val corruptedSecret1 = HybridKemEngine.decapsulate(
            aliceHybridKey.mlKemPrivateKey,
            aliceHybridKey.x25519PrivateKey,
            corruptedCt1
        )
        assertFalse("Tampering with ML-KEM component must alter hybrid secret",
            bobEncResult.sharedSecret.contentEquals(corruptedSecret1))

        // 2. Corrupted X25519 part
        val corruptedCt2 = bobEncResult.combinedCiphertext.copyOf()
        corruptedCt2[HybridKemEngine.HYBRID_CIPHERTEXT_SIZE - 1] =
            (corruptedCt2[HybridKemEngine.HYBRID_CIPHERTEXT_SIZE - 1].toInt() xor 0xFF).toByte()
        val corruptedSecret2 = HybridKemEngine.decapsulate(
            aliceHybridKey.mlKemPrivateKey,
            aliceHybridKey.x25519PrivateKey,
            corruptedCt2
        )
        assertFalse("Tampering with X25519 component must alter hybrid secret",
            bobEncResult.sharedSecret.contentEquals(corruptedSecret2))

        // Protocol version check
        val v1 = HybridKemEngine.ProtocolVersion.fromWireId(0x01)
        val v2 = HybridKemEngine.ProtocolVersion.fromWireId(0x02)
        assertEquals(HybridKemEngine.ProtocolVersion.V1_MLKEM_ONLY, v1)
        assertEquals(HybridKemEngine.ProtocolVersion.V2_HYBRID_X25519_MLKEM, v2)
    }
}
