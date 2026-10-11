package org.pqchat.dht.traffic

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.dht.bencode.Bencode
import java.security.Security

class BlindRepublishPoolTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupCrypto() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private fun createValidPacket(
        seq: Long = 1L,
        salt: ByteArray? = null,
        payloadSize: Int = 1000
    ): BlindRepublishEntry {
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        val v = CryptoUtils.secureRandomBytes(payloadSize)
        val signData = Bencode.encodeBep44SignData(v, seq, salt)
        val sig = Ed25519Engine.sign(seed, signData)

        return BlindRepublishEntry(
            target = target,
            publicKey = keyPair.publicKey,
            seq = seq,
            v = v,
            sig = sig,
            salt = salt
        )
    }

    @Test
    fun testVerifyAndAdd_ValidSignatureAccepted() {
        val pool = BlindRepublishPool(maxCapacity = 50, ttlMs = 7200_000L)
        val entry = createValidPacket()

        val accepted = pool.verifyAndAdd(entry)
        assertTrue("Valid packet must be accepted by BlindRepublishPool", accepted)
        assertEquals(1, pool.size())

        val retrieved = pool.getEntry(entry.target)
        assertNotNull(retrieved)
        assertArrayEquals(entry.publicKey, retrieved!!.publicKey)
        assertArrayEquals(entry.v, retrieved.v)
        assertArrayEquals(entry.sig, retrieved.sig)
    }

    @Test
    fun testVerifyAndAdd_InvalidSignatureRejected() {
        val pool = BlindRepublishPool(maxCapacity = 50)
        val entry = createValidPacket()

        // 1. Corrupted signature
        val corruptedSig = entry.sig.copyOf()
        corruptedSig[0] = (corruptedSig[0].toInt() xor 0xFF).toByte()
        val rejected1 = pool.verifyAndAdd(
            target = entry.target,
            publicKey = entry.publicKey,
            seq = entry.seq,
            v = entry.v,
            sig = corruptedSig,
            salt = entry.salt
        )
        assertFalse("Packet with corrupted signature must be rejected", rejected1)
        assertEquals(0, pool.size())

        // 2. Tampered payload
        val tamperedV = entry.v.copyOf()
        tamperedV[5] = (tamperedV[5].toInt() xor 0x01).toByte()
        val rejected2 = pool.verifyAndAdd(
            target = entry.target,
            publicKey = entry.publicKey,
            seq = entry.seq,
            v = tamperedV,
            sig = entry.sig,
            salt = entry.salt
        )
        assertFalse("Packet with tampered payload must be rejected", rejected2)
        assertEquals(0, pool.size())
    }

    @Test
    fun testVerifyAndAdd_InvalidStructuralSizesRejected() {
        val pool = BlindRepublishPool(maxCapacity = 50)
        val valid = createValidPacket()

        // Invalid target size
        assertFalse(pool.verifyAndAdd(valid.copy(target = ByteArray(19))))
        assertFalse(pool.verifyAndAdd(valid.copy(target = ByteArray(21))))

        // Invalid public key size
        assertFalse(pool.verifyAndAdd(valid.copy(publicKey = ByteArray(31))))

        // Invalid signature size
        assertFalse(pool.verifyAndAdd(valid.copy(sig = ByteArray(63))))

        // Invalid payload size (empty or > 1000)
        assertFalse(pool.verifyAndAdd(valid.copy(v = ByteArray(0))))
        assertFalse(pool.verifyAndAdd(valid.copy(v = ByteArray(1001))))

        assertEquals(0, pool.size())
    }

    @Test
    fun testLRUCapacityLimit_EvictsLeastRecentlyUsed() {
        val pool = BlindRepublishPool(maxCapacity = 3, ttlMs = 7200_000L)
        val entry1 = createValidPacket(seq = 1L)
        val entry2 = createValidPacket(seq = 2L)
        val entry3 = createValidPacket(seq = 3L)
        val entry4 = createValidPacket(seq = 4L)

        assertTrue(pool.verifyAndAdd(entry1))
        assertTrue(pool.verifyAndAdd(entry2))
        assertTrue(pool.verifyAndAdd(entry3))
        assertEquals(3, pool.size())

        // Access entry1 to make it most recently used (Order now: entry2, entry3, entry1)
        assertNotNull(pool.getEntry(entry1.target))

        // Insert entry4 -> entry2 (least recently used) must be evicted
        assertTrue(pool.verifyAndAdd(entry4))
        assertEquals(3, pool.size())

        assertNull("Entry 2 should have been evicted as LRU", pool.getEntry(entry2.target))
        assertNotNull("Entry 1 should be retained because it was accessed recently", pool.getEntry(entry1.target))
        assertNotNull("Entry 3 should be retained", pool.getEntry(entry3.target))
        assertNotNull("Entry 4 should be retained", pool.getEntry(entry4.target))
    }

    @Test
    fun testTTLEviction_EvictsOldEntries() {
        val ttlMs = 120 * 60 * 1000L // 120 minutes = 7,200,000 ms
        val pool = BlindRepublishPool(maxCapacity = 50, ttlMs = ttlMs)

        val baseTime = 1_000_000L
        val entry = createValidPacket()

        assertTrue(pool.verifyAndAdd(entry, now = baseTime))
        assertEquals(1, pool.size(now = baseTime + 60_000L)) // +1 minute -> alive

        // Check at 119 minutes -> still alive
        assertEquals(1, pool.size(now = baseTime + ttlMs - 1000L))
        assertNotNull(pool.getEntry(entry.target, now = baseTime + ttlMs - 1000L))

        // Check at 121 minutes -> expired
        val expiredTime = baseTime + ttlMs + 1000L
        assertEquals(0, pool.size(now = expiredTime))
        assertNull(pool.getEntry(entry.target, now = expiredTime))
        assertNull(pool.sampleRandomEntry(now = expiredTime))
    }

    @Test
    fun testSequenceNumber_DoesNotDowngrade() {
        val pool = BlindRepublishPool(maxCapacity = 50)
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)

        // Packet seq = 10
        val v10 = CryptoUtils.secureRandomBytes(500)
        val sig10 = Ed25519Engine.sign(seed, Bencode.encodeBep44SignData(v10, 10L, null))
        val entry10 = BlindRepublishEntry(target, keyPair.publicKey, 10L, v10, sig10)

        assertTrue(pool.verifyAndAdd(entry10))
        assertEquals(10L, pool.getEntry(target)!!.seq)

        // Attempt to insert older seq = 5 for same target -> rejected
        val v5 = CryptoUtils.secureRandomBytes(500)
        val sig5 = Ed25519Engine.sign(seed, Bencode.encodeBep44SignData(v5, 5L, null))
        val entry5 = BlindRepublishEntry(target, keyPair.publicKey, 5L, v5, sig5)

        assertFalse("Downgrading sequence number must be rejected", pool.verifyAndAdd(entry5))
        assertEquals(10L, pool.getEntry(target)!!.seq)

        // Attempt to insert newer seq = 15 for same target -> accepted and updated
        val v15 = CryptoUtils.secureRandomBytes(500)
        val sig15 = Ed25519Engine.sign(seed, Bencode.encodeBep44SignData(v15, 15L, null))
        val entry15 = BlindRepublishEntry(target, keyPair.publicKey, 15L, v15, sig15)

        assertTrue("Upgrading sequence number must be accepted", pool.verifyAndAdd(entry15))
        assertEquals(15L, pool.getEntry(target)!!.seq)
        assertEquals(1, pool.size())
    }

    @Test
    fun testSampleRandomEntry_PicksFromAvailableEntries() {
        val pool = BlindRepublishPool(maxCapacity = 50)
        assertNull("Empty pool returns null on sample", pool.sampleRandomEntry())

        val entry1 = createValidPacket(seq = 1L)
        val entry2 = createValidPacket(seq = 2L)
        pool.verifyAndAdd(entry1)
        pool.verifyAndAdd(entry2)

        val sampled = pool.sampleRandomEntry()
        assertNotNull(sampled)
        assertTrue(
            sampled!!.target.contentEquals(entry1.target) || sampled.target.contentEquals(entry2.target)
        )
    }

    @Test
    fun testNoIdentityLeak_ZeroIdentityOrDatabaseCoupling() {
        // Reflection check: BlindRepublishEntry must only hold raw cryptographic fields
        val fields = BlindRepublishEntry::class.java.declaredFields.map { it.name.lowercase() }
        val forbiddenTerms = listOf("contact", "user", "identity", "room", "name", "phone", "db", "dao")

        for (field in fields) {
            for (term in forbiddenTerms) {
                assertFalse(
                    "BlindRepublishEntry must not contain field '$field' referencing '$term'",
                    field.contains(term)
                )
            }
        }

        // Check types of fields in BlindRepublishEntry
        for (field in BlindRepublishEntry::class.java.declaredFields) {
            val typeName = field.type.simpleName
            assertTrue(
                "Field ${field.name} has unexpected non-cryptographic type $typeName",
                typeName in listOf("byte[]", "long", "Long", "ByteArray", "int")
            )
        }
    }
}
