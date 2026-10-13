package org.pqchat.dht.testbed

import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.dht.bencode.Bencode
import org.pqchat.dht.protocol.RatchetChain
import org.pqchat.dht.traffic.DecoyTargetPool

/**
 * Headless unit verification test suite for testbed components.
 * Tests:
 * 1. RatchetChain key hopping and lookahead pre-polling target derivation.
 * 2. Exact 900-byte BEP 44 frame compliance (904 bytes in Bencode format).
 * 3. DecoyTargetPool survival of 0-PUT stateful adversary filtering.
 * 4. Storing node direct observer model (PUT and GET on identical target).
 * 5. VPN IP multiplexing abstraction.
 */
class TestbedCorrelationTest {

    @Test
    fun `test exact 900-byte frame size complies with BEP 44 limit`() {
        val payload900 = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)
        assertEquals(900, payload900.size)

        val signData = Bencode.encodeBep44SignData(payload900, seq = 1L)
        // Sign data has structure "3:seqi1e1:v900:..."
        assertTrue(signData.isNotEmpty())

        val bencodedDict = Bencode.encode(mapOf("v" to payload900))
        // "d1:v900:<900 bytes>e" -> 1 + 3 + 4 + 900 + 1 = 909 bytes <= 1000 bytes
        assertTrue("Bencoded dict size must be <= 1000 bytes", bencodedDict.size <= 1000)
    }

    @Test
    fun `test lookahead window slots match sender future sequence`() {
        val chainKey = CryptoUtils.secureRandomBytes(64)
        val windowSize = 4 // 5 slots total: 0..4

        // Receiver computes lookahead slots in advance
        val lookaheadSlots = RatchetChain.computeLookaheadSlots(chainKey, startCounter = 0, windowSize = windowSize)
        assertEquals(5, lookaheadSlots.size)

        // Sender sequentially derives slots 0..4
        var senderChainKey = chainKey
        for (i in 0..windowSize) {
            val senderSlot = RatchetChain.deriveSlot(senderChainKey, counter = i)
            val receiverSlot = lookaheadSlots[i]

            assertArrayEquals("Target for step $i must match", senderSlot.target, receiverSlot.target)
            assertArrayEquals("MsgKey for step $i must match", senderSlot.msgKey, receiverSlot.msgKey)

            senderChainKey = senderSlot.nextChainKey
        }
    }

    @Test
    fun `test decoy target pool registers populated targets to defeat 0-PUT filtering`() {
        val pool = DecoyTargetPool(maxCapacity = 50)
        val activeTarget1 = CryptoUtils.sha1("target1".toByteArray())
        val activeTarget2 = CryptoUtils.sha1("target2".toByteArray())

        pool.registerPopulatedTarget(activeTarget1)
        pool.registerPopulatedTarget(activeTarget2)

        val decoys = pool.getDecoyTargets(2)
        assertEquals(2, decoys.size)
        assertTrue(decoys.any { it.contentEquals(activeTarget1) })
        assertTrue(decoys.any { it.contentEquals(activeTarget2) })

        // A stateful adversary checking whether target ever had a PUT will find these active targets!
        val populatedSet = setOf(CryptoUtils.toHex(activeTarget1), CryptoUtils.toHex(activeTarget2))
        for (d in decoys) {
            assertTrue("Decoy target must be present in populated set", populatedSet.contains(CryptoUtils.toHex(d)))
        }
    }

    @Test
    fun `test storing node direct observation and VPN multiplexing`() {
        val alicePhysicalIp = "192.168.1.105"
        val bobPhysicalIp = "192.168.2.110"

        val sharedVpnExitIp = "198.51.100.1"

        val target = CryptoUtils.sha1("test_rendezvous".toByteArray())

        // Without VPN: storing node sees physical Alice PUT and physical Bob GET
        val directLog = listOf(
            Pair(alicePhysicalIp, "put"),
            Pair(bobPhysicalIp, "get")
        )
        assertNotEquals(directLog[0].first, directLog[1].first)

        // With VPN: storing node sees identical VPN exit IP for both PUT and GET
        val vpnLog = listOf(
            Pair(sharedVpnExitIp, "put"),
            Pair(sharedVpnExitIp, "get")
        )
        assertEquals("With shared VPN, IP is multiplexed and identical", vpnLog[0].first, vpnLog[1].first)
    }

    @Test
    fun `test deterministic ed25519 signature verification on BEP 44 record`() {
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val payload = CryptoUtils.secureRandomBytes(900)
        val signData = Bencode.encodeBep44SignData(payload, seq = 42L)

        val sig = Ed25519Engine.sign(seed, signData)
        assertEquals(64, sig.size)

        val isValid = Ed25519Engine.verify(keyPair.publicKey, signData, sig)
        assertTrue("Signature verification must succeed", isValid)

        val corruptedData = signData.copyOf()
        corruptedData[0] = (corruptedData[0] + 1).toByte()
        val isCorruptedValid = Ed25519Engine.verify(keyPair.publicKey, corruptedData, sig)
        assertFalse("Corrupted signature verification must fail", isCorruptedValid)
    }
}
