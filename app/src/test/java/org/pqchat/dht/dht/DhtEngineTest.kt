package org.pqchat.dht.dht

import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.dht.bencode.Bencode
import org.pqchat.dht.dht.krpc.KrpcMessage
import java.net.InetSocketAddress

class DhtEngineTest {

    @Test
    fun testBencodeIntegerAndString() {
        val encodedInt = Bencode.encode(42L)
        assertEquals("i42e", String(encodedInt, Charsets.US_ASCII))
        assertEquals(42L, Bencode.decode(encodedInt))

        val encodedStr = Bencode.encode("pqchat")
        assertEquals("6:pqchat", String(encodedStr, Charsets.US_ASCII))
        val decodedStr = Bencode.decode(encodedStr) as ByteArray
        assertEquals("pqchat", String(decodedStr, Charsets.UTF_8))
    }

    @Test
    fun testBencodeListAndSortedDictionary() {
        val map = mapOf(
            "z" to "last",
            "a" to "first",
            "m" to 123L
        )
        val encodedMap = Bencode.encode(map)
        // Keys must be lexicographically sorted: "a", "m", "z"
        val expected = "d1:a5:first1:mi123e1:z4:laste"
        assertEquals(expected, String(encodedMap, Charsets.US_ASCII))

        val decodedMap = Bencode.decode(encodedMap) as Map<*, *>
        assertTrue(decodedMap.containsKey("a"))
        assertTrue(decodedMap.containsKey("m"))
        assertTrue(decodedMap.containsKey("z"))
    }

    @Test
    fun testBep44SignPayloadEncoding() {
        val v = "test_payload".toByteArray(Charsets.UTF_8)
        val seq = 5L
        val encodedNoSalt = Bencode.encodeBep44SignData(v, seq, null)
        val expected = "3:seqi5e1:v12:test_payload"
        assertEquals(expected, String(encodedNoSalt, Charsets.US_ASCII))

        val salt = "hs".toByteArray(Charsets.UTF_8)
        val encodedWithSalt = Bencode.encodeBep44SignData(v, seq, salt)
        val expectedWithSalt = "4:salt2:hs3:seqi5e1:v12:test_payload"
        assertEquals(expectedWithSalt, String(encodedWithSalt, Charsets.US_ASCII))
    }

    @Test
    fun testKrpcQueryAndResponseRoundTrip() {
        val nodeId = CryptoUtils.secureRandomBytes(20)
        val target = CryptoUtils.secureRandomBytes(20)
        val txId = byteArrayOf(0x01, 0x02)

        val query = KrpcMessage.createFindNodeQuery(nodeId, target, txId)
        val bencoded = query.toBencoded()

        val parsed = KrpcMessage.parse(bencoded)
        assertTrue(parsed is KrpcMessage.Query)
        val q = parsed as KrpcMessage.Query
        assertArrayEquals(txId, q.transactionId)
        assertEquals("find_node", q.method)
        assertTrue(q.readOnly)
    }

    @Test
    fun testBep44SigningAndVerification() {
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val v1000 = CryptoUtils.secureRandomBytes(1000)
        val seq = 1L

        val signData = Bencode.encodeBep44SignData(v1000, seq)
        val sig = Ed25519Engine.sign(seed, signData)
        assertEquals(64, sig.size)

        val valid = Ed25519Engine.verify(keyPair.publicKey, signData, sig)
        assertTrue(valid)

        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        assertEquals(20, target.size)
        assertArrayEquals(CryptoUtils.sha1(keyPair.publicKey), target)
    }

    @Test
    fun testDhtLeafNodeLocalMutableStore() = kotlinx.coroutines.runBlocking {
        val node = org.pqchat.dht.dht.leaf.DhtLeafNode()
        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        val payload = "Hello BEP 44 DHT Mutable".toByteArray(Charsets.UTF_8)

        val putSuccess = node.putMutable(
            target = target,
            v = payload,
            seq = 1L,
            sk = seed
        )
        assertTrue(putSuccess)

        val retrieved = node.getMutable(target)
        assertNotNull(retrieved)
        assertArrayEquals(payload, retrieved!!.v)
        assertEquals(1L, retrieved.seq)
        assertArrayEquals(keyPair.publicKey, retrieved.k)
        node.stop()
    }

    @Test
    fun testRealBep44RemotePutAndGet() = kotlinx.coroutines.runBlocking {
        val node = org.pqchat.dht.dht.leaf.DhtLeafNode()
        node.start()
        val bootstrapNodes = node.resolveBootstrapNodes()
        println("Bootstrap nodes: $bootstrapNodes")
        node.bootstrap()
        kotlinx.coroutines.delay(3000)
        println("Active peer count: ${node.getActivePeerCount()}")

        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        val payload = ByteArray(900) { 0x42.toByte() }

        println("Target hex: ${CryptoUtils.toHex(target)}")
        val putResult = node.putMutable(target, payload, 1L, null, seed)
        println("putMutable returned: $putResult")

        // Wait a few seconds for propagation
        kotlinx.coroutines.delay(4000)

        // Clear local store to force fetching exclusively from remote peers
        node.localMutableStore.clear()

        println("Attempting remote getMutable (local store cleared)...")
        val retrieved = node.getMutable(target)
        println("Remote getMutable result: ${retrieved?.let { String(it.v, Charsets.UTF_8) }}")

        node.stop()
    }
}
