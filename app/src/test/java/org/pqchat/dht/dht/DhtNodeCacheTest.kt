package org.pqchat.dht.dht

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.DhtNodeCacheDao
import org.pqchat.dht.data.db.DhtNodeCacheEntity
import org.pqchat.dht.dht.leaf.DhtLeafNode
import java.net.InetSocketAddress

class DhtNodeCacheTest {

    @Test
    fun testFastestNodesRotationAndLimit40() {
        val node = DhtLeafNode()

        // Insert 60 nodes with increasing RTTs: 5ms, 10ms, ..., 300ms
        for (i in 1..60) {
            val addr = InetSocketAddress("10.0.0.$i", 6881)
            val rtt = (i * 5).toLong()
            node.recordNodeSuccess(addr, rtt, CryptoUtils.secureRandomBytes(20))
        }

        val cached = node.getCachedFastestNodes()
        assertEquals("Cache must hold at most 40 fastest nodes", 40, cached.size)

        // Verify ordering: strictly ascending by rttMs
        for (i in 0 until cached.size - 1) {
            assertTrue(
                "Nodes must be sorted by RTT ascending: ${cached[i].rttMs} <= ${cached[i + 1].rttMs}",
                cached[i].rttMs <= cached[i + 1].rttMs
            )
        }

        // The fastest should be 5ms, and the 40th should be 200ms (40 * 5)
        assertEquals(5L, cached.first().rttMs)
        assertEquals(200L, cached.last().rttMs)

        // Any nodes slower than 200ms (nodes 41 to 60) must have been rotated out
        val ipsInCache = cached.map { it.address.address.hostAddress }.toSet()
        assertFalse("Node 50 should have been evicted", ipsInCache.contains("10.0.0.50"))
        assertFalse("Node 60 should have been evicted", ipsInCache.contains("10.0.0.60"))
        assertTrue("Node 1 should be retained", ipsInCache.contains("10.0.0.1"))

        node.stop()
    }

    @Test
    fun testExistingNodeRttUpdateAndReposition() {
        val node = DhtLeafNode()

        // Add 40 nodes with RTT 100ms to 490ms
        for (i in 1..40) {
            val addr = InetSocketAddress("192.168.1.$i", 7000)
            node.recordNodeSuccess(addr, (i * 10 + 100).toLong())
        }

        // Add node X with slow RTT = 450ms
        val addrX = InetSocketAddress("192.168.1.99", 7000)
        node.recordNodeSuccess(addrX, 450L)

        var cached = node.getCachedFastestNodes()
        val indexInitial = cached.indexOfFirst { it.address == addrX }
        assertTrue("Node X should be near end of cache", indexInitial >= 30)

        // Now Node X responds with very low RTT = 10ms
        node.recordNodeSuccess(addrX, 10L)

        cached = node.getCachedFastestNodes()
        val indexAfter = cached.indexOfFirst { it.address == addrX }
        assertTrue("Node X should advance toward the front of cache", indexAfter < indexInitial)

        node.stop()
    }

    @Test
    fun testSocketReuseAcrossLifecycle() {
        val node = DhtLeafNode()
        val socket1 = node.initSocket()

        assertNotNull(socket1)
        assertTrue("Socket must be bound", socket1.isBound)
        assertFalse("Socket must not be closed", socket1.isClosed)

        val port1 = node.localPort
        assertTrue("Local port must be allocated (> 0)", port1 > 0)

        // Calling initSocket again during the active session must reuse the exact same socket
        val socket2 = node.initSocket()
        assertSame("Socket instance must be reused in active session to preserve CGNAT pinhole", socket1, socket2)
        assertEquals(port1, node.localPort)

        // Calling stop must close the socket cleanly
        node.stop()
        assertTrue("Socket must be closed after stop()", socket1.isClosed)

        // Explicit preferred port must be honored
        val specificPortNode = DhtLeafNode(port = 19876)
        val specificSocket = specificPortNode.initSocket()
        assertEquals(19876, specificSocket.localPort)
        specificPortNode.stop()
    }

    @Test
    fun testDhtNodeCacheDaoInMemoryTrimming() = runBlocking {
        // Implement in-memory fake DAO to test DAO query & trimming contract
        val store = mutableMapOf<String, DhtNodeCacheEntity>()

        val fakeDao = object : DhtNodeCacheDao {
            override suspend fun getFastestNodes(limit: Int): List<DhtNodeCacheEntity> {
                return store.values.sortedBy { it.rttMs }.take(limit)
            }

            override suspend fun getAllNodes(): List<DhtNodeCacheEntity> {
                return store.values.sortedBy { it.rttMs }
            }

            override suspend fun getNode(ip: String, port: Int): DhtNodeCacheEntity? {
                return store["$ip:$port"]
            }

            override suspend fun insertOrUpdate(node: DhtNodeCacheEntity) {
                store["${node.ip}:${node.port}"] = node
            }

            override suspend fun insertOrUpdateAll(nodes: List<DhtNodeCacheEntity>) {
                nodes.forEach { insertOrUpdate(it) }
            }

            override suspend fun deleteNode(ip: String, port: Int) {
                store.remove("$ip:$port")
            }

            override suspend fun clearAll() {
                store.clear()
            }

            override suspend fun count(): Int = store.size
        }

        // Insert 50 entities
        for (i in 1..50) {
            fakeDao.upsertAndTrim(
                DhtNodeCacheEntity(
                    ip = "10.0.1.$i",
                    port = 6881,
                    lastSeen = System.currentTimeMillis(),
                    rttMs = (i * 10).toLong()
                ),
                maxCount = 40
            )
        }

        val all = fakeDao.getAllNodes()
        assertEquals("Database must contain exactly 40 fastest nodes", 40, all.size)
        assertEquals("Fastest node must have RTT 10ms", 10L, all.first().rttMs)
        assertEquals("40th node must have RTT 400ms", 400L, all.last().rttMs)
        assertNull("50th node must have been evicted", fakeDao.getNode("10.0.1.50", 6881))

        // Create DhtLeafNode with DAO and verify DB loading
        val leaf = DhtLeafNode(nodeCacheDao = fakeDao)
        leaf.loadCachedNodesFromDb()

        val loaded = leaf.getCachedFastestNodes()
        assertEquals(40, loaded.size)
        assertEquals(10L, loaded.first().rttMs)
        leaf.stop()
    }
}
