package org.pqchat.dht.dht

import kotlinx.coroutines.*
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.dht.bencode.Bencode
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * In-memory simulation of DHT network for e2e and integration tests.
 * Supports configurable:
 * - Artificial network delays (min/max latency ms)
 * - Packet / request loss rates (drop probability for put and get)
 * - Record TTL (time-to-live expiration)
 * - Delivery reordering simulation (jitter)
 */
class FakeDht(
    override val myNodeId: ByteArray = CryptoUtils.secureRandomBytes(20),
    var minDelayMs: Long = 0L,
    var maxDelayMs: Long = 0L,
    var dropProbability: Double = 0.0,
    var defaultTtlMs: Long? = null
) : DhtClient {

    data class StoredEntry(
        val item: DhtLeafNode.MutableItem,
        val storedAt: Long = System.currentTimeMillis(),
        val ttlMs: Long? = null
    ) {
        fun isExpired(now: Long = System.currentTimeMillis()): Boolean {
            return ttlMs != null && (now - storedAt) > ttlMs
        }
    }

    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private val storage = ConcurrentHashMap<String, StoredEntry>()
    val preWarmedTargets = ConcurrentHashMap.newKeySet<String>()

    val putCalls = AtomicInteger(0)
    val getCalls = AtomicInteger(0)
    val coverTrafficCalls = AtomicInteger(0)

    @Volatile
    private var isRunning = false

    override fun start() {
        isRunning = true
    }

    override fun stop() {
        isRunning = false
        scope.cancel()
        storage.clear()
        preWarmedTargets.clear()
    }

    override fun getActivePeerCount(): Int = if (isRunning) 8 else 0

    override suspend fun preWarmTarget(target: ByteArray): List<DhtLeafNode.DhtPeer> {
        val targetHex = CryptoUtils.toHex(target)
        preWarmedTargets.add(targetHex)
        simulateDelay()
        return listOf(
            DhtLeafNode.DhtPeer(
                nodeId = CryptoUtils.secureRandomBytes(20),
                address = InetSocketAddress("127.0.0.1", 6881),
                rttMs = 15L
            )
        )
    }

    override fun preWarmTargetAsync(target: ByteArray): Job {
        return scope.launch {
            preWarmTarget(target)
        }
    }

    override suspend fun getMutable(
        target: ByteArray,
        salt: ByteArray?,
        skipLocalStore: Boolean,
        timeoutMs: Long
    ): DhtLeafNode.MutableItem? {
        getCalls.incrementAndGet()
        simulateDelay()

        if (shouldDrop()) {
            return null
        }

        val targetHex = CryptoUtils.toHex(target)
        val entry = storage[targetHex] ?: return null

        if (entry.isExpired()) {
            storage.remove(targetHex)
            return null
        }

        return entry.item
    }

    override suspend fun putMutable(
        target: ByteArray,
        v: ByteArray,
        seq: Long,
        salt: ByteArray?,
        sk: ByteArray,
        skipLocalStore: Boolean
    ): Boolean {
        putCalls.incrementAndGet()
        simulateDelay()

        if (shouldDrop()) {
            return false
        }

        require(v.size <= 1000) { "BEP 44 payload cannot exceed 1000 bytes (got ${v.size})" }

        val signData = Bencode.encodeBep44SignData(v, seq, salt)
        val sig = org.pqchat.dht.crypto.Ed25519Engine.sign(sk, signData)
        val pk = org.pqchat.dht.crypto.Ed25519Engine.generateKeyPairFromSeed(sk).publicKey
        val targetHex = CryptoUtils.toHex(target)

        val existing = storage[targetHex]
        if (existing == null || seq >= existing.item.seq) {
            val item = DhtLeafNode.MutableItem(
                v = v.copyOf(),
                seq = seq,
                k = pk,
                sig = sig,
                salt = salt?.copyOf(),
                token = null,
                responder = InetSocketAddress("127.0.0.1", 6881)
            )
            storage[targetHex] = StoredEntry(
                item = item,
                storedAt = System.currentTimeMillis(),
                ttlMs = defaultTtlMs
            )
        }

        return true
    }

    override suspend fun sendCoverTrafficDummy(): Boolean {
        coverTrafficCalls.incrementAndGet()
        simulateDelay()
        return true
    }

    private suspend fun simulateDelay() {
        if (maxDelayMs > 0L) {
            val delayDuration = if (maxDelayMs > minDelayMs) {
                minDelayMs + (Math.random() * (maxDelayMs - minDelayMs)).toLong()
            } else {
                minDelayMs
            }
            if (delayDuration > 0L) {
                delay(delayDuration)
            }
        }
    }

    private fun shouldDrop(): Boolean {
        return dropProbability > 0.0 && Math.random() < dropProbability
    }

    fun clear() {
        storage.clear()
        preWarmedTargets.clear()
        putCalls.set(0)
        getCalls.set(0)
        coverTrafficCalls.set(0)
    }

    fun setEntryWithCustomTtl(target: ByteArray, item: DhtLeafNode.MutableItem, ttlMs: Long) {
        val targetHex = CryptoUtils.toHex(target)
        storage[targetHex] = StoredEntry(
            item = item,
            storedAt = System.currentTimeMillis(),
            ttlMs = ttlMs
        )
    }

    fun getStoredCount(): Int = storage.size
}
