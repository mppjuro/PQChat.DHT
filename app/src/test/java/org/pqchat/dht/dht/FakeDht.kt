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

    @Volatile
    override var replicationK: Int = 8

    override fun setAdaptiveK(isMobileOrCgnat: Boolean) {
        replicationK = if (isMobileOrCgnat) 16 else 8
    }

    var packetLossRate: Double
        get() = dropProbability
        set(value) { dropProbability = value }

    val keepalivePingCalls = AtomicInteger(0)

    override suspend fun sendKeepalivePing(): Boolean {
        keepalivePingCalls.incrementAndGet()
        bytesSent.addAndGet(50L)
        bytesReceived.addAndGet(50L)
        return true
    }

    data class StoredEntry(
        val item: DhtLeafNode.MutableItem,
        val storedAt: Long = System.currentTimeMillis(),
        val ttlMs: Long? = null,
        val replicas: Int = 8
    ) {
        fun isExpired(now: Long = System.currentTimeMillis()): Boolean {
            return ttlMs != null && (now - storedAt) > ttlMs
        }
    }

    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    val storage = ConcurrentHashMap<String, StoredEntry>()
    val preWarmedTargets = ConcurrentHashMap.newKeySet<String>()

    val putCalls = AtomicInteger(0)
    val getCalls = AtomicInteger(0)
    val coverTrafficCalls = AtomicInteger(0)
    val bytesSent = java.util.concurrent.atomic.AtomicLong(0L)
    val bytesReceived = java.util.concurrent.atomic.AtomicLong(0L)

    private val _lastOperationMetrics = java.util.concurrent.atomic.AtomicReference(org.pqchat.dht.dht.leaf.DhtOpMetrics())
    override val lastOperationMetrics: org.pqchat.dht.dht.leaf.DhtOpMetrics get() = _lastOperationMetrics.get()

    override val totalGetCalls: Long get() = getCalls.get().toLong()
    override val totalPutCalls: Long get() = putCalls.get().toLong()
    override val totalBytesSent: Long get() = bytesSent.get()
    override val totalBytesReceived: Long get() = bytesReceived.get()

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
        timeoutMs: Long,
        probeAllReplicas: Boolean
    ): DhtLeafNode.MutableItem? {
        getCalls.incrementAndGet()
        bytesSent.addAndGet(100L)
        simulateDelay()

        val targetHex = CryptoUtils.toHex(target)
        val entry = storage[targetHex]
        if (entry == null || entry.isExpired()) {
            if (entry != null && entry.isExpired()) storage.remove(targetHex)
            val metrics = org.pqchat.dht.dht.leaf.DhtOpMetrics(
                nodesQueried = replicationK * 2,
                nodesResponded = 0,
                lookupHops = 2
            )
            _lastOperationMetrics.set(metrics)
            return null
        }

        if (dropProbability > 0.0) {
            val failProb = Math.pow(dropProbability, entry.replicas.toDouble())
            if (Math.random() < failProb) {
                val metrics = org.pqchat.dht.dht.leaf.DhtOpMetrics(
                    nodesQueried = replicationK * 2,
                    nodesResponded = 0,
                    lookupHops = 2
                )
                _lastOperationMetrics.set(metrics)
                return null
            }
        }

        val survivingReplicas = if (entry.ttlMs != null && entry.ttlMs > 0L) {
            val elapsed = (System.currentTimeMillis() - entry.storedAt).coerceAtLeast(0L)
            val fraction = (1.0 - (elapsed.toDouble() / entry.ttlMs)).coerceIn(0.0, 1.0)
            maxOf(1, (entry.replicas * fraction).toInt())
        } else {
            entry.replicas
        }

        val metrics = org.pqchat.dht.dht.leaf.DhtOpMetrics(
            nodesQueried = replicationK * 2,
            nodesResponded = survivingReplicas,
            lookupHops = 1
        )
        _lastOperationMetrics.set(metrics)

        bytesReceived.addAndGet(entry.item.v.size.toLong() + 100L)
        return entry.item.copy(
            nodesQueried = metrics.nodesQueried,
            nodesResponded = metrics.nodesResponded,
            lookupHops = metrics.lookupHops
        )
    }

    override suspend fun putMutablePreSigned(
        target: ByteArray,
        v: ByteArray,
        seq: Long,
        salt: ByteArray?,
        pk: ByteArray,
        sig: ByteArray,
        skipLocalStore: Boolean
    ): Boolean {
        putCalls.incrementAndGet()
        bytesSent.addAndGet(v.size.toLong() + 100L)
        bytesReceived.addAndGet(50L)
        simulateDelay()

        val replicasStored = if (dropProbability > 0.0) {
            val successfulStores = (0 until replicationK).count { Math.random() >= dropProbability }
            if (successfulStores == 0) {
                val metrics = org.pqchat.dht.dht.leaf.DhtOpMetrics(
                    nodesQueried = replicationK * 2,
                    nodesResponded = 0,
                    lookupHops = 1
                )
                _lastOperationMetrics.set(metrics)
                return false
            }
            successfulStores
        } else {
            replicationK
        }

        require(v.size <= 1000) { "BEP 44 payload cannot exceed 1000 bytes (got ${v.size})" }

        val targetHex = CryptoUtils.toHex(target)
        val existing = storage[targetHex]
        val metrics = org.pqchat.dht.dht.leaf.DhtOpMetrics(
            nodesQueried = replicationK * 2,
            nodesResponded = replicasStored,
            lookupHops = 1
        )
        _lastOperationMetrics.set(metrics)

        if (existing == null || seq >= existing.item.seq) {
            val item = DhtLeafNode.MutableItem(
                v = v.copyOf(),
                seq = seq,
                k = pk.copyOf(),
                sig = sig.copyOf(),
                salt = salt?.copyOf(),
                token = null,
                responder = InetSocketAddress("127.0.0.1", 6881),
                nodesQueried = metrics.nodesQueried,
                nodesResponded = metrics.nodesResponded,
                lookupHops = metrics.lookupHops
            )
            storage[targetHex] = StoredEntry(
                item = item,
                storedAt = System.currentTimeMillis(),
                ttlMs = defaultTtlMs,
                replicas = replicasStored
            )
        }

        return true
    }

    override suspend fun putMutable(
        target: ByteArray,
        v: ByteArray,
        seq: Long,
        salt: ByteArray?,
        sk: ByteArray,
        skipLocalStore: Boolean
    ): Boolean {
        require(v.size <= 1000) { "BEP 44 payload cannot exceed 1000 bytes (got ${v.size})" }
        val signData = Bencode.encodeBep44SignData(v, seq, salt)
        val sig = org.pqchat.dht.crypto.Ed25519Engine.sign(sk, signData)
        val pk = org.pqchat.dht.crypto.Ed25519Engine.generateKeyPairFromSeed(sk).publicKey
        return putMutablePreSigned(target, v, seq, salt, pk, sig, skipLocalStore)
    }

    override suspend fun sendCoverTrafficDummy(): ByteArray? {
        coverTrafficCalls.incrementAndGet()
        bytesSent.addAndGet(org.pqchat.dht.crypto.BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES.toLong() + 100L)
        bytesReceived.addAndGet(50L)
        simulateDelay()
        val dummySeed = CryptoUtils.secureRandomBytes(32)
        val dummyKeyPair = org.pqchat.dht.crypto.Ed25519Engine.generateKeyPairFromSeed(dummySeed)
        val target = org.pqchat.dht.crypto.Ed25519Engine.computeTarget(dummyKeyPair.publicKey)
        val dummyPayload = CryptoUtils.secureRandomBytes(org.pqchat.dht.crypto.BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

        val signData = org.pqchat.dht.dht.bencode.Bencode.encodeBep44SignData(dummyPayload, DhtClient.DEFAULT_MUTABLE_SEQ, null)
        val sig = org.pqchat.dht.crypto.Ed25519Engine.sign(dummySeed, signData)
        val targetHex = CryptoUtils.toHex(target)

        val metrics = org.pqchat.dht.dht.leaf.DhtOpMetrics(
            nodesQueried = replicationK * 2,
            nodesResponded = replicationK,
            lookupHops = 1
        )
        _lastOperationMetrics.set(metrics)

        storage[targetHex] = StoredEntry(
            item = DhtLeafNode.MutableItem(
                v = dummyPayload,
                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                k = dummyKeyPair.publicKey,
                sig = sig,
                salt = null,
                token = null,
                responder = InetSocketAddress("127.0.0.1", 6881),
                nodesQueried = metrics.nodesQueried,
                nodesResponded = metrics.nodesResponded,
                lookupHops = metrics.lookupHops
            ),
            storedAt = System.currentTimeMillis(),
            ttlMs = defaultTtlMs
        )
        return target
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
        keepalivePingCalls.set(0)
    }

    fun setEntryWithCustomTtl(target: ByteArray, item: DhtLeafNode.MutableItem, ttlMs: Long) {
        val targetHex = CryptoUtils.toHex(target)
        storage[targetHex] = StoredEntry(
            item = item,
            storedAt = System.currentTimeMillis(),
            ttlMs = ttlMs
        )
    }

    /**
     * Evicts records that have not been refreshed/republished within olderThanMs.
     * Simulates Kademlia BEP 44 node eviction (typically ~2h on unrefreshed records).
     */
    fun evictUnrefreshedRecords(olderThanMs: Long, currentTimeMs: Long = System.currentTimeMillis()): Int {
        var evicted = 0
        val it = storage.entries.iterator()
        while (it.hasNext()) {
            val entry = it.next()
            if ((currentTimeMs - entry.value.storedAt) >= olderThanMs) {
                it.remove()
                evicted++
            }
        }
        return evicted
    }

    /**
     * Simulates random node churn by evicting a fraction of stored records.
     */
    fun simulateChurn(fraction: Double = 0.3): Int {
        var evicted = 0
        val it = storage.entries.iterator()
        while (it.hasNext()) {
            it.next()
            if (Math.random() < fraction) {
                it.remove()
                evicted++
            }
        }
        return evicted
    }

    fun getStoredCount(): Int = storage.size
}

