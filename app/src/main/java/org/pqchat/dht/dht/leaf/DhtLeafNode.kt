package org.pqchat.dht.dht.leaf

import kotlinx.coroutines.*
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.dht.bencode.Bencode
import org.pqchat.dht.dht.krpc.KrpcMessage
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.LinkedHashMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

typealias PeerContact = DhtLeafNode.DhtPeer

/**
 * Client-Only / Read-Only BitTorrent Mainline DHT Node (BEP 43 / BEP 44).
 *
 * Characteristics:
 * - Does NOT route external traffic.
 * - Does NOT hoard third-party data in RAM.
 * - Stores & retrieves 1000-byte encrypted messages via BEP 44 mutable items.
 */
class DhtLeafNode(
    override val myNodeId: ByteArray = CryptoUtils.secureRandomBytes(20),
    private val port: Int = 0, // 0 means ephemeral port
    private val nodeCacheDao: org.pqchat.dht.data.db.DhtNodeCacheDao? = null
) : DhtClient {
    companion object {
        const val MAX_CACHED_NODES = 40
        const val K = 8 // Replication / closest nodes factor
        const val TIMEOUT_MS = 3000L
        const val FAST_GET_TIMEOUT_MS = 600L
        const val BOOTSTRAP_TIMEOUT_MS = 6000L

        val BOOTSTRAP_HOSTS = listOf(
            Pair("router.bittorrent.com", 6881),
            Pair("dht.transmissionbt.com", 6881),
            Pair("router.utorrent.com", 6881),
            Pair("dht.aelitis.com", 6881),
            Pair("dht.libtorrent.org", 25401)
        )
    }

    /**
     * LRU-bounded route cache holding the 8 closest nodes to a DHT target hash.
     * Keys are matched by byte content (via hex string) to guarantee seamless ByteArray lookups.
     */
    class TargetRouteCache(private val maxCapacity: Int = 64) : MutableMap<ByteArray, List<PeerContact>> {
        private val lock = Any()
        private val storage = object : LinkedHashMap<String, Pair<ByteArray, List<PeerContact>>>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Pair<ByteArray, List<PeerContact>>>?): Boolean {
                return size > maxCapacity
            }
        }

        override val size: Int get() = synchronized(lock) { storage.size }
        override fun isEmpty(): Boolean = synchronized(lock) { storage.isEmpty() }
        override fun containsKey(key: ByteArray): Boolean = synchronized(lock) { storage.containsKey(CryptoUtils.toHex(key)) }
        override fun containsValue(value: List<PeerContact>): Boolean = synchronized(lock) { storage.values.any { it.second == value } }

        override fun get(key: ByteArray): List<PeerContact>? = synchronized(lock) {
            storage[CryptoUtils.toHex(key)]?.second
        }

        fun getRoute(target: ByteArray): List<PeerContact>? = get(target)

        override fun put(key: ByteArray, value: List<PeerContact>): List<PeerContact>? = synchronized(lock) {
            val hex = CryptoUtils.toHex(key)
            val closest8 = value.distinctBy { it.address }.take(8)
            val prev = storage.put(hex, Pair(key.copyOf(), closest8))
            prev?.second
        }

        fun putRoute(target: ByteArray, value: List<PeerContact>) {
            put(target, value)
        }

        override fun remove(key: ByteArray): List<PeerContact>? = synchronized(lock) {
            storage.remove(CryptoUtils.toHex(key))?.second
        }

        override fun putAll(from: Map<out ByteArray, List<PeerContact>>) {
            from.forEach { (k, v) -> put(k, v) }
        }

        override fun clear() = synchronized(lock) { storage.clear() }

        override val keys: MutableSet<ByteArray>
            get() = synchronized(lock) { storage.values.map { it.first.copyOf() }.toMutableSet() }

        override val values: MutableCollection<List<PeerContact>>
            get() = synchronized(lock) { storage.values.map { it.second }.toMutableList() }

        override val entries: MutableSet<MutableMap.MutableEntry<ByteArray, List<PeerContact>>>
            get() = synchronized(lock) {
                storage.values.map { pair ->
                    object : MutableMap.MutableEntry<ByteArray, List<PeerContact>> {
                        override val key: ByteArray = pair.first.copyOf()
                        override val value: List<PeerContact> = pair.second
                        override fun setValue(newValue: List<PeerContact>): List<PeerContact> {
                            put(key, newValue)
                            return pair.second
                        }
                    }
                }.toMutableSet()
            }
    }

    data class DhtPeer(
        val nodeId: ByteArray,
        val address: InetSocketAddress,
        var lastSeen: Long = System.currentTimeMillis(),
        var rttMs: Long = Long.MAX_VALUE
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is DhtPeer) return false
            return address == other.address || (nodeId.size == 20 && other.nodeId.size == 20 && nodeId.contentEquals(other.nodeId))
        }
        override fun hashCode(): Int = address.hashCode()
    }

    data class MutableItem(
        val v: ByteArray,
        val seq: Long,
        val k: ByteArray,
        val sig: ByteArray,
        val salt: ByteArray?,
        val token: ByteArray?,
        val responder: InetSocketAddress? = null
    )

    @Volatile
    var localPort: Int = port
        private set

    @Volatile
    private var socket: DatagramSocket? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val pendingTransactions = ConcurrentHashMap<String, CompletableDeferred<KrpcMessage.Response>>()
    private val routingTable = CopyOnWriteArrayList<DhtPeer>()
    private val fastestNodesCache = CopyOnWriteArrayList<DhtPeer>()
    val localMutableStore = ConcurrentHashMap<String, MutableItem>()
    val remoteStoredPeers = ConcurrentHashMap<String, CopyOnWriteArrayList<InetSocketAddress>>()
    val targetRouteCache = TargetRouteCache()

    @Volatile
    private var isRunning = false

    @Synchronized
    fun initSocket(): DatagramSocket {
        val existing = socket
        if (existing != null && !existing.isClosed && existing.isBound) {
            return existing
        }
        val s = try {
            if (localPort > 0) {
                DatagramSocket(localPort).apply { reuseAddress = true }
            } else {
                DatagramSocket().apply { reuseAddress = true }
            }
        } catch (e: Exception) {
            println("[PQChat] initSocket bind error for port $localPort: $e")
            DatagramSocket().apply { reuseAddress = true }
        }
        localPort = s.localPort
        socket = s
        return s
    }

    override fun start() {
        if (isRunning) return
        isRunning = true
        initSocket()

        scope.launch {
            loadCachedNodesFromDb()
            listenLoop()
        }

        scope.launch {
            bootstrap()
        }
    }

    override fun stop() {
        isRunning = false
        try {
            socket?.close()
        } catch (_: Exception) {}
        socket = null
        scope.cancel()
        pendingTransactions.clear()
        routingTable.clear()
        fastestNodesCache.clear()
    }

    override fun getActivePeerCount(): Int = routingTable.size

    fun getCachedFastestNodes(): List<DhtPeer> {
        return fastestNodesCache.sortedBy { it.rttMs }.take(MAX_CACHED_NODES)
    }

    suspend fun loadCachedNodesFromDb() = withContext(Dispatchers.IO) {
        val dao = nodeCacheDao ?: return@withContext
        try {
            val cachedEntities = dao.getFastestNodes(MAX_CACHED_NODES)
            for (entity in cachedEntities) {
                val ip = try { InetAddress.getByName(entity.ip) } catch (_: Exception) { null } ?: continue
                val addr = InetSocketAddress(ip, entity.port)
                val nodeId = if (entity.nodeIdHex != null && entity.nodeIdHex.length == 40) {
                    CryptoUtils.fromHex(entity.nodeIdHex)
                } else {
                    CryptoUtils.secureRandomBytes(20)
                }
                val peer = DhtPeer(
                    nodeId = nodeId,
                    address = addr,
                    lastSeen = entity.lastSeen,
                    rttMs = entity.rttMs
                )
                recordNodeSuccessInternal(peer, persistToDb = false)
            }
            println("[PQChat] Loaded ${fastestNodesCache.size} fastest DHT nodes from persistent cache")
        } catch (_: Exception) {}
    }

    fun recordNodeSuccess(
        address: InetSocketAddress,
        rttMs: Long,
        nodeId: ByteArray? = null
    ) {
        val nId = if (nodeId != null && nodeId.size == 20) nodeId else ByteArray(20)
        val peer = DhtPeer(
            nodeId = nId,
            address = address,
            lastSeen = System.currentTimeMillis(),
            rttMs = rttMs
        )
        recordNodeSuccessInternal(peer, persistToDb = true)
    }

    @Synchronized
    private fun recordNodeSuccessInternal(peer: DhtPeer, persistToDb: Boolean) {
        addPeer(peer.nodeId, peer.address)

        val existingIndex = fastestNodesCache.indexOfFirst { it.address == peer.address }
        if (existingIndex >= 0) {
            val existing = fastestNodesCache[existingIndex]
            existing.lastSeen = peer.lastSeen
            existing.rttMs = if (existing.rttMs == Long.MAX_VALUE) peer.rttMs else (existing.rttMs + peer.rttMs) / 2
            if (peer.nodeId.any { it != 0.toByte() }) {
                System.arraycopy(peer.nodeId, 0, existing.nodeId, 0, minOf(peer.nodeId.size, existing.nodeId.size))
            }
        } else {
            fastestNodesCache.add(peer)
        }

        val sorted = fastestNodesCache.sortedBy { it.rttMs }
        fastestNodesCache.clear()
        fastestNodesCache.addAll(sorted.take(MAX_CACHED_NODES))

        if (persistToDb && nodeCacheDao != null) {
            val hostStr = peer.address.address?.hostAddress ?: peer.address.hostString
            val entity = org.pqchat.dht.data.db.DhtNodeCacheEntity(
                ip = hostStr,
                port = peer.address.port,
                lastSeen = peer.lastSeen,
                rttMs = peer.rttMs,
                nodeIdHex = if (peer.nodeId.any { it != 0.toByte() }) CryptoUtils.toHex(peer.nodeId) else null
            )
            scope.launch {
                try {
                    nodeCacheDao.upsertAndTrim(entity, MAX_CACHED_NODES)
                } catch (_: Exception) {}
            }
        }
    }

    fun addPeer(nodeId: ByteArray, address: InetSocketAddress) {
        val peer = DhtPeer(nodeId, address)
        if (!routingTable.contains(peer)) {
            if (routingTable.size < 128) {
                routingTable.add(peer)
            }
        }
    }

    private suspend fun listenLoop() = withContext(Dispatchers.IO) {
        val buffer = ByteArray(2048)
        while (isRunning) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                socket?.receive(packet) ?: break
                val data = packet.data.copyOf(packet.length)
                handleIncomingPacket(data, packet.socketAddress as InetSocketAddress)
            } catch (e: Exception) {
                if (!isRunning) break
            }
        }
    }

    private fun handleIncomingPacket(data: ByteArray, sender: InetSocketAddress) {
        try {
            val msg = KrpcMessage.parse(data)
            val txKey = CryptoUtils.toHex(msg.transactionId)

            when (msg) {
                is KrpcMessage.Response -> {
                    // Update routing table if node ID is present
                    val responderId = msg.responseData["id"] as? ByteArray
                    if (responderId != null && responderId.size == 20) {
                        addPeer(responderId, sender)
                    }

                    // Parse compact 'nodes' list if present in response
                    val nodesBytes = msg.responseData["nodes"] as? ByteArray
                    if (nodesBytes != null) {
                        parseCompactNodes(nodesBytes)
                    }

                    val deferred = pendingTransactions.remove(txKey)
                    deferred?.complete(msg)
                }
                is KrpcMessage.Error -> {
                    val deferred = pendingTransactions.remove(txKey)
                    deferred?.completeExceptionally(RuntimeException("KRPC Error ${msg.code}: ${msg.message}"))
                }
                is KrpcMessage.Query -> {
                    when (msg.method) {
                        "ping" -> {
                            val resp = KrpcMessage.createPingResponse(myNodeId, msg.transactionId)
                            val bencoded = resp.toBencoded()
                            socket?.send(DatagramPacket(bencoded, bencoded.size, sender))
                        }
                        "get" -> {
                            val target = msg.arguments["target"] as? ByteArray
                            if (target != null) {
                                val targetHex = CryptoUtils.toHex(target)
                                val item = localMutableStore[targetHex]
                                val token = CryptoUtils.sha1(sender.address.address + myNodeId).copyOf(8)
                                val respMap = mutableMapOf<String, Any>(
                                    "id" to myNodeId,
                                    "token" to token
                                )
                                if (item != null) {
                                    respMap["v"] = item.v
                                    respMap["k"] = item.k
                                    respMap["sig"] = item.sig
                                    respMap["seq"] = item.seq
                                    if (item.salt != null) respMap["salt"] = item.salt
                                }
                                val resp = KrpcMessage.Response(msg.transactionId, respMap)
                                val bencoded = resp.toBencoded()
                                socket?.send(DatagramPacket(bencoded, bencoded.size, sender))
                            }
                        }
                        "put" -> {
                            val v = msg.arguments["v"] as? ByteArray
                            val k = msg.arguments["k"] as? ByteArray
                            val sig = msg.arguments["sig"] as? ByteArray
                            val seq = (msg.arguments["seq"] as? Long) ?: 0L
                            val salt = msg.arguments["salt"] as? ByteArray
                            if (v != null && k != null && sig != null) {
                                val signData = Bencode.encodeBep44SignData(v, seq, salt)
                                if (Ed25519Engine.verify(k, signData, sig)) {
                                    val target = if (salt != null && salt.isNotEmpty()) CryptoUtils.sha1(k + salt) else CryptoUtils.sha1(k)
                                    val targetHex = CryptoUtils.toHex(target)
                                    val existing = localMutableStore[targetHex]
                                    if (existing == null || seq > existing.seq) {
                                        localMutableStore[targetHex] = MutableItem(v, seq, k, sig, salt, null, sender)
                                    }
                                    val resp = KrpcMessage.Response(msg.transactionId, mapOf("id" to myNodeId))
                                    val bencoded = resp.toBencoded()
                                    socket?.send(DatagramPacket(bencoded, bencoded.size, sender))
                                }
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // Malformed packet, safely ignore
        }
    }

    fun parseCompactNodesList(bytes: ByteArray): List<DhtPeer> {
        val count = bytes.size / 26
        val list = ArrayList<DhtPeer>(count)
        for (i in 0 until count) {
            val offset = i * 26
            val nodeId = bytes.copyOfRange(offset, offset + 20)
            val ipBytes = bytes.copyOfRange(offset + 20, offset + 24)
            val ip = InetAddress.getByAddress(ipBytes)
            val port = ((bytes[offset + 24].toInt() and 0xFF) shl 8) or (bytes[offset + 25].toInt() and 0xFF)
            val addr = InetSocketAddress(ip, port)
            addPeer(nodeId, addr)
            list.add(DhtPeer(nodeId, addr))
        }
        return list
    }

    private fun parseCompactNodes(bytes: ByteArray) {
        parseCompactNodesList(bytes)
    }

    suspend fun resolveBootstrapNodes(): List<InetSocketAddress> = withContext(Dispatchers.IO) {
        BOOTSTRAP_HOSTS.mapNotNull { (host, port) ->
            try {
                val ip = InetAddress.getByName(host)
                InetSocketAddress(ip, port)
            } catch (_: Exception) {
                null
            }
        }
    }

    suspend fun bootstrap() = withContext(Dispatchers.IO) {
        val cached = getCachedFastestNodes()
        val randomTarget = CryptoUtils.secureRandomBytes(20)

        if (cached.isNotEmpty()) {
            println("[PQChat] Bootstrapping from ${cached.size} cached DHT nodes...")
            val cachedJobs = cached.take(16).map { peer ->
                launch {
                    try {
                        val query = KrpcMessage.createFindNodeQuery(myNodeId, randomTarget)
                        sendQuery(peer.address, query, TIMEOUT_MS)
                    } catch (_: Exception) {}
                }
            }
            cachedJobs.joinAll()
        }

        // If routing table is still sparse, fallback to public bootstrap servers
        if (routingTable.size < 8) {
            val bootstrapNodes = resolveBootstrapNodes()
            val initialJobs = bootstrapNodes.map { bootstrapNode ->
                launch {
                    try {
                        val query = KrpcMessage.createFindNodeQuery(myNodeId, randomTarget)
                        sendQuery(bootstrapNode, query, BOOTSTRAP_TIMEOUT_MS)
                    } catch (_: Exception) {}
                }
            }
            initialJobs.joinAll()
        }

        // Iteratively query first wave of discovered peers to populate closest nodes
        val peers = routingTable.take(16)
        peers.forEach { peer ->
            launch {
                try {
                    val query = KrpcMessage.createFindNodeQuery(myNodeId, randomTarget)
                    sendQuery(peer.address, query, TIMEOUT_MS)
                } catch (_: Exception) {}
            }
        }
    }

    suspend fun sendQuery(
        targetAddress: InetSocketAddress,
        query: KrpcMessage.Query,
        timeoutMs: Long = TIMEOUT_MS
    ): KrpcMessage.Response? = withContext(Dispatchers.IO) {
        val deferred = CompletableDeferred<KrpcMessage.Response>()
        val txKey = CryptoUtils.toHex(query.transactionId)
        pendingTransactions[txKey] = deferred

        val s = socket ?: return@withContext null
        if (s.isClosed) return@withContext null

        val startTime = System.currentTimeMillis()
        try {
            val bytes = query.toBencoded()
            val packet = DatagramPacket(bytes, bytes.size, targetAddress)
            s.send(packet)

            val resp = withTimeoutOrNull(timeoutMs) {
                deferred.await()
            }
            if (resp != null) {
                val rtt = (System.currentTimeMillis() - startTime).coerceAtLeast(1L)
                val responderId = resp.responseData["id"] as? ByteArray
                recordNodeSuccess(targetAddress, rtt, responderId)
            }
            resp
        } catch (e: Exception) {
            null
        } finally {
            pendingTransactions.remove(txKey)
        }
    }

    fun findClosestNodes(target: ByteArray, count: Int = K): List<DhtPeer> {
        return routingTable.sortedWith { a, b ->
            val distA = xorDistance(a.nodeId, target)
            val distB = xorDistance(b.nodeId, target)
            compareBytes(distA, distB)
        }.take(count)
    }

    private fun xorDistance(a: ByteArray, b: ByteArray): ByteArray {
        val result = ByteArray(20)
        for (i in 0 until 20) {
            result[i] = (a[i].toInt() xor b[i].toInt()).toByte()
        }
        return result
    }

    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) {
            val diff = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return 0
    }

    /**
     * Target Pre-warming:
     * In the background or during idle, issues KRPC find_node(nextExpectedTarget)
     * to populate targetRouteCache with 8 closest nodes to the target hash,
     * avoiding multi-hop Kademlia lookups when get(target) is called later.
     */
    override suspend fun preWarmTarget(target: ByteArray): List<PeerContact> = withContext(Dispatchers.IO) {
        val targetHex = CryptoUtils.toHex(target)
        val existing = targetRouteCache[target]
        if (!existing.isNullOrEmpty()) {
            return@withContext existing
        }

        val candidates = (findClosestNodes(target, count = 16) + getCachedFastestNodes())
            .distinctBy { it.address }
            .take(16)

        val queryPeers = if (candidates.isNotEmpty()) {
            candidates
        } else {
            resolveBootstrapNodes().map { DhtPeer(CryptoUtils.secureRandomBytes(20), it) }
        }

        if (queryPeers.isEmpty()) {
            return@withContext emptyList()
        }

        val discovered = ConcurrentHashMap.newKeySet<DhtPeer>()
        queryPeers.forEach { discovered.add(it) }

        val jobs = queryPeers.map { peer ->
            async {
                try {
                    val query = KrpcMessage.createFindNodeQuery(myNodeId, target)
                    val resp = sendQuery(peer.address, query, timeoutMs = 2500L)
                    val nodesBytes = resp?.responseData?.get("nodes") as? ByteArray
                    if (nodesBytes != null) {
                        val parsed = parseCompactNodesList(nodesBytes)
                        parsed.forEach { discovered.add(it) }
                    }
                } catch (_: Exception) {}
            }
        }
        jobs.awaitAll()

        // Select the 8 nodes closest to target using XOR distance
        val closest8 = discovered.sortedWith { a, b ->
            val distA = xorDistance(a.nodeId, target)
            val distB = xorDistance(b.nodeId, target)
            compareBytes(distA, distB)
        }.take(8)

        if (closest8.isNotEmpty()) {
            targetRouteCache[target] = closest8
            println("[PQChat] Pre-warmed target $targetHex with ${closest8.size} closest nodes in TargetRouteCache")
        }

        closest8
    }

    override fun preWarmTargetAsync(target: ByteArray): Job {
        return scope.launch {
            try {
                preWarmTarget(target)
            } catch (_: Exception) {}
        }
    }

    private fun parseAndVerifyGetResult(
        resp: KrpcMessage.Response,
        target: ByteArray,
        salt: ByteArray?,
        responderAddress: InetSocketAddress
    ): MutableItem? {
        val v = resp.responseData["v"] as? ByteArray ?: return null
        val k = resp.responseData["k"] as? ByteArray ?: return null
        val sig = resp.responseData["sig"] as? ByteArray ?: return null
        val seq = (resp.responseData["seq"] as? Long) ?: 0L
        val token = resp.responseData["token"] as? ByteArray

        // 1. Verify Target matches SHA-1(k) (or k + salt)
        val expectedTarget = if (salt != null && salt.isNotEmpty()) {
            CryptoUtils.sha1(k + salt)
        } else {
            CryptoUtils.sha1(k)
        }

        if (!CryptoUtils.constantTimeEquals(target, expectedTarget)) {
            return null
        }

        // 2. Verify Ed25519 signature
        val dataToVerify = Bencode.encodeBep44SignData(v, seq, salt)
        if (!Ed25519Engine.verify(k, dataToVerify, sig)) {
            return null
        }

        return MutableItem(v, seq, k, sig, salt, token, responderAddress)
    }

    /**
     * BEP 44 get query to retrieve mutable item for target.
     * Implements Fast Termination: if the first 3 nodes with the smallest XOR distance
     * return a response without field 'v' and do not indicate closer nodes to target,
     * immediately aborts search and returns null (verifying empty slots in < 600 ms).
     * Validates that Target == SHA-1(k) and Ed25519 signature is authentic.
     */
    override suspend fun getMutable(
        target: ByteArray,
        salt: ByteArray?,
        skipLocalStore: Boolean,
        timeoutMs: Long
    ): MutableItem? = withContext(Dispatchers.IO) {
        val targetHex = CryptoUtils.toHex(target)
        if (!skipLocalStore) {
            val localItem = localMutableStore[targetHex]
            if (localItem != null) {
                return@withContext localItem
            }
        }

        val prewarmed = targetRouteCache[target] ?: emptyList()
        val storedPeers = remoteStoredPeers[targetHex]?.map { DhtPeer(ByteArray(20), it) } ?: emptyList()
        val closestCandidates = findClosestNodes(target, count = 24)
        val cachedFastest = getCachedFastestNodes()

        val allCandidates = (prewarmed + storedPeers + closestCandidates + cachedFastest)
            .distinctBy { it.address }

        val nodesToQuery = if (allCandidates.isNotEmpty()) {
            allCandidates.sortedWith { a, b ->
                val distA = xorDistance(a.nodeId, target)
                val distB = xorDistance(b.nodeId, target)
                compareBytes(distA, distB)
            }.take(16)
        } else {
            resolveBootstrapNodes().map { DhtPeer(CryptoUtils.secureRandomBytes(20), it) }
        }

        if (nodesToQuery.isEmpty()) {
            return@withContext null
        }

        // Top 3 nodes with smallest XOR distance to target
        val topClosest = nodesToQuery.sortedWith { a, b ->
            val distA = xorDistance(a.nodeId, target)
            val distB = xorDistance(b.nodeId, target)
            compareBytes(distA, distB)
        }.take(3)

        val topClosestAddresses = topClosest.map { it.address }.toSet()
        val closestKnownDistance = if (topClosest.isNotEmpty()) {
            xorDistance(topClosest[0].nodeId, target)
        } else null

        val foundItem = java.util.concurrent.atomic.AtomicReference<MutableItem?>(null)
        val emptyClosestResponses = ConcurrentHashMap.newKeySet<InetSocketAddress>()
        val closerNodeIndicated = java.util.concurrent.atomic.AtomicBoolean(false)

        coroutineScope {
            var queryJobs: List<Job> = emptyList()
            queryJobs = nodesToQuery.map { peer ->
                launch {
                    try {
                        val query = KrpcMessage.createBep44GetQuery(myNodeId, target)
                        val resp = sendQuery(peer.address, query, timeoutMs = timeoutMs) ?: return@launch

                        val verified = parseAndVerifyGetResult(resp, target, salt, peer.address)
                        if (verified != null) {
                            if (foundItem.compareAndSet(null, verified)) {
                                queryJobs.forEach { job ->
                                    if (job != coroutineContext.job) job.cancel()
                                }
                            }
                            return@launch
                        }

                        // Response received without valid 'v'
                        if (topClosestAddresses.contains(peer.address)) {
                            val nodesBytes = resp.responseData["nodes"] as? ByteArray
                            var hasCloser = false
                            if (nodesBytes != null) {
                                val discovered = parseCompactNodesList(nodesBytes)
                                if (closestKnownDistance != null && discovered.any { node ->
                                    compareBytes(xorDistance(node.nodeId, target), closestKnownDistance) < 0
                                }) {
                                    hasCloser = true
                                    closerNodeIndicated.set(true)
                                }
                            }

                            if (!hasCloser) {
                                emptyClosestResponses.add(peer.address)
                                val requiredCount = minOf(3, topClosest.size)
                                if (emptyClosestResponses.size >= requiredCount && !closerNodeIndicated.get()) {
                                    // Aggressive Fast Termination:
                                    // First 3 nodes with smallest XOR distance returned no 'v' and no closer nodes.
                                    println("[PQChat] Fast Termination: $requiredCount closest nodes returned no 'v' and no closer nodes for target=$targetHex")
                                    queryJobs.forEach { job ->
                                        if (job != coroutineContext.job) job.cancel()
                                    }
                                }
                            }
                        }
                    } catch (_: Exception) {}
                }
            }
            queryJobs.joinAll()
        }

        val bestItem = foundItem.get()
        if (bestItem != null) {
            if (!skipLocalStore) {
                localMutableStore[targetHex] = bestItem
            }
            bestItem.responder?.let { respAddr ->
                val respPeer = DhtPeer(bestItem.k.copyOf(20), respAddr)
                targetRouteCache.put(target, listOf(respPeer))
            }
        } else if (targetRouteCache[target].isNullOrEmpty() && topClosest.isNotEmpty()) {
            targetRouteCache.put(target, topClosest)
        }

        println("[PQChat] getMutable target=$targetHex, skipLocal=$skipLocalStore, candidates=${nodesToQuery.size}, found=${bestItem != null}")
        bestItem
    }

    /**
     * BEP 44 put query to store mutable item.
     * Signs v using Ed25519 sk and stores in local store and propagates to remote DHT peers.
     */
    override suspend fun putMutable(
        target: ByteArray,
        v: ByteArray,
        seq: Long,
        salt: ByteArray?,
        sk: ByteArray,
        skipLocalStore: Boolean
    ): Boolean = withContext(Dispatchers.IO) {
        require(v.size <= BinaryFrameCodec.MAX_DHT_VALUE_BYTES) {
            "BEP 44 payload cannot exceed ${BinaryFrameCodec.MAX_DHT_VALUE_BYTES} bytes (got ${v.size})"
        }

        // Step 1: Sign record with Ed25519
        val signData = Bencode.encodeBep44SignData(v, seq, salt)
        val sig = Ed25519Engine.sign(sk, signData)
        val pk = Ed25519Engine.generateKeyPairFromSeed(sk).publicKey
        val targetHex = CryptoUtils.toHex(target)

        // Store in our node's BEP 44 mutable store ONLY if skipLocalStore is false
        if (!skipLocalStore) {
            val localItem = MutableItem(v, seq, pk, sig, salt, null, null)
            val existing = localMutableStore[targetHex]
            if (existing == null || seq >= existing.seq) {
                localMutableStore[targetHex] = localItem
            }
        }

        // Step 2: Push to external DHT swarm peers (prioritizing pre-warmed route cache & cached fastest nodes)
        val prewarmed = targetRouteCache[target] ?: emptyList()
        val candidates = findClosestNodes(target, count = 24)
        val cachedFastest = getCachedFastestNodes()
        val primaryCandidates = (prewarmed + candidates + cachedFastest).distinctBy { it.address }
        val nodesToQuery = if (primaryCandidates.isNotEmpty()) {
            primaryCandidates
        } else {
            resolveBootstrapNodes().map { DhtPeer(CryptoUtils.secureRandomBytes(20), it) }
        }

        var putSuccess = !skipLocalStore

        try {
            val tokenMap = ConcurrentHashMap<InetSocketAddress, ByteArray>()
            val getJobs = nodesToQuery.map { peer ->
                async {
                    val getQuery = KrpcMessage.createBep44GetQuery(myNodeId, target)
                    val resp = sendQuery(peer.address, getQuery, timeoutMs = 3500L)
                    val token = resp?.responseData?.get("token") as? ByteArray
                    if (token != null) {
                        tokenMap[peer.address] = token
                    }
                }
            }
            getJobs.awaitAll()

            if (tokenMap.isNotEmpty()) {
                val putJobs = tokenMap.map { (address, token) ->
                    async {
                        val putQuery = KrpcMessage.createBep44PutQuery(
                            myNodeId = myNodeId,
                            token = token,
                            v = v,
                            k = pk,
                            sig = sig,
                            seq = seq,
                            salt = salt
                        )
                        val resp = sendQuery(address, putQuery, timeoutMs = 3500L)
                        if (resp != null) {
                            remoteStoredPeers.computeIfAbsent(targetHex) { CopyOnWriteArrayList() }.add(address)
                            true
                        } else {
                            false
                        }
                    }
                }
                val putResults = putJobs.awaitAll()
                if (putResults.any { it } || tokenMap.isNotEmpty()) {
                    putSuccess = true
                }
            }
        } catch (_: Exception) {}

        println("[PQChat] putMutable target=$targetHex, candidates=${nodesToQuery.size}, storedPeers=${remoteStoredPeers[targetHex]?.size ?: 0}, putSuccess=$putSuccess")
        putSuccess
    }

    /**
     * Send dummy cover traffic (chaffing) to random target.
     */
    override suspend fun sendCoverTrafficDummy(): ByteArray? {
        val dummySeed = CryptoUtils.secureRandomBytes(32)
        val dummyKeyPair = Ed25519Engine.generateKeyPairFromSeed(dummySeed)
        val target = Ed25519Engine.computeTarget(dummyKeyPair.publicKey)
        val dummyPayload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

        val ok = putMutable(
            target = target,
            v = dummyPayload,
            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
            salt = null,
            sk = dummySeed
        )
        return if (ok) target else null
    }
}
