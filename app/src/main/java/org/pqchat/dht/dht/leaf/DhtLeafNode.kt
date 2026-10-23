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
import org.pqchat.dht.network.tor.Socks5Client
import org.pqchat.dht.network.tor.Socks5CommandNotSupportedException
import org.pqchat.dht.network.tor.TorTcpTunnelClient

typealias PeerContact = DhtLeafNode.DhtPeer

/**
 * Client-Only / Read-Only BitTorrent Mainline DHT Node (BEP 43 / BEP 44).
 *
 * Characteristics:
 * - Does NOT route external traffic.
 * - Does NOT hoard third-party data in RAM.
 * - Stores & retrieves 1000-byte encrypted messages via BEP 44 mutable items.
 */
open class DhtLeafNode(
    override val myNodeId: ByteArray = CryptoUtils.secureRandomBytes(20),
    private val port: Int = 0, // 0 means ephemeral port
    private val nodeCacheDao: org.pqchat.dht.data.db.DhtNodeCacheDao? = null,
    val autoBootstrap: Boolean = true
) : DhtClient {
    companion object {
        const val TAG = "PQChat"
        const val DEFAULT_DHT_PORT = 49160
        const val MAX_CACHED_NODES = 40
        const val DEFAULT_K = 8 // Default replication / closest nodes factor
        const val CGNAT_LTE_K = 16 // Adaptive replication factor under LTE / Restrictive NAT / CGNAT
        const val K = DEFAULT_K
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

        /**
         * Extracts the IPv4 /24 (or IPv6 /48) subnet prefix for an address.
         */
        fun getSubnet24Prefix(address: InetSocketAddress): String {
            val inet = address.address
            if (inet != null) {
                val raw = inet.address
                if (raw.size == 4) {
                    return "${raw[0].toInt() and 0xFF}.${raw[1].toInt() and 0xFF}.${raw[2].toInt() and 0xFF}.0/24"
                } else if (raw.size == 16) {
                    return "${raw[0].toInt() and 0xFF}:${raw[1].toInt() and 0xFF}:${raw[2].toInt() and 0xFF}/48"
                }
            }
            val host = address.hostString
            val parts = host.split(".")
            return if (parts.size == 4) {
                "${parts[0]}.${parts[1]}.${parts[2]}.0/24"
            } else {
                host
            }
        }

        /**
         * Checks if an address is loopback or local testing network.
         */
        fun isLoopbackOrLocal(address: InetSocketAddress): Boolean {
            val inet = address.address
            if (inet != null) {
                return inet.isLoopbackAddress || inet.isSiteLocalAddress
            }
            val host = address.hostString
            return host == "127.0.0.1" || host == "localhost" || host.startsWith("192.168.") || host.startsWith("10.")
        }

        /**
         * Diversifies candidate peers by /24 IP subnet bucketing.
         * Enforces a ceiling of [maxPerSubnet] nodes per /24 subnet to prevent Sybil/Eclipse attackers
         * from monopolizing the routing table or replication set.
         */
        fun diversifyCandidatesBySubnet(
            candidates: List<DhtPeer>,
            count: Int,
            maxPerSubnet: Int = 2
        ): List<DhtPeer> {
            if (candidates.size <= count && candidates.all { isLoopbackOrLocal(it.address) }) {
                return candidates
            }
            val selected = mutableListOf<DhtPeer>()
            val subnetCounts = mutableMapOf<String, Int>()
            val remaining = mutableListOf<DhtPeer>()

            for (peer in candidates) {
                val subnet = getSubnet24Prefix(peer.address)
                val current = subnetCounts.getOrDefault(subnet, 0)
                if (current < maxPerSubnet && selected.size < count) {
                    selected.add(peer)
                    subnetCounts[subnet] = current + 1
                } else {
                    remaining.add(peer)
                }
            }

            for (peer in remaining) {
                if (selected.size >= count) break
                selected.add(peer)
            }

            return selected
        }

        fun xorDistance(a: ByteArray, b: ByteArray): ByteArray {
            val result = ByteArray(20)
            for (i in 0 until 20) {
                result[i] = (a[i].toInt() xor b[i].toInt()).toByte()
            }
            return result
        }

        fun compareBytes(a: ByteArray, b: ByteArray): Int {
            for (i in a.indices) {
                val diff = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
                if (diff != 0) return diff
            }
            return 0
        }
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
        override fun containsKey(key: ByteArray): Boolean =
            synchronized(lock) { storage.containsKey(CryptoUtils.toHex(key)) }

        override fun containsValue(value: List<PeerContact>): Boolean =
            synchronized(lock) { storage.values.any { it.second == value } }

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
            return address == other.address || (nodeId.size == 20 && other.nodeId.size == 20 && nodeId.contentEquals(
                other.nodeId
            ))
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
        val responder: InetSocketAddress? = null,
        val nodesQueried: Int = 0,
        val nodesResponded: Int = 0,
        val lookupHops: Int = 0
    )

    @Volatile
    var localPort: Int = port
        private set

    @Volatile
    private var socket: DatagramSocket? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val pendingTransactions = ConcurrentHashMap<String, CompletableDeferred<KrpcMessage.Response>>()
    private val routingTable = CopyOnWriteArrayList<DhtPeer>()
    private fun logInfo(tag: String, msg: String) {
        println("[$tag] $msg")
        try {
            android.util.Log.i(tag, msg)
        } catch (_: Throwable) {
            // Ignored in non-Android unit test environments
        }
    }

    private val fastestNodesCache = CopyOnWriteArrayList<DhtPeer>()
    private val _totalGetCalls = java.util.concurrent.atomic.AtomicLong(0L)
    override val totalGetCalls: Long get() = _totalGetCalls.get()

    private val _totalPutCalls = java.util.concurrent.atomic.AtomicLong(0L)
    override val totalPutCalls: Long get() = _totalPutCalls.get()

    private val _totalBytesSent = java.util.concurrent.atomic.AtomicLong(0L)
    override val totalBytesSent: Long get() = _totalBytesSent.get()

    private val _totalBytesReceived = java.util.concurrent.atomic.AtomicLong(0L)
    override val totalBytesReceived: Long get() = _totalBytesReceived.get()

    private val _lastOperationMetrics = java.util.concurrent.atomic.AtomicReference(DhtOpMetrics())
    override val lastOperationMetrics: DhtOpMetrics get() = _lastOperationMetrics.get()

    val localMutableStore = ConcurrentHashMap<String, MutableItem>()
    val storage: ConcurrentHashMap<String, MutableItem> get() = localMutableStore
    val remoteStoredPeers = ConcurrentHashMap<String, CopyOnWriteArrayList<InetSocketAddress>>()
    val targetRouteCache = TargetRouteCache()

    @Volatile
    override var replicationK: Int = DEFAULT_K

    override fun setAdaptiveK(isMobileOrCgnat: Boolean) {
        replicationK = if (isMobileOrCgnat) CGNAT_LTE_K else DEFAULT_K
    }

    val bootstrapRouterIps = ConcurrentHashMap.newKeySet<String>()

    fun isBootstrapRouter(address: InetSocketAddress): Boolean {
        if (BOOTSTRAP_HOSTS.any { it.first.equals(address.hostString, ignoreCase = true) }) return true
        val ip = address.address?.hostAddress ?: return false
        return bootstrapRouterIps.contains(ip)
    }

    @Volatile
    private var torProxyConfig: TorProxyConfig? = null

    @Volatile
    private var torUdpAssociation: Socks5Client.Socks5UdpAssociation? = null

    @Volatile
    private var torTcpTunnelClient: TorTcpTunnelClient? = null

    @Volatile
    final override var torTransportMode: TorTransportMode = TorTransportMode.DIRECT_UDP
        private set

    @Volatile
    final override var torDiagnosticMessage: String? = null
        private set

    private var torListenerJob: Job? = null

    override val isTorRoutingActive: Boolean
        get() = torProxyConfig?.enabled == true &&
                ((torTransportMode == TorTransportMode.SOCKS5_UDP && torUdpAssociation?.isClosed == false) ||
                 torTransportMode == TorTransportMode.SOCKS5_TCP)

    @Synchronized
    override fun setTorProxy(config: TorProxyConfig?) {
        torProxyConfig = config
        torListenerJob?.cancel()
        torListenerJob = null
        try {
            torUdpAssociation?.close()
        } catch (_: Exception) {
        }
        torUdpAssociation = null
        torTcpTunnelClient = null

        if (config?.enabled == true) {
            val wasBlocked = torTransportMode == TorTransportMode.BLOCKED_ERROR
            if (config.socksPort <= 0) {
                torTransportMode = TorTransportMode.BLOCKED_ERROR
                torDiagnosticMessage = "Tor is enabled in settings, waiting for SOCKS5 tunnel establishment (port ${config.socksPort}). Fail-Closed active."
                println("[PQChat] DhtLeafNode: $torDiagnosticMessage")
                return
            }
            val client = Socks5Client(
                proxyHost = config.socksHost,
                proxyPort = config.socksPort,
                connectTimeoutMs = config.timeoutMs,
                readTimeoutMs = config.timeoutMs
            )
            try {
                val assoc = client.createUdpAssociation()
                torUdpAssociation = assoc
                torTransportMode = TorTransportMode.SOCKS5_UDP
                startTorRelayListener(assoc)
                torDiagnosticMessage = "Tor SOCKS5 UDP ASSOCIATE aktywny (${config.socksHost}:${config.socksPort})"
                println("[PQChat] DhtLeafNode: $torDiagnosticMessage")
            } catch (e: Socks5CommandNotSupportedException) {
                // Standard Tor daemon: UDP ASSOCIATE is rejected (CMD 0x03 not supported)
                // Switch to length-prefixed KRPC over streaming TCP SOCKS5 sockets!
                torUdpAssociation = null
                torTcpTunnelClient = TorTcpTunnelClient(client)
                torTransportMode = TorTransportMode.SOCKS5_TCP
                torDiagnosticMessage = "Standard Tor daemon: UDP ASSOCIATE not supported (code 0x%02X). Active TCP SOCKS5 tunnel (length-prefixed KRPC).".format(e.replyCode)
                println("[PQChat] DhtLeafNode: $torDiagnosticMessage")
            } catch (e: Exception) {
                torUdpAssociation = null
                torTransportMode = TorTransportMode.BLOCKED_ERROR
                torDiagnosticMessage = "Error connecting to Tor SOCKS5 proxy (${config.socksHost}:${config.socksPort}): ${e.message}. Fail-Closed active."
                println("[PQChat] DhtLeafNode: $torDiagnosticMessage")
            }

            if (wasBlocked && isTorRoutingActive && autoBootstrap && isRunning) {
                scope.launch {
                    bootstrap()
                }
            }
        } else {
            torTransportMode = TorTransportMode.DIRECT_UDP
            torDiagnosticMessage = null
            println("[PQChat] DhtLeafNode: Tor routing disabled, returned to direct UDP transport")
        }
    }

    private fun startTorRelayListener(assoc: org.pqchat.dht.network.tor.Socks5Client.Socks5UdpAssociation) {
        torListenerJob = scope.launch(Dispatchers.IO) {
            val buffer = ByteArray(4096)
            while (isRunning && !assoc.isClosed && isTorRoutingActive) {
                try {
                    val packet = assoc.receive(buffer) ?: continue
                    _totalBytesReceived.addAndGet(packet.data.size.toLong())
                    handleIncomingPacket(packet.data, packet.sender)
                } catch (e: Exception) {
                    if (!isRunning || assoc.isClosed) break
                }
            }
        }
    }

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
                DatagramSocket(0).apply { reuseAddress = true }
            }
        } catch (e: Exception) {
            println("[PQChat] initSocket bind error for port $localPort: $e, falling back to random free system port")
            DatagramSocket(0).apply { reuseAddress = true }
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

        if (autoBootstrap) {
            scope.launch {
                bootstrap()
            }
        }
    }

    override fun stop() {
        isRunning = false
        torListenerJob?.cancel()
        torListenerJob = null
        try {
            torUdpAssociation?.close()
        } catch (_: Exception) {
        }
        torUdpAssociation = null
        torTcpTunnelClient = null
        try {
            socket?.close()
        } catch (_: Exception) {
        }
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
                val ip = try {
                    InetAddress.getByName(entity.ip)
                } catch (_: Exception) {
                    null
                } ?: continue
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
        } catch (_: Exception) {
        }
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
                } catch (_: Exception) {
                }
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
                _totalBytesReceived.addAndGet(packet.length.toLong())
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
                            sendKrpcResponse(bencoded, sender)
                        }

                        "find_node" -> {
                            val target = msg.arguments["target"] as? ByteArray
                            val closest = if (target != null && target.size == 20) {
                                findClosestNodes(target, count = 8)
                            } else {
                                routingTable.take(8)
                            }
                            val compactNodes = serializeCompactNodes(closest)
                            val resp = KrpcMessage.Response(
                                msg.transactionId,
                                mapOf("id" to myNodeId, "nodes" to compactNodes)
                            )
                            val bencoded = resp.toBencoded()
                            sendKrpcResponse(bencoded, sender)
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
                                sendKrpcResponse(bencoded, sender)
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
                                    val target =
                                        if (salt != null && salt.isNotEmpty()) CryptoUtils.sha1(k + salt) else CryptoUtils.sha1(
                                            k
                                        )
                                    val targetHex = CryptoUtils.toHex(target)
                                    val existing = localMutableStore[targetHex]
                                    if (existing == null || seq > existing.seq) {
                                        localMutableStore[targetHex] = MutableItem(v, seq, k, sig, salt, null, sender)
                                    }
                                    val resp = KrpcMessage.Response(msg.transactionId, mapOf("id" to myNodeId))
                                    val bencoded = resp.toBencoded()
                                    sendKrpcResponse(bencoded, sender)
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

    private fun sendKrpcResponse(bencoded: ByteArray, recipient: InetSocketAddress) {
        if (torProxyConfig?.enabled == true) {
            if (torTransportMode == TorTransportMode.SOCKS5_UDP) {
                torUdpAssociation?.send(bencoded, recipient)
                _totalBytesSent.addAndGet(bencoded.size.toLong())
            }
            // In SOCKS5_TCP or BLOCKED_ERROR, never leak responses over direct clearnet socket.
        } else {
            socket?.send(DatagramPacket(bencoded, bencoded.size, recipient))
            _totalBytesSent.addAndGet(bencoded.size.toLong())
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

    fun serializeCompactNodes(nodes: List<DhtPeer>): ByteArray {
        val baos = java.io.ByteArrayOutputStream(nodes.size * 26)
        for (node in nodes) {
            val ip = node.address.address ?: continue
            if (ip !is java.net.Inet4Address) continue
            val id = if (node.nodeId.size == 20) node.nodeId else node.nodeId.copyOf(20)
            baos.write(id)
            baos.write(ip.address)
            val port = node.address.port
            baos.write((port ushr 8) and 0xFF)
            baos.write(port and 0xFF)
        }
        return baos.toByteArray()
    }

    fun getLocalPeers(): List<DhtPeer> {
        val localEndpoints = listOf(
            Pair("10.0.2.2", DEFAULT_DHT_PORT),
            Pair("10.0.2.2", 49161),
            Pair("10.0.2.2", 49162),
            Pair("127.0.0.1", DEFAULT_DHT_PORT),
            Pair("127.0.0.1", 49161),
            Pair("127.0.0.1", 49162),
            Pair("10.0.2.15", DEFAULT_DHT_PORT),
            Pair("10.0.2.16", DEFAULT_DHT_PORT),
            Pair("10.0.2.17", DEFAULT_DHT_PORT)
        )
        return localEndpoints.mapNotNull { (ipStr, p) ->
            try {
                DhtPeer(ByteArray(20), InetSocketAddress(InetAddress.getByName(ipStr), p))
            } catch (_: Exception) {
                null
            }
        }
    }

    suspend fun resolveBootstrapNodes(): List<InetSocketAddress> = withContext(Dispatchers.IO) {
        val list = mutableListOf<InetSocketAddress>()
        if (torProxyConfig?.enabled != true) {
            for (peer in getLocalPeers()) {
                list.add(peer.address)
            }
        }
        for ((host, port) in BOOTSTRAP_HOSTS) {
            if (torProxyConfig?.enabled == true) {
                // Prevent DNS leaks: pass unresolved domain to be resolved by Tor exit node
                list.add(InetSocketAddress.createUnresolved(host, port))
            } else {
                try {
                    val ips = InetAddress.getAllByName(host)
                    for (ip in ips) {
                        val addr = InetSocketAddress(ip, port)
                        list.add(addr)
                        ip.hostAddress?.let { bootstrapRouterIps.add(it) }
                    }
                } catch (_: Exception) {
                }
            }
        }
        list
    }

    suspend fun bootstrap() = withContext(Dispatchers.IO) {
        val cached = getCachedFastestNodes()
        val randomTarget = CryptoUtils.secureRandomBytes(20)

        // Probe local LAN / emulator subnet neighbors in parallel
        val localNodes = if (torProxyConfig?.enabled == true) emptyList() else getLocalPeers().map { it.address }
        val localJobs = localNodes.map { node ->
            launch {
                try {
                    val query = KrpcMessage.createFindNodeQuery(myNodeId, randomTarget)
                    sendQuery(node, query, 1000L)
                } catch (_: Exception) {
                }
            }
        }

        val cachedJobs = if (cached.isNotEmpty()) {
            println("[PQChat] Bootstrapping from ${cached.size} cached DHT nodes...")
            cached.take(16).map { peer ->
                launch {
                    try {
                        val query = KrpcMessage.createFindNodeQuery(myNodeId, randomTarget)
                        sendQuery(peer.address, query, TIMEOUT_MS)
                    } catch (_: Exception) {
                    }
                }
            }
        } else emptyList()

        // Fallback or augment with public bootstrap servers
        val bootstrapNodes = resolveBootstrapNodes()
        val initialJobs = bootstrapNodes.map { bootstrapNode ->
            launch {
                try {
                    val query = KrpcMessage.createFindNodeQuery(myNodeId, randomTarget)
                    sendQuery(bootstrapNode, query, BOOTSTRAP_TIMEOUT_MS)
                } catch (_: Exception) {
                }
            }
        }

        // Wait for initial discover queries across local, cached, and public bootstrap nodes
        (localJobs + cachedJobs + initialJobs).joinAll()

        // Iteratively query first waves of discovered peers to populate routing table
        val queried = ConcurrentHashMap.newKeySet<InetSocketAddress>()
        queried.addAll(bootstrapNodes)
        queried.addAll(localNodes)

        var rounds = 0
        while (routingTable.size < 16 && rounds < 2) {
            rounds++
            val peersToQuery = routingTable.filter { it.address !in queried && !isBootstrapRouter(it.address) }.take(16)
            if (peersToQuery.isEmpty()) break
            peersToQuery.forEach { queried.add(it.address) }
            val waveJobs = peersToQuery.map { peer ->
                launch {
                    try {
                        val query = KrpcMessage.createFindNodeQuery(myNodeId, randomTarget)
                        sendQuery(peer.address, query, TIMEOUT_MS)
                    } catch (_: Exception) {
                    }
                }
            }
            waveJobs.joinAll()
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

        val startTime = System.currentTimeMillis()
        try {
            val bytes = query.toBencoded()

            // FAIL-CLOSED PROTECTION: If Tor is enabled in settings, NEVER emit to clearnet UDP!
            if (torProxyConfig?.enabled == true) {
                when (torTransportMode) {
                    TorTransportMode.SOCKS5_UDP -> {
                        val assoc = torUdpAssociation
                        if (assoc == null || assoc.isClosed) {
                            println("[PQChat] DhtLeafNode: Tor UDP association unavailable. Dropping packet to prevent clearnet leak (Fail-Closed).")
                            return@withContext null
                        }
                        assoc.send(bytes, targetAddress)
                        _totalBytesSent.addAndGet(bytes.size.toLong())
                    }
                    TorTransportMode.SOCKS5_TCP -> {
                        val tcpClient = torTcpTunnelClient
                        if (tcpClient == null) {
                            println("[PQChat] DhtLeafNode: Tor TCP tunnel client unavailable. Dropping packet to prevent clearnet leak (Fail-Closed).")
                            return@withContext null
                        }
                        return@withContext try {
                            val respBytes = tcpClient.sendQuery(targetAddress, bytes, timeoutMs)
                            _totalBytesSent.addAndGet(bytes.size.toLong())
                            _totalBytesReceived.addAndGet(respBytes.size.toLong())
                            val parsed = KrpcMessage.parse(respBytes) as? KrpcMessage.Response
                            if (parsed != null) {
                                val rtt = (System.currentTimeMillis() - startTime).coerceAtLeast(1L)
                                val responderId = parsed.responseData["id"] as? ByteArray
                                recordNodeSuccess(targetAddress, rtt, responderId)
                            }
                            parsed
                        } catch (e: Exception) {
                            null
                        }
                    }
                    else -> {
                        // TorTransportMode.BLOCKED_ERROR or any inactive state:
                        // FAIL-CLOSED! Strictly no raw UDP packet emission!
                        println("[PQChat] DhtLeafNode: Clearnet transmission blocked: Tor is enabled but routing mode is $torTransportMode (Fail-Closed).")
                        return@withContext null
                    }
                }
            } else {
                // Direct clearnet UDP socket (only when Tor is explicitly disabled in settings)
                val s = socket ?: return@withContext null
                if (s.isClosed) return@withContext null
                val packet = DatagramPacket(bytes, bytes.size, targetAddress)
                s.send(packet)
                _totalBytesSent.addAndGet(bytes.size.toLong())
            }

            val effectiveTimeout = if (isTorRoutingActive) maxOf(timeoutMs, 4000L) else timeoutMs
            val resp = withTimeoutOrNull(effectiveTimeout) {
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


    /**
     * Performs iterative Kademlia find_node lookup to discover the [k] closest swarm peers to [target].
     * Traverses the DHT across multiple hops, querying closest candidates in batches and updating
     * the candidate pool with returned compact node info until convergence or maximum hops reached.
     */
    internal suspend fun iterativeFindClosestNodes(target: ByteArray, k: Int = replicationK): List<DhtPeer> = withContext(Dispatchers.IO) {
        if (socket == null && torProxyConfig?.enabled != true) {
            return@withContext emptyList()
        }
        val targetHex = CryptoUtils.toHex(target)
        val localPeers = getLocalPeers()
        val cachedRoute = targetRouteCache[target] ?: emptyList()
        val routingPeers = findClosestNodes(target, count = maxOf(16, k * 2))
        val cachedFastest = getCachedFastestNodes()

        val swarmPeers = (cachedRoute + routingPeers + cachedFastest)
            .filter { !isBootstrapRouter(it.address) }
            .distinctBy { it.address }

        val initialPeers = if (swarmPeers.isNotEmpty()) {
            swarmPeers
        } else if (localPeers.isNotEmpty()) {
            localPeers
        } else if (autoBootstrap) {
            resolveBootstrapNodes().map { DhtPeer(CryptoUtils.secureRandomBytes(20), it) }
        } else {
            emptyList()
        }

        if (initialPeers.isEmpty() || torTransportMode == TorTransportMode.BLOCKED_ERROR) {
            return@withContext emptyList()
        }

        val isLiveNetwork = initialPeers.any { !isLoopbackOrLocal(it.address) }
        val maxHops = if (isLiveNetwork) 5 else 3

        val candidatePool = ConcurrentHashMap<InetSocketAddress, DhtPeer>()
        initialPeers.forEach { candidatePool[it.address] = it }

        val queriedAddresses = ConcurrentHashMap.newKeySet<InetSocketAddress>()
        val verifiedNodes = ConcurrentHashMap<InetSocketAddress, DhtPeer>()

        for (hop in 1..maxHops) {
            val unqueried = candidatePool.values
                .filter { it.address !in queriedAddresses && (candidatePool.size <= 3 || !isBootstrapRouter(it.address)) }
                .sortedWith { a, b ->
                    val distA = xorDistance(a.nodeId, target)
                    val distB = xorDistance(b.nodeId, target)
                    compareBytes(distA, distB)
                }

            if (unqueried.isEmpty()) break

            val batchCount = if (hop == 1) minOf(20, unqueried.size) else minOf(8, unqueried.size)
            val currentHopNodes = if (isLiveNetwork) {
                diversifyCandidatesBySubnet(unqueried, count = batchCount, maxPerSubnet = 2)
            } else {
                unqueried.take(batchCount)
            }

            if (currentHopNodes.isEmpty()) break

            currentHopNodes.forEach { queriedAddresses.add(it.address) }

            coroutineScope {
                currentHopNodes.map { peer ->
                    launch {
                        try {
                            val query = KrpcMessage.createFindNodeQuery(myNodeId, target)
                            val resp = sendQuery(peer.address, query, timeoutMs = 2500L)
                            if (resp != null) {
                                val respId = resp.responseData["id"] as? ByteArray
                                if (respId != null && respId.size == 20 && !isBootstrapRouter(peer.address)) {
                                    val verifiedPeer = DhtPeer(respId, peer.address)
                                    verifiedNodes[peer.address] = verifiedPeer
                                    addPeer(respId, peer.address)
                                }
                                val nodesBytes = resp.responseData["nodes"] as? ByteArray
                                if (nodesBytes != null) {
                                    val discovered = parseCompactNodesList(nodesBytes)
                                    discovered.forEach { node ->
                                        if (!isBootstrapRouter(node.address) && node.nodeId.any { b -> b != 0.toByte() }) {
                                            candidatePool.putIfAbsent(node.address, node)
                                        }
                                    }
                                }
                            }
                        } catch (_: Exception) {}
                    }
                }.joinAll()
            }

            if (verifiedNodes.size >= k) {
                val sortedVerified = verifiedNodes.values.sortedWith { a, b ->
                    compareBytes(xorDistance(a.nodeId, target), xorDistance(b.nodeId, target))
                }
                val topK = sortedVerified.take(k)
                val allTopKQueried = topK.all { it.address in queriedAddresses }
                val farthestTopKDist = xorDistance(topK.last().nodeId, target)
                val hasCloserUnqueried = candidatePool.values.any {
                    it.address !in queriedAddresses &&
                    it.nodeId.any { b -> b != 0.toByte() } &&
                    compareBytes(xorDistance(it.nodeId, target), farthestTopKDist) < 0
                }
                if (allTopKQueried && !hasCloserUnqueried) {
                    break
                }
            }
        }

        val poolToSelect = if (verifiedNodes.isNotEmpty()) {
            verifiedNodes.values.toList()
        } else {
            candidatePool.values.toList()
        }

        val filtered = poolToSelect
            .filter { (poolToSelect.size <= 2 || !isBootstrapRouter(it.address)) && it.nodeId.any { b -> b != 0.toByte() } }
            .distinctBy { it.address }
            .sortedWith { a, b ->
                val distA = xorDistance(a.nodeId, target)
                val distB = xorDistance(b.nodeId, target)
                compareBytes(distA, distB)
            }

        val closest = if (isLiveNetwork && filtered.size > k) {
            diversifyCandidatesBySubnet(filtered, count = k, maxPerSubnet = 2)
        } else {
            filtered.take(k)
        }

        if (closest.isNotEmpty()) {
            targetRouteCache.put(target, closest)
        }

        closest
    }

    /**
     * Target Pre-warming:
     * In the background or during idle, issues KRPC find_node(nextExpectedTarget)
     * to populate targetRouteCache with closest nodes to the target hash,
     * avoiding multi-hop Kademlia lookups when get(target) is called later.
     */
    override suspend fun preWarmTarget(target: ByteArray): List<PeerContact> = withContext(Dispatchers.IO) {
        val existing = targetRouteCache[target]
        if (!existing.isNullOrEmpty()) {
            return@withContext existing
        }
        val closest = iterativeFindClosestNodes(target, k = 8)
        logInfo(TAG, "[PQChat] Pre-warmed target ${CryptoUtils.toHex(target)} with ${closest.size} closest nodes in TargetRouteCache")
        closest
    }

    override fun preWarmTargetAsync(target: ByteArray): Job {
        return scope.launch {
            try {
                preWarmTarget(target)
            } catch (_: Exception) {
            }
        }
    }

    private fun parseAndVerifyGetResult(
        resp: KrpcMessage.Response,
        salt: ByteArray?,
        responderAddress: InetSocketAddress
    ): MutableItem? {
        val v = resp.responseData["v"] as? ByteArray ?: return null
        val k = resp.responseData["k"] as? ByteArray ?: return null
        val sig = resp.responseData["sig"] as? ByteArray ?: return null
        val seq = (resp.responseData["seq"] as? Long) ?: 0L
        val token = resp.responseData["token"] as? ByteArray

        // 1. Verify Ed25519 signature
        val dataToVerify = Bencode.encodeBep44SignData(v, seq, salt)
        if (!Ed25519Engine.verify(k, dataToVerify, sig)) {
            return null
        }

        // For standard BEP 44 as well as custom rendezvous targets (e.g. Handshake Target_0),
        // the authentic Ed25519 signature proves authorship, and the payload is further
        // authenticated via AEAD and KEM transcript binding.
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
        timeoutMs: Long,
        probeAllReplicas: Boolean
    ): MutableItem? = withContext(Dispatchers.IO) {
        _totalGetCalls.incrementAndGet()
        val targetHex = CryptoUtils.toHex(target)
        if (!skipLocalStore) {
            val localItem = localMutableStore[targetHex]
            if (localItem != null) {
                val metrics = DhtOpMetrics(nodesQueried = 0, nodesResponded = 1, lookupHops = 0)
                _lastOperationMetrics.set(metrics)
                return@withContext localItem.copy(nodesQueried = 0, nodesResponded = 1, lookupHops = 0)
            }
        }

        val wasPrewarmed = !targetRouteCache[target].isNullOrEmpty()
        val prewarmed = targetRouteCache[target] ?: preWarmTarget(target)
        val storedPeers = remoteStoredPeers[targetHex]?.mapNotNull { addr ->
            (prewarmed + routingTable).firstOrNull { it.address == addr } ?: DhtPeer(target, addr)
        } ?: emptyList()
        val closestCandidates = findClosestNodes(target, count = 24)
        val localPeers = getLocalPeers()
        val cachedFastest = getCachedFastestNodes()

        val remoteCandidates = if (wasPrewarmed && prewarmed.isNotEmpty()) {
            val prewarmedAddrs = prewarmed.map { it.address }.toSet()
            val remaining = (closestCandidates + cachedFastest)
                .filter { it.address !in prewarmedAddrs && !isBootstrapRouter(it.address) }
                .sortedWith { a, b ->
                    val distA = xorDistance(a.nodeId, target)
                    val distB = xorDistance(b.nodeId, target)
                    compareBytes(distA, distB)
                }
            prewarmed + remaining
        } else {
            (prewarmed + closestCandidates + cachedFastest)
                .distinctBy { it.address }
                .filter { !isBootstrapRouter(it.address) }
                .sortedWith { a, b ->
                    val distA = xorDistance(a.nodeId, target)
                    val distB = xorDistance(b.nodeId, target)
                    compareBytes(distA, distB)
                }
        }

        val allCandidates = (storedPeers + remoteCandidates).distinctBy { it.address }
        val candidatePool = ConcurrentHashMap<InetSocketAddress, DhtPeer>()
        allCandidates.forEach { candidatePool[it.address] = it }
        if (candidatePool.isEmpty()) {
            if (localPeers.isNotEmpty()) {
                localPeers.forEach { candidatePool[it.address] = it }
            } else if (autoBootstrap) {
                resolveBootstrapNodes().forEach {
                    candidatePool[it] = DhtPeer(CryptoUtils.secureRandomBytes(20), it)
                }
            }
        }

        if (candidatePool.isEmpty() || torTransportMode == TorTransportMode.BLOCKED_ERROR) {
            _lastOperationMetrics.set(DhtOpMetrics(nodesQueried = 0, nodesResponded = 0, lookupHops = 0))
            return@withContext null
        }

        val isLiveNetwork = candidatePool.values.any { !isLoopbackOrLocal(it.address) }
        val minHops = if (isLiveNetwork) 4 else 1
        val maxHops = if (isLiveNetwork) 5 else 2

        val queriedAddresses = ConcurrentHashMap.newKeySet<InetSocketAddress>()
        val emptyResponses = ConcurrentHashMap.newKeySet<InetSocketAddress>()
        val foundItem = java.util.concurrent.atomic.AtomicReference<MutableItem?>(null)
        val verifiedResponses = java.util.concurrent.atomic.AtomicInteger(0)
        val totalResponses = java.util.concurrent.atomic.AtomicInteger(0)
        val verifiedSubnets = ConcurrentHashMap.newKeySet<String>()
        var hopsExecuted = 0

        for (hop in 1..maxHops) {
            val unqueried = candidatePool.values
                .filter { it.address !in queriedAddresses && !isBootstrapRouter(it.address) }
                .sortedWith { a, b ->
                    val distA = xorDistance(a.nodeId, target)
                    val distB = xorDistance(b.nodeId, target)
                    compareBytes(distA, distB)
                }

            if (unqueried.isEmpty()) break

            val batchCount = if (hop == 1) 20 else 8
            val currentHopNodes = if (isLiveNetwork) {
                diversifyCandidatesBySubnet(unqueried, count = batchCount, maxPerSubnet = 2)
            } else {
                unqueried.take(batchCount)
            }

            if (currentHopNodes.isEmpty()) break

            currentHopNodes.forEach { queriedAddresses.add(it.address) }
            hopsExecuted = hop

            coroutineScope {
                var queryJobs: List<Job> = emptyList()
                queryJobs = currentHopNodes.map { peer ->
                    launch {
                        try {
                            val query = KrpcMessage.createBep44GetQuery(myNodeId, target)
                            val resp = sendQuery(peer.address, query, timeoutMs = timeoutMs) ?: return@launch
                            totalResponses.incrementAndGet()

                            val respId = resp.responseData["id"] as? ByteArray
                            if (respId != null && respId.size == 20 && !isBootstrapRouter(peer.address)) {
                                candidatePool[peer.address] = DhtPeer(respId, peer.address)
                                addPeer(respId, peer.address)
                            }

                            val verified = parseAndVerifyGetResult(resp, salt, peer.address)
                            if (verified != null) {
                                verifiedResponses.incrementAndGet()
                                verifiedSubnets.add(getSubnet24Prefix(peer.address))

                                while (true) {
                                    val current = foundItem.get()
                                    if (current == null || verified.seq > current.seq) {
                                        if (foundItem.compareAndSet(current, verified)) {
                                            break
                                        }
                                    } else {
                                        break
                                    }
                                }

                                if (!probeAllReplicas) {
                                    val currBest = foundItem.get()
                                    val currSeq = currBest?.seq ?: 0L
                                    val minQuorum = minOf(3, currentHopNodes.size)
                                    val canTerminate = wasPrewarmed ||
                                            (currSeq > DhtClient.DEFAULT_MUTABLE_SEQ && verifiedResponses.get() >= minOf(2, currentHopNodes.size)) ||
                                            (verifiedResponses.get() >= minQuorum && verifiedSubnets.size >= minOf(2, minQuorum)) ||
                                            (verifiedResponses.get() >= minOf(5, currentHopNodes.size))
                                    if (canTerminate) {
                                        queryJobs.forEach { job ->
                                            if (job != coroutineContext.job) job.cancel()
                                        }
                                        return@launch
                                    }
                                }
                            } else {
                                emptyResponses.add(peer.address)
                                val nodesBytes = resp.responseData["nodes"] as? ByteArray
                                if (nodesBytes != null) {
                                    val discovered = parseCompactNodesList(nodesBytes)
                                    discovered.forEach { node ->
                                        if (!isBootstrapRouter(node.address) && node.nodeId.any { it != 0.toByte() }) {
                                            candidatePool.putIfAbsent(node.address, node)
                                        }
                                    }
                                }

                                // In-batch Fast Termination check only if we've reached minHops
                                if (!probeAllReplicas && hop >= minHops) {
                                    val eligible = candidatePool.values.filter { !isBootstrapRouter(it.address) }
                                    val top3 = eligible.sortedWith { a, b ->
                                        val distA = xorDistance(a.nodeId, target)
                                        val distB = xorDistance(b.nodeId, target)
                                        compareBytes(distA, distB)
                                    }.take(3)
                                    val required = minOf(3, eligible.size)
                                    if (top3.size >= required && top3.take(required).all { it.address in emptyResponses }) {
                                        val storedAddrs = storedPeers.map { it.address }.toSet()
                                        if (storedAddrs.all { it in emptyResponses }) {
                                            queryJobs.forEach { job ->
                                                if (job != coroutineContext.job) job.cancel()
                                            }
                                        }
                                    }
                                }
                            }
                        } catch (_: Exception) {
                        }
                    }
                }
                queryJobs.joinAll()
            }

            // If we found a verified item and probeAllReplicas is false, finish search immediately
            if (foundItem.get() != null && !probeAllReplicas) {
                break
            }

            // Fast-Termination evaluation
            if (!probeAllReplicas && foundItem.get() == null) {
                val eligiblePeers = candidatePool.values.filter { !isBootstrapRouter(it.address) }
                val top3Overall = eligiblePeers.sortedWith { a, b ->
                    val distA = xorDistance(a.nodeId, target)
                    val distB = xorDistance(b.nodeId, target)
                    compareBytes(distA, distB)
                }.take(3)

                val top3Count = minOf(3, eligiblePeers.size)
                val allTop3Empty = top3Overall.size >= top3Count && top3Overall.take(top3Count).all { it.address in emptyResponses }

                val storedAddrs = storedPeers.map { it.address }.toSet()
                val storedPending = storedAddrs.any { it !in emptyResponses }

                val unqueriedPeers = candidatePool.values.filter { it.address !in queriedAddresses && !isBootstrapRouter(it.address) }

                // Find minimum XOR distance among all nodes queried so far
                var minQueriedDist: ByteArray? = null
                for (addr in queriedAddresses) {
                    val p = candidatePool[addr] ?: continue
                    if (p.nodeId.all { it == 0.toByte() }) continue
                    val d = xorDistance(p.nodeId, target)
                    if (minQueriedDist == null || compareBytes(d, minQueriedDist) < 0) {
                        minQueriedDist = d
                    }
                }

                val hasCloserUnqueried = minQueriedDist != null && unqueriedPeers.any {
                    it.nodeId.any { b -> b != 0.toByte() } && compareBytes(xorDistance(it.nodeId, target), minQueriedDist) < 0
                }

                val canFastTerminate = (hop >= minHops || !hasCloserUnqueried || unqueriedPeers.isEmpty())

                if (canFastTerminate && allTop3Empty && !storedPending) {
                    println("[PQChat] Fast Termination: $top3Count closest nodes from pool returned no 'v', no closer candidates in queue (hop=$hop, minHops=$minHops) for target=$targetHex")
                    break
                }
            }
        }

        val totalQueried = queriedAddresses.size
        val totalResponded = if (probeAllReplicas) {
            verifiedResponses.get()
        } else if (foundItem.get() != null) {
            maxOf(1, verifiedResponses.get())
        } else {
            totalResponses.get()
        }
        val hops = maxOf(1, hopsExecuted)

        val metrics = DhtOpMetrics(
            nodesQueried = totalQueried,
            nodesResponded = totalResponded,
            lookupHops = hops
        )
        _lastOperationMetrics.set(metrics)

        val bestItem = foundItem.get()
        val finalBestItem = bestItem?.copy(
            nodesQueried = totalQueried,
            nodesResponded = totalResponded,
            lookupHops = hops
        )

        if (finalBestItem != null) {
            if (!skipLocalStore) {
                localMutableStore[targetHex] = finalBestItem
            }
            finalBestItem.responder?.let { respAddr ->
                val respPeer = DhtPeer(finalBestItem.k.copyOf(20), respAddr)
                val existing = targetRouteCache[target] ?: emptyList()
                targetRouteCache.put(target, (listOf(respPeer) + existing).distinctBy { it.address }.take(8))
            }
        } else {
            targetRouteCache.remove(target)
        }

        val vFoundSize = finalBestItem?.v?.size ?: 0
        val sigValid = finalBestItem != null
        logInfo(TAG, "[PQChat] getMutable target=$targetHex, skipLocal=$skipLocalStore, candidates=$totalQueried, responded=$totalResponded, hops=$hops, found=${finalBestItem != null}, vFoundSize=$vFoundSize, sigValid=$sigValid")
        finalBestItem
    }

    private suspend fun queryTokensForTarget(
        peers: List<DhtPeer>,
        target: ByteArray,
        tokenMap: ConcurrentHashMap<InetSocketAddress, ByteArray>
    ) = coroutineScope {
        val targetTokens = minOf(replicationK, peers.size)
        var getJobs: List<Job> = emptyList()
        getJobs = peers.map { peer ->
            launch {
                try {
                    val getQuery = KrpcMessage.createBep44GetQuery(myNodeId, target)
                    val resp = sendQuery(peer.address, getQuery, timeoutMs = 2500L)
                    val token = resp?.responseData?.get("token") as? ByteArray
                    if (token != null) {
                        tokenMap[peer.address] = token
                        if (tokenMap.size >= targetTokens) {
                            getJobs.forEach { if (it != coroutineContext.job) it.cancel() }
                        }
                    }
                } catch (_: Exception) {}
            }
        }
        val startGet = System.currentTimeMillis()
        while (tokenMap.size < targetTokens && (System.currentTimeMillis() - startGet) < 3500L) {
            if (tokenMap.size >= minOf(4, targetTokens) && (System.currentTimeMillis() - startGet) > 1500L) {
                getJobs.forEach { it.cancel() }
                break
            }
            delay(25)
        }
        getJobs.forEach { it.cancel() }
    }

    /**
     * BEP 44 put query to store mutable item using pre-existing public key and Ed25519 signature.
     * Signs v using Ed25519 sk and stores in local store and propagates to remote DHT peers.
     */
    override suspend fun putMutablePreSigned(
        target: ByteArray,
        v: ByteArray,
        seq: Long,
        salt: ByteArray?,
        pk: ByteArray,
        sig: ByteArray,
        skipLocalStore: Boolean
    ): Boolean = withContext(Dispatchers.IO) {
        val tStart = System.currentTimeMillis()
        _totalPutCalls.incrementAndGet()
        require(v.size <= BinaryFrameCodec.MAX_DHT_VALUE_BYTES) {
            "BEP 44 payload cannot exceed ${BinaryFrameCodec.MAX_DHT_VALUE_BYTES} bytes (got ${v.size})"
        }
        val targetHex = CryptoUtils.toHex(target)

        // Store in our node's BEP 44 mutable store ONLY if skipLocalStore is false
        if (!skipLocalStore) {
            val localItem = MutableItem(v, seq, pk, sig, salt, null, null)
            val existing = localMutableStore[targetHex]
            if (existing == null || seq >= existing.seq) {
                localMutableStore[targetHex] = localItem
            }
        }

        if (torTransportMode == TorTransportMode.BLOCKED_ERROR) {
            logInfo(TAG, "[PQChat] putMutablePreSigned blocked: Tor Fail-Closed active")
            _lastOperationMetrics.set(DhtOpMetrics(nodesQueried = 0, nodesResponded = 0, lookupHops = 0))
            return@withContext false
        }

        var closestPeers = iterativeFindClosestNodes(target, k = replicationK)
        logInfo(TAG, "[PQChat] PUT iter find_node: target=$targetHex closest=${closestPeers.size}")

        // If storing locally and no remote peers are present, return immediately without DNS re-bootstrap
        if (closestPeers.isEmpty() && !skipLocalStore) {
            _lastOperationMetrics.set(DhtOpMetrics(nodesQueried = 0, nodesResponded = 0, lookupHops = 0))
            val rttMs = System.currentTimeMillis() - tStart
            logInfo(TAG, "[PQChat] PUT target=$targetHex stored locally (skipLocalStore=false, no remote peers) rtt=${rttMs}ms")
            return@withContext true
        }

        val tokenMap = ConcurrentHashMap<InetSocketAddress, ByteArray>()
        if (closestPeers.isNotEmpty()) {
            queryTokensForTarget(closestPeers, target, tokenMap)
        }

        if (tokenMap.isEmpty()) {
            logInfo(TAG, "[PQChat] PUT target=$targetHex tokenMap is empty (candidates=${closestPeers.size}). Clearing dead cache and forcing DNS re-bootstrap...")
            try {
                nodeCacheDao?.clearAll()
            } catch (_: Exception) {}
            fastestNodesCache.clear()
            routingTable.clear()
            targetRouteCache.remove(target)

            if (autoBootstrap) {
                val dnsRouters = listOf(
                    Pair("router.bittorrent.com", 6881),
                    Pair("dht.transmissionbt.com", 6881),
                    Pair("router.utorrent.com", 6881)
                )
                val bootstrapAddresses = mutableListOf<InetSocketAddress>()
                for ((host, port) in dnsRouters) {
                    if (torProxyConfig?.enabled == true) {
                        bootstrapAddresses.add(InetSocketAddress.createUnresolved(host, port))
                    } else {
                        try {
                            val ips = InetAddress.getAllByName(host)
                            for (ip in ips) {
                                val addr = InetSocketAddress(ip, port)
                                bootstrapAddresses.add(addr)
                                ip.hostAddress?.let { bootstrapRouterIps.add(it) }
                            }
                        } catch (_: Exception) {}
                    }
                }
                if (bootstrapAddresses.isNotEmpty()) {
                    coroutineScope {
                        bootstrapAddresses.map { addr ->
                            launch {
                                try {
                                    val q = KrpcMessage.createFindNodeQuery(myNodeId, target)
                                    sendQuery(addr, q, BOOTSTRAP_TIMEOUT_MS)
                                } catch (_: Exception) {}
                            }
                        }.joinAll()
                    }
                }

                closestPeers = iterativeFindClosestNodes(target, k = replicationK)
                logInfo(TAG, "[PQChat] PUT retry iter find_node after DNS bootstrap: target=$targetHex closest=${closestPeers.size}")
                if (closestPeers.isNotEmpty()) {
                    queryTokensForTarget(closestPeers, target, tokenMap)
                }
            }
        }

        if (tokenMap.isEmpty()) {
            _lastOperationMetrics.set(DhtOpMetrics(nodesQueried = closestPeers.size, nodesResponded = 0, lookupHops = 0))
            val rttMs = System.currentTimeMillis() - tStart
            logInfo(TAG, "[PQChat] PUT target=$targetHex success=${!skipLocalStore} rtt=${rttMs}ms candidates=${closestPeers.size} tokenOkCount=0 putOkCount=0 skipLocalStore=$skipLocalStore")
            return@withContext !skipLocalStore
        }

        val tokenOkCount = tokenMap.size
        val successfulPuts = java.util.concurrent.atomic.AtomicInteger(0)
        val targetPuts = minOf(replicationK, tokenMap.size)

        coroutineScope {
            var putJobs: List<Job> = emptyList()
            putJobs = tokenMap.map { (address, token) ->
                launch {
                    try {
                        val putQuery = KrpcMessage.createBep44PutQuery(
                            myNodeId = myNodeId,
                            token = token,
                            v = v,
                            k = pk,
                            sig = sig,
                            seq = seq,
                            salt = salt,
                            readOnly = false
                        )
                        val resp = sendQuery(address, putQuery, timeoutMs = 2500L)
                        if (resp != null) {
                            remoteStoredPeers.computeIfAbsent(targetHex) { CopyOnWriteArrayList() }.add(address)
                            val successfulPeer = closestPeers.firstOrNull { it.address == address } ?: DhtPeer(target, address)
                            val currentCached = targetRouteCache[target] ?: emptyList()
                            targetRouteCache.put(target, (listOf(successfulPeer) + currentCached).distinctBy { it.address }.take(8))
                            val count = successfulPuts.incrementAndGet()
                            if (count >= targetPuts) {
                                putJobs.forEach { if (it != coroutineContext.job) it.cancel() }
                            }
                        }
                    } catch (_: Exception) {}
                }
            }
            val startPut = System.currentTimeMillis()
            while (successfulPuts.get() < targetPuts && (System.currentTimeMillis() - startPut) < 3500L) {
                if (successfulPuts.get() >= minOf(4, targetPuts) && (System.currentTimeMillis() - startPut) > 1500L) {
                    putJobs.forEach { it.cancel() }
                    break
                }
                delay(25)
            }
            putJobs.forEach { it.cancel() }
        }

        val putOkCount = successfulPuts.get()
        logInfo(TAG, "[PQChat] PUT stored on $putOkCount/${closestPeers.size} peers")

        val putSuccess = if (skipLocalStore) {
            putOkCount >= 1
        } else {
            putOkCount > 0 || true
        }

        val wasPrewarmed = !targetRouteCache[target].isNullOrEmpty()
        val hops = if (wasPrewarmed) 1 else 2
        val putMetrics = DhtOpMetrics(
            nodesQueried = closestPeers.size,
            nodesResponded = putOkCount,
            lookupHops = hops
        )
        _lastOperationMetrics.set(putMetrics)

        if (!putSuccess && skipLocalStore) {
            targetRouteCache.remove(target)
        }

        val rttMs = System.currentTimeMillis() - tStart
        logInfo(TAG, "[PQChat] PUT target=$targetHex success=$putSuccess rtt=${rttMs}ms candidates=${closestPeers.size} tokenOkCount=$tokenOkCount putOkCount=$putOkCount skipLocalStore=$skipLocalStore")

        putSuccess
    }

    /**
     * BEP 44 put query to store mutable item.
     * Signs v using Ed25519 sk and delegates to putMutablePreSigned.
     */
    override suspend fun putMutable(
        target: ByteArray,
        v: ByteArray,
        seq: Long,
        salt: ByteArray?,
        sk: ByteArray,
        skipLocalStore: Boolean
    ): Boolean {
        require(v.size <= BinaryFrameCodec.MAX_DHT_VALUE_BYTES) {
            "BEP 44 payload cannot exceed ${BinaryFrameCodec.MAX_DHT_VALUE_BYTES} bytes (got ${v.size})"
        }
        val signData = Bencode.encodeBep44SignData(v, seq, salt)
        val sig = Ed25519Engine.sign(sk, signData)
        val pk = Ed25519Engine.generateKeyPairFromSeed(sk).publicKey
        return putMutablePreSigned(target, v, seq, salt, pk, sig, skipLocalStore)
    }

    /**
     * Send dummy cover traffic (chaffing) to random target.
     */
    override suspend fun sendCoverTrafficDummy(): ByteArray? {
        if (torTransportMode == TorTransportMode.BLOCKED_ERROR) {
            return null
        }
        val dummySeed = CryptoUtils.secureRandomBytes(32)
        val dummyKeyPair = Ed25519Engine.generateKeyPairFromSeed(dummySeed)
        val target = Ed25519Engine.computeTarget(dummyKeyPair.publicKey)
        val dummyPayload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

        val ok = putMutable(
            target = target,
            v = dummyPayload,
            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
            salt = null,
            sk = dummySeed,
            skipLocalStore = true
        )
        return if (ok) target else null
    }

    /**
     * Sends a lightweight KRPC ping query to maintain carrier UDP NAT mapping table (20–25s timeout).
     */
    override suspend fun sendKeepalivePing(): Boolean = withContext(Dispatchers.IO) {
        val targetPeer = getCachedFastestNodes().firstOrNull()
            ?: routingTable.firstOrNull()
            ?: getLocalPeers().firstOrNull()
            ?: resolveBootstrapNodes().firstOrNull()?.let { DhtPeer(ByteArray(20), it) }
            ?: return@withContext false

        try {
            val pingQuery = KrpcMessage.createPingQuery(myNodeId)
            val resp = sendQuery(targetPeer.address, pingQuery, timeoutMs = 2000L)
            resp != null
        } catch (_: Exception) {
            false
        }
    }
}

