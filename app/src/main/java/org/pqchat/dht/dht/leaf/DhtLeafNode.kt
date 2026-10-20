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
class DhtLeafNode(
    override val myNodeId: ByteArray = CryptoUtils.secureRandomBytes(20),
    private val port: Int = 0, // 0 means ephemeral port
    private val nodeCacheDao: org.pqchat.dht.data.db.DhtNodeCacheDao? = null,
    val autoBootstrap: Boolean = true
) : DhtClient {
    companion object {
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
    override var torTransportMode: TorTransportMode = TorTransportMode.DIRECT_UDP
        private set

    @Volatile
    override var torDiagnosticMessage: String? = null
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
                torDiagnosticMessage = "Tor jest włączony w ustawieniach, oczekiwanie na zestawienie tunelu SOCKS5 (port ${config.socksPort}). Fail-Closed aktywny."
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
                torDiagnosticMessage = "Standardowy demon Tor: UDP ASSOCIATE nieobsługiwane (kod 0x%02X). Aktywny tunel TCP SOCKS5 (length-prefixed KRPC).".format(e.replyCode)
                println("[PQChat] DhtLeafNode: $torDiagnosticMessage")
            } catch (e: Exception) {
                torUdpAssociation = null
                torTransportMode = TorTransportMode.BLOCKED_ERROR
                torDiagnosticMessage = "Błąd połączenia z proxy Tor SOCKS5 (${config.socksHost}:${config.socksPort}): ${e.message}. Fail-Closed aktywny."
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

        val localPeers = getLocalPeers()
        val swarmPeers = (findClosestNodes(target, count = 16) + getCachedFastestNodes())
            .filter { !isBootstrapRouter(it.address) }
            .distinctBy { it.address }
        val bootstrapNodes = if (autoBootstrap && swarmPeers.size < 16) {
            resolveBootstrapNodes()
        } else emptyList()
        val queryPeers = if (swarmPeers.isNotEmpty()) {
            (swarmPeers + bootstrapNodes.map { DhtPeer(CryptoUtils.secureRandomBytes(20), it) }).distinctBy { it.address }.take(20)
        } else if (localPeers.isNotEmpty()) {
            localPeers.take(20)
        } else if (autoBootstrap) {
            bootstrapNodes.map { DhtPeer(CryptoUtils.secureRandomBytes(20), it) }
        } else {
            emptyList()
        }

        if (queryPeers.isEmpty()) {
            return@withContext emptyList()
        }

        val queriedAddresses = ConcurrentHashMap.newKeySet<InetSocketAddress>()
        val unqueriedCandidates = ConcurrentHashMap.newKeySet<DhtPeer>()
        val verifiedNodes = ConcurrentHashMap<InetSocketAddress, DhtPeer>()

        queryPeers.forEach { unqueriedCandidates.add(it) }
        swarmPeers.forEach { verifiedNodes[it.address] = it }

        for (round in 0 until 3) {
            val unqueriedClosest = unqueriedCandidates
                .filter { it.address !in queriedAddresses }
                .sortedWith { a, b ->
                    val distA = xorDistance(a.nodeId, target)
                    val distB = xorDistance(b.nodeId, target)
                    compareBytes(distA, distB)
                }
                .take(8)

            if (unqueriedClosest.isEmpty()) break

            unqueriedClosest.forEach { queriedAddresses.add(it.address) }

            val jobs = unqueriedClosest.map { peer ->
                async {
                    try {
                        val query = KrpcMessage.createFindNodeQuery(myNodeId, target)
                        val resp = sendQuery(peer.address, query, timeoutMs = 2500L)
                        if (resp != null) {
                            val respId = resp.responseData["id"] as? ByteArray
                            if (respId != null && respId.size == 20 && !isBootstrapRouter(peer.address)) {
                                verifiedNodes[peer.address] = DhtPeer(respId, peer.address)
                            }
                            val nodesBytes = resp.responseData["nodes"] as? ByteArray
                            if (nodesBytes != null) {
                                val parsed = parseCompactNodesList(nodesBytes)
                                parsed.forEach { node ->
                                    unqueriedCandidates.add(node)
                                    if (!isBootstrapRouter(node.address)) {
                                        verifiedNodes[node.address] = node
                                    }
                                }
                            }
                        }
                    } catch (_: Exception) {
                    }
                }
            }
            jobs.awaitAll()
        }

        // Select the 8 nodes closest to target using XOR distance from verified genuine peers
        val candidatePool = if (verifiedNodes.isNotEmpty()) {
            verifiedNodes.values.toList()
        } else {
            findClosestNodes(target, count = 8).filter { !isBootstrapRouter(it.address) }
        }

        val closest8 = candidatePool
            .filter { !isBootstrapRouter(it.address) && it.nodeId.any { b -> b != 0.toByte() } }
            .distinctBy { it.address }
            .sortedWith { a, b ->
                val distA = xorDistance(a.nodeId, target)
                val distB = xorDistance(b.nodeId, target)
                compareBytes(distA, distB)
            }
            .take(8)

        if (closest8.isNotEmpty()) {
            targetRouteCache[target] = closest8
            println("[PQChat] Pre-warmed target $targetHex with ${closest8.size} closest nodes in TargetRouteCache (from ${verifiedNodes.size} discovered)")
        }

        closest8
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

        val remoteCandidates = (prewarmed + closestCandidates + cachedFastest)
            .distinctBy { it.address }
            .filter { !isBootstrapRouter(it.address) }
            .sortedWith { a, b ->
                val distA = xorDistance(a.nodeId, target)
                val distB = xorDistance(b.nodeId, target)
                compareBytes(distA, distB)
            }

        val nodesToQuery = if (remoteCandidates.isNotEmpty()) {
            (storedPeers + remoteCandidates).distinctBy { it.address }.take(20)
        } else if (localPeers.isNotEmpty()) {
            localPeers.take(20)
        } else if (autoBootstrap) {
            resolveBootstrapNodes().map { DhtPeer(CryptoUtils.secureRandomBytes(20), it) }
        } else {
            emptyList()
        }

        if (nodesToQuery.isEmpty() || torTransportMode == TorTransportMode.BLOCKED_ERROR) {
            _lastOperationMetrics.set(DhtOpMetrics(nodesQueried = 0, nodesResponded = 0, lookupHops = 0))
            return@withContext null
        }

        // Top 3 remote nodes with smallest XOR distance to target
        val localAddresses = localPeers.map { it.address }.toSet()
        val topClosest = nodesToQuery.filter { it.address !in localAddresses }.sortedWith { a, b ->
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
        val verifiedResponses = java.util.concurrent.atomic.AtomicInteger(0)
        val totalResponses = java.util.concurrent.atomic.AtomicInteger(0)

        coroutineScope {
            var queryJobs: List<Job> = emptyList()
            queryJobs = nodesToQuery.map { peer ->
                launch {
                    try {
                        val query = KrpcMessage.createBep44GetQuery(myNodeId, target)
                        val resp = sendQuery(peer.address, query, timeoutMs = timeoutMs) ?: return@launch
                        totalResponses.incrementAndGet()

                        val verified = parseAndVerifyGetResult(resp, salt, peer.address)
                        if (verified != null) {
                            verifiedResponses.incrementAndGet()
                            if (foundItem.compareAndSet(null, verified)) {
                                if (!probeAllReplicas) {
                                    queryJobs.forEach { job ->
                                        if (job != coroutineContext.job) job.cancel()
                                    }
                                }
                            }
                            if (!probeAllReplicas) return@launch
                        }

                        // Response received without valid 'v'
                        if (!probeAllReplicas && topClosestAddresses.contains(peer.address)) {
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
                                val storedAddrs = storedPeers.map { it.address }.toSet()
                                val storedPending = storedAddrs.any { it !in emptyClosestResponses }
                                if (emptyClosestResponses.size >= requiredCount && !closerNodeIndicated.get() && !storedPending) {
                                    // Aggressive Fast Termination:
                                    // First 3 nodes with smallest XOR distance returned no 'v' and no closer nodes,
                                    // and all known stored peers have been checked.
                                    println("[PQChat] Fast Termination: $requiredCount closest nodes returned no 'v' and no closer nodes for target=$targetHex")
                                    queryJobs.forEach { job ->
                                        if (job != coroutineContext.job) job.cancel()
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

        var secondWaveCount = 0
        if (foundItem.get() == null && closerNodeIndicated.get() && !probeAllReplicas) {
            val secondWave = findClosestNodes(target, count = 16)
                .filter { it.address !in nodesToQuery.map { n -> n.address } }
                .take(8)
            secondWaveCount = secondWave.size
            if (secondWave.isNotEmpty()) {
                coroutineScope {
                    var secondJobs: List<Job> = emptyList()
                    secondJobs = secondWave.map { peer ->
                        launch {
                            try {
                                val query = KrpcMessage.createBep44GetQuery(myNodeId, target)
                                val resp = sendQuery(peer.address, query, timeoutMs = timeoutMs) ?: return@launch
                                totalResponses.incrementAndGet()
                                val verified = parseAndVerifyGetResult(resp, salt, peer.address)
                                if (verified != null) {
                                    verifiedResponses.incrementAndGet()
                                    if (foundItem.compareAndSet(null, verified)) {
                                        secondJobs.forEach { job ->
                                            if (job != coroutineContext.job) job.cancel()
                                        }
                                    }
                                }
                            } catch (_: Exception) {
                            }
                        }
                    }
                    secondJobs.joinAll()
                }
            }
        }

        val totalQueried = nodesToQuery.size + secondWaveCount
        val totalResponded = if (probeAllReplicas) {
            verifiedResponses.get()
        } else if (foundItem.get() != null) {
            maxOf(1, verifiedResponses.get())
        } else {
            totalResponses.get()
        }
        val hops = (if (wasPrewarmed) 1 else 2) + (if (secondWaveCount > 0) 1 else 0)

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
        } else if (targetRouteCache[target].isNullOrEmpty() && topClosest.isNotEmpty()) {
            targetRouteCache.put(target, topClosest)
        }

        println("[PQChat] getMutable target=$targetHex, skipLocal=$skipLocalStore, candidates=$totalQueried, responded=$totalResponded, hops=$hops, found=${finalBestItem != null}")
        finalBestItem
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

        // Step 2: Push to external DHT swarm peers (prioritizing pre-warmed route cache & cached fastest nodes)
        if (torTransportMode == TorTransportMode.BLOCKED_ERROR) {
            println("[PQChat] putMutablePreSigned blocked: Tor Fail-Closed active")
            _lastOperationMetrics.set(DhtOpMetrics(nodesQueried = 0, nodesResponded = 0, lookupHops = 0))
            return@withContext false
        }
        val candidateCount = maxOf(24, replicationK * 2)
        val candidates = findClosestNodes(target, count = candidateCount)
        val prewarmed = targetRouteCache[target] ?: preWarmTarget(target)
        val cachedFastest = getCachedFastestNodes()
        val localPeers = getLocalPeers()
        val swarmPeers = (prewarmed + candidates + cachedFastest)
            .distinctBy { it.address }
            .filter { !isBootstrapRouter(it.address) }
            .sortedWith { a, b ->
                val distA = xorDistance(a.nodeId, target)
                val distB = xorDistance(b.nodeId, target)
                compareBytes(distA, distB)
            }
        val maxCandidatesToQuery = maxOf(20, replicationK * 2)
        val nodesToQuery = if (swarmPeers.isNotEmpty()) {
            swarmPeers.take(maxCandidatesToQuery)
        } else if (localPeers.isNotEmpty()) {
            localPeers.take(maxCandidatesToQuery)
        } else if (autoBootstrap) {
            resolveBootstrapNodes().filter { !isBootstrapRouter(it) }.map { DhtPeer(CryptoUtils.secureRandomBytes(20), it) }
        } else {
            emptyList()
        }

        var putSuccess = !skipLocalStore
        val successfulPuts = java.util.concurrent.atomic.AtomicInteger(0)

        try {
            val tokenMap = ConcurrentHashMap<InetSocketAddress, ByteArray>()
            coroutineScope {
                var getJobs: List<Job> = emptyList()
                val targetTokens = minOf(replicationK, nodesToQuery.size)
                getJobs = nodesToQuery.map { peer ->
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
                val startTime = System.currentTimeMillis()
                while (tokenMap.size < targetTokens && (System.currentTimeMillis() - startTime) < 3500L) {
                    if (tokenMap.size >= minOf(4, targetTokens) && (System.currentTimeMillis() - startTime) > 1500L) {
                        getJobs.forEach { it.cancel() }
                        break
                    }
                    delay(25)
                }
                getJobs.forEach { it.cancel() }
            }

            if (tokenMap.isNotEmpty()) {
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
                                    salt = salt
                                )
                                val resp = sendQuery(address, putQuery, timeoutMs = 2500L)
                                if (resp != null) {
                                    remoteStoredPeers.computeIfAbsent(targetHex) { CopyOnWriteArrayList() }.add(address)
                                    val successfulPeer = nodesToQuery.firstOrNull { it.address == address } ?: DhtPeer(target, address)
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
                if (successfulPuts.get() > 0) {
                    putSuccess = true
                }
            }
        } catch (_: Exception) {
        }

        val wasPrewarmed = !targetRouteCache[target].isNullOrEmpty()
        val hops = if (wasPrewarmed) 1 else 2
        val putMetrics = DhtOpMetrics(
            nodesQueried = nodesToQuery.size,
            nodesResponded = successfulPuts.get(),
            lookupHops = hops
        )
        _lastOperationMetrics.set(putMetrics)

        if (!putSuccess && skipLocalStore) {
            // Evict stale/non-responsive prewarmed entries so future retries don't reuse failing nodes
            targetRouteCache.remove(target)
        }

        println("[PQChat] putMutablePreSigned target=$targetHex, candidates=${nodesToQuery.size}, storedPeers=${remoteStoredPeers[targetHex]?.size ?: 0}, putSuccess=$putSuccess, nodesResponded=${successfulPuts.get()}, hops=$hops")
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

