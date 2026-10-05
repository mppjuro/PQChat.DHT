package org.pqchat.dht.dht.leaf

import kotlinx.coroutines.*
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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Client-Only / Read-Only BitTorrent Mainline DHT Node (BEP 43 / BEP 44).
 *
 * Characteristics:
 * - Does NOT route external traffic.
 * - Does NOT hoard third-party data in RAM.
 * - Stores & retrieves 1000-byte encrypted messages via BEP 44 mutable items.
 */
class DhtLeafNode(
    val myNodeId: ByteArray = CryptoUtils.secureRandomBytes(20),
    private val port: Int = 0 // 0 means ephemeral port
) {
    companion object {
        const val K = 8 // Replication / closest nodes factor
        const val TIMEOUT_MS = 3000L
        const val BOOTSTRAP_TIMEOUT_MS = 6000L

        val BOOTSTRAP_HOSTS = listOf(
            Pair("router.bittorrent.com", 6881),
            Pair("dht.transmissionbt.com", 6881),
            Pair("router.utorrent.com", 6881),
            Pair("dht.aelitis.com", 6881)
        )
    }

    data class DhtPeer(
        val nodeId: ByteArray,
        val address: InetSocketAddress,
        var lastSeen: Long = System.currentTimeMillis()
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is DhtPeer) return false
            return nodeId.contentEquals(other.nodeId) || address == other.address
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
        val responder: InetSocketAddress
    )

    private var socket: DatagramSocket? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val pendingTransactions = ConcurrentHashMap<String, CompletableDeferred<KrpcMessage.Response>>()
    private val routingTable = CopyOnWriteArrayList<DhtPeer>()

    @Volatile
    private var isRunning = false

    fun start() {
        if (isRunning) return
        isRunning = true
        socket = DatagramSocket(port)

        scope.launch {
            listenLoop()
        }

        scope.launch {
            bootstrap()
        }
    }

    fun stop() {
        isRunning = false
        try {
            socket?.close()
        } catch (_: Exception) {}
        scope.cancel()
        pendingTransactions.clear()
        routingTable.clear()
    }

    fun getActivePeerCount(): Int = routingTable.size

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
                    // Read-only leaf node ignores incoming queries or sends read-only empty response
                }
            }
        } catch (_: Exception) {
            // Malformed packet, safely ignore
        }
    }

    private fun parseCompactNodes(bytes: ByteArray) {
        val count = bytes.size / 26
        for (i in 0 until count) {
            val offset = i * 26
            val nodeId = bytes.copyOfRange(offset, offset + 20)
            val ipBytes = bytes.copyOfRange(offset + 20, offset + 24)
            val ip = InetAddress.getByAddress(ipBytes)
            val port = ((bytes[offset + 24].toInt() and 0xFF) shl 8) or (bytes[offset + 25].toInt() and 0xFF)
            addPeer(nodeId, InetSocketAddress(ip, port))
        }
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
        val bootstrapNodes = resolveBootstrapNodes()
        val randomTarget = CryptoUtils.secureRandomBytes(20)
        for (bootstrapNode in bootstrapNodes) {
            launch {
                try {
                    val query = KrpcMessage.createFindNodeQuery(myNodeId, randomTarget)
                    sendQuery(bootstrapNode, query, BOOTSTRAP_TIMEOUT_MS)
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

        try {
            val bytes = query.toBencoded()
            val packet = DatagramPacket(bytes, bytes.size, targetAddress)
            socket?.send(packet)

            withTimeoutOrNull(timeoutMs) {
                deferred.await()
            }
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
     * BEP 44 get query to retrieve mutable item for target.
     * Validates that Target == SHA-1(k) and Ed25519 signature is authentic.
     */
    suspend fun getMutable(target: ByteArray, salt: ByteArray? = null): MutableItem? = withContext(Dispatchers.IO) {
        val candidates = findClosestNodes(target, count = 12)
        val nodesToQuery = if (candidates.isNotEmpty()) {
            candidates
        } else {
            resolveBootstrapNodes().map {
                DhtPeer(CryptoUtils.secureRandomBytes(20), it)
            }
        }

        val deferreds = nodesToQuery.map { peer ->
            async {
                val query = KrpcMessage.createBep44GetQuery(myNodeId, target)
                val resp = sendQuery(peer.address, query) ?: return@async null

                val v = resp.responseData["v"] as? ByteArray ?: return@async null
                val k = resp.responseData["k"] as? ByteArray ?: return@async null
                val sig = resp.responseData["sig"] as? ByteArray ?: return@async null
                val seq = (resp.responseData["seq"] as? Long) ?: 0L
                val token = resp.responseData["token"] as? ByteArray

                // 1. Verify Target matches SHA-1(k) (or k + salt)
                val expectedTarget = if (salt != null && salt.isNotEmpty()) {
                    CryptoUtils.sha1(k + salt)
                } else {
                    CryptoUtils.sha1(k)
                }

                if (!CryptoUtils.constantTimeEquals(target, expectedTarget)) {
                    return@async null
                }

                // 2. Verify Ed25519 signature
                val dataToVerify = Bencode.encodeBep44SignData(v, seq, salt)
                if (!Ed25519Engine.verify(k, dataToVerify, sig)) {
                    return@async null
                }

                MutableItem(v, seq, k, sig, salt, token, peer.address)
            }
        }

        // Return highest sequence valid item
        val results = deferreds.awaitAll().filterNotNull()
        results.maxByOrNull { it.seq }
    }

    /**
     * BEP 44 put query to store mutable item.
     * Signs v using Ed25519 sk and sends put to nodes that returned tokens.
     */
    suspend fun putMutable(
        target: ByteArray,
        v: ByteArray,
        seq: Long,
        salt: ByteArray? = null,
        sk: ByteArray
    ): Boolean = withContext(Dispatchers.IO) {
        require(v.size == 1000) { "BEP 44 payload must be exactly 1000 bytes" }

        val candidates = findClosestNodes(target, count = 12)
        val nodesToQuery = if (candidates.isNotEmpty()) {
            candidates
        } else {
            resolveBootstrapNodes().map {
                DhtPeer(CryptoUtils.secureRandomBytes(20), it)
            }
        }

        // Step 1: Send GET to obtain write tokens
        val tokenMap = ConcurrentHashMap<InetSocketAddress, ByteArray>()
        val getJobs = nodesToQuery.map { peer ->
            launch {
                val getQuery = KrpcMessage.createBep44GetQuery(myNodeId, target)
                val resp = sendQuery(peer.address, getQuery)
                val token = resp?.responseData?.get("token") as? ByteArray
                if (token != null) {
                    tokenMap[peer.address] = token
                }
            }
        }
        getJobs.joinAll()

        if (tokenMap.isEmpty()) {
            return@withContext false
        }

        // Step 2: Sign record with Ed25519
        val signData = Bencode.encodeBep44SignData(v, seq, salt)
        val sig = Ed25519Engine.sign(sk, signData)
        val pk = Ed25519Engine.generateKeyPairFromSeed(sk).publicKey

        // Step 3: Send PUT to all token-providing nodes
        val putDeferreds = tokenMap.map { (address, token) ->
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
                val resp = sendQuery(address, putQuery)
                resp != null
            }
        }

        val putResults = putDeferreds.awaitAll()
        putResults.any { it }
    }

    /**
     * Send dummy cover traffic (chaffing) to random target.
     */
    suspend fun sendCoverTrafficDummy(): Boolean {
        val dummySeed = CryptoUtils.secureRandomBytes(32)
        val dummyKeyPair = Ed25519Engine.generateKeyPairFromSeed(dummySeed)
        val target = Ed25519Engine.computeTarget(dummyKeyPair.publicKey)
        val dummyPayload = CryptoUtils.secureRandomBytes(1000)

        return putMutable(
            target = target,
            v = dummyPayload,
            seq = 1L,
            salt = null,
            sk = dummySeed
        )
    }
}
