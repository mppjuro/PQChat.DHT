package org.pqchat.dht.dht.leaf

import kotlinx.coroutines.Job

data class TorProxyConfig(
    val enabled: Boolean = true,
    val socksHost: String = "127.0.0.1",
    val socksPort: Int = 9050,
    val timeoutMs: Int = 3000
)

/**
 * Operating transport mode for DHT packet transmission.
 */
enum class TorTransportMode {
    /** Tor disabled in settings: raw direct UDP socket used. */
    DIRECT_UDP,
    /** Tor enabled: datagrams routed via RFC 1928 SOCKS5 UDP ASSOCIATE relay. */
    SOCKS5_UDP,
    /** Tor enabled: standard Tor daemon rejected UDP ASSOCIATE; tunneled via SOCKS5 TCP streaming socket (length-prefixed KRPC). */
    SOCKS5_TCP,
    /** Tor enabled in settings, but SOCKS5 proxy is offline or errored. Fail-closed: all direct UDP transmission is blocked. */
    BLOCKED_ERROR
}

/**
 * Common abstraction for DHT client implementations (production leaf node, fake/mock nodes for testing).
 */
interface DhtClient {
    /**
     * Unique 20-byte Node ID.
     */
    val myNodeId: ByteArray

    /**
     * Configures Tor SOCKS5 proxy routing.
     * When null or enabled=false, direct UDP networking is used immediately.
     */
    fun setTorProxy(config: TorProxyConfig?) {}

    /**
     * Whether KRPC queries are currently routed through Tor SOCKS5 proxy.
     */
    val isTorRoutingActive: Boolean get() = false

    /**
     * Current Tor transport mode.
     */
    val torTransportMode: TorTransportMode get() = TorTransportMode.DIRECT_UDP

    /**
     * Real-time diagnostic message about Tor proxy capabilities and transport state.
     */
    val torDiagnosticMessage: String? get() = null

    /**
     * Empirical telemetry: cumulative count of BEP 44 GET queries executed.
     */
    val totalGetCalls: Long get() = 0L

    /**
     * Empirical telemetry: cumulative count of BEP 44 PUT queries executed.
     */
    val totalPutCalls: Long get() = 0L

    /**
     * Empirical telemetry: cumulative number of bytes sent via the UDP / KRPC socket.
     */
    val totalBytesSent: Long get() = 0L

    /**
     * Empirical telemetry: cumulative number of bytes received via the UDP / KRPC socket.
     */
    val totalBytesReceived: Long get() = 0L

    /**
     * Start DHT client background loops, listeners or workers.
     */
    fun start()

    /**
     * Gracefully stop the DHT client and release networking resources.
     */
    fun stop()

    /**
     * Returns count of active discovered peers in routing table / swarm.
     */
    fun getActivePeerCount(): Int

    /**
     * Asynchronously pre-warms routes/nodes closest to target.
     */
    suspend fun preWarmTarget(target: ByteArray): List<DhtLeafNode.DhtPeer>

    /**
     * Non-blocking trigger to pre-warm target in background scope.
     */
    fun preWarmTargetAsync(target: ByteArray): Job

    /**
     * BEP 44 get query to retrieve mutable item for target.
     * Returns null if not found, timeout or verification failure.
     */
    suspend fun getMutable(
        target: ByteArray,
        salt: ByteArray? = null,
        skipLocalStore: Boolean = false,
        timeoutMs: Long = DhtLeafNode.FAST_GET_TIMEOUT_MS
    ): DhtLeafNode.MutableItem?

    companion object {
        /**
         * Constant sequence number used for BEP 44 mutable puts across unique ephemeral targets.
         * Using a constant seq prevents metadata leakage (such as conversation counters or file transfer sizes)
         * to public DHT nodes.
         */
        const val DEFAULT_MUTABLE_SEQ: Long = 1L
    }

    /**
     * BEP 44 put query to store mutable item.
     */
    suspend fun putMutable(
        target: ByteArray,
        v: ByteArray,
        seq: Long = DEFAULT_MUTABLE_SEQ,
        salt: ByteArray? = null,
        sk: ByteArray,
        skipLocalStore: Boolean = false
    ): Boolean

    /**
     * BEP 44 put query to store mutable item using pre-existing public key and Ed25519 signature.
     * Used for Blind Cooperative Republishing of third-party encrypted records where private seed is unknown.
     */
    suspend fun putMutablePreSigned(
        target: ByteArray,
        v: ByteArray,
        seq: Long = DEFAULT_MUTABLE_SEQ,
        salt: ByteArray? = null,
        pk: ByteArray,
        sig: ByteArray,
        skipLocalStore: Boolean = false
    ): Boolean

    /**
     * Send dummy cover traffic (chaffing) to random target.
     * Returns the 20-byte target actually published to DHT, or null on failure.
     */
    suspend fun sendCoverTrafficDummy(): ByteArray?

    /**
     * Replication factor K: number of closest DHT nodes storing mutable items.
     * Default is 8 on Wi-Fi, adaptive 16 on Mobile LTE / Restrictive NAT / CGNAT.
     */
    var replicationK: Int
        get() = 8
        set(_) {}

    /**
     * Dynamically sets replication factor K based on mobile / CGNAT network environment.
     */
    fun setAdaptiveK(isMobileOrCgnat: Boolean) {}

    /**
     * Sends a lightweight KRPC ping query to maintain carrier NAT mapping tables (20–25s timeout).
     */
    suspend fun sendKeepalivePing(): Boolean = false
}

