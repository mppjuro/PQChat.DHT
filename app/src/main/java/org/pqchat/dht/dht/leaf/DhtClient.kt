package org.pqchat.dht.dht.leaf

import kotlinx.coroutines.Job

/**
 * Common abstraction for DHT client implementations (production leaf node, fake/mock nodes for testing).
 */
interface DhtClient {
    /**
     * Unique 20-byte Node ID.
     */
    val myNodeId: ByteArray

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
     * Send dummy cover traffic (chaffing) to random target.
     * Returns the 20-byte target actually published to DHT, or null on failure.
     */
    suspend fun sendCoverTrafficDummy(): ByteArray?
}
