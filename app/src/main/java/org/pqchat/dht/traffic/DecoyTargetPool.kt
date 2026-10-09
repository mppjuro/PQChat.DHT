package org.pqchat.dht.traffic

import org.pqchat.dht.crypto.CryptoUtils
import java.util.concurrent.ConcurrentLinkedDeque

/**
 * Thread-safe pool of populated, real and expiring DHT targets.
 *
 * In accordance with docs/threat_model.md Section 3.2:
 * "Decoy GET Distinguishability & 0-PUT Target Distinguishability":
 * Decoy GETs must target populated records (dummy PUTs, Cover-Traffic ACKs,
 * past/expiring contact slots) rather than unpopulated random 160-bit hashes,
 * ensuring they survive stateful adversary 0-PUT filtering.
 */
class DecoyTargetPool(
    private val maxCapacity: Int = 100
) {
    private val pool = ConcurrentLinkedDeque<ByteArray>()

    /**
     * Registers a target known to have a real record stored in the DHT
     * (e.g. from Poisson cover traffic, Decoy PUT slots, or actual message deliveries).
     */
    fun registerPopulatedTarget(target: ByteArray) {
        if (target.isEmpty()) return
        val copy = target.copyOf()
        // Deduplicate recent target if already present
        pool.removeIf { it.contentEquals(copy) }
        pool.addFirst(copy)
        while (pool.size > maxCapacity) {
            pool.removeLast()
        }
    }

    /**
     * Registers multiple populated targets at once.
     */
    fun registerPopulatedTargets(targets: Collection<ByteArray>) {
        for (t in targets) {
            registerPopulatedTarget(t)
        }
    }

    /**
     * Returns a list of real / expiring decoy targets to query.
     * If the pool contains fewer entries than requested, falls back to fallbackProvider
     * (e.g. past contact slots or active lookahead slots), or derives an Ed25519 target.
     */
    fun getDecoyTargets(
        count: Int,
        fallbackProvider: (() -> List<ByteArray>)? = null
    ): List<ByteArray> {
        if (count <= 0) return emptyList()
        val targets = mutableListOf<ByteArray>()
        val snapshot = pool.toList()

        if (snapshot.isNotEmpty()) {
            val shuffled = snapshot.shuffled(CryptoUtils.secureRandom)
            targets.addAll(shuffled.take(count))
        }

        if (targets.size < count && fallbackProvider != null) {
            val fallbackCandidates = fallbackProvider().filter { candidate ->
                targets.none { it.contentEquals(candidate) }
            }
            targets.addAll(fallbackCandidates.take(count - targets.size))
        }

        return targets
    }

    fun getAllPopulatedTargets(): List<ByteArray> {
        return pool.map { it.copyOf() }
    }

    fun size(): Int = pool.size

    fun clear() {
        pool.clear()
    }

    companion object {
        /** Global shared default pool instance for application lifecycle */
        val defaultInstance = DecoyTargetPool()
    }
}
