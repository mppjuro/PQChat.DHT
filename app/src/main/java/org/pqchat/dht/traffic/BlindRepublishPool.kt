package org.pqchat.dht.traffic

import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.dht.bencode.Bencode

/**
 * Raw BEP 44 mutable data tuple for Blind Cooperative Republishing.
 *
 * Stores strictly the raw cryptographic parameters required to execute a BEP 44 `put` query.
 * Must NEVER hold any user identity, contact reference, Room entity, or decrypted data.
 */
data class BlindRepublishEntry(
    val target: ByteArray,
    val publicKey: ByteArray,
    val seq: Long,
    val v: ByteArray,
    val sig: ByteArray,
    val salt: ByteArray? = null,
    val addedAt: Long = System.currentTimeMillis()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BlindRepublishEntry) return false
        return target.contentEquals(other.target) &&
                publicKey.contentEquals(other.publicKey) &&
                seq == other.seq &&
                v.contentEquals(other.v) &&
                sig.contentEquals(other.sig) &&
                (salt == null && other.salt == null || (salt != null && other.salt != null && salt.contentEquals(other.salt)))
    }

    override fun hashCode(): Int {
        var result = target.contentHashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + seq.hashCode()
        result = 31 * result + v.contentHashCode()
        result = 31 * result + sig.contentHashCode()
        result = 31 * result + (salt?.contentHashCode() ?: 0)
        return result
    }
}

/**
 * Thread-safe LRU cache with TTL eviction for Blind Cooperative Republishing (P2P Relay).
 *
 * Caches third-party encrypted, authentic BEP 44 packets intercepted during DHT lookups,
 * decoy queries, or mailbox sweeps. These packets are periodically republished as substitute
 * for synthetic Poisson decoy traffic, assisting offline users in packet retention without
 * incurring synthetic traffic overhead or revealing message metadata.
 */
class BlindRepublishPool(
    val maxCapacity: Int = DEFAULT_MAX_CAPACITY,
    val ttlMs: Long = DEFAULT_TTL_MS
) {
    private val lock = Any()

    // Access-ordered LinkedHashMap for true LRU eviction (accessOrder = true)
    private val storage = object : LinkedHashMap<String, BlindRepublishEntry>(maxCapacity, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, BlindRepublishEntry>?): Boolean {
            return size > maxCapacity
        }
    }

    /**
     * Verifies Ed25519 signature of incoming BEP 44 mutable record and adds to LRU cache.
     * Rejects packets with invalid signatures, incorrect sizes, or downgraded sequence numbers.
     *
     * @return true if accepted and cached, false if rejected.
     */
    fun verifyAndAdd(
        target: ByteArray,
        publicKey: ByteArray,
        seq: Long,
        v: ByteArray,
        sig: ByteArray,
        salt: ByteArray? = null,
        now: Long = System.currentTimeMillis()
    ): Boolean {
        // 1. Structural validation
        if (target.size != 20 || publicKey.size != 32 || sig.size != 64 || v.isEmpty() || v.size > 1000) {
            return false
        }

        // 2. Cryptographic signature verification over BEP 44 bencoded signData
        val signData = try {
            Bencode.encodeBep44SignData(v, seq, salt)
        } catch (_: Exception) {
            return false
        }

        if (!Ed25519Engine.verify(publicKey, signData, sig)) {
            return false
        }

        val targetHex = CryptoUtils.toHex(target)
        val entry = BlindRepublishEntry(
            target = target.copyOf(),
            publicKey = publicKey.copyOf(),
            seq = seq,
            v = v.copyOf(),
            sig = sig.copyOf(),
            salt = salt?.copyOf(),
            addedAt = now
        )

        synchronized(lock) {
            pruneExpiredLocked(now)

            val existing = storage[targetHex]
            if (existing != null && seq < existing.seq) {
                // Do not downgrade sequence number
                return false
            }

            storage[targetHex] = entry
            while (storage.size > maxCapacity) {
                val eldestKey = storage.keys.firstOrNull() ?: break
                storage.remove(eldestKey)
            }
        }

        return true
    }

    fun verifyAndAdd(entry: BlindRepublishEntry, now: Long = System.currentTimeMillis()): Boolean {
        return verifyAndAdd(
            target = entry.target,
            publicKey = entry.publicKey,
            seq = entry.seq,
            v = entry.v,
            sig = entry.sig,
            salt = entry.salt,
            now = now
        )
    }

    /**
     * Samples an entry at random from current valid, unexpired entries in the pool.
     * Returns null if pool is empty or all items expired.
     */
    fun sampleRandomEntry(now: Long = System.currentTimeMillis()): BlindRepublishEntry? {
        synchronized(lock) {
            pruneExpiredLocked(now)
            if (storage.isEmpty()) return null
            val entries = storage.values.toList()
            val randomIndex = CryptoUtils.secureRandom.nextInt(entries.size)
            // Trigger LRU touch on sampled entry
            val selected = entries[randomIndex]
            val key = CryptoUtils.toHex(selected.target)
            return storage[key] ?: selected
        }
    }

    fun getEntry(target: ByteArray, now: Long = System.currentTimeMillis()): BlindRepublishEntry? {
        val targetHex = CryptoUtils.toHex(target)
        synchronized(lock) {
            pruneExpiredLocked(now)
            return storage[targetHex]
        }
    }

    fun getAllEntries(now: Long = System.currentTimeMillis()): List<BlindRepublishEntry> {
        synchronized(lock) {
            pruneExpiredLocked(now)
            return storage.values.toList()
        }
    }

    fun size(now: Long = System.currentTimeMillis()): Int {
        synchronized(lock) {
            pruneExpiredLocked(now)
            return storage.size
        }
    }

    fun pruneExpired(now: Long = System.currentTimeMillis()): Int {
        synchronized(lock) {
            return pruneExpiredLocked(now)
        }
    }

    private fun pruneExpiredLocked(now: Long): Int {
        val iterator = storage.entries.iterator()
        var pruned = 0
        while (iterator.hasNext()) {
            val entry = iterator.next().value
            if (now - entry.addedAt > ttlMs) {
                iterator.remove()
                pruned++
            }
        }
        return pruned
    }

    fun clear() {
        synchronized(lock) {
            storage.clear()
        }
    }

    companion object {
        const val DEFAULT_MAX_CAPACITY = 50
        const val DEFAULT_TTL_MS = 120 * 60 * 1000L // 120 minut (2 godziny)

        /** Global singleton pool instance */
        val defaultInstance = BlindRepublishPool()
    }
}
