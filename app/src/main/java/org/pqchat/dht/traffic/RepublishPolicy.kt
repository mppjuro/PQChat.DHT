package org.pqchat.dht.traffic

import org.pqchat.dht.data.settings.DefaultRepublishConfig

/**
 * Tiers for exponential backoff republishing of unacknowledged messages.
 */
enum class RepublishTier {
    TIER1_INITIAL,   // 0 - 2h (default 15m)
    TIER2_EXTENDED,  // 2h - 12h (default 1h)
    TIER3_LONG_TERM, // 12h - 48h (default 6h)
    EXPIRED          // >= 48h (TTL exceeded)
}

/**
 * Configuration and evaluation policy for unacknowledged message republishing in DHT.
 *
 * Implements Exponential Backoff and TTL limit per architecture requirements:
 * - 0 - 2h: 15 minutes (default)
 * - 2 - 12h: 1 hour (default)
 * - 12 - 48h: 6 hours (default)
 * - >= 48h: TTL expired -> EXPIRED_OFFLINE, stop radio wakeups.
 */
data class RepublishPolicy(
    val tier1IntervalMs: Long = DefaultRepublishConfig.TIER1_INTERVAL,
    val tier1ThresholdMs: Long = DefaultRepublishConfig.TIER1_THRESHOLD,
    val tier2IntervalMs: Long = DefaultRepublishConfig.TIER2_INTERVAL,
    val tier2ThresholdMs: Long = DefaultRepublishConfig.TIER2_THRESHOLD,
    val tier3IntervalMs: Long = DefaultRepublishConfig.TIER3_INTERVAL,
    val maxTtlMs: Long = DefaultRepublishConfig.MAX_TTL
) {
    /**
     * Returns true if message age exceeds or equals the maximum TTL.
     */
    fun isExpired(ageMs: Long): Boolean = ageMs >= maxTtlMs

    /**
     * Maps message age to its corresponding backoff tier.
     */
    fun getTier(ageMs: Long): RepublishTier = when {
        ageMs >= maxTtlMs -> RepublishTier.EXPIRED
        ageMs < tier1ThresholdMs -> RepublishTier.TIER1_INITIAL
        ageMs < tier2ThresholdMs -> RepublishTier.TIER2_EXTENDED
        else -> RepublishTier.TIER3_LONG_TERM
    }

    /**
     * Returns the republish interval in milliseconds for a specific tier.
     * Returns -1 if the tier is EXPIRED.
     */
    fun getIntervalForTier(tier: RepublishTier): Long = when (tier) {
        RepublishTier.TIER1_INITIAL -> tier1IntervalMs
        RepublishTier.TIER2_EXTENDED -> tier2IntervalMs
        RepublishTier.TIER3_LONG_TERM -> tier3IntervalMs
        RepublishTier.EXPIRED -> -1L
    }

    /**
     * Returns the republish interval in milliseconds for a given message age.
     * Returns -1 if expired.
     */
    fun getIntervalForAge(ageMs: Long): Long = getIntervalForTier(getTier(ageMs))
}

/**
 * Decision representing how WorkManager should be scheduled based on active unacknowledged messages.
 */
data class WorkScheduleDecision(
    val shouldSchedule: Boolean,
    val intervalMinutes: Long,
    val tier: RepublishTier?,
    val activeTaskCount: Int,
    val expiredTaskIds: List<Long>
)
