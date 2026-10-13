package org.pqchat.dht.traffic

import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.data.settings.DefaultRepublishConfig
import org.pqchat.dht.data.settings.REPUBLISH_TIER3_OPTIONS

/**
 * Unit verification tests for RepublishPolicy calibration against BEP 44 Mainline DHT limitations.
 * Verifies:
 * 1. Default Tier 3 interval is 90 minutes (1.5 hours) rather than 6 hours.
 * 2. Tier 3 interval (1.5h) strictly precedes native BEP 44 node eviction (~2.0h / 120m).
 * 3. Settings manager properly exposes 1.0h and 1.5h options for long-term republishing.
 */
class RepublishPolicyCalibrationTest {

    @Test
    fun testTier3DefaultIntervalIs90Minutes() {
        val policy = RepublishPolicy()
        // Tier 3 is configured to 90 minutes (5_400_000 ms)
        assertEquals(90 * 60 * 1000L, policy.tier3IntervalMs)
        assertEquals(90 * 60 * 1000L, DefaultRepublishConfig.TIER3_INTERVAL)

        // 90 minutes must be strictly less than 2 hours (120 minutes)
        val bep44NodeTtlMs = 2 * 60 * 60 * 1000L
        assertTrue(
            "Tier 3 republish interval must be < 2h BEP 44 node eviction TTL",
            policy.tier3IntervalMs < bep44NodeTtlMs
        )
    }

    @Test
    fun testTierTransitionsAndIntervals() {
        val policy = RepublishPolicy()

        // Tier 1: 0 to 2h (15 min interval)
        assertEquals(RepublishTier.TIER1_INITIAL, policy.getTier(0L))
        assertEquals(15 * 60 * 1000L, policy.getIntervalForAge(30 * 60 * 1000L))

        // Tier 2: 2h to 12h (1h interval)
        assertEquals(RepublishTier.TIER2_EXTENDED, policy.getTier(2 * 60 * 60 * 1000L))
        assertEquals(60 * 60 * 1000L, policy.getIntervalForAge(6 * 60 * 60 * 1000L))

        // Tier 3: 12h to 48h (1.5h / 90m interval)
        assertEquals(RepublishTier.TIER3_LONG_TERM, policy.getTier(12 * 60 * 60 * 1000L))
        assertEquals(RepublishTier.TIER3_LONG_TERM, policy.getTier(24 * 60 * 60 * 1000L))
        assertEquals(90 * 60 * 1000L, policy.getIntervalForAge(24 * 60 * 60 * 1000L))

        // Expired: >= 48h
        assertEquals(RepublishTier.EXPIRED, policy.getTier(48 * 60 * 60 * 1000L))
        assertTrue(policy.isExpired(48 * 60 * 60 * 1000L))
    }

    @Test
    fun testSettingsManagerExposesCalibratedTier3Options() {
        val settingsManager = AppSettingsManager()
        val defaultPolicy = settingsManager.getRepublishPolicy()

        assertEquals(90 * 60 * 1000L, defaultPolicy.tier3IntervalMs)

        // Check dropdown options contains 1.5 hours option
        val has90MinOption = REPUBLISH_TIER3_OPTIONS.any { it.millis == 90 * 60 * 1000L }
        val has60MinOption = REPUBLISH_TIER3_OPTIONS.any { it.millis == 60 * 60 * 1000L }

        assertTrue("REPUBLISH_TIER3_OPTIONS must contain 1.5h option", has90MinOption)
        assertTrue("REPUBLISH_TIER3_OPTIONS must contain 1.0h option", has60MinOption)
    }
}
