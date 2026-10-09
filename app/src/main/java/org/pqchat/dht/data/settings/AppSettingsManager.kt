package org.pqchat.dht.data.settings

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class ThemeMode {
    SYSTEM,
    DARK,
    LIGHT
}

data class SyncIntervalOption(
    val label: String,
    val millis: Long
)

val SYNC_INTERVAL_OPTIONS = listOf(
    SyncIntervalOption("5 sekund", 5_000L),
    SyncIntervalOption("10 sekund", 10_000L),
    SyncIntervalOption("20 sekund", 20_000L),
    SyncIntervalOption("30 sekund", 30_000L),
    SyncIntervalOption("1 minuta", 60_000L),
    SyncIntervalOption("2 minuty", 120_000L),
    SyncIntervalOption("3 minuty", 180_000L),
    SyncIntervalOption("5 minut", 300_000L),
    SyncIntervalOption("10 minut", 600_000L),
    SyncIntervalOption("15 minut", 900_000L),
    SyncIntervalOption("30 minut", 1_800_000L),
    SyncIntervalOption("1 godzina", 3_600_000L),
    SyncIntervalOption("2 godziny", 7_200_000L)
)

object DefaultIntervals {
    const val FOREGROUND_CHAT = 10_000L // 10 sekund
    const val APP_ACTIVE = 60_000L       // 1 minuta
    const val BACKGROUND_IDLE = 300_000L // 5 minut
    const val DOZE_SLEEP = 900_000L      // 15 minut
}

object DefaultRepublishConfig {
    const val TIER1_INTERVAL = 15 * 60 * 1000L       // 15 minut (do 2h)
    const val TIER1_THRESHOLD = 2 * 60 * 60 * 1000L   // 2 godziny
    const val TIER2_INTERVAL = 60 * 60 * 1000L       // 1 godzina (do 12h)
    const val TIER2_THRESHOLD = 12 * 60 * 60 * 1000L  // 12 godzin
    const val TIER3_INTERVAL = 6 * 60 * 60 * 1000L   // 6 godzin (powyżej 12h)
    const val MAX_TTL = 48 * 60 * 60 * 1000L         // 48 godzin (maksymalny TTL)
}

val REPUBLISH_TIER1_OPTIONS = listOf(
    SyncIntervalOption("5 minut", 5 * 60 * 1000L),
    SyncIntervalOption("10 minut", 10 * 60 * 1000L),
    SyncIntervalOption("15 minut", 15 * 60 * 1000L),
    SyncIntervalOption("30 minut", 30 * 60 * 1000L),
    SyncIntervalOption("1 godzina", 60 * 60 * 1000L)
)

val REPUBLISH_TIER2_OPTIONS = listOf(
    SyncIntervalOption("30 minut", 30 * 60 * 1000L),
    SyncIntervalOption("1 godzina", 60 * 60 * 1000L),
    SyncIntervalOption("2 godziny", 2 * 60 * 60 * 1000L),
    SyncIntervalOption("3 godziny", 3 * 60 * 60 * 1000L),
    SyncIntervalOption("4 godziny", 4 * 60 * 60 * 1000L)
)

val REPUBLISH_TIER3_OPTIONS = listOf(
    SyncIntervalOption("2 godziny", 2 * 60 * 60 * 1000L),
    SyncIntervalOption("4 godziny", 4 * 60 * 60 * 1000L),
    SyncIntervalOption("6 godzin", 6 * 60 * 60 * 1000L),
    SyncIntervalOption("8 godzin", 8 * 60 * 60 * 1000L),
    SyncIntervalOption("12 godzin", 12 * 60 * 60 * 1000L)
)

val REPUBLISH_TTL_OPTIONS = listOf(
    SyncIntervalOption("12 godzin", 12 * 60 * 60 * 1000L),
    SyncIntervalOption("24 godziny", 24 * 60 * 60 * 1000L),
    SyncIntervalOption("36 godzin", 36 * 60 * 60 * 1000L),
    SyncIntervalOption("48 godzin", 48 * 60 * 60 * 1000L),
    SyncIntervalOption("72 godziny", 72 * 60 * 60 * 1000L)
)

class AppSettingsManager(context: Context? = null) {

    private val prefs: SharedPreferences? =
        context?.getSharedPreferences("pqchat_settings", Context.MODE_PRIVATE)

    private val _themeMode = MutableStateFlow(
        try {
            ThemeMode.valueOf(prefs?.getString(KEY_THEME_MODE, ThemeMode.SYSTEM.name) ?: ThemeMode.SYSTEM.name)
        } catch (_: Exception) {
            ThemeMode.SYSTEM
        }
    )
    val themeMode: StateFlow<ThemeMode> = _themeMode.asStateFlow()

    private val _intervalForegroundChat = MutableStateFlow(
        prefs?.getLong(KEY_INTERVAL_FOREGROUND, DefaultIntervals.FOREGROUND_CHAT) ?: DefaultIntervals.FOREGROUND_CHAT
    )
    val intervalForegroundChat: StateFlow<Long> = _intervalForegroundChat.asStateFlow()

    private val _intervalAppActive = MutableStateFlow(
        prefs?.getLong(KEY_INTERVAL_APP_ACTIVE, DefaultIntervals.APP_ACTIVE) ?: DefaultIntervals.APP_ACTIVE
    )
    val intervalAppActive: StateFlow<Long> = _intervalAppActive.asStateFlow()

    private val _intervalBackgroundIdle = MutableStateFlow(
        prefs?.getLong(KEY_INTERVAL_BG_IDLE, DefaultIntervals.BACKGROUND_IDLE) ?: DefaultIntervals.BACKGROUND_IDLE
    )
    val intervalBackgroundIdle: StateFlow<Long> = _intervalBackgroundIdle.asStateFlow()

    private val _intervalDozeSleep = MutableStateFlow(
        prefs?.getLong(KEY_INTERVAL_DOZE, DefaultIntervals.DOZE_SLEEP) ?: DefaultIntervals.DOZE_SLEEP
    )
    val intervalDozeSleep: StateFlow<Long> = _intervalDozeSleep.asStateFlow()

    private val _isForegroundServiceEnabled = MutableStateFlow(
        prefs?.getBoolean(KEY_FOREGROUND_SERVICE, false) ?: false
    )
    val isForegroundServiceEnabled: StateFlow<Boolean> = _isForegroundServiceEnabled.asStateFlow()

    // DHT Republishing policy settings (Tier 1..3 and Max TTL)
    private val _intervalRepublishTier1 = MutableStateFlow(
        prefs?.getLong(KEY_REPUBLISH_TIER1, DefaultRepublishConfig.TIER1_INTERVAL) ?: DefaultRepublishConfig.TIER1_INTERVAL
    )
    val intervalRepublishTier1: StateFlow<Long> = _intervalRepublishTier1.asStateFlow()

    private val _intervalRepublishTier2 = MutableStateFlow(
        prefs?.getLong(KEY_REPUBLISH_TIER2, DefaultRepublishConfig.TIER2_INTERVAL) ?: DefaultRepublishConfig.TIER2_INTERVAL
    )
    val intervalRepublishTier2: StateFlow<Long> = _intervalRepublishTier2.asStateFlow()

    private val _intervalRepublishTier3 = MutableStateFlow(
        prefs?.getLong(KEY_REPUBLISH_TIER3, DefaultRepublishConfig.TIER3_INTERVAL) ?: DefaultRepublishConfig.TIER3_INTERVAL
    )
    val intervalRepublishTier3: StateFlow<Long> = _intervalRepublishTier3.asStateFlow()

    private val _republishMaxTtl = MutableStateFlow(
        prefs?.getLong(KEY_REPUBLISH_MAX_TTL, DefaultRepublishConfig.MAX_TTL) ?: DefaultRepublishConfig.MAX_TTL
    )
    val republishMaxTtl: StateFlow<Long> = _republishMaxTtl.asStateFlow()

    fun setThemeMode(mode: ThemeMode) {
        prefs?.edit()?.putString(KEY_THEME_MODE, mode.name)?.apply()
        _themeMode.value = mode
    }

    fun setIntervalForegroundChat(millis: Long) {
        prefs?.edit()?.putLong(KEY_INTERVAL_FOREGROUND, millis)?.apply()
        _intervalForegroundChat.value = millis
    }

    fun setIntervalAppActive(millis: Long) {
        prefs?.edit()?.putLong(KEY_INTERVAL_APP_ACTIVE, millis)?.apply()
        _intervalAppActive.value = millis
    }

    fun setIntervalBackgroundIdle(millis: Long) {
        prefs?.edit()?.putLong(KEY_INTERVAL_BG_IDLE, millis)?.apply()
        _intervalBackgroundIdle.value = millis
    }

    fun setIntervalDozeSleep(millis: Long) {
        prefs?.edit()?.putLong(KEY_INTERVAL_DOZE, millis)?.apply()
        _intervalDozeSleep.value = millis
    }

    fun setForegroundServiceEnabled(enabled: Boolean) {
        prefs?.edit()?.putBoolean(KEY_FOREGROUND_SERVICE, enabled)?.apply()
        _isForegroundServiceEnabled.value = enabled
    }

    fun setIntervalRepublishTier1(millis: Long) {
        prefs?.edit()?.putLong(KEY_REPUBLISH_TIER1, millis)?.apply()
        _intervalRepublishTier1.value = millis
    }

    fun setIntervalRepublishTier2(millis: Long) {
        prefs?.edit()?.putLong(KEY_REPUBLISH_TIER2, millis)?.apply()
        _intervalRepublishTier2.value = millis
    }

    fun setIntervalRepublishTier3(millis: Long) {
        prefs?.edit()?.putLong(KEY_REPUBLISH_TIER3, millis)?.apply()
        _intervalRepublishTier3.value = millis
    }

    fun setRepublishMaxTtl(millis: Long) {
        prefs?.edit()?.putLong(KEY_REPUBLISH_MAX_TTL, millis)?.apply()
        _republishMaxTtl.value = millis
    }

    fun getRepublishPolicy(): org.pqchat.dht.traffic.RepublishPolicy = org.pqchat.dht.traffic.RepublishPolicy(
        tier1IntervalMs = _intervalRepublishTier1.value,
        tier1ThresholdMs = DefaultRepublishConfig.TIER1_THRESHOLD,
        tier2IntervalMs = _intervalRepublishTier2.value,
        tier2ThresholdMs = DefaultRepublishConfig.TIER2_THRESHOLD,
        tier3IntervalMs = _intervalRepublishTier3.value,
        maxTtlMs = _republishMaxTtl.value
    )

    companion object {
        private const val KEY_THEME_MODE = "theme_mode"
        private const val KEY_INTERVAL_FOREGROUND = "interval_foreground"
        private const val KEY_INTERVAL_APP_ACTIVE = "interval_app_active"
        private const val KEY_INTERVAL_BG_IDLE = "interval_bg_idle"
        private const val KEY_INTERVAL_DOZE = "interval_doze"
        private const val KEY_FOREGROUND_SERVICE = "foreground_service_enabled"
        private const val KEY_REPUBLISH_TIER1 = "republish_tier1_interval"
        private const val KEY_REPUBLISH_TIER2 = "republish_tier2_interval"
        private const val KEY_REPUBLISH_TIER3 = "republish_tier3_interval"
        private const val KEY_REPUBLISH_MAX_TTL = "republish_max_ttl"
    }
}
