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

class AppSettingsManager(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("pqchat_settings", Context.MODE_PRIVATE)

    private val _themeMode = MutableStateFlow(
        try {
            ThemeMode.valueOf(prefs.getString(KEY_THEME_MODE, ThemeMode.SYSTEM.name) ?: ThemeMode.SYSTEM.name)
        } catch (_: Exception) {
            ThemeMode.SYSTEM
        }
    )
    val themeMode: StateFlow<ThemeMode> = _themeMode.asStateFlow()

    private val _intervalForegroundChat = MutableStateFlow(
        prefs.getLong(KEY_INTERVAL_FOREGROUND, DefaultIntervals.FOREGROUND_CHAT)
    )
    val intervalForegroundChat: StateFlow<Long> = _intervalForegroundChat.asStateFlow()

    private val _intervalAppActive = MutableStateFlow(
        prefs.getLong(KEY_INTERVAL_APP_ACTIVE, DefaultIntervals.APP_ACTIVE)
    )
    val intervalAppActive: StateFlow<Long> = _intervalAppActive.asStateFlow()

    private val _intervalBackgroundIdle = MutableStateFlow(
        prefs.getLong(KEY_INTERVAL_BG_IDLE, DefaultIntervals.BACKGROUND_IDLE)
    )
    val intervalBackgroundIdle: StateFlow<Long> = _intervalBackgroundIdle.asStateFlow()

    private val _intervalDozeSleep = MutableStateFlow(
        prefs.getLong(KEY_INTERVAL_DOZE, DefaultIntervals.DOZE_SLEEP)
    )
    val intervalDozeSleep: StateFlow<Long> = _intervalDozeSleep.asStateFlow()

    fun setThemeMode(mode: ThemeMode) {
        prefs.edit().putString(KEY_THEME_MODE, mode.name).apply()
        _themeMode.value = mode
    }

    fun setIntervalForegroundChat(millis: Long) {
        prefs.edit().putLong(KEY_INTERVAL_FOREGROUND, millis).apply()
        _intervalForegroundChat.value = millis
    }

    fun setIntervalAppActive(millis: Long) {
        prefs.edit().putLong(KEY_INTERVAL_APP_ACTIVE, millis).apply()
        _intervalAppActive.value = millis
    }

    fun setIntervalBackgroundIdle(millis: Long) {
        prefs.edit().putLong(KEY_INTERVAL_BG_IDLE, millis).apply()
        _intervalBackgroundIdle.value = millis
    }

    fun setIntervalDozeSleep(millis: Long) {
        prefs.edit().putLong(KEY_INTERVAL_DOZE, millis).apply()
        _intervalDozeSleep.value = millis
    }

    companion object {
        private const val KEY_THEME_MODE = "theme_mode"
        private const val KEY_INTERVAL_FOREGROUND = "interval_foreground"
        private const val KEY_INTERVAL_APP_ACTIVE = "interval_app_active"
        private const val KEY_INTERVAL_BG_IDLE = "interval_bg_idle"
        private const val KEY_INTERVAL_DOZE = "interval_doze"
    }
}
