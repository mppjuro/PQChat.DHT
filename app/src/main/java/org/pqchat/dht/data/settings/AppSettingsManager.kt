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

enum class PinAuthResult {
    NORMAL_UNLOCK,
    DURESS_TRIGGERED,
    INVALID,
    NO_PIN_SET
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
    const val TIER3_INTERVAL = 90 * 60 * 1000L       // 1.5 godziny / 90 minut (skalibrowane pod natywny TTL BEP 44 ~2h)
    const val MAX_TTL = 48 * 60 * 60 * 1000L         // 48 godzin (maksymalny TTL)
}

object DefaultImageCompression {
    const val DEFAULT_MAX_EDGE = 1000 // Default max edge value: 1000px
    const val DEFAULT_COLOR_COUNT = 128 // Default PNG8 color count
    const val MIN_COLORS = 8
    const val MAX_COLORS = 256
    const val MIN_MAX_EDGE = 400
    const val MAX_MAX_EDGE = 1600
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
    SyncIntervalOption("1 godzina", 60 * 60 * 1000L),
    SyncIntervalOption("1.5 godziny", 90 * 60 * 1000L),
    SyncIntervalOption("2 godziny", 2 * 60 * 60 * 1000L),
    SyncIntervalOption("3 godziny", 3 * 60 * 60 * 1000L),
    SyncIntervalOption("4 godziny", 4 * 60 * 60 * 1000L),
    SyncIntervalOption("6 godzin", 6 * 60 * 60 * 1000L)
)

val REPUBLISH_TTL_OPTIONS = listOf(
    SyncIntervalOption("12 godzin", 12 * 60 * 60 * 1000L),
    SyncIntervalOption("24 godziny", 24 * 60 * 60 * 1000L),
    SyncIntervalOption("36 godzin", 36 * 60 * 60 * 1000L),
    SyncIntervalOption("48 godzin", 48 * 60 * 60 * 1000L),
    SyncIntervalOption("72 godziny", 72 * 60 * 60 * 1000L)
)

val RESEARCH_PROBE_INTERVAL_OPTIONS = listOf(
    SyncIntervalOption("5 minut", 5 * 60 * 1000L),
    SyncIntervalOption("10 minut", 10 * 60 * 1000L),
    SyncIntervalOption("15 minut (zalecane)", 15 * 60 * 1000L),
    SyncIntervalOption("30 minut", 30 * 60 * 1000L),
    SyncIntervalOption("1 godzina", 60 * 60 * 1000L)
)

class AppSettingsManager(
    context: Context? = null,
    sharedPreferences: SharedPreferences? = null
) {

    private val prefs: SharedPreferences? =
        sharedPreferences ?: context?.getSharedPreferences("pqchat_settings", Context.MODE_PRIVATE)

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

    private val _imageMaxEdge = MutableStateFlow(
        prefs?.getInt(KEY_IMAGE_MAX_EDGE, DefaultImageCompression.DEFAULT_MAX_EDGE) ?: DefaultImageCompression.DEFAULT_MAX_EDGE
    )
    val imageMaxEdge: StateFlow<Int> = _imageMaxEdge.asStateFlow()

    private val _imageColorCount = MutableStateFlow(
        prefs?.getInt(KEY_IMAGE_COLOR_COUNT, DefaultImageCompression.DEFAULT_COLOR_COUNT) ?: DefaultImageCompression.DEFAULT_COLOR_COUNT
    )
    val imageColorCount: StateFlow<Int> = _imageColorCount.asStateFlow()

    private val _isCrowdsourcedRepublishEnabled = MutableStateFlow(
        prefs?.getBoolean(KEY_CROWDSOURCED_REPUBLISH, true) ?: true
    )
    val isCrowdsourcedRepublishEnabled: StateFlow<Boolean> = _isCrowdsourcedRepublishEnabled.asStateFlow()

    private val _isTorEnabled = MutableStateFlow(
        prefs?.getBoolean(KEY_TOR_ENABLED, false) ?: false
    )
    val isTorEnabled: StateFlow<Boolean> = _isTorEnabled.asStateFlow()

    private val _isBiometricLockEnabled = MutableStateFlow(
        prefs?.getBoolean(KEY_BIOMETRIC_LOCK, false) ?: false
    )
    val isBiometricLockEnabled: StateFlow<Boolean> = _isBiometricLockEnabled.asStateFlow()

    private val _isAppLockPinSet = MutableStateFlow(
        prefs?.getString(KEY_APP_LOCK_PIN_HASH, null) != null
    )
    val isAppLockPinSet: StateFlow<Boolean> = _isAppLockPinSet.asStateFlow()

    private val _isDuressPinSet = MutableStateFlow(
        prefs?.getString(KEY_DURESS_PIN_HASH, null) != null
    )
    val isDuressPinSet: StateFlow<Boolean> = _isDuressPinSet.asStateFlow()

    private val _isDuressActive = MutableStateFlow(
        prefs?.getBoolean(KEY_IS_DURESS_ACTIVE, false) ?: false
    )
    val isDuressActive: StateFlow<Boolean> = _isDuressActive.asStateFlow()

    // Master's thesis anonymous research telemetry (default FALSE, explicitly opt-in)
    private val _isAnonymousStatsEnabled = MutableStateFlow(
        prefs?.getBoolean(KEY_ANONYMOUS_STATS, false) ?: false
    )
    val isAnonymousStatsEnabled: StateFlow<Boolean> = _isAnonymousStatsEnabled.asStateFlow()

    private val _statsProbeIntervalMs = MutableStateFlow(
        prefs?.getLong(KEY_STATS_PROBE_INTERVAL, 15 * 60 * 1000L) ?: (15 * 60 * 1000L)
    )
    val statsProbeIntervalMs: StateFlow<Long> = _statsProbeIntervalMs.asStateFlow()

    // Strict Poisson Traffic Shaping (default TRUE, proactive privacy defense against traffic analysis)
    private val _isStrictPoissonShapingEnabled = MutableStateFlow(
        prefs?.getBoolean(KEY_STRICT_POISSON_SHAPING, true) ?: true
    )
    val isStrictPoissonShapingEnabled: StateFlow<Boolean> = _isStrictPoissonShapingEnabled.asStateFlow()

    // Dead Man's Switch / Safety Canary configuration
    private val _isDeadManSwitchEnabled = MutableStateFlow(
        prefs?.getBoolean(KEY_DEAD_MAN_SWITCH_ENABLED, false) ?: false
    )
    val isDeadManSwitchEnabled: StateFlow<Boolean> = _isDeadManSwitchEnabled.asStateFlow()

    private val _deadManSwitchTimeoutHours = MutableStateFlow(
        prefs?.getInt(KEY_DEAD_MAN_TIMEOUT_HOURS, 24) ?: 24
    )
    val deadManSwitchTimeoutHours: StateFlow<Int> = _deadManSwitchTimeoutHours.asStateFlow()

    private val _deadManTrustedContactIds = MutableStateFlow<Set<String>>(
        prefs?.getStringSet(KEY_DEAD_MAN_TRUSTED_CONTACTS, emptySet()) ?: emptySet()
    )
    val deadManTrustedContactIds: StateFlow<Set<String>> = _deadManTrustedContactIds.asStateFlow()

    private val _deadManEmergencyNote = MutableStateFlow(
        prefs?.getString(KEY_DEAD_MAN_EMERGENCY_NOTE, "Safety canary alert: User inactivity threshold reached or emergency SOS triggered.")
            ?: "Safety canary alert: User inactivity threshold reached or emergency SOS triggered."
    )
    val deadManEmergencyNote: StateFlow<String> = _deadManEmergencyNote.asStateFlow()

    private val _lastUserActivityTimestamp = MutableStateFlow(
        prefs?.getLong(KEY_DEAD_MAN_LAST_ACTIVITY, System.currentTimeMillis()) ?: System.currentTimeMillis()
    )
    val lastUserActivityTimestamp: StateFlow<Long> = _lastUserActivityTimestamp.asStateFlow()

    private val _isCanaryTriggered = MutableStateFlow(
        prefs?.getBoolean(KEY_CANARY_TRIGGERED, false) ?: false
    )
    val isCanaryTriggered: StateFlow<Boolean> = _isCanaryTriggered.asStateFlow()

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

    fun setImageMaxEdge(maxEdge: Int) {
        val clamped = maxEdge.coerceIn(DefaultImageCompression.MIN_MAX_EDGE, DefaultImageCompression.MAX_MAX_EDGE)
        prefs?.edit()?.putInt(KEY_IMAGE_MAX_EDGE, clamped)?.apply()
        _imageMaxEdge.value = clamped
    }

    fun setImageColorCount(count: Int) {
        val clamped = count.coerceIn(DefaultImageCompression.MIN_COLORS, DefaultImageCompression.MAX_COLORS)
        prefs?.edit()?.putInt(KEY_IMAGE_COLOR_COUNT, clamped)?.apply()
        _imageColorCount.value = clamped
    }

    fun setCrowdsourcedRepublishEnabled(enabled: Boolean) {
        prefs?.edit()?.putBoolean(KEY_CROWDSOURCED_REPUBLISH, enabled)?.apply()
        _isCrowdsourcedRepublishEnabled.value = enabled
    }

    fun setTorEnabled(enabled: Boolean) {
        prefs?.edit()?.putBoolean(KEY_TOR_ENABLED, enabled)?.apply()
        _isTorEnabled.value = enabled
    }

    fun setBiometricLockEnabled(enabled: Boolean) {
        prefs?.edit()?.putBoolean(KEY_BIOMETRIC_LOCK, enabled)?.apply()
        _isBiometricLockEnabled.value = enabled
    }

    /**
     * Hashes a PIN with a salt using SHA-256.
     */
    fun hashPin(pin: String, salt: ByteArray): ByteArray {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update(salt)
        return digest.digest(pin.toByteArray(Charsets.UTF_8))
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val hexChars = "0123456789abcdef"
        val result = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val i = b.toInt() and 0xFF
            result.append(hexChars[i ushr 4])
            result.append(hexChars[i and 0x0F])
        }
        return result.toString()
    }

    private fun hexToBytes(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }

    fun setAppLockPin(pin: String?) {
        val editor = prefs?.edit()
        if (pin.isNullOrBlank()) {
            editor?.remove(KEY_APP_LOCK_PIN_HASH)
            editor?.remove(KEY_APP_LOCK_PIN_SALT)
            editor?.apply()
            _isAppLockPinSet.value = false
        } else {
            val salt = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
            val hash = hashPin(pin.trim(), salt)
            editor?.putString(KEY_APP_LOCK_PIN_SALT, bytesToHex(salt))
            editor?.putString(KEY_APP_LOCK_PIN_HASH, bytesToHex(hash))
            editor?.apply()
            _isAppLockPinSet.value = true
        }
    }

    fun setDuressPin(pin: String?) {
        val editor = prefs?.edit()
        if (pin.isNullOrBlank()) {
            editor?.remove(KEY_DURESS_PIN_HASH)
            editor?.remove(KEY_DURESS_PIN_SALT)
            editor?.apply()
            _isDuressPinSet.value = false
        } else {
            val salt = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
            val hash = hashPin(pin.trim(), salt)
            editor?.putString(KEY_DURESS_PIN_SALT, bytesToHex(salt))
            editor?.putString(KEY_DURESS_PIN_HASH, bytesToHex(hash))
            editor?.apply()
            _isDuressPinSet.value = true
        }
    }

    fun setDuressActive(active: Boolean) {
        prefs?.edit()?.putBoolean(KEY_IS_DURESS_ACTIVE, active)?.apply()
        _isDuressActive.value = active
    }

    fun clearDuressActive() {
        setDuressActive(false)
    }

    fun verifyPin(inputPin: String): PinAuthResult {
        val cleanPin = inputPin.trim()
        if (cleanPin.isEmpty()) return PinAuthResult.INVALID

        val duressHashHex = prefs?.getString(KEY_DURESS_PIN_HASH, null)
        val duressSaltHex = prefs?.getString(KEY_DURESS_PIN_SALT, null)
        if (duressHashHex != null && duressSaltHex != null) {
            val salt = hexToBytes(duressSaltHex)
            val computedHash = bytesToHex(hashPin(cleanPin, salt))
            if (computedHash.equals(duressHashHex, ignoreCase = true)) {
                return PinAuthResult.DURESS_TRIGGERED
            }
        }

        val appLockHashHex = prefs?.getString(KEY_APP_LOCK_PIN_HASH, null)
        val appLockSaltHex = prefs?.getString(KEY_APP_LOCK_PIN_SALT, null)
        if (appLockHashHex != null && appLockSaltHex != null) {
            val salt = hexToBytes(appLockSaltHex)
            val computedHash = bytesToHex(hashPin(cleanPin, salt))
            if (computedHash.equals(appLockHashHex, ignoreCase = true)) {
                return PinAuthResult.NORMAL_UNLOCK
            }
        }

        if (duressHashHex == null && appLockHashHex == null) {
            return PinAuthResult.NO_PIN_SET
        }

        return PinAuthResult.INVALID
    }

    fun setAnonymousStatsEnabled(enabled: Boolean) {
        prefs?.edit()?.putBoolean(KEY_ANONYMOUS_STATS, enabled)?.apply()
        _isAnonymousStatsEnabled.value = enabled
    }

    fun setStatsProbeIntervalMs(millis: Long) {
        prefs?.edit()?.putLong(KEY_STATS_PROBE_INTERVAL, millis)?.apply()
        _statsProbeIntervalMs.value = millis
    }

    fun setStrictPoissonShapingEnabled(enabled: Boolean) {
        prefs?.edit()?.putBoolean(KEY_STRICT_POISSON_SHAPING, enabled)?.apply()
        _isStrictPoissonShapingEnabled.value = enabled
    }

    fun setDeadManSwitchEnabled(enabled: Boolean) {
        prefs?.edit()?.putBoolean(KEY_DEAD_MAN_SWITCH_ENABLED, enabled)?.apply()
        _isDeadManSwitchEnabled.value = enabled
        if (enabled) {
            recordUserActivity()
        }
    }

    fun setDeadManSwitchTimeoutHours(hours: Int) {
        val clamped = hours.coerceIn(1, 720)
        prefs?.edit()?.putInt(KEY_DEAD_MAN_TIMEOUT_HOURS, clamped)?.apply()
        _deadManSwitchTimeoutHours.value = clamped
    }

    fun setDeadManTrustedContactIds(ids: Set<String>) {
        prefs?.edit()?.putStringSet(KEY_DEAD_MAN_TRUSTED_CONTACTS, ids)?.apply()
        _deadManTrustedContactIds.value = ids
    }

    fun addDeadManTrustedContactId(contactId: String) {
        val current = _deadManTrustedContactIds.value.toMutableSet()
        current.add(contactId)
        setDeadManTrustedContactIds(current)
    }

    fun removeDeadManTrustedContactId(contactId: String) {
        val current = _deadManTrustedContactIds.value.toMutableSet()
        current.remove(contactId)
        setDeadManTrustedContactIds(current)
    }

    fun setDeadManEmergencyNote(note: String) {
        prefs?.edit()?.putString(KEY_DEAD_MAN_EMERGENCY_NOTE, note)?.apply()
        _deadManEmergencyNote.value = note
    }

    fun recordUserActivity(timestamp: Long = System.currentTimeMillis()) {
        prefs?.edit()?.putLong(KEY_DEAD_MAN_LAST_ACTIVITY, timestamp)?.apply()
        _lastUserActivityTimestamp.value = timestamp
    }

    fun setCanaryTriggered(triggered: Boolean) {
        prefs?.edit()?.putBoolean(KEY_CANARY_TRIGGERED, triggered)?.apply()
        _isCanaryTriggered.value = triggered
    }

    fun isDeadManSwitchExpired(): Boolean {
        if (!_isDeadManSwitchEnabled.value || _isCanaryTriggered.value) return false
        val timeoutMs = _deadManSwitchTimeoutHours.value * 3600_000L
        val elapsed = System.currentTimeMillis() - _lastUserActivityTimestamp.value
        return elapsed > timeoutMs
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
        private const val KEY_IMAGE_MAX_EDGE = "image_max_edge"
        private const val KEY_IMAGE_COLOR_COUNT = "image_color_count"
        private const val KEY_CROWDSOURCED_REPUBLISH = "crowdsourced_republish_enabled"
        private const val KEY_TOR_ENABLED = "tor_enabled"
        private const val KEY_BIOMETRIC_LOCK = "biometric_lock_enabled"
        private const val KEY_APP_LOCK_PIN_HASH = "app_lock_pin_hash"
        private const val KEY_APP_LOCK_PIN_SALT = "app_lock_pin_salt"
        private const val KEY_DURESS_PIN_HASH = "duress_pin_hash"
        private const val KEY_DURESS_PIN_SALT = "duress_pin_salt"
        private const val KEY_IS_DURESS_ACTIVE = "is_duress_active"
        private const val KEY_ANONYMOUS_STATS = "anonymous_stats_enabled"
        private const val KEY_STATS_PROBE_INTERVAL = "stats_probe_interval"
        private const val KEY_STRICT_POISSON_SHAPING = "strict_poisson_shaping_enabled"
        private const val KEY_DEAD_MAN_SWITCH_ENABLED = "dead_man_switch_enabled"
        private const val KEY_DEAD_MAN_TIMEOUT_HOURS = "dead_man_timeout_hours"
        private const val KEY_DEAD_MAN_TRUSTED_CONTACTS = "dead_man_trusted_contacts"
        private const val KEY_DEAD_MAN_EMERGENCY_NOTE = "dead_man_emergency_note"
        private const val KEY_DEAD_MAN_LAST_ACTIVITY = "dead_man_last_activity"
        private const val KEY_CANARY_TRIGGERED = "canary_triggered"
    }
}

data class DeadManTimeoutOption(
    val label: String,
    val hours: Int
)

val DEAD_MAN_TIMEOUT_OPTIONS = listOf(
    DeadManTimeoutOption("12 hours", 12),
    DeadManTimeoutOption("24 hours (1 day)", 24),
    DeadManTimeoutOption("48 hours (2 days)", 48),
    DeadManTimeoutOption("72 hours (3 days)", 72),
    DeadManTimeoutOption("168 hours (7 days)", 168)
)
