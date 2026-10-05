package org.pqchat.dht.traffic

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Adaptive Polling State Machine according to Android Lifecycle and screen state.
 *
 * State 1: Foreground Focus (Active Chat) -> Configurable (Default 10s)
 * State 2: App Active (Other Chat / Contact List) -> Configurable (Default 60s / 1m)
 * State 3: Background Idle (Screen on, app minimized) -> Configurable (Default 300s / 5m)
 * State 4: Deep Sleep / Doze (Screen off) -> Configurable (Default 900s / 15m)
 */
class AdaptivePollingManager(
    private val onPollRequested: suspend (contactId: String?) -> Unit
) {
    enum class PollingState(val label: String) {
        FOREGROUND_CHAT("Foreground Chat"),
        APP_ACTIVE_OTHER("App Active"),
        BACKGROUND_IDLE("Background Idle"),
        DOZE_SLEEP("Deep Sleep / Doze")
    }

    @Volatile var intervalForegroundChatMs: Long = 10_000L
    @Volatile var intervalAppActiveMs: Long = 60_000L
    @Volatile var intervalBackgroundIdleMs: Long = 300_000L
    @Volatile var intervalDozeSleepMs: Long = 900_000L

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var pollingJob: Job? = null

    private val _currentState = MutableStateFlow(PollingState.APP_ACTIVE_OTHER)
    val currentState: StateFlow<PollingState> = _currentState.asStateFlow()

    @Volatile
    var activeChatContactId: String? = null
        private set

    fun updateIntervals(
        foreground: Long,
        appActive: Long,
        bgIdle: Long,
        doze: Long
    ) {
        intervalForegroundChatMs = foreground
        intervalAppActiveMs = appActive
        intervalBackgroundIdleMs = bgIdle
        intervalDozeSleepMs = doze
        restartPollingLoop()
    }

    fun getCurrentIntervalMs(): Long {
        return when (_currentState.value) {
            PollingState.FOREGROUND_CHAT -> intervalForegroundChatMs
            PollingState.APP_ACTIVE_OTHER -> intervalAppActiveMs
            PollingState.BACKGROUND_IDLE -> intervalBackgroundIdleMs
            PollingState.DOZE_SLEEP -> intervalDozeSleepMs
        }
    }

    fun onChatOpened(contactId: String) {
        activeChatContactId = contactId
        transitionTo(PollingState.FOREGROUND_CHAT)
    }

    fun onChatClosed() {
        activeChatContactId = null
        transitionTo(PollingState.APP_ACTIVE_OTHER)
    }

    fun onAppForegrounded() {
        if (activeChatContactId != null) {
            transitionTo(PollingState.FOREGROUND_CHAT)
        } else {
            transitionTo(PollingState.APP_ACTIVE_OTHER)
        }
    }

    fun onAppMinimized() {
        transitionTo(PollingState.BACKGROUND_IDLE)
    }

    fun onDeviceScreenOff() {
        transitionTo(PollingState.DOZE_SLEEP)
    }

    @Synchronized
    fun transitionTo(newState: PollingState) {
        if (_currentState.value == newState && pollingJob?.isActive == true) return
        _currentState.value = newState
        restartPollingLoop()
    }

    private fun restartPollingLoop() {
        pollingJob?.cancel()
        val state = _currentState.value

        // In DOZE_SLEEP, polling is primarily driven by WorkManager / AlarmManager
        if (state == PollingState.DOZE_SLEEP) return

        pollingJob = scope.launch {
            while (isActive) {
                try {
                    onPollRequested(activeChatContactId)
                } catch (_: Exception) {}
                delay(getCurrentIntervalMs())
            }
        }
    }

    fun stop() {
        pollingJob?.cancel()
        scope.cancel()
    }
}
