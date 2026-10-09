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
    private var onIdlePreWarm: (suspend (contactId: String?) -> Unit)? = null

    constructor(
        onPollRequested: suspend (contactId: String?) -> Unit,
        onIdlePreWarm: (suspend (contactId: String?) -> Unit)?
    ) : this(onPollRequested) {
        this.onIdlePreWarm = onIdlePreWarm
    }
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
    private var immediateSignal: CompletableDeferred<Unit>? = null

    private val _currentState = MutableStateFlow(PollingState.APP_ACTIVE_OTHER)
    val currentState: StateFlow<PollingState> = _currentState.asStateFlow()

    /** Milliseconds remaining until the next DHT poll. Updated every 250 ms. */
    private val _nextPollInMs = MutableStateFlow(0L)
    val nextPollInMs: StateFlow<Long> = _nextPollInMs.asStateFlow()

    /** Indicates whether a DHT poll is currently running. */
    private val _isSyncing = MutableStateFlow(true)
    val isSyncing: StateFlow<Boolean> = _isSyncing.asStateFlow()

    @Volatile
    private var forceImmediatePoll = false

    @Volatile
    var immediatePollTimeoutMs: Long = 15_000L

    /** Signal the polling loop to fire a poll immediately (resets the countdown). */
    fun triggerImmediatePoll() {
        if (_isSyncing.value) return
        _isSyncing.value = true

        val job = pollingJob
        if (job != null && job.isActive) {
            forceImmediatePoll = true
            immediateSignal?.complete(Unit)
        } else {
            // In DOZE_SLEEP or when loop is paused, launch a one-shot poll with timeout protection
            scope.launch {
                try {
                    withTimeoutOrNull(immediatePollTimeoutMs) {
                        onPollRequested(activeChatContactId)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                } finally {
                    lastPollFinishedTimestamp = System.currentTimeMillis()
                    _isSyncing.value = false
                }
            }
        }
    }

    /**
     * Random jitter ratio applied to polling intervals (±30% per docs/threat_model.md).
     * Distorts polling periodicity to prevent timing correlation attacks.
     */
    @Volatile
    var jitterRatio: Double = 0.30

    @Volatile
    private var currentCycleIntervalMs: Long = 0L

    /**
     * Computes jittered interval: interval * (1 + Uniform(-jitterRatio, +jitterRatio)).
     * E.g. for 0.30, resulting interval is within [0.70 * base, 1.30 * base].
     */
    fun computeJitteredInterval(baseIntervalMs: Long, customJitterRatio: Double = jitterRatio): Long {
        if (customJitterRatio <= 0.0) return baseIntervalMs
        val factor = (1.0 - customJitterRatio) + (org.pqchat.dht.crypto.CryptoUtils.secureRandom.nextDouble() * (2.0 * customJitterRatio))
        return (baseIntervalMs * factor).toLong().coerceAtLeast(100L)
    }

    @Volatile
    var activeChatContactId: String? = null
        private set

    fun updateIntervals(
        foreground: Long,
        appActive: Long,
        bgIdle: Long,
        doze: Long
    ) {
        val changed = intervalForegroundChatMs != foreground ||
                intervalAppActiveMs != appActive ||
                intervalBackgroundIdleMs != bgIdle ||
                intervalDozeSleepMs != doze
        intervalForegroundChatMs = foreground
        intervalAppActiveMs = appActive
        intervalBackgroundIdleMs = bgIdle
        intervalDozeSleepMs = doze
        if (changed && !_isSyncing.value) {
            val base = getCurrentIntervalMs()
            currentCycleIntervalMs = computeJitteredInterval(base)
            immediateSignal?.complete(Unit)
        }
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

    @Volatile
    private var lastPollFinishedTimestamp: Long = 0L

    @Synchronized
    fun transitionTo(newState: PollingState) {
        val stateChanged = _currentState.value != newState
        _currentState.value = newState

        if (newState == PollingState.DOZE_SLEEP) {
            pollingJob?.cancel()
            _isSyncing.value = false
            _nextPollInMs.value = -1L
            return
        }

        if (pollingJob?.isActive == true) {
            if (!stateChanged) return
            // Screen or state changed while loop is active:
            // Do NOT unconditionally sync immediately. Instead, recalculate time to next sync.
            // If the time elapsed since last poll is already >= new interval, trigger immediate poll now.
            val interval = getCurrentIntervalMs()
            val timeSinceLastPoll = System.currentTimeMillis() - lastPollFinishedTimestamp
            if (timeSinceLastPoll >= interval) {
                // Necessary to sync immediately
                triggerImmediatePoll()
            } else {
                // Recalculate remaining countdown with jitter without forcing immediate poll
                val jittered = computeJitteredInterval(interval)
                currentCycleIntervalMs = jittered
                val remaining = (jittered - timeSinceLastPoll).coerceAtLeast(0L)
                _nextPollInMs.value = remaining
                immediateSignal?.complete(Unit)
            }
        } else {
            restartPollingLoop()
        }
    }

    private fun restartPollingLoop() {
        val oldJob = pollingJob
        oldJob?.cancel()
        val state = _currentState.value

        // In DOZE_SLEEP, polling is primarily driven by WorkManager / AlarmManager
        if (state == PollingState.DOZE_SLEEP) {
            _isSyncing.value = false
            _nextPollInMs.value = -1L
            return
        }

        _isSyncing.value = true
        pollingJob = scope.launch {
            val myJob = coroutineContext.job
            while (isActive) {
                _isSyncing.value = true
                try {
                    withTimeoutOrNull(30_000L) {
                        onPollRequested(activeChatContactId)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                } finally {
                    lastPollFinishedTimestamp = System.currentTimeMillis()
                    if (pollingJob == myJob) {
                        val base = getCurrentIntervalMs()
                        val scheduledInterval = computeJitteredInterval(base)
                        currentCycleIntervalMs = scheduledInterval
                        _nextPollInMs.value = scheduledInterval
                        _isSyncing.value = false
                    }
                }

                // During idle period between polls, run pre-warming in background to warm routes before next poll
                if (onIdlePreWarm != null && isActive) {
                    scope.launch {
                        try {
                            onIdlePreWarm?.invoke(activeChatContactId)
                        } catch (_: Exception) {}
                    }
                }

                // Countdown loop; recalculates deadline whenever interval changes or state transitions occur
                while (isActive) {
                    if (forceImmediatePoll) {
                        forceImmediatePoll = false
                        break
                    }
                    val targetInterval = if (currentCycleIntervalMs > 0L) currentCycleIntervalMs else getCurrentIntervalMs()
                    val timeSinceLastPoll = System.currentTimeMillis() - lastPollFinishedTimestamp
                    val remaining = (targetInterval - timeSinceLastPoll).coerceAtLeast(0L)
                    if (remaining <= 0L) {
                        // Interval has elapsed, proceed to next poll
                        break
                    }
                    _nextPollInMs.value = remaining

                    val signal = CompletableDeferred<Unit>()
                    immediateSignal = signal
                    try {
                        withTimeoutOrNull(minOf(remaining, 250L)) { signal.await() }
                    } finally {
                        immediateSignal = null
                    }
                }
            }
        }
    }

    fun stop() {
        val job = pollingJob
        pollingJob = null
        job?.cancel()
        _isSyncing.value = false
        scope.cancel()
    }
}
