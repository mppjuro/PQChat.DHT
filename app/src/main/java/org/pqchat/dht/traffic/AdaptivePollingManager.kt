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
    var trafficGenerator: PoissonTrafficGenerator? = null
    var blindRepublishPool: BlindRepublishPool = BlindRepublishPool.defaultInstance
    @Volatile var isCrowdsourcedRepublishEnabled: Boolean = true
    var onCoverTrafficTick: (suspend () -> Unit)? = null
    var onKeepalivePingRequested: (suspend () -> Unit)? = null
    private var keepaliveJob: Job? = null
    @Volatile var pollBatchSize: Int = N_POLL_TARGETS

    constructor(
        onPollRequested: suspend (contactId: String?) -> Unit,
        onIdlePreWarm: (suspend (contactId: String?) -> Unit)?,
        trafficGenerator: PoissonTrafficGenerator? = null,
        blindRepublishPool: BlindRepublishPool = BlindRepublishPool.defaultInstance
    ) : this(onPollRequested) {
        this.onIdlePreWarm = onIdlePreWarm
        this.trafficGenerator = trafficGenerator
        this.blindRepublishPool = blindRepublishPool
    }

    /**
     * Executes a cover traffic tick:
     * If crowdsourced republishing is enabled and BlindRepublishPool has entries,
     * republishes a random third-party BEP 44 packet.
     * Otherwise, sends a synthetic decoy dummy packet.
     */
    suspend fun executeCoverTrafficTick(dhtClient: org.pqchat.dht.dht.leaf.DhtClient? = null) {
        val tg = trafficGenerator
        if (tg != null) {
            tg.processCoverTrafficTick()
            return
        }
        val customHook = onCoverTrafficTick
        if (customHook != null) {
            customHook.invoke()
            return
        }
        if (dhtClient != null) {
            if (isCrowdsourcedRepublishEnabled && blindRepublishPool.size() > 0) {
                val entry = blindRepublishPool.sampleRandomEntry()
                if (entry != null) {
                    val tStart = System.currentTimeMillis()
                    val ok = dhtClient.putMutablePreSigned(
                        target = entry.target,
                        v = entry.v,
                        seq = entry.seq,
                        salt = entry.salt,
                        pk = entry.publicKey,
                        sig = entry.sig,
                        skipLocalStore = false
                    )
                    val rttMs = System.currentTimeMillis() - tStart
                    try {
                        org.pqchat.dht.PQChatApplication.instance.researchTelemetryManager.recordPacketEvent(
                            role = org.pqchat.dht.research.PacketRole.CROWD_REPUBLISH,
                            target = entry.target,
                            seqNum = entry.seq,
                            payloadBytes = entry.v.size,
                            rttMs = rttMs,
                            nodesQueried = dhtClient.lastNodesQueried,
                            nodesResponded = dhtClient.lastNodesResponded,
                            lookupHops = dhtClient.lastLookupHops,
                            success = ok
                        )
                    } catch (_: Throwable) {}
                    return
                }
            }
            val dummyTarget = dhtClient.sendCoverTrafficDummy()
            if (dummyTarget != null) {
                try {
                    org.pqchat.dht.PQChatApplication.instance.researchTelemetryManager.recordPacketEvent(
                        role = org.pqchat.dht.research.PacketRole.COVER_DUMMY_SENT,
                        target = dummyTarget,
                        payloadBytes = 900,
                        nodesQueried = dhtClient.lastNodesQueried,
                        nodesResponded = dhtClient.lastNodesResponded,
                        lookupHops = dhtClient.lastLookupHops,
                        success = true
                    )
                } catch (_: Throwable) {}
            }
        }
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
                } catch (e: Exception) {
                    android.util.Log.e("AdaptivePollingManager", "Immediate poll request failed", e)
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

    @Volatile
    var isScreenInteractive: Boolean = true
        private set

    @Volatile
    var isAppForeground: Boolean = true
        private set

    companion object {
        const val N_POLL_TARGETS = 8
        const val DEFAULT_POLL_BATCH_SIZE = N_POLL_TARGETS

        /**
         * Resolves the target PollingState based on the triplet:
         * (isScreenInteractive, isAppForeground, activeChatContactId).
         *
         * Pure function with deterministic resolution per AGENTS.md Section 6:
         * 1. Screen OFF (!isScreenInteractive) -> DOZE_SLEEP (15m, device asleep/locked, loop paused).
         * 2. Screen ON, App in background (!isAppForeground) -> BACKGROUND_IDLE (5m, device active, app minimized).
         * 3. Screen ON, App in foreground, Chat selected (activeChatContactId != null) -> FOREGROUND_CHAT (10s).
         * 4. Screen ON, App in foreground, No chat selected (activeChatContactId == null) -> APP_ACTIVE_OTHER (1m).
         */
        fun resolvePollingState(
            isScreenInteractive: Boolean,
            isAppForeground: Boolean,
            activeChatContactId: String?
        ): PollingState {
            return when {
                !isScreenInteractive -> PollingState.DOZE_SLEEP
                !isAppForeground -> PollingState.BACKGROUND_IDLE
                activeChatContactId != null -> PollingState.FOREGROUND_CHAT
                else -> PollingState.APP_ACTIVE_OTHER
            }
        }
    }

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

    @Synchronized
    fun evaluateState(): PollingState {
        val target = resolvePollingState(isScreenInteractive, isAppForeground, activeChatContactId)
        transitionTo(target)
        return target
    }

    fun onChatOpened(contactId: String) {
        activeChatContactId = contactId
        evaluateState()
    }

    fun onChatClosed() {
        activeChatContactId = null
        evaluateState()
    }

    fun onAppForegrounded() {
        isAppForeground = true
        evaluateState()
    }

    fun onAppMinimized() {
        isAppForeground = false
        evaluateState()
    }

    fun onDeviceScreenOff() {
        isScreenInteractive = false
        evaluateState()
    }

    fun onDeviceScreenOn() {
        isScreenInteractive = true
        evaluateState()
    }

    fun setScreenInteractive(interactive: Boolean) {
        isScreenInteractive = interactive
        evaluateState()
    }

    fun setAppForeground(foreground: Boolean) {
        isAppForeground = foreground
        evaluateState()
    }

    fun updateInputs(
        isScreenInteractive: Boolean = this.isScreenInteractive,
        isAppForeground: Boolean = this.isAppForeground,
        activeChatContactId: String? = this.activeChatContactId
    ): PollingState {
        this.isScreenInteractive = isScreenInteractive
        this.isAppForeground = isAppForeground
        this.activeChatContactId = activeChatContactId
        return evaluateState()
    }

    @Volatile
    private var lastPollFinishedTimestamp: Long = 0L

    @Synchronized
    fun transitionTo(newState: PollingState) {
        val stateChanged = _currentState.value != newState
        _currentState.value = newState

        if (newState == PollingState.FOREGROUND_CHAT) {
            startKeepaliveLoop()
        } else {
            stopKeepaliveLoop()
        }

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
                } catch (e: Exception) {
                    android.util.Log.e("AdaptivePollingManager", "Adaptive poll cycle failed", e)
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
                        } catch (e: Exception) {
                            android.util.Log.w("AdaptivePollingManager", "Idle pre-warming failed", e)
                        }
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

    private fun startKeepaliveLoop() {
        keepaliveJob?.cancel()
        keepaliveJob = scope.launch {
            while (isActive && _currentState.value == PollingState.FOREGROUND_CHAT) {
                // Keepalive 20-25 seconds (randomized between 20000 and 25000 ms)
                // Preserves carrier CGNAT / LTE UDP NAT mapping tables (which timeout after 30s)
                val delayMs = 20_000L + (org.pqchat.dht.crypto.CryptoUtils.secureRandom.nextDouble() * 5_000L).toLong()
                delay(delayMs)
                if (isActive && _currentState.value == PollingState.FOREGROUND_CHAT) {
                    try {
                        onKeepalivePingRequested?.invoke()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        android.util.Log.w("AdaptivePollingManager", "Keepalive ping failed", e)
                    }
                }
            }
        }
    }

    private fun stopKeepaliveLoop() {
        keepaliveJob?.cancel()
        keepaliveJob = null
    }

    fun stop() {
        stopKeepaliveLoop()
        val job = pollingJob
        pollingJob = null
        job?.cancel()
        _isSyncing.value = false
        scope.cancel()
    }
}

