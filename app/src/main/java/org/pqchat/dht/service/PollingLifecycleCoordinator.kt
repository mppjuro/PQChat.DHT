package org.pqchat.dht.service

import android.content.Context
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner

/**
 * Unified Lifecycle and Screen State Coordinator for Adaptive Polling.
 *
 * Coordinates:
 * 1. ProcessLifecycleOwner (Process-level foreground/background transitions across Activities)
 * 2. Screen state (dynamic BroadcastReceiver for ACTION_SCREEN_OFF and ACTION_SCREEN_ON)
 * 3. PowerManager.isInteractive (Hardware screen state query)
 *
 * Single Source of Truth:
 * Ensures all transitions between the 4 polling states (AGENTS.md Section 6) are evaluated
 * consistently in one place without race conditions or conflicting callbacks:
 * - State 1: FOREGROUND_CHAT (10s) -> Screen ON, App Foreground, Active Chat selected
 * - State 2: APP_ACTIVE_OTHER (1m) -> Screen ON, App Foreground, Contact List / Settings
 * - State 3: BACKGROUND_IDLE (5m) -> Screen ON, App Minimized (Device in use)
 * - State 4: DOZE_SLEEP (15m) -> Screen OFF (Device locked/asleep, loop paused, driven by AlarmManager/WorkManager)
 */
class PollingLifecycleCoordinator(
    private val context: Context,
    private val pollingScheduler: PollingScheduler,
    private val lifecycleOwner: LifecycleOwner = ProcessLifecycleOwner.get()
) : DefaultLifecycleObserver {

    internal var screenStateReceiver: ScreenStateReceiver? = null
        private set
    private var isRegistered = false

    val currentState: org.pqchat.dht.traffic.AdaptivePollingManager.PollingState
        get() = pollingScheduler.pollingManager.currentState.value

    companion object {
        private const val TAG = "PollingLifecycleCoordinator"
    }

    internal fun notifyScreenOff() {
        screenStateReceiver?.onReceive(context, android.content.Intent(android.content.Intent.ACTION_SCREEN_OFF))
    }

    internal fun notifyScreenOn() {
        screenStateReceiver?.onReceive(context, android.content.Intent(android.content.Intent.ACTION_SCREEN_ON))
    }

    /**
     * Starts observation of process lifecycle and registers dynamic screen state receiver.
     */
    @Synchronized
    fun start() {
        if (isRegistered) return
        isRegistered = true

        // 1. Query initial hardware screen state and process state
        val isScreenOn = isScreenInteractive(context)
        val isForeground = try {
            lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to query initial process lifecycle state", e)
            false
        }

        Log.i(TAG, "Starting polling lifecycle coordinator: isScreenOn=$isScreenOn, isForeground=$isForeground")
        pollingScheduler.pollingManager.updateInputs(
            isScreenInteractive = isScreenOn,
            isAppForeground = isForeground
        )

        // 2. Register ProcessLifecycleOwner observer
        try {
            lifecycleOwner.lifecycle.addObserver(this)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to add lifecycle observer", e)
        }

        // 3. Register dynamic ScreenStateReceiver
        screenStateReceiver = ScreenStateReceiver(
            pollingScheduler = pollingScheduler,
            isAppForegroundProvider = {
                try {
                    lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
                } catch (_: Exception) {
                    false
                }
            }
        )
        try {
            androidx.core.content.ContextCompat.registerReceiver(
                context,
                screenStateReceiver,
                ScreenStateReceiver.createIntentFilter(),
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register ScreenStateReceiver", e)
        }
    }

    /**
     * Stops observation and unregisters receivers.
     */
    @Synchronized
    fun stop() {
        if (!isRegistered) return
        isRegistered = false

        try {
            lifecycleOwner.lifecycle.removeObserver(this)
        } catch (_: Exception) {}

        screenStateReceiver?.let { receiver ->
            try {
                context.unregisterReceiver(receiver)
            } catch (_: Exception) {}
        }
        screenStateReceiver = null
    }

    override fun onStart(owner: LifecycleOwner) {
        Log.d(TAG, "Process entered foreground (onStart)")
        val isScreenOn = isScreenInteractive(context)
        pollingScheduler.pollingManager.updateInputs(
            isScreenInteractive = isScreenOn,
            isAppForeground = true
        )
    }

    override fun onStop(owner: LifecycleOwner) {
        Log.d(TAG, "Process entered background (onStop)")
        val isScreenOn = isScreenInteractive(context)
        pollingScheduler.pollingManager.updateInputs(
            isScreenInteractive = isScreenOn,
            isAppForeground = false
        )
    }

    private fun isScreenInteractive(ctx: Context): Boolean {
        return ScreenStateReceiver.isScreenInteractive(ctx)
    }
}
