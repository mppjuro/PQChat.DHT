package org.pqchat.dht.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.PowerManager
import android.util.Log
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner

/**
 * Dynamically registered BroadcastReceiver that monitors device screen state.
 *
 * Transitions the AdaptivePollingManager state:
 * - ACTION_SCREEN_OFF: Transitions to DOZE_SLEEP and schedules next Doze alarm.
 * - ACTION_SCREEN_ON: Transitions to FOREGROUND_CHAT / APP_ACTIVE if the app is currently visible,
 *   or to BACKGROUND_IDLE if the app is minimized but device is active.
 */
class ScreenStateReceiver(
    private val onScreenOffCallback: () -> Unit,
    private val onScreenOnCallback: (isAppForegrounded: Boolean) -> Unit,
    private val isAppForegroundProvider: () -> Boolean = {
        try {
            ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to query ProcessLifecycleOwner state", e)
            false
        }
    }
) : BroadcastReceiver() {

    constructor(
        pollingScheduler: PollingScheduler,
        isAppForegroundProvider: () -> Boolean = {
            try {
                ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to query ProcessLifecycleOwner state", e)
                false
            }
        }
    ) : this(
        onScreenOffCallback = {
            Log.i(TAG, "Screen turned OFF -> transitioning to DOZE_SLEEP")
            pollingScheduler.onDeviceScreenOff()
        },
        onScreenOnCallback = { isForegrounded ->
            Log.i(TAG, "Screen turned ON (isForegrounded=$isForegrounded)")
            pollingScheduler.onDeviceScreenOn(isForegrounded)
        },
        isAppForegroundProvider = isAppForegroundProvider
    )

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        Log.d(TAG, "Screen state broadcast received: $action")

        when (action) {
            Intent.ACTION_SCREEN_OFF -> {
                onScreenOffCallback()
            }
            Intent.ACTION_SCREEN_ON -> {
                val isAppForegrounded = isAppForegroundProvider()
                onScreenOnCallback(isAppForegrounded)
            }
        }
    }

    companion object {
        private const val TAG = "ScreenStateReceiver"

        fun createIntentFilter(): IntentFilter {
            return IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_SCREEN_ON)
            }
        }

        fun isScreenInteractive(context: Context): Boolean {
            val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            return powerManager?.isInteractive ?: true
        }
    }
}
