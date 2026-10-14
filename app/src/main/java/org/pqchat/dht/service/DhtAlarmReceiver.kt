package org.pqchat.dht.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.PowerManager
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.pqchat.dht.PQChatApplication

/**
 * BroadcastReceiver triggered by AlarmManager.setAndAllowWhileIdle during Doze mode.
 * Wakes up modem radio and CPU with a transient WakeLock to poll DHT during maintenance windows.
 */
class DhtAlarmReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != ACTION_DOZE_POLL) return

        val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        val wakeLock = powerManager?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "pqchat:dht_doze_poll")
        var lockStartTime = 0L
        try {
            wakeLock?.acquire(30_000L) // Max 30s safety timeout
            lockStartTime = org.pqchat.dht.debug.AndroidResourceProfiler.onWakeLockAcquired("pqchat:dht_doze_poll")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to acquire wake lock for Doze poll", e)
        }

        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            val app = context.applicationContext as? PQChatApplication
            try {
                val repository = app?.repository
                if (repository == null) {
                    Log.w(TAG, "PQChatApplication repository not initialized, skipping Doze poll")
                    return@launch
                }

                repository.pollAllContactsIncoming()
            } catch (e: Exception) {
                Log.e(TAG, "Error during Doze DHT poll pass", e)
            } finally {
                // Ensure the next Doze alarm is scheduled even if polling fails or throws
                try {
                    app?.pollingScheduler?.scheduleNextDozeAlarm()
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to reschedule next Doze alarm in finally", e)
                }

                try {
                    if (wakeLock?.isHeld == true) {
                        wakeLock.release()
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to release wake lock", e)
                } finally {
                    if (lockStartTime > 0L) {
                        org.pqchat.dht.debug.AndroidResourceProfiler.onWakeLockReleased(lockStartTime, "pqchat:dht_doze_poll")
                    }
                }
                pendingResult.finish()
            }
        }
    }

    companion object {
        private const val TAG = "DhtAlarmReceiver"
        const val ACTION_DOZE_POLL = "org.pqchat.dht.ACTION_DOZE_POLL"
    }
}
