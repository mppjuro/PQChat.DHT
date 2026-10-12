package org.pqchat.dht.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.pqchat.dht.PQChatApplication
import org.pqchat.dht.traffic.PollingWorker

/**
 * BroadcastReceiver triggered when device boot completes or the application package is updated.
 *
 * Restores background execution capabilities:
 * 1. Reschedules AlarmManager Doze polling alarm (cleared by OS during reboot).
 * 2. Re-enqueues WorkManager periodic maintenance tasks.
 * 3. Restores republish policy schedule for undelivered messages.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        Log.i(TAG, "Received boot event broadcast: $action")

        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }

        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // 1. Re-enqueue periodic WorkManager task
                PollingWorker.enqueuePeriodicWork(context)

                // 2. Reschedule AlarmManager Doze maintenance alarm
                val app = context.applicationContext as? PQChatApplication
                app?.pollingScheduler?.let { scheduler ->
                    scheduler.scheduleNextDozeAlarm()
                    scheduler.applyRepublishSchedule()
                }
                Log.i(TAG, "Successfully restored background tasks and Doze alarms after boot")
            } catch (e: Exception) {
                Log.e(TAG, "Error restoring background tasks on boot", e)
            } finally {
                pendingResult.finish()
            }
        }
    }

    companion object {
        private const val TAG = "BootReceiver"
    }
}
