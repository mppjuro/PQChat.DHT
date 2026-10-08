package org.pqchat.dht.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.PowerManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.pqchat.dht.PQChatApplication
import org.pqchat.dht.data.db.AppDatabase
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.leaf.DhtLeafNode

/**
 * BroadcastReceiver triggered by AlarmManager.setAndAllowWhileIdle during Doze mode.
 * Wakes up modem radio and CPU with a transient WakeLock to poll DHT during maintenance windows.
 */
class DhtAlarmReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_DOZE_POLL) return

        val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        val wakeLock = powerManager?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "pqchat:dht_doze_poll")
        wakeLock?.acquire(30_000L) // Max 30s safety timeout

        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val app = context.applicationContext as? PQChatApplication
                val repository = app?.repository ?: run {
                    val db = AppDatabase.getInstance(context.applicationContext)
                    val node = DhtLeafNode(nodeCacheDao = db.dhtNodeCacheDao())
                    ChatRepository(db, node)
                }

                repository.pollAllContactsIncoming()

                // Reschedule for next Doze interval
                app?.pollingScheduler?.scheduleNextDozeAlarm()
            } catch (_: Exception) {
            } finally {
                try {
                    if (wakeLock?.isHeld == true) {
                        wakeLock.release()
                    }
                } catch (_: Exception) {}
                pendingResult.finish()
            }
        }
    }

    companion object {
        const val ACTION_DOZE_POLL = "org.pqchat.dht.ACTION_DOZE_POLL"
    }
}
