package org.pqchat.dht.service

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import kotlinx.coroutines.*
import org.pqchat.dht.PQChatApplication
import org.pqchat.dht.data.db.AppDatabase
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.ui.util.NotificationHelper

/**
 * Foreground Service maintaining a continuous, low-latency (10s) DHT listener loop
 * when enabled by user settings or active foreground monitoring.
 */
class ChatHeadService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var pollingJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        val notification = NotificationHelper.createForegroundNotification(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NotificationHelper.FOREGROUND_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NotificationHelper.FOREGROUND_NOTIFICATION_ID, notification)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (pollingJob?.isActive != true) {
            startContinuousLoop()
        }
        return START_STICKY
    }

    private fun startContinuousLoop() {
        pollingJob?.cancel()
        pollingJob = serviceScope.launch {
            val app = applicationContext as? PQChatApplication
            val repository = app?.repository ?: run {
                val db = AppDatabase.getInstance(applicationContext)
                val node = DhtLeafNode(nodeCacheDao = db.dhtNodeCacheDao())
                ChatRepository(db, node)
            }

            while (isActive) {
                try {
                    repository.pollAllContactsIncoming()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {}

                val interval = app?.settingsManager?.intervalForegroundChat?.value ?: 10_000L
                delay(interval.coerceAtLeast(5_000L))
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        pollingJob?.cancel()
        serviceScope.cancel()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
