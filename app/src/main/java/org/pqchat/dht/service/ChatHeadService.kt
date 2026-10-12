package org.pqchat.dht.service

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import kotlinx.coroutines.*
import org.pqchat.dht.PQChatApplication
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
            val repository = app?.repository
            if (repository == null) {
                Log.e(TAG, "PQChatApplication repository not initialized, stopping ChatHeadService")
                stopSelf()
                return@launch
            }

            while (isActive) {
                try {
                    repository.pollAllContactsIncoming()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e(TAG, "Error in continuous polling loop", e)
                }

                val interval = app.settingsManager.intervalForegroundChat.value
                delay(interval.coerceAtLeast(5_000L))
            }
        }
    }

    /**
     * Android 15 (API 35+) Foreground Service timeout callback for FOREGROUND_SERVICE_TYPE_DATA_SYNC.
     * Prevents system ANR/crash when dataSync foreground service reaches its execution budget.
     */
    override fun onTimeout(startId: Int, fgsType: Int) {
        if (Build.VERSION.SDK_INT >= 35) {
            try {
                super.onTimeout(startId, fgsType)
            } catch (_: NoSuchMethodError) {}
        }
        Log.w(TAG, "Foreground service dataSync timed out (startId=$startId, fgsType=$fgsType). Stopping service.")
        pollingJob?.cancel()
        stopSelf(startId)
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

    companion object {
        private const val TAG = "ChatHeadService"
    }
}
