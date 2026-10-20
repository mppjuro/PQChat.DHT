package org.pqchat.dht.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import kotlinx.coroutines.*
import org.pqchat.dht.PQChatApplication
import org.pqchat.dht.traffic.PollingWorker
import org.pqchat.dht.ui.util.NotificationHelper

/**
 * Foreground Service maintaining a continuous, low-latency (10s) DHT listener loop
 * when enabled by user settings or active foreground monitoring.
 */
class ChatHeadService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var pollingJob: Job? = null
    internal var wakeLock: PowerManager.WakeLock? = null
    private var lockStartTime: Long = 0L

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

        try {
            val powerManager = getSystemService(Context.POWER_SERVICE) as? PowerManager
            wakeLock = powerManager?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKELOCK_TAG)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to create wake lock for ChatHeadService", e)
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
                    acquireWakeLock()
                    repository.pollConstantBatch(null)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e(TAG, "Error in continuous polling loop", e)
                } finally {
                    releaseWakeLock()
                }

                val interval = app.settingsManager.intervalForegroundChat.value
                delay(interval.coerceAtLeast(5_000L))
            }
        }
    }

    private fun acquireWakeLock() {
        try {
            if (wakeLock?.isHeld == false) {
                wakeLock?.acquire(30_000L) // 30s safety timeout per poll iteration
                lockStartTime = org.pqchat.dht.debug.AndroidResourceProfiler.onWakeLockAcquired(WAKELOCK_TAG)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to acquire wake lock in ChatHeadService", e)
        }
    }

    internal fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to release wake lock in ChatHeadService", e)
        } finally {
            if (lockStartTime > 0L) {
                org.pqchat.dht.debug.AndroidResourceProfiler.onWakeLockReleased(lockStartTime, WAKELOCK_TAG)
                lockStartTime = 0L
            }
        }
    }

    /**
     * Android 15 (API 35+) Foreground Service timeout callback for FOREGROUND_SERVICE_TYPE_DATA_SYNC.
     * Prevents system ANR/crash when dataSync foreground service reaches its 6-hour execution budget.
     * Safely stops the service (stopSelf), releases WakeLock, and delegates further polling
     * to PollingScheduler (AlarmManager.setAndAllowWhileIdle + WorkManager), preventing
     * ForegroundServiceDidNotStopInTimeException.
     */
    override fun onTimeout(startId: Int, fgsType: Int) {
        if (Build.VERSION.SDK_INT >= 35) {
            try {
                super.onTimeout(startId, fgsType)
            } catch (_: NoSuchMethodError) {}
        }
        Log.w(TAG, "Foreground service dataSync timed out (startId=$startId, fgsType=$fgsType). Stopping service and delegating to PollingScheduler.")

        // 1. Cancel polling coroutines
        pollingJob?.cancel()

        // 2. Safely release WakeLock
        releaseWakeLock()

        // 3. Delegate further polling to PollingScheduler (AlarmManager + WorkManager)
        try {
            val app = applicationContext as? PQChatApplication
            app?.pollingScheduler?.scheduleNextDozeAlarm()
            PollingWorker.enqueuePeriodicWork(applicationContext)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delegate background polling on FGS timeout", e)
        }

        // 4. Safely stop self to avoid ForegroundServiceDidNotStopInTimeException
        stopSelf(startId)
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        pollingJob?.cancel()
        serviceScope.cancel()
        releaseWakeLock()
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
        private const val WAKELOCK_TAG = "pqchat:chat_head_service"
    }
}
