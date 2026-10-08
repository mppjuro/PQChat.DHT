package org.pqchat.dht.service

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import kotlinx.coroutines.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.traffic.AdaptivePollingManager
import org.pqchat.dht.traffic.PollingWorker
import org.pqchat.dht.ui.util.NotificationHelper
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Central coordinator for DHT polling intervals and background execution:
 * 10s (Foreground Chat) / 1m (App Active) / 5m (Background Idle) / 15m (Doze Sleep).
 * Orchestrates WorkManager, AlarmManager (setAndAllowWhileIdle), and optional ChatHeadService.
 */
class PollingScheduler(
    private val context: Context? = null,
    val repository: ChatRepository,
    val dhtLeafNode: DhtLeafNode? = null,
    val settingsManager: AppSettingsManager
) {
    private val schedulerScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    val pollingManager: AdaptivePollingManager = AdaptivePollingManager(
        onPollRequested = { contactId ->
            if (contactId != null) {
                repository.pollContactIncoming(contactId)
            } else {
                repository.pollAllContactsIncoming()
            }
        },
        onIdlePreWarm = { contactId ->
            if (contactId != null) {
                repository.preWarmContactNextTarget(contactId)
            } else {
                repository.preWarmAllContactsNextTargets()
            }
        }
    )

    private val isStarted = AtomicBoolean(false)

    init {
        // Wire incoming message notification delivery
        repository.onIncomingMessageDelivered = { contactId, textContent, isImage ->
            handleIncomingMessageDelivered(contactId, textContent, isImage)
        }

        // Keep polling manager intervals synchronized with settings
        schedulerScope.launch {
            settingsManager.intervalForegroundChat.collect { fg ->
                pollingManager.updateIntervals(
                    foreground = fg,
                    appActive = settingsManager.intervalAppActive.value,
                    bgIdle = settingsManager.intervalBackgroundIdle.value,
                    doze = settingsManager.intervalDozeSleep.value
                )
            }
        }
        schedulerScope.launch {
            settingsManager.intervalAppActive.collect { active ->
                pollingManager.updateIntervals(
                    foreground = settingsManager.intervalForegroundChat.value,
                    appActive = active,
                    bgIdle = settingsManager.intervalBackgroundIdle.value,
                    doze = settingsManager.intervalDozeSleep.value
                )
            }
        }
        schedulerScope.launch {
            settingsManager.intervalBackgroundIdle.collect { idle ->
                pollingManager.updateIntervals(
                    foreground = settingsManager.intervalForegroundChat.value,
                    appActive = settingsManager.intervalAppActive.value,
                    bgIdle = idle,
                    doze = settingsManager.intervalDozeSleep.value
                )
            }
        }
        schedulerScope.launch {
            settingsManager.intervalDozeSleep.collect { doze ->
                pollingManager.updateIntervals(
                    foreground = settingsManager.intervalForegroundChat.value,
                    appActive = settingsManager.intervalAppActive.value,
                    bgIdle = settingsManager.intervalBackgroundIdle.value,
                    doze = doze
                )
            }
        }
        schedulerScope.launch {
            settingsManager.isForegroundServiceEnabled.collect { enabled ->
                if (enabled && isStarted.get()) {
                    startForegroundService()
                } else if (!enabled) {
                    stopForegroundService()
                }
            }
        }
    }

    fun start() {
        if (!isStarted.compareAndSet(false, true)) return

        // Enqueue WorkManager periodic background worker (every 15 min for Doze maintenance)
        context?.let { PollingWorker.enqueuePeriodicWork(it) }

        // Start adaptive polling loop
        pollingManager.onAppForegrounded()

        // Start foreground service if enabled by user
        if (settingsManager.isForegroundServiceEnabled.value) {
            startForegroundService()
        }
    }

    fun onChatOpened(contactId: String) {
        pollingManager.onChatOpened(contactId)
    }

    fun onChatClosed() {
        pollingManager.onChatClosed()
    }

    fun onAppForegrounded() {
        pollingManager.onAppForegrounded()
        cancelDozeAlarm()
    }

    fun onAppMinimized() {
        pollingManager.onAppMinimized()
        scheduleNextDozeAlarm()
    }

    fun onDeviceScreenOff() {
        pollingManager.onDeviceScreenOff()
        scheduleNextDozeAlarm()
    }

    fun triggerImmediatePoll() {
        pollingManager.triggerImmediatePoll()
    }

    var notificationNotifier: ((contactId: String, name: String, preview: String) -> Unit)? = null

    internal fun handleIncomingMessageDelivered(contactId: String, textContent: String, isImage: Boolean) {
        if (contactId == ChatRepository.SELF_CONTACT_ID) return

        val state = pollingManager.currentState.value
        val activeChat = pollingManager.activeChatContactId

        // Do not notify if user is actively in the chat with this sender
        val isUserInThisChat = (state == AdaptivePollingManager.PollingState.FOREGROUND_CHAT && activeChat == contactId)
        if (!isUserInThisChat) {
            schedulerScope.launch {
                val contact = repository.getContact(contactId)
                val contactName = contact?.name ?: "PQChat"
                val messagePreview = if (isImage) "📷 Otrzymano zaszyfrowany plik obrazu" else textContent
                if (notificationNotifier != null) {
                    notificationNotifier?.invoke(contactId, contactName, messagePreview)
                } else {
                    context?.let { ctx ->
                        NotificationHelper.showMessageNotification(
                            context = ctx,
                            contactName = contactName,
                            messagePreview = messagePreview,
                            notificationId = kotlin.math.abs(contactId.hashCode())
                        )
                    }
                }
            }
        }
    }

    fun scheduleNextDozeAlarm() {
        val ctx = context ?: return
        val alarmManager = ctx.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        val intent = Intent(ctx, DhtAlarmReceiver::class.java).apply {
            action = DhtAlarmReceiver.ACTION_DOZE_POLL
        }
        val pendingIntent = PendingIntent.getBroadcast(
            ctx,
            DOZE_ALARM_REQUEST_CODE,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val intervalMs = settingsManager.intervalDozeSleep.value.coerceAtLeast(60_000L)
        val triggerAtMillis = System.currentTimeMillis() + intervalMs

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            alarmManager.setAndAllowWhileIdle(
                AlarmManager.RTC_WAKEUP,
                triggerAtMillis,
                pendingIntent
            )
        } else {
            alarmManager.set(
                AlarmManager.RTC_WAKEUP,
                triggerAtMillis,
                pendingIntent
            )
        }
    }

    fun cancelDozeAlarm() {
        val ctx = context ?: return
        val alarmManager = ctx.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        val intent = Intent(ctx, DhtAlarmReceiver::class.java).apply {
            action = DhtAlarmReceiver.ACTION_DOZE_POLL
        }
        val pendingIntent = PendingIntent.getBroadcast(
            ctx,
            DOZE_ALARM_REQUEST_CODE,
            intent,
            PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE
        )
        if (pendingIntent != null) {
            alarmManager.cancel(pendingIntent)
            pendingIntent.cancel()
        }
    }

    fun startForegroundService() {
        val ctx = context ?: return
        val intent = Intent(ctx, ChatHeadService::class.java)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ctx.startForegroundService(intent)
            } else {
                ctx.startService(intent)
            }
        } catch (_: Exception) {}
    }

    fun stopForegroundService() {
        val ctx = context ?: return
        val intent = Intent(ctx, ChatHeadService::class.java)
        try {
            ctx.stopService(intent)
        } catch (_: Exception) {}
    }

    fun setForegroundServiceEnabled(enabled: Boolean) {
        settingsManager.setForegroundServiceEnabled(enabled)
        if (enabled) {
            startForegroundService()
        } else {
            stopForegroundService()
        }
    }

    fun stop() {
        isStarted.set(false)
        pollingManager.stop()
        cancelDozeAlarm()
        stopForegroundService()
        schedulerScope.cancel()
    }

    companion object {
        const val DOZE_ALARM_REQUEST_CODE = 4401
    }
}
