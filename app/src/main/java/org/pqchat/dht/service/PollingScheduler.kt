package org.pqchat.dht.service

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.combine
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.traffic.AdaptivePollingManager
import org.pqchat.dht.traffic.PollingWorker
import org.pqchat.dht.traffic.RepublishPolicy
import org.pqchat.dht.traffic.RepublishTier
import org.pqchat.dht.traffic.WorkScheduleDecision
import org.pqchat.dht.ui.util.NotificationHelper
import java.util.concurrent.TimeUnit
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

        // Synchronize republish policy changes with WorkManager scheduler
        schedulerScope.launch {
            combine(
                settingsManager.intervalRepublishTier1,
                settingsManager.intervalRepublishTier2,
                settingsManager.intervalRepublishTier3,
                settingsManager.republishMaxTtl
            ) { _, _, _, _ ->
                settingsManager.getRepublishPolicy()
            }.collect { policy ->
                applyRepublishSchedule(policy = policy)
            }
        }

        // When a republish task is registered, unregistered, or updated in repository
        repository.onRepublishTaskUpdated = {
            schedulerScope.launch {
                applyRepublishSchedule()
            }
        }
    }

    fun start() {
        if (!isStarted.compareAndSet(false, true)) return

        // Enqueue WorkManager periodic background worker (every 15 min for Doze maintenance)
        context?.let { PollingWorker.enqueuePeriodicWork(it) }

        // Evaluate and schedule republishing for any pending delivery messages
        schedulerScope.launch {
            applyRepublishSchedule()
        }

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
        context?.let { PollingWorker.cancelRepublishWork(it) }
        stopForegroundService()
        schedulerScope.cancel()
    }

    /**
     * Evaluates active republish tasks and determines the schedule for WorkManager.
     * Selects the earliest republish interval across all active tasks based on their ages.
     * Identifies expired tasks exceeding the TTL limit.
     */
    fun evaluateRepublishSchedule(
        currentTimeMs: Long = System.currentTimeMillis(),
        policy: RepublishPolicy = settingsManager.getRepublishPolicy(),
        tasks: List<PollingWorker.RepublishTask> = PollingWorker.getRegisteredRepublishTasks()
    ): WorkScheduleDecision {
        val expiredIds = mutableListOf<Long>()
        val activeTasks = mutableListOf<PollingWorker.RepublishTask>()

        for (task in tasks) {
            val age = (currentTimeMs - task.initialSentTimestamp).coerceAtLeast(0L)
            if (policy.isExpired(age)) {
                expiredIds.add(task.messageId)
            } else {
                activeTasks.add(task)
            }
        }

        if (activeTasks.isEmpty()) {
            return WorkScheduleDecision(
                shouldSchedule = false,
                intervalMinutes = 0L,
                tier = null,
                activeTaskCount = 0,
                expiredTaskIds = expiredIds
            )
        }

        var minIntervalMs = Long.MAX_VALUE
        var highestPriorityTier = RepublishTier.TIER3_LONG_TERM

        for (task in activeTasks) {
            val age = (currentTimeMs - task.initialSentTimestamp).coerceAtLeast(0L)
            val tier = policy.getTier(age)
            val interval = policy.getIntervalForTier(tier)
            if (interval in 1 until minIntervalMs) {
                minIntervalMs = interval
                highestPriorityTier = tier
            }
        }

        // WorkManager minimum periodic interval constraint is 15 minutes
        val intervalMinutes = TimeUnit.MILLISECONDS
            .toMinutes(minIntervalMs)
            .coerceAtLeast(15L)

        return WorkScheduleDecision(
            shouldSchedule = true,
            intervalMinutes = intervalMinutes,
            tier = highestPriorityTier,
            activeTaskCount = activeTasks.size,
            expiredTaskIds = expiredIds
        )
    }

    /**
     * Applies the calculated republish schedule:
     * - Marks expired messages as EXPIRED_OFFLINE in Room DB and unregisters them.
     * - Scans DB for any pending messages that expired offline.
     * - If active tasks remain, schedules or updates WorkManager periodic republish work.
     * - If no active tasks remain, cancels WorkManager republish work to stop waking device radio.
     */
    suspend fun applyRepublishSchedule(
        currentTimeMs: Long = System.currentTimeMillis(),
        policy: RepublishPolicy = settingsManager.getRepublishPolicy()
    ): WorkScheduleDecision = withContext(Dispatchers.IO) {
        val decision = evaluateRepublishSchedule(currentTimeMs, policy)

        // Mark expired messages in DB and unregister
        for (expiredId in decision.expiredTaskIds) {
            repository.markMessageExpiredOffline(expiredId)
        }

        // Also check any offline pending messages in DB that might have expired
        repository.expireOutdatedPendingMessages(policy.maxTtlMs, currentTimeMs)

        val ctx = context
        if (ctx != null) {
            if (decision.shouldSchedule) {
                PollingWorker.scheduleRepublishWork(ctx, decision.intervalMinutes)
            } else {
                PollingWorker.cancelRepublishWork(ctx)
            }
        }

        decision
    }

    companion object {
        const val DOZE_ALARM_REQUEST_CODE = 4401
    }
}
