package org.pqchat.dht.traffic

import android.content.Context
import androidx.work.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.pqchat.dht.PQChatApplication
import org.pqchat.dht.data.db.AppDatabase
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import java.util.concurrent.TimeUnit

/**
 * Background WorkManager worker executed during Doze mode and periodic background windows.
 */
class PollingWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        return@withContext try {
            val app = applicationContext as? PQChatApplication
            val repository = app?.repository ?: run {
                val db = AppDatabase.getInstance(applicationContext)
                val dhtNode = DhtLeafNode(nodeCacheDao = db.dhtNodeCacheDao())
                ChatRepository(db, dhtNode)
            }
            val settingsManager = app?.settingsManager ?: org.pqchat.dht.data.settings.AppSettingsManager(applicationContext)
            val policy = settingsManager.getRepublishPolicy()

            // 1. Poll all registered contact incoming slots from DHT
            repository.pollAllContactsIncoming()

            // 2. Check pending ACKs
            repository.checkPendingAcks()

            // 3. Mark any messages that expired offline in Room DB
            repository.expireOutdatedPendingMessages(policy.maxTtlMs)

            // 4. Execute periodic republish pass with Exponential Backoff & TTL
            executeRepublishPass(
                dhtClient = repository.dhtLeafNode,
                policy = policy,
                onMessageExpired = { messageId ->
                    repository.markMessageExpiredOffline(messageId)
                }
            )

            // 5. Update republish WorkManager schedule (adjust interval or stop if all messages ACKed/expired)
            app?.pollingScheduler?.applyRepublishSchedule(policy = policy)

            // 6. Keep Doze alarm synced for maintenance windows
            app?.pollingScheduler?.scheduleNextDozeAlarm()

            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }

    data class RepublishTask(
        val messageId: Long,
        val contactId: String,
        val target: ByteArray,
        val payload: ByteArray,
        val edPrivateKeySeed: ByteArray,
        val seq: Long = DhtClient.DEFAULT_MUTABLE_SEQ,
        val initialSentTimestamp: Long = System.currentTimeMillis(),
        var lastRepublishedTimestamp: Long = initialSentTimestamp,
        val intervalMs: Long = 60_000L,
        val maxRetries: Int = 40,
        var currentAttempts: Int = 0
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RepublishTask) return false
            return messageId == other.messageId && contactId == other.contactId
        }

        override fun hashCode(): Int = messageId.hashCode()
    }

    companion object {
        const val WORK_NAME = "PQChatPollingWorker"
        const val REPUBLISH_WORK_NAME = "PQChatRepublishWorker"
        const val TAG_REPUBLISH = "republish_work"

        private val republishTasks = java.util.concurrent.ConcurrentHashMap<Long, RepublishTask>()

        fun registerRepublishTask(task: RepublishTask) {
            republishTasks[task.messageId] = task
        }

        fun unregisterRepublishTask(messageId: Long): RepublishTask? {
            return republishTasks.remove(messageId)
        }

        fun isRepublishTaskRegistered(messageId: Long): Boolean {
            return republishTasks.containsKey(messageId)
        }

        fun getRegisteredRepublishTasks(): List<RepublishTask> {
            return republishTasks.values.toList()
        }

        fun clearRepublishTasks() {
            republishTasks.clear()
        }

        suspend fun executeRepublishPass(
            dhtClient: DhtClient,
            policy: RepublishPolicy = RepublishPolicy(),
            currentTimeMs: Long = System.currentTimeMillis(),
            onMessageExpired: (suspend (messageId: Long) -> Unit)? = null
        ): Int {
            var count = 0
            val tasks = republishTasks.values.toList()
            for (task in tasks) {
                val age = (currentTimeMs - task.initialSentTimestamp).coerceAtLeast(0L)
                if (policy.isExpired(age)) {
                    republishTasks.remove(task.messageId)
                    onMessageExpired?.invoke(task.messageId)
                    continue
                }

                if (task.currentAttempts >= task.maxRetries) {
                    republishTasks.remove(task.messageId)
                    continue
                }

                val interval = policy.getIntervalForAge(age)
                val timeSinceLast = if (task.lastRepublishedTimestamp == 0L) {
                    Long.MAX_VALUE
                } else {
                    (currentTimeMs - task.lastRepublishedTimestamp).coerceAtLeast(0L)
                }

                if (timeSinceLast >= interval) {
                    val ok = dhtClient.putMutable(
                        target = task.target,
                        v = task.payload,
                        seq = task.seq,
                        salt = null,
                        sk = task.edPrivateKeySeed
                    )
                    if (ok) {
                        task.lastRepublishedTimestamp = currentTimeMs
                        task.currentAttempts++
                        count++
                    }
                }
            }
            return count
        }

        fun buildPeriodicWorkRequest(intervalMinutes: Long): PeriodicWorkRequest {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            return PeriodicWorkRequestBuilder<PollingWorker>(
                intervalMinutes.coerceAtLeast(15L), TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES)
                .addTag(TAG_REPUBLISH)
                .build()
        }

        fun scheduleRepublishWork(context: Context, intervalMinutes: Long) {
            try {
                val workRequest = buildPeriodicWorkRequest(intervalMinutes)
                WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                    REPUBLISH_WORK_NAME,
                    ExistingPeriodicWorkPolicy.UPDATE,
                    workRequest
                )
            } catch (_: Exception) {}
        }

        fun cancelRepublishWork(context: Context) {
            try {
                WorkManager.getInstance(context).cancelUniqueWork(REPUBLISH_WORK_NAME)
            } catch (_: Exception) {}
        }

        fun enqueuePeriodicWork(context: Context, intervalMinutes: Long = 15L) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val periodicWork = PeriodicWorkRequestBuilder<PollingWorker>(
                intervalMinutes.coerceAtLeast(15L), TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                periodicWork
            )
        }

        fun cancelPeriodicWork(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        }

        fun enqueueImmediateOneShot(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val oneShot = OneTimeWorkRequestBuilder<PollingWorker>()
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueue(oneShot)
        }
    }
}
