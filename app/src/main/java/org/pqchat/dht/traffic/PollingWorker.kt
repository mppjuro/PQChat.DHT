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
        val app = applicationContext as? PQChatApplication
        val repository = app?.repository
        if (repository == null) {
            android.util.Log.e("PollingWorker", "PQChatApplication repository not initialized, aborting worker")
            return@withContext Result.failure()
        }

        return@withContext try {
            val settingsManager = app.settingsManager
            val policy = settingsManager.getRepublishPolicy()

            // 1. Poll incoming contact and group slots via constant-size decoy-padded batch
            repository.pollConstantBatch(null)

            // 2. Check pending ACKs
            repository.checkPendingAcks()

            // 3. Mark any messages that expired offline in Room DB
            repository.expireOutdatedPendingMessages(policy.maxTtlMs)

            // 4. Keep Doze alarm synced for maintenance windows
            app.pollingScheduler.scheduleNextDozeAlarm()

            Result.success()
        } catch (e: Exception) {
            android.util.Log.e("PollingWorker", "Error during PollingWorker background execution", e)
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
                    val tStart = System.currentTimeMillis()
                    val ok = dhtClient.putMutable(
                        target = task.target,
                        v = task.payload,
                        seq = task.seq,
                        salt = null,
                        sk = task.edPrivateKeySeed
                    )
                    val rttMs = System.currentTimeMillis() - tStart
                    try {
                        org.pqchat.dht.PQChatApplication.instance.researchTelemetryManager.recordPacketEvent(
                            role = org.pqchat.dht.research.PacketRole.OWN_REPUBLISH,
                            target = task.target,
                            seqNum = task.seq,
                            payloadBytes = task.payload.size,
                            rttMs = rttMs,
                            nodesQueried = dhtClient.lastNodesQueried,
                            nodesResponded = dhtClient.lastNodesResponded,
                            lookupHops = dhtClient.lastLookupHops,
                            success = ok,
                            republishAttempt = task.currentAttempts + 1,
                            messageAgeMs = age
                        )
                    } catch (_: Throwable) {}

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
            RepublishWorker.scheduleRepublishWork(context, intervalMinutes)
        }

        fun cancelRepublishWork(context: Context) {
            RepublishWorker.cancelRepublishWork(context)
        }

        fun enqueuePeriodicWork(context: Context, intervalMinutes: Long = 15L) {
            try {
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
            } catch (e: Throwable) {
                android.util.Log.w("PollingWorker", "Failed to enqueue periodic work (e.g. in test environment)", e)
            }
        }

        fun cancelPeriodicWork(context: Context) {
            try {
                WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
            } catch (e: Throwable) {
                android.util.Log.w("PollingWorker", "Failed to cancel periodic work", e)
            }
        }

        fun enqueueImmediateOneShot(context: Context) {
            try {
                val constraints = Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()

                val oneShot = OneTimeWorkRequestBuilder<PollingWorker>()
                    .setConstraints(constraints)
                    .build()

                WorkManager.getInstance(context).enqueue(oneShot)
            } catch (e: Throwable) {
                android.util.Log.w("PollingWorker", "Failed to enqueue one-shot work", e)
            }
        }
    }
}
