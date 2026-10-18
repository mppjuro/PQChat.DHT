package org.pqchat.dht.traffic

import android.content.Context
import androidx.work.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.pqchat.dht.PQChatApplication
import org.pqchat.dht.dht.leaf.DhtClient
import java.util.concurrent.TimeUnit

/**
 * Dedicated WorkManager periodic worker refreshing unacknowledged messages every 60–90 minutes.
 * Operates independently from the incoming polling loop according to AGENTS.md spec.
 *
 * Architecture requirements:
 * - Refreshes unacknowledged DHT messages (BEP 44 mutable items) every 60–90 minutes to prevent node eviction (~2h).
 * - Verifies pending ACKs before republishing.
 * - Expires messages exceeding TTL (48h) and sets status to "EXPIRED_OFFLINE" / "EXPIRED_DHT".
 * - When all messages are delivered or expired, cancels periodic republish work to prevent radio wakeups.
 */
class RepublishWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val app = applicationContext as? PQChatApplication
        val repository = app?.repository
        if (repository == null) {
            android.util.Log.e("RepublishWorker", "PQChatApplication repository not initialized, aborting worker")
            return@withContext Result.failure()
        }

        try {
            val settingsManager = app.settingsManager
            val policy = settingsManager.getRepublishPolicy()

            // 1. Mark any messages that expired offline in Room DB
            repository.expireOutdatedPendingMessages(policy.maxTtlMs)

            // 2. Check pending ACKs before republishing (in case an ACK arrived)
            repository.checkPendingAcks()

            // 3. Execute periodic republish pass with Exponential Backoff (60-90m tiers)
            executeRepublishPass(
                dhtClient = repository.dhtLeafNode,
                policy = policy,
                onMessageExpired = { messageId ->
                    repository.markMessageExpiredOffline(messageId)
                }
            )

            // 4. Update republish WorkManager schedule (adjust interval or cancel if empty)
            app.pollingScheduler.applyRepublishSchedule(policy = policy)

            Result.success()
        } catch (e: Exception) {
            android.util.Log.e("RepublishWorker", "Error during RepublishWorker background execution", e)
            Result.retry()
        }
    }

    companion object {
        const val WORK_NAME = "PQChatRepublishPeriodicWorker"
        const val TAG_REPUBLISH = "republish_work"
        const val DEFAULT_INTERVAL_MINUTES = 75L // 60–90 min window (75m ± 15m flex)

        fun scheduleRepublishWork(context: Context, intervalMinutes: Long = DEFAULT_INTERVAL_MINUTES) {
            try {
                // Ensure interval is within 60–90 minutes range (constrained by minimum 15m)
                val targetInterval = intervalMinutes.coerceAtLeast(15L)
                val constraints = Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()

                val workRequest = PeriodicWorkRequestBuilder<RepublishWorker>(
                    targetInterval, TimeUnit.MINUTES,
                    15L, TimeUnit.MINUTES // 15m flex window -> executes every 60-90 minutes
                )
                    .setConstraints(constraints)
                    .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES)
                    .addTag(TAG_REPUBLISH)
                    .build()

                WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                    WORK_NAME,
                    ExistingPeriodicWorkPolicy.UPDATE,
                    workRequest
                )
            } catch (e: Throwable) {
                android.util.Log.w("RepublishWorker", "Failed to schedule republish work", e)
            }
        }

        fun cancelRepublishWork(context: Context) {
            try {
                WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
            } catch (e: Throwable) {
                android.util.Log.w("RepublishWorker", "Failed to cancel republish work", e)
            }
        }

        /**
         * Delegates execution of republish pass to PollingWorker static task pool.
         */
        suspend fun executeRepublishPass(
            dhtClient: DhtClient,
            policy: RepublishPolicy = RepublishPolicy(),
            currentTimeMs: Long = System.currentTimeMillis(),
            onMessageExpired: (suspend (messageId: Long) -> Unit)? = null
        ): Int {
            return PollingWorker.executeRepublishPass(dhtClient, policy, currentTimeMs, onMessageExpired)
        }
    }
}
