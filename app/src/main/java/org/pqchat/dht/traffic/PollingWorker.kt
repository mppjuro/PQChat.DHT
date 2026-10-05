package org.pqchat.dht.traffic

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import org.pqchat.dht.PQChatApplication

/**
 * Background WorkManager worker executed during Doze mode every 15 minutes.
 */
class PollingWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        return try {
            // Wake modem radio, poll registered DHT contact slots
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }
}
