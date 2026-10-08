package org.pqchat.dht

import android.app.Application
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ProcessLifecycleOwner
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.pqchat.dht.data.db.AppDatabase
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.service.PollingScheduler
import org.pqchat.dht.traffic.PoissonTrafficGenerator
import org.pqchat.dht.ui.util.NotificationHelper
import java.security.Security

class PQChatApplication : Application() {

    companion object {
        lateinit var instance: PQChatApplication
            private set
    }

    lateinit var database: AppDatabase
        private set
    lateinit var dhtLeafNode: DhtLeafNode
        private set
    lateinit var repository: ChatRepository
        private set
    lateinit var trafficGenerator: PoissonTrafficGenerator
        private set
    lateinit var settingsManager: AppSettingsManager
        private set
    lateinit var pollingScheduler: PollingScheduler
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Register Bouncy Castle Provider (includes PQC in 1.78+)
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)

        // Initialize Notification Channels
        NotificationHelper.createNotificationChannel(this)

        // Initialize Core Components & Singletons
        database = AppDatabase.getInstance(this)
        dhtLeafNode = DhtLeafNode(nodeCacheDao = database.dhtNodeCacheDao()).apply { start() }
        val pendingAckQueue = org.pqchat.dht.traffic.PendingAckQueue()
        repository = ChatRepository(database, dhtLeafNode, pendingAckQueue)
        trafficGenerator = PoissonTrafficGenerator(dhtLeafNode, pendingAckQueue = pendingAckQueue).apply { start() }
        settingsManager = AppSettingsManager(this)
        pollingScheduler = PollingScheduler(this, repository, dhtLeafNode, settingsManager).apply { start() }

        // Process-level lifecycle observation: keeps background polling active across activity recreations
        ProcessLifecycleOwner.get().lifecycle.addObserver(LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> pollingScheduler.onAppForegrounded()
                Lifecycle.Event.ON_STOP -> {
                    pollingScheduler.onAppMinimized()
                    pollingScheduler.scheduleNextDozeAlarm()
                }
                else -> {}
            }
        })
    }

    override fun onTerminate() {
        super.onTerminate()
        pollingScheduler.stop()
        trafficGenerator.stop()
        dhtLeafNode.stop()
    }
}
