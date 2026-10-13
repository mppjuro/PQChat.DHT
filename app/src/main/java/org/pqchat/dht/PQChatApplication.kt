package org.pqchat.dht

import android.app.Application
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.pqchat.dht.data.db.AppDatabase
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.service.PollingScheduler
import org.pqchat.dht.traffic.PoissonTrafficGenerator
import org.pqchat.dht.ui.util.NotificationHelper
import kotlinx.coroutines.launch
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
    lateinit var embeddedTorManager: org.pqchat.dht.network.tor.EmbeddedTorManager
        private set
    lateinit var lifecycleCoordinator: org.pqchat.dht.service.PollingLifecycleCoordinator
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
        dhtLeafNode = DhtLeafNode(port = DhtLeafNode.DEFAULT_DHT_PORT, nodeCacheDao = database.dhtNodeCacheDao()).apply { start() }
        val pendingAckQueue = org.pqchat.dht.traffic.PendingAckQueue()
        settingsManager = AppSettingsManager(this)
        repository = ChatRepository(database, dhtLeafNode, pendingAckQueue)
        trafficGenerator = PoissonTrafficGenerator(
            dhtLeafNode,
            pendingAckQueue = pendingAckQueue,
            blindRepublishPool = repository.blindRepublishPool,
            crowdsourcedRepublishEnabledProvider = { settingsManager.isCrowdsourcedRepublishEnabled.value }
        ).apply { start() }
        pollingScheduler = PollingScheduler(this, repository, dhtLeafNode, settingsManager).apply { start() }
        embeddedTorManager = org.pqchat.dht.network.tor.EmbeddedTorManager(this)

        val appScope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO + kotlinx.coroutines.SupervisorJob())
        appScope.launch {
            settingsManager.isTorEnabled.collect { enabled ->
                if (enabled) {
                    embeddedTorManager.start()
                } else {
                    embeddedTorManager.stop()
                    dhtLeafNode.setTorProxy(null)
                }
            }
        }

        appScope.launch {
            embeddedTorManager.state.collect { state ->
                if (state is org.pqchat.dht.network.tor.TorState.Connected && settingsManager.isTorEnabled.value) {
                    dhtLeafNode.setTorProxy(
                        org.pqchat.dht.dht.leaf.TorProxyConfig(
                            enabled = true,
                            socksHost = "127.0.0.1",
                            socksPort = state.socksPort
                        )
                    )
                }
            }
        }

        // Unified Lifecycle and Screen State Coordinator for Adaptive Polling
        lifecycleCoordinator = org.pqchat.dht.service.PollingLifecycleCoordinator(this, pollingScheduler).apply { start() }
    }

    override fun onTerminate() {
        super.onTerminate()
        lifecycleCoordinator.stop()
        pollingScheduler.stop()
        trafficGenerator.stop()
        dhtLeafNode.stop()
        embeddedTorManager.stop()
    }
}
