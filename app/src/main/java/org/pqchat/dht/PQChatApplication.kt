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
    lateinit var resourceProfiler: org.pqchat.dht.debug.AndroidResourceProfiler
        private set
    lateinit var researchTelemetryManager: org.pqchat.dht.research.ResearchTelemetryManager
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Register Bouncy Castle Provider (includes PQC in 1.78+)
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)

        // Initialize Notification Channels
        NotificationHelper.createNotificationChannel(this)

        // Initialize Settings Manager first to determine Tor policy synchronously
        settingsManager = AppSettingsManager(this)
        val isTorInitiallyEnabled = settingsManager.isTorEnabled.value

        // Initialize Core Components & Singletons
        database = AppDatabase.getInstance(this)
        dhtLeafNode = DhtLeafNode(port = DhtLeafNode.DEFAULT_DHT_PORT, nodeCacheDao = database.dhtNodeCacheDao())

        // 1 & 2: Fail-Closed Tor configuration prior to any network start or worker queues
        if (isTorInitiallyEnabled) {
            dhtLeafNode.setTorProxy(
                org.pqchat.dht.dht.leaf.TorProxyConfig(
                    enabled = true,
                    socksHost = "127.0.0.1",
                    socksPort = 0
                )
            )
        }

        dhtLeafNode.start()

        val pendingAckQueue = org.pqchat.dht.traffic.PendingAckQueue()
        val outboundPoissonQueue = org.pqchat.dht.traffic.OutboundPoissonQueue()
        repository = ChatRepository(
            database = database,
            dhtLeafNode = dhtLeafNode,
            pendingAckQueue = pendingAckQueue,
            outboundPoissonQueue = outboundPoissonQueue,
            strictPoissonShapingEnabledProvider = { settingsManager.isStrictPoissonShapingEnabled.value },
            settingsManager = settingsManager
        )
        trafficGenerator = PoissonTrafficGenerator(
            dhtLeafNode = dhtLeafNode,
            pendingAckQueue = pendingAckQueue,
            blindRepublishPool = repository.blindRepublishPool,
            outboundPoissonQueue = outboundPoissonQueue,
            crowdsourcedRepublishEnabledProvider = { settingsManager.isCrowdsourcedRepublishEnabled.value },
            safetyCanaryProvider = { repository.pollPendingSafetyCanary() },
            researchTelemetryProvider = { if (::researchTelemetryManager.isInitialized) researchTelemetryManager else null }
        ).apply { start() }
        pollingScheduler = PollingScheduler(this, repository, dhtLeafNode, settingsManager).apply { start() }
        embeddedTorManager = org.pqchat.dht.network.tor.EmbeddedTorManager(this)

        val appScope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO + kotlinx.coroutines.SupervisorJob())
        appScope.launch {
            settingsManager.isTorEnabled.collect { enabled ->
                if (enabled) {
                    dhtLeafNode.setTorProxy(
                        org.pqchat.dht.dht.leaf.TorProxyConfig(
                            enabled = true,
                            socksHost = "127.0.0.1",
                            socksPort = 0
                        )
                    )
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
                    trafficGenerator.triggerImmediateTick()
                } else if ((state is org.pqchat.dht.network.tor.TorState.Error || state is org.pqchat.dht.network.tor.TorState.Disconnected) && settingsManager.isTorEnabled.value) {
                    dhtLeafNode.setTorProxy(
                        org.pqchat.dht.dht.leaf.TorProxyConfig(
                            enabled = true,
                            socksHost = "127.0.0.1",
                            socksPort = 0
                        )
                    )
                }
            }
        }

        // Unified Lifecycle and Screen State Coordinator for Adaptive Polling
        lifecycleCoordinator = org.pqchat.dht.service.PollingLifecycleCoordinator(this, pollingScheduler).apply { start() }

        // Empirical Android Resource Telemetry Profiler (for research / thesis telemetry)
        resourceProfiler = org.pqchat.dht.debug.AndroidResourceProfiler(
            context = this,
            dhtClient = dhtLeafNode,
            lifecycleCoordinator = lifecycleCoordinator,
            trafficGenerator = trafficGenerator
        )

        // Academic Research & Firebase Sync Telemetry Coordinator (Master's Thesis)
        researchTelemetryManager = org.pqchat.dht.research.ResearchTelemetryManager(
            context = this,
            settingsManager = settingsManager,
            dhtClient = dhtLeafNode,
            resourceProfiler = resourceProfiler
        )
    }

    override fun onTerminate() {
        super.onTerminate()
        researchTelemetryManager.stop()
        resourceProfiler.stopSession()
        lifecycleCoordinator.stop()
        pollingScheduler.stop()
        trafficGenerator.stop()
        dhtLeafNode.stop()
        embeddedTorManager.stop()
    }
}
