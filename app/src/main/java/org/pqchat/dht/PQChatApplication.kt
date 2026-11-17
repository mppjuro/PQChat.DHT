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

    private var networkCallback: android.net.ConnectivityManager.NetworkCallback? = null

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
        if (DhtLeafNode.isEmulator()) {
            DhtLeafNode.isLocalTestbedMode = true
            if (DhtLeafNode.customBootstrapEndpoints.isEmpty()) {
                DhtLeafNode.customBootstrapEndpoints = listOf(Pair("10.0.2.2", 30000))
            }
        }

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
        embeddedTorManager = org.pqchat.dht.network.tor.EmbeddedTorManager(this).apply {
            onCircuitChanged = { circuitId ->
                dhtLeafNode.onTorCircuitChanged(circuitId)
            }
        }
        registerNetworkInterfaceMonitor()

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

    private fun registerNetworkInterfaceMonitor() {
        try {
            val cm = getSystemService(android.net.ConnectivityManager::class.java) ?: return
            val callback = object : android.net.ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: android.net.Network) {
                    notifyNetworkSignature(cm, network)
                }

                override fun onCapabilitiesChanged(
                    network: android.net.Network,
                    networkCapabilities: android.net.NetworkCapabilities
                ) {
                    notifyNetworkSignature(cm, network, networkCapabilities)
                }

                override fun onLinkPropertiesChanged(
                    network: android.net.Network,
                    linkProperties: android.net.LinkProperties
                ) {
                    notifyNetworkSignature(cm, network, linkProperties = linkProperties)
                }

                override fun onLost(network: android.net.Network) {
                    dhtLeafNode.onNetworkInterfaceLost()
                }
            }
            networkCallback = callback
            cm.registerDefaultNetworkCallback(callback)
        } catch (_: Throwable) {
            // ConnectivityManager unavailable or permission restricted
        }
    }

    private fun notifyNetworkSignature(
        cm: android.net.ConnectivityManager,
        network: android.net.Network,
        capsOverride: android.net.NetworkCapabilities? = null,
        linkProperties: android.net.LinkProperties? = null
    ) {
        val caps = capsOverride ?: cm.getNetworkCapabilities(network)
        val links = linkProperties ?: cm.getLinkProperties(network)
        val transports = buildList {
            if (caps != null) {
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)) add("WIFI")
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)) add("CELLULAR")
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) add("VPN")
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET)) add("ETHERNET")
            }
        }.joinToString("+").ifEmpty { "OTHER" }
        val iface = links?.interfaceName ?: "unknown"
        val addrs = links?.linkAddresses
            ?.mapNotNull { it.address?.hostAddress }
            ?.sorted()
            ?.joinToString(",")
            ?: ""
        val signature = "$network|$transports|$iface|$addrs"
        dhtLeafNode.onNetworkInterfaceChanged(signature)
        pollingScheduler.updateNetworkAdaptiveK()
    }

    override fun onTerminate() {
        super.onTerminate()
        networkCallback?.let { cb ->
            try {
                getSystemService(android.net.ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
            } catch (_: Throwable) {}
            networkCallback = null
        }
        researchTelemetryManager.stop()
        resourceProfiler.stopSession()
        lifecycleCoordinator.stop()
        pollingScheduler.stop()
        trafficGenerator.stop()
        dhtLeafNode.stop()
        embeddedTorManager.stop()
    }
}
