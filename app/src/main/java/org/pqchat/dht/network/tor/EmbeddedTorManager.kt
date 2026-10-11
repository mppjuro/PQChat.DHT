package org.pqchat.dht.network.tor

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.InetSocketAddress
import javax.net.SocketFactory

/**
 * High-level manager orchestrating the embedded Tor engine lifecycle.
 *
 * Responsibilities:
 * - Controls the start, stop, and restart transitions of the Tor engine.
 * - Tracks real-time bootstrapping progress (0-100%) and publishes [TorState].
 * - Exposes an RFC 1928-compliant [TorSocketFactory] and [Socks5Client] with domain-based
 *   routing to prevent DNS leaks.
 * - Safe release of background processes and coroutine scopes.
 */
class EmbeddedTorManager(
    private val context: Context? = null,
    val dataDir: File = context?.getDir("tor", Context.MODE_PRIVATE)
        ?: File(System.getProperty("java.io.tmpdir"), "pqchat_tor_${System.currentTimeMillis()}"),
    private val processRunner: TorProcessRunner = DefaultTorProcessRunner(context = context)
) {

    private val managerScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var startJob: Job? = null

    private val _state = MutableStateFlow<TorState>(TorState.Disconnected)
    val state: StateFlow<TorState> = _state.asStateFlow()

    val isConnected: Boolean
        get() = _state.value is TorState.Connected

    val socksPort: Int?
        get() = (_state.value as? TorState.Connected)?.socksPort

    val controlPort: Int?
        get() = (_state.value as? TorState.Connected)?.controlPort

    val socketFactory: SocketFactory = TorSocketFactory {
        socksPort?.let { InetSocketAddress("127.0.0.1", it) }
    }

    /**
     * Returns a configured [Socks5Client] if Tor is currently connected.
     */
    fun getSocks5Client(): Socks5Client? {
        val port = socksPort ?: return null
        return Socks5Client("127.0.0.1", port)
    }

    /**
     * Starts the embedded Tor engine asynchronously.
     */
    suspend fun start() = withContext(Dispatchers.IO) {
        if (_state.value is TorState.Starting || _state.value is TorState.Bootstrapping || _state.value is TorState.Connected) {
            return@withContext
        }

        _state.value = TorState.Starting

        val config = TorConfig(
            dataDir = dataDir,
            socksPort = 0, // dynamic ephemeral
            controlPort = 0
        )

        startJob?.cancel()
        startJob = managerScope.launch {
            try {
                processRunner.start(
                    config = config,
                    onBootstrapUpdate = { progress, summary ->
                        _state.value = TorState.Bootstrapping(progress, summary)
                    },
                    onReady = { readySocksPort, readyControlPort ->
                        _state.value = TorState.Connected(readySocksPort, readyControlPort)
                    },
                    onError = { message, cause ->
                        _state.value = TorState.Error(message, cause)
                    }
                )
            } catch (e: Exception) {
                _state.value = TorState.Error("Tor initialization failed: ${e.message}", e)
            }
        }
    }

    /**
     * Gracefully stops the Tor engine and reverts state to [TorState.Disconnected].
     */
    fun stop() {
        startJob?.cancel()
        startJob = null
        try {
            processRunner.stop()
        } catch (_: Exception) {
        }
        _state.value = TorState.Disconnected
    }

    /**
     * Restarts the Tor engine.
     */
    suspend fun restart() {
        stop()
        start()
    }
}
