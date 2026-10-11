package org.pqchat.dht.network.tor

/**
 * Interface abstracting execution of the underlying Tor engine process.
 * Allows switching between native process execution and simulated test engines.
 */
interface TorProcessRunner {
    /**
     * Starts the Tor engine with the provided configuration.
     * Invokes callbacks on progress updates, readiness, or errors.
     */
    suspend fun start(
        config: TorConfig,
        onBootstrapUpdate: (progress: Int, summary: String) -> Unit,
        onReady: (socksPort: Int, controlPort: Int) -> Unit,
        onError: (message: String, cause: Throwable?) -> Unit
    )

    /**
     * Gracefully stops the Tor engine process and releases all bound ports/sockets.
     */
    fun stop()

    /**
     * Whether the Tor engine process/runner is currently running.
     */
    fun isRunning(): Boolean
}
