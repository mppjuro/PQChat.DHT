package org.pqchat.dht.network.tor

/**
 * Represents the lifecycle and bootstrapping states of the embedded Tor client.
 */
sealed class TorState {
    /**
     * Tor engine is stopped and inactive.
     */
    data object Disconnected : TorState()

    /**
     * Tor engine process is initializing / starting up.
     */
    data object Starting : TorState()

    /**
     * Tor engine is connecting to directory authorities and building circuits.
     * @param progress Percentage of bootstrapping completed (0..100).
     * @param summary Human-readable description of current bootstrap phase.
     */
    data class Bootstrapping(
        val progress: Int,
        val summary: String = ""
    ) : TorState()

    /**
     * Tor engine is fully connected and ready to route traffic.
     * @param socksPort Local port where SOCKS5 proxy is listening.
     * @param controlPort Local port where Tor ControlPort is listening (if enabled).
     */
    data class Connected(
        val socksPort: Int,
        val controlPort: Int = 0
    ) : TorState()

    /**
     * Tor engine encountered a critical error during execution.
     * @param message Description of the error.
     * @param cause Underlying exception, if available.
     */
    data class Error(
        val message: String,
        val cause: Throwable? = null
    ) : TorState()
}
