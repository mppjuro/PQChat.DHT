package org.pqchat.dht.network.tor

import java.io.File

/**
 * Configuration parameters for the embedded Tor engine.
 */
data class TorConfig(
    val dataDir: File,
    val socksPort: Int = 0, // 0 means dynamic ephemeral port
    val controlPort: Int = 0,
    val dnsPort: Int = 0,
    val torrcFile: File = File(dataDir, "torrc"),
    val customDirectives: List<String> = emptyList()
) {
    /**
     * Generates standard torrc content with strict client-only and metadata-protection directives.
     */
    fun generateTorrc(actualSocksPort: Int, actualControlPort: Int): String {
        return buildString {
            appendLine("# ==================================================")
            appendLine("# PQChat Embedded Tor Configuration (Auto-generated)")
            appendLine("# ==================================================")
            appendLine("DataDirectory ${dataDir.absolutePath}")
            appendLine("SocksPort 127.0.0.1:$actualSocksPort")
            if (actualControlPort > 0) {
                appendLine("ControlPort 127.0.0.1:$actualControlPort")
                appendLine("CookieAuthentication 0")
            }
            if (dnsPort > 0) {
                appendLine("DNSPort 127.0.0.1:$dnsPort")
            }
            appendLine("ClientOnly 1")
            appendLine("AvoidDiskWrites 1")
            appendLine("SafeLogging 1")
            appendLine("LearnCircuitBuildTimeout 1")
            customDirectives.forEach { appendLine(it) }
        }
    }
}
