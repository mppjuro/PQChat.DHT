package org.pqchat.dht.network.tor

import android.content.Context
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Default implementation of [TorProcessRunner].
 *
 * If a native Tor binary is found (in Android nativeLibraryDir, filesDir, or system PATH),
 * it manages the external Tor process lifecycle and monitors stdout/torrc.
 *
 * If no native binary is found (e.g. running JVM unit tests or test environments),
 * it starts an embedded RFC 1928-compliant SOCKS5 proxy server with simulated
 * bootstrap progression (0 -> 100%).
 */
class DefaultTorProcessRunner(
    private val context: Context? = null,
    private val customBinary: File? = null,
    val forceSimulation: Boolean = false,
    val isAndroidRuntimeOverride: Boolean? = null
) : TorProcessRunner {

    private val running = AtomicBoolean(false)
    private var process: Process? = null
    private var runnerScope: CoroutineScope? = null
    private var runnerJob: Job? = null

    // Simulation server references
    private var simServerSocket: ServerSocket? = null
    private var simUdpSocket: DatagramSocket? = null
    private val activeSimSockets = ConcurrentHashMap.newKeySet<Socket>()

    companion object {
        const val DEFAULT_TOR_SOCKS_PORT = 9050
        const val ORBOT_SOCKS_PORT = 9150

        /**
         * Detects if the current execution is running inside the Android runtime (ART/Dalvik).
         */
        fun isAndroidRuntime(): Boolean {
            val vmName = System.getProperty("java.vm.name") ?: ""
            if (vmName.contains("Dalvik", ignoreCase = true)) return true
            val vendor = System.getProperty("java.vendor") ?: ""
            if (vendor.contains("Android", ignoreCase = true)) return true
            return false
        }
    }

    override fun isRunning(): Boolean = running.get()

    override suspend fun start(
        config: TorConfig,
        onBootstrapUpdate: (progress: Int, summary: String) -> Unit,
        onReady: (socksPort: Int, controlPort: Int) -> Unit,
        onError: (message: String, cause: Throwable?) -> Unit
    ) = withContext(Dispatchers.IO) {
        if (running.get()) {
            return@withContext
        }
        running.set(true)

        val scope = CoroutineScope(Dispatchers.IO)
        runnerScope = scope

        val isAndroid = isAndroidRuntimeOverride ?: (isAndroidRuntime() || context != null)
        val binary = findTorBinary()

        if (binary != null && !forceSimulation) {
            startNativeProcess(binary, config, onBootstrapUpdate, onReady, onError, scope)
        } else if (forceSimulation && !isAndroid) {
            // Simulation is strictly restricted to JVM unit tests (forceSimulation=true on non-Android runtime)
            startSimulation(config, onBootstrapUpdate, onReady, onError, scope)
        } else {
            // Native binary not found and not a JVM test simulation.
            // Check if an external Tor daemon or Orbot proxy is already listening on SOCKS5.
            val candidatePorts = if (config.socksPort > 0) {
                listOf(config.socksPort)
            } else {
                listOf(DEFAULT_TOR_SOCKS_PORT, ORBOT_SOCKS_PORT)
            }

            val activeExternalPort = candidatePorts.firstOrNull { port ->
                probeSocks5Proxy("127.0.0.1", port)
            }

            if (activeExternalPort != null) {
                // An active external Tor/Orbot daemon is responding on SOCKS5 port
                onBootstrapUpdate(100, "Połączono z zewnętrznym proxy Tor/Orbot na porcie $activeExternalPort")
                onReady(activeExternalPort, 0)

                // Monitor external proxy liveness
                runnerJob = scope.launch {
                    while (isActive && running.get()) {
                        delay(10000)
                        if (!probeSocks5Proxy("127.0.0.1", activeExternalPort, 2000)) {
                            if (running.get()) {
                                onError(
                                    "Zewnętrzny demon Tor/Orbot na porcie $activeExternalPort przestał odpowiadać",
                                    null
                                )
                            }
                            break
                        }
                    }
                }
            } else {
                running.set(false)
                val errorMessage = if (isAndroid && forceSimulation) {
                    "Symulator Tor jest niedozwolony na urządzeniach Android. Wymagany natywny silnik libtor.so lub zewnętrzny Orbot na porcie 9050."
                } else {
                    "Natywny silnik Tor (libtor.so) nie jest dostępny i nie wykryto aktywnego proxy Tor/Orbot na porcie SOCKS5 (127.0.0.1:9050/9150)."
                }
                onError(errorMessage, java.io.FileNotFoundException("Native Tor binary (libtor.so) not found"))
            }
        }
    }

    private fun probeSocks5Proxy(host: String, port: Int, timeoutMs: Int = 1000): Boolean {
        return try {
            Socket().use { s ->
                s.soTimeout = timeoutMs
                s.connect(InetSocketAddress(host, port), timeoutMs)
                val out = s.getOutputStream()
                val `in` = s.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val ver = `in`.read()
                val method = `in`.read()
                ver == 0x05 && method == 0x00
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun findTorBinary(): File? {
        if (customBinary != null) {
            return if (customBinary.exists() && customBinary.canExecute()) customBinary else null
        }
        // 1. Android nativeLibraryDir (e.g., libtor.so)
        val nativeDir = context?.applicationInfo?.nativeLibraryDir
        if (nativeDir != null) {
            val libTor = File(nativeDir, "libtor.so")
            if (libTor.exists() && libTor.canExecute()) {
                return libTor
            }
        }
        // 2. App filesDir/bin/tor
        val appBin = context?.filesDir?.let { File(it, "bin/tor") }
        if (appBin != null && appBin.exists() && appBin.canExecute()) {
            return appBin
        }
        // 3. System PATH (for local desktop / developer runs)
        val pathEnv = System.getenv("PATH") ?: ""
        val paths = pathEnv.split(File.pathSeparator)
        val isWindows = System.getProperty("os.name")?.lowercase()?.contains("win") == true
        val executableName = if (isWindows) "tor.exe" else "tor"

        for (dir in paths) {
            val f = File(dir, executableName)
            if (f.exists() && f.canExecute()) {
                return f
            }
        }
        return null
    }

    private suspend fun startNativeProcess(
        binary: File,
        config: TorConfig,
        onBootstrapUpdate: (progress: Int, summary: String) -> Unit,
        onReady: (socksPort: Int, controlPort: Int) -> Unit,
        onError: (message: String, cause: Throwable?) -> Unit,
        scope: CoroutineScope
    ) {
        try {
            config.dataDir.mkdirs()

            val actualSocksPort = if (config.socksPort > 0) config.socksPort else findFreePort()
            val actualControlPort = if (config.controlPort > 0) config.controlPort else findFreePort()

            val torrcContent = config.generateTorrc(actualSocksPort, actualControlPort)
            config.torrcFile.writeText(torrcContent)

            val pb = ProcessBuilder(
                binary.absolutePath,
                "-f",
                config.torrcFile.absolutePath
            ).apply {
                redirectErrorStream(true)
                directory(config.dataDir)
            }

            val proc = pb.start()
            process = proc

            val bootstrapRegex = Regex(".*Bootstrapped\\s+(\\d+)%(?:\\s*\\((.*?)\\))?:\\s*(.*)")
            var isReadyFired = false

            runnerJob = scope.launch {
                val reader = BufferedReader(InputStreamReader(proc.inputStream))
                try {
                    while (isActive && running.get()) {
                        val line = reader.readLine() ?: break
                        val match = bootstrapRegex.find(line)
                        if (match != null) {
                            val progress = match.groupValues[1].toIntOrNull() ?: 0
                            val tag = match.groupValues.getOrNull(2) ?: ""
                            val summary = match.groupValues.getOrNull(3) ?: tag
                            onBootstrapUpdate(progress, summary)

                            if (progress == 100 && !isReadyFired) {
                                isReadyFired = true
                                onReady(actualSocksPort, actualControlPort)
                            }
                        }
                    }
                } catch (e: Exception) {
                    if (running.get() && e !is CancellationException) {
                        onError("Error reading Tor process output: ${e.message}", e)
                    }
                } finally {
                    reader.close()
                }
            }

            scope.launch {
                val exitCode = proc.waitFor()
                if (running.get() && exitCode != 0) {
                    onError("Tor process exited unexpectedly with code $exitCode", null)
                }
            }
        } catch (e: Exception) {
            onError("Failed to launch Tor native process: ${e.message}", e)
        }
    }

    private suspend fun startSimulation(
        config: TorConfig,
        onBootstrapUpdate: (progress: Int, summary: String) -> Unit,
        onReady: (socksPort: Int, controlPort: Int) -> Unit,
        onError: (message: String, cause: Throwable?) -> Unit,
        scope: CoroutineScope
    ) {
        try {
            val socksPort = if (config.socksPort > 0) config.socksPort else findFreePort()
            val controlPort = if (config.controlPort > 0) config.controlPort else findFreePort()

            // Start local SOCKS5 server for handling both TCP and UDP Associate
            val serverSocket = ServerSocket(socksPort, 50, InetAddress.getByName("127.0.0.1"))
            serverSocket.reuseAddress = true
            simServerSocket = serverSocket

            runnerJob = scope.launch {
                // Listen loop for incoming TCP SOCKS5 connections
                launch {
                    try {
                        while (isActive && running.get()) {
                            val clientSocket = serverSocket.accept()
                            activeSimSockets.add(clientSocket)
                            launch {
                                handleSimSocks5Client(clientSocket)
                            }
                        }
                    } catch (_: Exception) {
                    }
                }

                // Simulate realistic bootstrap milestones
                val milestones = listOf(
                    5 to "Connecting to directory mirror",
                    15 to "Establishing encrypted TLS tunnel",
                    30 to "Loading networkstatus consensus",
                    50 to "Loading authority certificates",
                    75 to "Connecting to guard relays",
                    90 to "Establishing Tor circuits",
                    100 to "Done"
                )

                for ((pct, msg) in milestones) {
                    if (!isActive || !running.get()) break
                    delay(30)
                    onBootstrapUpdate(pct, msg)
                }

                if (isActive && running.get()) {
                    delay(20)
                    onReady(socksPort, controlPort)
                }
            }
        } catch (e: Exception) {
            onError("Failed to start embedded simulation: ${e.message}", e)
        }
    }

    private suspend fun handleSimSocks5Client(clientSocket: Socket) = withContext(Dispatchers.IO) {
        try {
            val `in` = clientSocket.getInputStream()
            val out = clientSocket.getOutputStream()

            // 1. Handshake
            val ver = `in`.read()
            if (ver != 0x05) {
                clientSocket.close()
                return@withContext
            }
            val nMethods = `in`.read()
            val methods = ByteArray(nMethods)
            `in`.read(methods)

            // Reply: NO AUTH
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()

            // 2. Request
            `in`.read() // reqVer
            val cmd = `in`.read()
            `in`.read() // rsv
            val atyp = `in`.read()

            when (cmd) {
                0x01 -> { // CONNECT
                    val targetAddr = when (atyp) {
                        0x01 -> {
                            val ip = ByteArray(4)
                            `in`.read(ip)
                            InetAddress.getByAddress(ip)
                        }
                        0x03 -> {
                            val len = `in`.read()
                            val domainBytes = ByteArray(len)
                            `in`.read(domainBytes)
                            val domain = String(domainBytes)
                            try {
                                InetAddress.getByName(domain)
                            } catch (_: Exception) {
                                InetAddress.getByName("127.0.0.1")
                            }
                        }
                        0x04 -> {
                            val ip = ByteArray(16)
                            `in`.read(ip)
                            InetAddress.getByAddress(ip)
                        }
                        else -> {
                            clientSocket.close()
                            return@withContext
                        }
                    }
                    val port = (`in`.read() shl 8) or `in`.read()

                    // Reply success: BND.ADDR = 127.0.0.1:port
                    out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (port shr 8).toByte(), (port and 0xFF).toByte()))
                    out.flush()

                    // Try to connect to target if accessible, else hold stream open
                    try {
                        val remoteSocket = Socket(targetAddr, port)
                        activeSimSockets.add(remoteSocket)
                        val job1 = launch {
                            try {
                                val buf = ByteArray(4096)
                                while (isActive) {
                                    val r = `in`.read(buf)
                                    if (r == -1) break
                                    remoteSocket.getOutputStream().write(buf, 0, r)
                                    remoteSocket.getOutputStream().flush()
                                }
                            } catch (_: Exception) {
                            }
                        }
                        val job2 = launch {
                            try {
                                val buf = ByteArray(4096)
                                while (isActive) {
                                    val r = remoteSocket.getInputStream().read(buf)
                                    if (r == -1) break
                                    out.write(buf, 0, r)
                                    out.flush()
                                }
                            } catch (_: Exception) {
                            }
                        }
                        job1.join()
                        job2.join()
                        remoteSocket.close()
                    } catch (_: Exception) {
                    }
                }

                0x03 -> { // UDP ASSOCIATE
                    // Read DST.ADDR / PORT from client
                    when (atyp) {
                        0x01 -> `in`.skip(4)
                        0x03 -> {
                            val len = `in`.read()
                            `in`.skip(len.toLong())
                        }
                        0x04 -> `in`.skip(16)
                    }
                    `in`.skip(2) // DST.PORT

                    // Allocate a UDP relay socket
                    val relayUdpSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
                    simUdpSocket = relayUdpSocket
                    val relayPort = relayUdpSocket.localPort

                    // Reply: REP = 0x00, BND = 127.0.0.1:relayPort
                    out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (relayPort shr 8).toByte(), (relayPort and 0xFF).toByte()))
                    out.flush()

                    // Listen loop for UDP relaying
                    val relayJob = launch {
                        val buffer = ByteArray(4096)

                        while (isActive && running.get() && !relayUdpSocket.isClosed) {
                            try {
                                val packet = DatagramPacket(buffer, buffer.size)
                                relayUdpSocket.receive(packet)

                                val length = packet.length
                                if (length < 10) continue

                                val bb = ByteBuffer.wrap(packet.data, 0, length)
                                bb.short // RSV
                                bb.get()  // FRAG
                                val dstAtyp = bb.get().toInt() and 0xFF

                                val dstAddr: InetSocketAddress = when (dstAtyp) {
                                    0x01 -> {
                                        val ip = ByteArray(4)
                                        bb.get(ip)
                                        val p = bb.short.toInt() and 0xFFFF
                                        InetSocketAddress(InetAddress.getByAddress(ip), p)
                                    }
                                    0x03 -> {
                                        val len = bb.get().toInt() and 0xFF
                                        val domain = ByteArray(len)
                                        bb.get(domain)
                                        val p = bb.short.toInt() and 0xFFFF
                                        InetSocketAddress(InetAddress.getByName(String(domain)), p)
                                    }
                                    else -> continue
                                }

                                val payloadLen = length - bb.position()
                                val payload = ByteArray(payloadLen)
                                System.arraycopy(packet.data, bb.position(), payload, 0, payloadLen)

                                val clientUdpAddress = InetSocketAddress(packet.address, packet.port)

                                // Forward payload directly to actual target DHT node via UDP
                                val forwardSocket = DatagramSocket()
                                val forwardPacket = DatagramPacket(payload, payload.size, dstAddr)
                                forwardSocket.send(forwardPacket)

                                // Listen for response and relay back wrapped in SOCKS5 UDP header
                                launch {
                                    try {
                                        forwardSocket.soTimeout = 3000
                                        val respBuf = ByteArray(4096)
                                        val respPacket = DatagramPacket(respBuf, respBuf.size)
                                        forwardSocket.receive(respPacket)

                                        val respSender = respPacket.socketAddress as InetSocketAddress
                                        val ipBytes = respSender.address.address
                                        val header = ByteBuffer.allocate(4 + ipBytes.size + 2)
                                        header.putShort(0)
                                        header.put(0)
                                        header.put(if (ipBytes.size == 4) 0x01.toByte() else 0x04.toByte())
                                        header.put(ipBytes)
                                        header.putShort(respSender.port.toShort())

                                        val headerBytes = header.array()
                                        val encapsulated = ByteArray(headerBytes.size + respPacket.length)
                                        System.arraycopy(headerBytes, 0, encapsulated, 0, headerBytes.size)
                                        System.arraycopy(respPacket.data, 0, encapsulated, headerBytes.size, respPacket.length)

                                        val toClient = DatagramPacket(encapsulated, encapsulated.size, clientUdpAddress)
                                        relayUdpSocket.send(toClient)
                                    } catch (_: Exception) {
                                    } finally {
                                        forwardSocket.close()
                                    }
                                }
                            } catch (_: Exception) {
                                break
                            }
                        }
                    }

                    // Keep TCP connection open; when TCP connection closes, association closes
                    try {
                        while (isActive && running.get()) {
                            if (`in`.read() == -1) break
                        }
                    } catch (_: Exception) {
                    } finally {
                        relayJob.cancel()
                        relayUdpSocket.close()
                    }
                }
                else -> {
                    clientSocket.close()
                }
            }
        } catch (_: Exception) {
        } finally {
            activeSimSockets.remove(clientSocket)
            try {
                clientSocket.close()
            } catch (_: Exception) {
            }
        }
    }

    override fun stop() {
        if (!running.compareAndSet(true, false)) {
            return
        }
        runnerJob?.cancel()
        runnerScope = null

        // Stop native process
        process?.let { p ->
            try {
                p.destroy()
            } catch (_: Exception) {
            }
        }
        process = null

        // Close simulated sockets
        try {
            simServerSocket?.close()
        } catch (_: Exception) {
        }
        simServerSocket = null

        try {
            simUdpSocket?.close()
        } catch (_: Exception) {
        }
        simUdpSocket = null

        for (s in activeSimSockets) {
            try {
                s.close()
            } catch (_: Exception) {
            }
        }
        activeSimSockets.clear()
    }

    private fun findFreePort(): Int {
        ServerSocket(0).use { ss ->
            ss.reuseAddress = true
            return ss.localPort
        }
    }
}
