package org.pqchat.dht.network.tor

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.ServerSocket
import java.nio.charset.StandardCharsets

class EmbeddedTorManagerTest {

    private var torManager: EmbeddedTorManager? = null

    @After
    fun tearDown() {
        torManager?.stop()
        torManager = null
    }

    @Test
    fun `initial state is Disconnected`() {
        val manager = EmbeddedTorManager(
            context = null,
            dataDir = File(System.getProperty("java.io.tmpdir"), "tor_test_${System.nanoTime()}"),
            processRunner = DefaultTorProcessRunner(forceSimulation = true)
        )
        torManager = manager

        assertEquals(TorState.Disconnected, manager.state.value)
        assertFalse(manager.isConnected)
        assertNull(manager.socksPort)
    }

    @Test
    fun `start transitions through Starting, Bootstrapping and Connected`() = runBlocking {
        val manager = EmbeddedTorManager(
            context = null,
            dataDir = File(System.getProperty("java.io.tmpdir"), "tor_test_${System.nanoTime()}"),
            processRunner = DefaultTorProcessRunner(forceSimulation = true)
        )
        torManager = manager

        val emittedStates = mutableListOf<TorState>()
        val collectJob = launch {
            manager.state.collect { emittedStates.add(it) }
        }

        manager.start()

        // Wait for bootstrap progression
        var waitCount = 0
        while (manager.state.value !is TorState.Connected && waitCount < 50) {
            delay(50)
            waitCount++
        }

        collectJob.cancel()

        assertTrue("Expected Connected state, got ${manager.state.value}", manager.state.value is TorState.Connected)
        assertTrue(manager.isConnected)
        assertNotNull(manager.socksPort)
        assertTrue(manager.socksPort!! > 0)

        // Verify progression contains Starting and Bootstrapping
        assertTrue(emittedStates.any { it is TorState.Starting })
        val bootstrapStates = emittedStates.filterIsInstance<TorState.Bootstrapping>()
        assertTrue("Expected multiple bootstrap progress reports", bootstrapStates.size >= 3)
        assertTrue(bootstrapStates.any { it.progress == 100 })
    }

    @Test
    fun `stop reverts state to Disconnected`() = runBlocking {
        val manager = EmbeddedTorManager(
            context = null,
            dataDir = File(System.getProperty("java.io.tmpdir"), "tor_test_${System.nanoTime()}"),
            processRunner = DefaultTorProcessRunner(forceSimulation = true)
        )
        torManager = manager

        manager.start()
        var waitCount = 0
        while (manager.state.value !is TorState.Connected && waitCount < 50) {
            delay(50)
            waitCount++
        }

        assertTrue(manager.isConnected)

        manager.stop()

        assertEquals(TorState.Disconnected, manager.state.value)
        assertFalse(manager.isConnected)
    }

    @Test
    fun `process runner error transitions state to Error`() = runBlocking {
        val failingRunner = object : TorProcessRunner {
            override suspend fun start(
                config: TorConfig,
                onBootstrapUpdate: (progress: Int, summary: String) -> Unit,
                onReady: (socksPort: Int, controlPort: Int) -> Unit,
                onError: (message: String, cause: Throwable?) -> Unit
            ) {
                onError("Simulated fatal torrc parsing error", RuntimeException("torrc syntax error"))
            }

            override fun stop() {}
            override fun isRunning(): Boolean = false
        }

        val manager = EmbeddedTorManager(
            context = null,
            dataDir = File(System.getProperty("java.io.tmpdir"), "tor_test_${System.nanoTime()}"),
            processRunner = failingRunner
        )
        torManager = manager

        manager.start()
        delay(50)

        val currentState = manager.state.value
        assertTrue("Expected Error state, got $currentState", currentState is TorState.Error)
        val errorState = currentState as TorState.Error
        assertEquals("Simulated fatal torrc parsing error", errorState.message)
        assertNotNull(errorState.cause)
    }

    @Test
    fun `socks5 client and socket factory route domain via ATYP 0x03 preventing DNS leak`() = runBlocking {
        // Spin up a mock SOCKS5 server to verify exact RFC 1928 bytes sent by client
        val mockServer = ServerSocket(0)
        val mockPort = mockServer.localPort

        var receivedAtyp = -1
        var receivedDomain = ""
        var receivedPort = -1

        val serverJob = launch(kotlinx.coroutines.Dispatchers.IO) {
            val client = mockServer.accept()
            val `in` = DataInputStream(client.getInputStream())
            val out = DataOutputStream(client.getOutputStream())

            // 1. Handshake
            `in`.readUnsignedByte() // ver
            val nMethods = `in`.readUnsignedByte()
            val methods = ByteArray(nMethods)
            `in`.readFully(methods)

            out.write(byteArrayOf(0x05, 0x00)) // NO AUTH
            out.flush()

            // 2. Request
            `in`.readUnsignedByte() // reqVer
            `in`.readUnsignedByte() // cmd
            `in`.readUnsignedByte() // rsv
            val atyp = `in`.readUnsignedByte()
            receivedAtyp = atyp

            if (atyp == 0x03) { // Domain Name
                val domainLen = `in`.readUnsignedByte()
                val domainBytes = ByteArray(domainLen)
                `in`.readFully(domainBytes)
                receivedDomain = String(domainBytes, StandardCharsets.US_ASCII)
            }
            receivedPort = `in`.readUnsignedShort()

            // Reply: Succeeded
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1A, 0xE1.toByte()))
            out.flush()

            delay(100)
            client.close()
        }

        val socks5Client = Socks5Client("127.0.0.1", mockPort)
        val socket = socks5Client.connectTcp("onion-test-host.hidden", 6881)

        serverJob.join()
        mockServer.close()
        socket.close()

        assertEquals("Expected SOCKS5 ATYP 0x03 (DOMAINNAME)", 0x03, receivedAtyp)
        assertEquals("onion-test-host.hidden", receivedDomain)
        assertEquals(6881, receivedPort)
    }
}
