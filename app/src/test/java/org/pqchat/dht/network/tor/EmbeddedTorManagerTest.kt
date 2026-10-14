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

    @Test
    fun `process runner with forceSimulation false and no binary transitions to Error instead of Connected`() = runBlocking {
        val nonExistentBinary = File(System.getProperty("java.io.tmpdir"), "non_existent_tor_binary_${System.nanoTime()}")
        val runner = DefaultTorProcessRunner(
            context = null,
            customBinary = nonExistentBinary,
            forceSimulation = false,
            isAndroidRuntimeOverride = false
        )
        val manager = EmbeddedTorManager(
            context = null,
            dataDir = File(System.getProperty("java.io.tmpdir"), "tor_test_${System.nanoTime()}"),
            processRunner = runner
        )
        torManager = manager

        manager.start()
        var waitCount = 0
        while (manager.state.value !is TorState.Error && waitCount < 50) {
            delay(50)
            waitCount++
        }

        val state = manager.state.value
        assertTrue("Expected Error state when binary missing and forceSimulation false, got $state", state is TorState.Error)
        assertFalse(manager.isConnected)
    }

    @Test
    fun `process runner on Android runtime strictly blocks simulation and transitions to Error`() = runBlocking {
        val runner = DefaultTorProcessRunner(
            context = null,
            customBinary = File(System.getProperty("java.io.tmpdir"), "fake_binary_${System.nanoTime()}"),
            forceSimulation = true, // even if forceSimulation is requested
            isAndroidRuntimeOverride = true // simulated Android runtime!
        )
        val manager = EmbeddedTorManager(
            context = null,
            dataDir = File(System.getProperty("java.io.tmpdir"), "tor_test_${System.nanoTime()}"),
            processRunner = runner
        )
        torManager = manager

        manager.start()
        var waitCount = 0
        while (manager.state.value !is TorState.Error && waitCount < 50) {
            delay(50)
            waitCount++
        }

        val state = manager.state.value
        assertTrue("Expected Error state when on Android runtime even with forceSimulation=true, got $state", state is TorState.Error)
        val errorState = state as TorState.Error
        assertTrue("Error message should mention Android simulator restriction", errorState.message.contains("Android"))
        assertFalse(manager.isConnected)
    }

    @Test
    fun `detectCapabilities identifies Tor SOCKS5 rejecting UDP ASSOCIATE with code 0x07`() = runBlocking {
        val mockServer = ServerSocket(0)
        val mockPort = mockServer.localPort

        val serverJob = launch(kotlinx.coroutines.Dispatchers.IO) {
            // First probe from detectCapabilities(): createUdpAssociation()
            val client1 = mockServer.accept()
            val in1 = DataInputStream(client1.getInputStream())
            val out1 = DataOutputStream(client1.getOutputStream())
            in1.readUnsignedByte(); val n1 = in1.readUnsignedByte(); in1.readFully(ByteArray(n1))
            out1.write(byteArrayOf(0x05, 0x00)); out1.flush()
            in1.readUnsignedByte() // ver
            val cmd1 = in1.readUnsignedByte() // cmd 0x03 (UDP ASSOCIATE)
            in1.readUnsignedByte() // rsv
            val atyp1 = in1.readUnsignedByte()
            if (atyp1 == 0x01) in1.skipBytes(4)
            else if (atyp1 == 0x03) { val len = in1.readUnsignedByte(); in1.skipBytes(len) }
            in1.readUnsignedShort()
            // Reject reply: 0x07 = Command not supported (standard Tor daemon behavior)
            out1.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            out1.flush()
            client1.close()

            // Second probe from detectCapabilities(): TCP CONNECT probe
            val client2 = mockServer.accept()
            val in2 = DataInputStream(client2.getInputStream())
            val out2 = DataOutputStream(client2.getOutputStream())
            in2.readUnsignedByte(); val n2 = in2.readUnsignedByte(); in2.readFully(ByteArray(n2))
            out2.write(byteArrayOf(0x05, 0x00)); out2.flush()
            // TCP probe socket verifies ver==0x05 && method==0x00 and closes
            client2.close()
        }

        val socks5Client = Socks5Client("127.0.0.1", mockPort, connectTimeoutMs = 1000, readTimeoutMs = 1000)
        val caps = socks5Client.detectCapabilities()

        serverJob.join()
        mockServer.close()

        assertTrue("Should support TCP CONNECT", caps.supportsTcpConnect)
        assertFalse("Should NOT support UDP ASSOCIATE", caps.supportsUdpAssociate)
        assertEquals("Rejection code should be 0x07", 7, caps.udpRejectionCode)
    }

    @Test
    fun `TorTcpTunnelClient frames length-prefixed KRPC message over SOCKS5 TCP stream`() = runBlocking {
        val mockServer = ServerSocket(0)
        val mockPort = mockServer.localPort

        var receivedQueryLen = -1
        var receivedQueryPayload: ByteArray? = null

        val serverJob = launch(kotlinx.coroutines.Dispatchers.IO) {
            val client = mockServer.accept()
            val `in` = DataInputStream(client.getInputStream())
            val out = DataOutputStream(client.getOutputStream())

            // SOCKS5 Handshake
            `in`.readUnsignedByte(); val n = `in`.readUnsignedByte(); `in`.readFully(ByteArray(n))
            out.write(byteArrayOf(0x05, 0x00)); out.flush()

            // SOCKS5 Connect Request
            `in`.readUnsignedByte(); `in`.readUnsignedByte(); `in`.readUnsignedByte()
            val atyp = `in`.readUnsignedByte()
            if (atyp == 0x03) {
                val len = `in`.readUnsignedByte()
                `in`.skipBytes(len)
            } else if (atyp == 0x01) {
                `in`.skipBytes(4)
            }
            `in`.readUnsignedShort()

            // SOCKS5 Connect Reply
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1A, 0xE1.toByte()))
            out.flush()

            // Length-prefixed KRPC frame: 4 bytes length + payload
            receivedQueryLen = `in`.readInt()
            val payload = ByteArray(receivedQueryLen)
            `in`.readFully(payload)
            receivedQueryPayload = payload

            // Send back length-prefixed KRPC response
            val simulatedResp = "d1:rd2:id20:01234567890123456789e1:t2:aae".toByteArray(StandardCharsets.UTF_8)
            out.writeInt(simulatedResp.size)
            out.write(simulatedResp)
            out.flush()

            delay(50)
            client.close()
        }

        val socks5Client = Socks5Client("127.0.0.1", mockPort)
        val tunnelClient = TorTcpTunnelClient(socks5Client)

        val sampleQuery = "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aae".toByteArray(StandardCharsets.UTF_8)
        val target = java.net.InetSocketAddress.createUnresolved("target.dht.node", 6881)
        val respBytes = tunnelClient.sendQuery(target, sampleQuery, timeoutMs = 3000L)

        serverJob.join()
        mockServer.close()

        assertEquals(sampleQuery.size, receivedQueryLen)
        assertArrayEquals(sampleQuery, receivedQueryPayload)
        val respString = String(respBytes, StandardCharsets.UTF_8)
        assertTrue("Response should contain KRPC response dict", respString.contains("d1:r"))
    }
}
