package org.pqchat.dht.network.tor

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.dht.krpc.KrpcMessage
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.dht.leaf.TorProxyConfig
import org.pqchat.dht.dht.leaf.TorTransportMode
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.Security
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.pqchat.dht.traffic.OutboundPoissonFrame
import org.pqchat.dht.traffic.OutboundPoissonQueue
import org.pqchat.dht.traffic.PendingAck
import org.pqchat.dht.traffic.PendingAckQueue
import org.pqchat.dht.traffic.PoissonTrafficGenerator

/**
 * Fast, deterministic local unit tests verifying Tor transport fail-closed policy,
 * local DNS leak prevention, and capability-based transport mode fallback.
 */
class TorFailClosedTest {

    companion object {
        @JvmStatic
        @BeforeAll
        fun setupCrypto() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private var leafNode: DhtLeafNode? = null
    private var testSocket: DatagramSocket? = null

    @AfterEach
    fun tearDown() {
        leafNode?.stop()
        leafNode = null
        testSocket?.close()
        testSocket = null
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    fun `when Tor is enabled and proxy is unreachable, fail-closed strictly blocks clearnet UDP packets`() = runBlocking {
        val clearnetCatcher = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        testSocket = clearnetCatcher
        val catcherAddress = InetSocketAddress(clearnetCatcher.localAddress, clearnetCatcher.localPort)
        val packetsReceived = AtomicInteger(0)

        val listenThread = Thread {
            val buf = ByteArray(2048)
            while (!clearnetCatcher.isClosed) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    clearnetCatcher.receive(pkt)
                    packetsReceived.incrementAndGet()
                } catch (_: Exception) {
                    break
                }
            }
        }.apply { isDaemon = true; start() }

        val node = DhtLeafNode(port = 0, autoBootstrap = false)
        leafNode = node
        node.start()

        // Configure Tor to point to an unreachable port with short 200ms timeout
        val unreachablePort = findClosedPort()
        val config = TorProxyConfig(
            enabled = true,
            socksHost = "127.0.0.1",
            socksPort = unreachablePort,
            timeoutMs = 200
        )
        node.setTorProxy(config)

        // Transport mode must transition to BLOCKED_ERROR
        assertEquals(TorTransportMode.BLOCKED_ERROR, node.torTransportMode)
        assertFalse("Tor routing should not be active when in BLOCKED_ERROR", node.isTorRoutingActive)
        assertNotNull("Diagnostic message must be present", node.torDiagnosticMessage)
        assertTrue("Diagnostic message should mention Fail-Closed", node.torDiagnosticMessage!!.contains("Fail-Closed"))

        // Attempt sending query to catcher address
        val ping = KrpcMessage.createPingQuery(node.myNodeId)
        val response = node.sendQuery(catcherAddress, ping, timeoutMs = 200L)

        // Fail-Closed verification:
        assertNull("sendQuery must abort and return null", response)
        delay(50)
        assertEquals("Zero packets must leak to the clearnet UDP socket (Fail-Closed)", 0, packetsReceived.get())

        clearnetCatcher.close()
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    fun `when Tor is enabled, resolveBootstrapNodes excludes LAN peers and avoids DNS leak`() = runBlocking {
        val node = DhtLeafNode(port = 0, autoBootstrap = false)
        leafNode = node
        node.start()

        // 1. Clearnet mode: local peers ARE present
        node.setTorProxy(null)
        val clearnetNodes = node.resolveBootstrapNodes()
        assertTrue("Clearnet bootstrap should include local peers", clearnetNodes.any { it.address?.hostAddress == "127.0.0.1" || it.address?.hostAddress == "10.0.2.2" })

        // 2. Tor enabled mode: LAN peers MUST be excluded, and bootstrap nodes MUST be unresolved
        val config = TorProxyConfig(enabled = true, socksHost = "127.0.0.1", socksPort = 9050, timeoutMs = 200)
        node.setTorProxy(config)
        val torNodes = node.resolveBootstrapNodes()

        // Verify zero LAN peers
        assertFalse("Tor bootstrap must not include local LAN peers", torNodes.any { it.hostString == "127.0.0.1" || it.hostString == "10.0.2.2" })

        // Verify all nodes are unresolved (to ensure DNS resolution is delegated to Tor exit node)
        for (addr in torNodes) {
            assertTrue("Bootstrap address ${addr.hostString} must be unresolved to prevent local DNS leak", addr.isUnresolved)
        }
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    fun `when Tor is enabled, incoming query does not trigger response over clearnet socket`() = runBlocking {
        val senderSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        testSocket = senderSocket
        val responsesReceived = AtomicInteger(0)

        val listenThread = Thread {
            val buf = ByteArray(2048)
            while (!senderSocket.isClosed) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    senderSocket.receive(pkt)
                    responsesReceived.incrementAndGet()
                } catch (_: Exception) {
                    break
                }
            }
        }.apply { isDaemon = true; start() }

        val node = DhtLeafNode(port = 0, autoBootstrap = false)
        leafNode = node
        node.start()

        // Enable Tor in BLOCKED_ERROR mode
        val unreachablePort = findClosedPort()
        node.setTorProxy(TorProxyConfig(enabled = true, socksHost = "127.0.0.1", socksPort = unreachablePort, timeoutMs = 200))

        // Send a ping query directly to node's local port from an external socket
        val ping = KrpcMessage.createPingQuery(CryptoUtils.secureRandomBytes(20))
        val pingBytes = ping.toBencoded()
        val nodeAddr = InetSocketAddress("127.0.0.1", node.localPort)
        senderSocket.send(DatagramPacket(pingBytes, pingBytes.size, nodeAddr))

        // Give node time to process packet
        delay(100)

        // Verify zero response packets were emitted over clearnet socket
        assertEquals("Node must not reply over clearnet UDP socket when Tor is enabled", 0, responsesReceived.get())

        senderSocket.close()
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    fun `when Tor SOCKS5 rejects UDP ASSOCIATE, leaf node automatically configures TCP SOCKS5 mode`() = runBlocking {
        val mockProxy = ServerSocket(0)
        val proxyPort = mockProxy.localPort

        val serverThread = Thread {
            try {
                val client = mockProxy.accept()
                val `in` = DataInputStream(client.getInputStream())
                val out = DataOutputStream(client.getOutputStream())

                // SOCKS5 Handshake
                `in`.readUnsignedByte(); val n = `in`.readUnsignedByte(); `in`.readFully(ByteArray(n))
                out.write(byteArrayOf(0x05, 0x00)); out.flush()

                // SOCKS5 Request
                `in`.readUnsignedByte() // ver
                val cmd = `in`.readUnsignedByte() // cmd 0x03
                `in`.readUnsignedByte() // rsv
                val atyp = `in`.readUnsignedByte()
                if (atyp == 0x01) `in`.skipBytes(4)
                else if (atyp == 0x03) { val len = `in`.readUnsignedByte(); `in`.skipBytes(len) }
                `in`.readUnsignedShort()

                // Reject UDP ASSOCIATE with 0x07 (Command not supported, like standard Tor daemon)
                out.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                out.flush()
                client.close()
            } catch (_: Exception) {
            } finally {
                try { mockProxy.close() } catch (_: Exception) {}
            }
        }.apply { isDaemon = true; start() }

        val node = DhtLeafNode(port = 0, autoBootstrap = false)
        leafNode = node
        node.start()

        val config = TorProxyConfig(enabled = true, socksHost = "127.0.0.1", socksPort = proxyPort, timeoutMs = 1000)
        node.setTorProxy(config)

        // Leaf node should have detected UDP rejection and switched to SOCKS5_TCP mode!
        assertEquals("Should automatically switch to SOCKS5_TCP", TorTransportMode.SOCKS5_TCP, node.torTransportMode)
        assertTrue("Tor routing must be active in SOCKS5_TCP mode", node.isTorRoutingActive)
        assertTrue("Diagnostic message should mention TCP SOCKS5", node.torDiagnosticMessage!!.contains("TCP SOCKS5"))

        serverThread.join(1000)
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    fun `when application performs cold start with Tor enabled, fail-closed ensures zero clearnet UDP packets before Tor tunnel is connected`() = runBlocking {
        val clearnetCatcher = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        testSocket = clearnetCatcher
        val catcherAddress = InetSocketAddress(clearnetCatcher.localAddress, clearnetCatcher.localPort)
        val packetsReceived = AtomicInteger(0)

        val listenThread = Thread {
            val buf = ByteArray(2048)
            while (!clearnetCatcher.isClosed) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    clearnetCatcher.receive(pkt)
                    packetsReceived.incrementAndGet()
                } catch (_: Exception) {
                    break
                }
            }
        }.apply { isDaemon = true; start() }

        // 1. Cold start scenario with isTorEnabled = true
        val isTorEnabled = true
        val node = DhtLeafNode(port = 0, autoBootstrap = true)
        leafNode = node

        // Synchronous check & pre-configuration before start(), workers, or traffic generator
        if (isTorEnabled) {
            node.setTorProxy(TorProxyConfig(enabled = true, socksHost = "127.0.0.1", socksPort = 0))
        }

        // 2. Start leaf node (with autoBootstrap = true, which triggers background bootstrap)
        node.start()

        // Verify fail-closed blocked mode
        assertEquals(TorTransportMode.BLOCKED_ERROR, node.torTransportMode)
        assertFalse("Tor routing should not be active during Tor bootstrap fail-closed state", node.isTorRoutingActive)
        assertEquals("Total sent bytes counter on node must remain 0", 0L, node.totalBytesSent)

        // 3. Set up traffic queues and Poisson traffic generator
        val pendingAckQueue = PendingAckQueue()
        val outboundPoissonQueue = OutboundPoissonQueue()

        val queuedFrame = OutboundPoissonFrame(
            target = CryptoUtils.secureRandomBytes(20),
            payload = ByteArray(900),
            sk = CryptoUtils.secureRandomBytes(32),
            seqNum = 1,
            messageId = 123L
        )
        outboundPoissonQueue.enqueue(queuedFrame)

        val queuedAck = PendingAck(
            contactId = "alice",
            messageId = "msg-123",
            ratchetKey = CryptoUtils.secureRandomBytes(32),
            seqNum = 1
        )
        pendingAckQueue.enqueue(queuedAck)

        val trafficGenerator = PoissonTrafficGenerator(
            dhtLeafNode = node,
            pendingAckQueue = pendingAckQueue,
            outboundPoissonQueue = outboundPoissonQueue
        )
        trafficGenerator.start()

        // 4. Trigger cover traffic tick while Tor is in BLOCKED_ERROR
        trafficGenerator.processCoverTrafficTick()

        // Queues must remain intact and NOT be dropped/lost while transport is blocked
        assertEquals("Outbound Poisson frame must remain queued while Tor is blocked", 1, outboundPoissonQueue.size)
        assertEquals("Pending ACK must remain queued while Tor is blocked", 1, pendingAckQueue.size)

        // Attempt direct query & dummy cover to catcher address
        val ping = KrpcMessage.createPingQuery(node.myNodeId)
        val queryResponse = node.sendQuery(catcherAddress, ping, timeoutMs = 200L)
        assertNull("Direct query must return null when Tor is blocked", queryResponse)

        val dummyTarget = node.sendCoverTrafficDummy()
        assertNull("Dummy cover must fail when Tor is blocked", dummyTarget)

        // Let any background bootstrap or coroutines settle
        delay(200)

        // 5. CRITICAL: 0 clearnet UDP packets must have been received by the catcher
        assertEquals("Zero clearnet UDP packets must leak before Tor tunnel connects", 0, packetsReceived.get())
        assertEquals("Total sent bytes counter on node must remain 0", 0L, node.totalBytesSent)

        trafficGenerator.stop()
        clearnetCatcher.close()
    }

    private fun findClosedPort(): Int {
        val ss = ServerSocket(0)
        val p = ss.localPort
        ss.close()
        return p
    }
}
