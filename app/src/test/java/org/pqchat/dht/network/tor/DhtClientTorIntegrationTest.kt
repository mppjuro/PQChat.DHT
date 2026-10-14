package org.pqchat.dht.network.tor

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.dht.krpc.KrpcMessage
import org.pqchat.dht.dht.leaf.TorTransportMode
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.dht.leaf.TorProxyConfig
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.ByteBuffer
import java.security.Security
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

@Tag("slow")
class DhtClientTorIntegrationTest {

    companion object {
        @JvmStatic
        @BeforeAll
        fun setupCrypto() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private var leafNode: DhtLeafNode? = null
    private var mockSocksServer: MockSocks5Server? = null
    private var directPeerSocket: DatagramSocket? = null

    @AfterEach
    fun tearDown() {
        leafNode?.stop()
        leafNode = null
        mockSocksServer?.stop()
        mockSocksServer = null
        directPeerSocket?.close()
        directPeerSocket = null
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    fun `conditional routing switches seamlessly between Tor SOCKS5 and direct UDP socket`() = runBlocking {
        withTimeout(15_000L) {
            // 1. Initialize mock SOCKS5 proxy server
            val socksServer = MockSocks5Server().apply { start() }
            mockSocksServer = socksServer

            // 2. Initialize a direct local DHT peer socket to receive direct queries
            val directPeer = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
            directPeerSocket = directPeer
            val directPeerAddress = InetSocketAddress(directPeer.localAddress, directPeer.localPort)

            // Responder thread on the direct peer socket
            val responderThread = Thread {
                val buf = ByteArray(2048)
                while (!directPeer.isClosed) {
                    try {
                        val pkt = DatagramPacket(buf, buf.size)
                        directPeer.receive(pkt)
                        val req = KrpcMessage.parse(pkt.data.copyOf(pkt.length))
                        val resp = KrpcMessage.createPingResponse(CryptoUtils.secureRandomBytes(20), req.transactionId)
                        val respBytes = resp.toBencoded()
                        directPeer.send(DatagramPacket(respBytes, respBytes.size, pkt.socketAddress))
                    } catch (_: Exception) {
                        break
                    }
                }
            }.apply {
                isDaemon = true
                start()
            }

            // 3. Initialize DhtLeafNode
            val node = DhtLeafNode(port = 0, autoBootstrap = false)
            leafNode = node
            node.start()

            try {
                // =========================================================================
                // SCENARIO A: Tor is DISABLED (default state)
                // =========================================================================
                assertFalse("Tor routing should be inactive by default", node.isTorRoutingActive)
                assertEquals("No SOCKS5 connections should have occurred", 0, socksServer.tcpHandshakeCount.get())

                val ping1 = KrpcMessage.createPingQuery(node.myNodeId)
                val resp1 = node.sendQuery(directPeerAddress, ping1, timeoutMs = 2000L)

                assertNotNull("Direct query should succeed via direct UDP socket", resp1)
                assertEquals("Direct query must not touch the SOCKS5 proxy", 0, socksServer.udpPacketsRelayed.get())

                // =========================================================================
                // SCENARIO B: Enable Tor routing via SOCKS5 proxy
                // =========================================================================
                val torConfig = TorProxyConfig(
                    enabled = true,
                    socksHost = "127.0.0.1",
                    socksPort = socksServer.serverPort
                )
                node.setTorProxy(torConfig)

                assertTrue("Tor routing must be active after setTorProxy", node.isTorRoutingActive)
                assertTrue("SOCKS5 TCP handshake must have occurred", socksServer.tcpHandshakeCount.get() >= 1)
                assertTrue("SOCKS5 UDP ASSOCIATE must have occurred", socksServer.udpAssociateCount.get() >= 1)

                val ping2 = KrpcMessage.createPingQuery(node.myNodeId)
                val resp2 = node.sendQuery(directPeerAddress, ping2, timeoutMs = 3000L)

                assertNotNull("Tor-routed query should receive response relayed by SOCKS5 proxy", resp2)
                assertTrue("SOCKS5 relay must have intercepted and forwarded the packet", socksServer.udpPacketsRelayed.get() >= 1)

                val packetsRelayedWithTor = socksServer.udpPacketsRelayed.get()

                // =========================================================================
                // SCENARIO C: Disable Tor routing - immediately revert to direct socket
                // =========================================================================
                node.setTorProxy(null)

                assertFalse("Tor routing must be inactive after disabling", node.isTorRoutingActive)

                val ping3 = KrpcMessage.createPingQuery(node.myNodeId)
                val resp3 = node.sendQuery(directPeerAddress, ping3, timeoutMs = 2000L)

                assertNotNull("Direct query after disabling Tor must succeed", resp3)
                assertEquals(
                    "No new packets should be relayed through SOCKS5 proxy after disabling Tor",
                    packetsRelayedWithTor,
                    socksServer.udpPacketsRelayed.get()
                )
            } finally {
                directPeer.close()
                responderThread.interrupt()
                node.stop()
                socksServer.stop()
            }
        }
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    fun `Tor SOCKS5 proxy rejecting UDP ASSOCIATE falls back to length-prefixed TCP streaming tunnel`() = runBlocking {
        withTimeout(15_000L) {
            // Mock SOCKS5 proxy that rejects UDP ASSOCIATE with 0x07 (Command not supported)
            val mockProxy = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1")).apply { reuseAddress = true }
            val proxyPort = mockProxy.localPort

            // Mock DHT peer that speaks length-prefixed KRPC over TCP
            val mockNodeServer = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1")).apply { reuseAddress = true }
            val dhtNodePort = mockNodeServer.localPort

            val proxyJob = Thread {
                while (!mockProxy.isClosed) {
                    try {
                        val client = mockProxy.accept()
                        Thread {
                            val `in` = DataInputStream(client.getInputStream())
                            val out = DataOutputStream(client.getOutputStream())

                            `in`.readUnsignedByte(); val n = `in`.readUnsignedByte(); `in`.readFully(ByteArray(n))
                            out.write(byteArrayOf(0x05, 0x00)); out.flush()

                            `in`.readUnsignedByte()
                            val cmd = `in`.readUnsignedByte()
                            `in`.readUnsignedByte()
                            val atyp = `in`.readUnsignedByte()
                            if (atyp == 0x01) `in`.skipBytes(4)
                            else if (atyp == 0x03) { val len = `in`.readUnsignedByte(); `in`.skipBytes(len) }
                            val port = `in`.readUnsignedShort()

                            if (cmd == 0x03) { // UDP ASSOCIATE
                                // Standard Tor daemon behavior: reject with 0x07
                                out.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                                out.flush()
                                client.close()
                            } else if (cmd == 0x01) { // TCP CONNECT
                                out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (port shr 8).toByte(), (port and 0xFF).toByte()))
                                out.flush()

                                val remote = java.net.Socket("127.0.0.1", port)
                                val t1 = Thread {
                                    val buf = ByteArray(4096)
                                    val rIn = remote.getInputStream()
                                    val cOut = client.getOutputStream()
                                    while (true) {
                                        val r = rIn.read(buf)
                                        if (r == -1) break
                                        cOut.write(buf, 0, r); cOut.flush()
                                    }
                                }.apply { isDaemon = true; start() }

                                val cIn = client.getInputStream()
                                val rOut = remote.getOutputStream()
                                val buf = ByteArray(4096)
                                while (true) {
                                    val r = cIn.read(buf)
                                    if (r == -1) break
                                    rOut.write(buf, 0, r); rOut.flush()
                                }
                            }
                        }.apply { isDaemon = true; start() }
                    } catch (_: Exception) {
                        break
                    }
                }
            }.apply { isDaemon = true; start() }

            val nodeJob = Thread {
                while (!mockNodeServer.isClosed) {
                    try {
                        val client = mockNodeServer.accept()
                        Thread {
                            val `in` = DataInputStream(client.getInputStream())
                            val out = DataOutputStream(client.getOutputStream())

                            val len = `in`.readInt()
                            val data = ByteArray(len)
                            `in`.readFully(data)

                            val query = KrpcMessage.parse(data)
                            val resp = KrpcMessage.createPingResponse(CryptoUtils.secureRandomBytes(20), query.transactionId)
                            val respBytes = resp.toBencoded()

                            out.writeInt(respBytes.size)
                            out.write(respBytes)
                            out.flush()
                            client.close()
                        }.apply { isDaemon = true; start() }
                    } catch (_: Exception) {
                        break
                    }
                }
            }.apply { isDaemon = true; start() }

            val node = DhtLeafNode(port = 0, autoBootstrap = false)
            leafNode = node
            node.start()

            try {
                val config = TorProxyConfig(enabled = true, socksHost = "127.0.0.1", socksPort = proxyPort)
                node.setTorProxy(config)

                assertEquals(TorTransportMode.SOCKS5_TCP, node.torTransportMode)
                assertTrue(node.isTorRoutingActive)
                assertTrue(node.torDiagnosticMessage!!.contains("TCP SOCKS5"))

                val ping = KrpcMessage.createPingQuery(node.myNodeId)
                val targetAddr = InetSocketAddress("127.0.0.1", dhtNodePort)
                val resp = node.sendQuery(targetAddr, ping, timeoutMs = 4000L)

                assertNotNull("Query via SOCKS5 TCP tunnel must succeed", resp)
                assertEquals(CryptoUtils.toHex(ping.transactionId), CryptoUtils.toHex(resp!!.transactionId))
            } finally {
                node.stop()
                mockProxy.close()
                mockNodeServer.close()
            }
        }
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `Fail-closed behavior when Tor is enabled strictly blocks clearnet UDP leaks`() = runBlocking {
        withTimeout(10_000L) {
            val clearnetCatcher = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
            val catcherAddr = InetSocketAddress(clearnetCatcher.localAddress, clearnetCatcher.localPort)
            val packetsReceived = AtomicInteger(0)

            val catcherThread = Thread {
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

            try {
                // Find closed port
                val tempSs = ServerSocket(0)
                val closedPort = tempSs.localPort
                tempSs.close()

                val config = TorProxyConfig(enabled = true, socksHost = "127.0.0.1", socksPort = closedPort, timeoutMs = 300)
                node.setTorProxy(config)

                assertEquals(TorTransportMode.BLOCKED_ERROR, node.torTransportMode)
                assertFalse(node.isTorRoutingActive)
                assertTrue(node.torDiagnosticMessage!!.contains("Fail-Closed"))

                val ping = KrpcMessage.createPingQuery(node.myNodeId)
                val resp = node.sendQuery(catcherAddr, ping, timeoutMs = 500L)

                assertNull("sendQuery must return null when Tor proxy is in error", resp)
                kotlinx.coroutines.delay(200)
                assertEquals("Zero packets must leak over clearnet socket (Fail-Closed)", 0, packetsReceived.get())
            } finally {
                clearnetCatcher.close()
                node.stop()
            }
        }
    }

    /**
     * Minimal RFC 1928 SOCKS5 test server with UDP ASSOCIATE relay capabilities.
     */
    private class MockSocks5Server {
        private var serverSocket: ServerSocket? = null
        private var relaySocket: DatagramSocket? = null
        @Volatile
        private var isRunning = false

        val tcpHandshakeCount = AtomicInteger(0)
        val udpAssociateCount = AtomicInteger(0)
        val udpPacketsRelayed = AtomicInteger(0)

        val serverPort: Int get() = serverSocket?.localPort ?: 0

        fun start() {
            isRunning = true
            val ss = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1")).apply { reuseAddress = true }
            serverSocket = ss

            val relay = DatagramSocket(0, InetAddress.getByName("127.0.0.1")).apply { reuseAddress = true }
            relaySocket = relay

            // 1. Thread handling TCP control connections
            Thread {
                while (isRunning && !ss.isClosed) {
                    try {
                        val client = ss.accept()
                        Thread {
                            handleTcpClient(client, relay.localPort)
                        }.apply {
                            isDaemon = true
                            start()
                        }
                    } catch (_: Exception) {
                        break
                    }
                }
            }.apply {
                isDaemon = true
                start()
            }

            // 2. Thread handling UDP datagrams arriving at the relay
            Thread {
                val buf = ByteArray(4096)
                while (isRunning && !relay.isClosed) {
                    try {
                        val pkt = DatagramPacket(buf, buf.size)
                        relay.receive(pkt)
                        handleRelayUdpPacket(pkt)
                    } catch (_: Exception) {
                        break
                    }
                }
            }.apply {
                isDaemon = true
                start()
            }
        }

        private fun handleTcpClient(client: java.net.Socket, relayPort: Int) {
            try {
                val `in` = DataInputStream(client.getInputStream())
                val out = DataOutputStream(client.getOutputStream())

                // Handshake
                `in`.readUnsignedByte() // ver
                val nMethods = `in`.readUnsignedByte()
                val methods = ByteArray(nMethods)
                `in`.readFully(methods)

                tcpHandshakeCount.incrementAndGet()
                out.write(byteArrayOf(0x05, 0x00)) // NO AUTH
                out.flush()

                // Request
                `in`.readUnsignedByte() // reqVer
                val cmd = `in`.readUnsignedByte()
                `in`.readUnsignedByte() // rsv
                val atyp = `in`.readUnsignedByte()

                if (cmd == 0x03) { // UDP ASSOCIATE
                    udpAssociateCount.incrementAndGet()
                    when (atyp) {
                        0x01 -> `in`.skipBytes(4)
                        0x03 -> {
                            val len = `in`.readUnsignedByte()
                            `in`.skipBytes(len)
                        }
                        0x04 -> `in`.skipBytes(16)
                    }
                    `in`.readUnsignedShort() // Port

                    // Reply: 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, relayPort
                    out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (relayPort shr 8).toByte(), (relayPort and 0xFF).toByte()))
                    out.flush()

                    // Keep alive until client closes
                    while (isRunning && !client.isClosed) {
                        if (`in`.read() == -1) break
                    }
                } else {
                    client.close()
                }
            } catch (_: Exception) {
            } finally {
                try {
                    client.close()
                } catch (_: Exception) {
                }
            }
        }

        private fun handleRelayUdpPacket(pkt: DatagramPacket) {
            val length = pkt.length
            if (length < 10) return

            udpPacketsRelayed.incrementAndGet()

            val bb = ByteBuffer.wrap(pkt.data, 0, length)
            bb.short // RSV
            bb.get()  // FRAG
            val atyp = bb.get().toInt() and 0xFF

            val targetAddr: InetSocketAddress = when (atyp) {
                0x01 -> {
                    val ip = ByteArray(4)
                    bb.get(ip)
                    val port = bb.short.toInt() and 0xFFFF
                    InetSocketAddress(InetAddress.getByAddress(ip), port)
                }
                0x03 -> {
                    val len = bb.get().toInt() and 0xFF
                    val domainBytes = ByteArray(len)
                    bb.get(domainBytes)
                    val port = bb.short.toInt() and 0xFFFF
                    InetSocketAddress(InetAddress.getByName(String(domainBytes)), port)
                }
                else -> return
            }

            val payloadLen = length - bb.position()
            val payload = ByteArray(payloadLen)
            System.arraycopy(pkt.data, bb.position(), payload, 0, payloadLen)

            // Simulate DHT KRPC Ping response
            try {
                val query = KrpcMessage.parse(payload)
                val resp = KrpcMessage.createPingResponse(CryptoUtils.secureRandomBytes(20), query.transactionId)
                val respBytes = resp.toBencoded()

                // Encapsulate response with SOCKS5 UDP header from targetAddr
                val ipBytes = targetAddr.address.address
                val respHeader = ByteBuffer.allocate(4 + ipBytes.size + 2)
                respHeader.putShort(0.toShort())
                respHeader.put(0.toByte())
                respHeader.put(0x01.toByte())
                respHeader.put(ipBytes)
                respHeader.putShort(targetAddr.port.toShort())

                val headerBytes = respHeader.array()
                val fullPacket = ByteArray(headerBytes.size + respBytes.size)
                System.arraycopy(headerBytes, 0, fullPacket, 0, headerBytes.size)
                System.arraycopy(respBytes, 0, fullPacket, headerBytes.size, respBytes.size)

                val relay = relaySocket ?: return
                val toClient = DatagramPacket(fullPacket, fullPacket.size, pkt.socketAddress)
                relay.send(toClient)
            } catch (_: Exception) {
            }
        }

        fun stop() {
            isRunning = false
            try {
                serverSocket?.close()
            } catch (_: Exception) {
            }
            try {
                relaySocket?.close()
            } catch (_: Exception) {
            }
        }
    }
}
