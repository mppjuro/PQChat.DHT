package org.pqchat.dht.network.tor

import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

open class Socks5Exception(message: String, cause: Throwable? = null) : IOException(message, cause)

class Socks5CommandNotSupportedException(
    val replyCode: Int,
    message: String = "SOCKS5 UDP ASSOCIATE (CMD 0x03) rejected with reply code 0x%02X (Command not supported by Tor daemon)".format(replyCode)
) : Socks5Exception(message)

/**
 * High-performance, RFC 1928-compliant SOCKS5 proxy client.
 *
 * Implements:
 * - TCP CONNECT with remote domain name resolution (ATYP 0x03) preventing DNS leaks.
 * - UDP ASSOCIATE for routing datagrams (e.g. DHT KRPC packets) through SOCKS5 relay.
 * - Proxy capability detection (standard Tor daemon vs full UDP relay).
 */
class Socks5Client(
    val proxyHost: String = "127.0.0.1",
    val proxyPort: Int = 9050,
    private val connectTimeoutMs: Int = 5000,
    private val readTimeoutMs: Int = 10000
) {

    data class Socks5Capabilities(
        val supportsTcpConnect: Boolean,
        val supportsUdpAssociate: Boolean,
        val udpRejectionCode: Int? = null,
        val description: String = ""
    )

    data class Socks5UdpPacket(
        val data: ByteArray,
        val sender: InetSocketAddress
    )

    /**
     * Probes the SOCKS5 proxy to detect whether it supports TCP CONNECT, UDP ASSOCIATE,
     * or is a standard Tor daemon that rejects UDP ASSOCIATE.
     */
    fun detectCapabilities(): Socks5Capabilities {
        var tcpOk = false
        var udpOk = false
        var rejection: Int? = null

        try {
            val assoc = createUdpAssociation()
            assoc.close()
            udpOk = true
        } catch (e: Socks5CommandNotSupportedException) {
            rejection = e.replyCode
        } catch (_: Exception) {
        }

        try {
            Socket().use { s ->
                s.soTimeout = connectTimeoutMs
                s.connect(InetSocketAddress(proxyHost, proxyPort), connectTimeoutMs)
                val out = DataOutputStream(s.getOutputStream())
                val `in` = DataInputStream(s.getInputStream())
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val ver = `in`.readUnsignedByte()
                val method = `in`.readUnsignedByte()
                tcpOk = (ver == 0x05 && method == 0x00)
            }
        } catch (_: Exception) {
        }

        val desc = when {
            udpOk -> "Full SOCKS5 (TCP + UDP ASSOCIATE)"
            tcpOk -> "Standard Tor SOCKS5 (TCP CONNECT only, UDP rejected with code 0x%02X)".format(rejection ?: 0x07)
            else -> "Proxy unreachable on $proxyHost:$proxyPort"
        }

        return Socks5Capabilities(
            supportsTcpConnect = tcpOk,
            supportsUdpAssociate = udpOk,
            udpRejectionCode = rejection,
            description = desc
        )
    }

    /**
     * Establishes a TCP connection to the destination through SOCKS5 proxy.
     * Prevents DNS leaks by transmitting the raw domain string to the proxy (ATYP 0x03)
     * without performing local DNS resolution.
     */
    fun connectTcp(targetHost: String, targetPort: Int): Socket {
        val socket = Socket()
        socket.soTimeout = readTimeoutMs
        socket.connect(InetSocketAddress(proxyHost, proxyPort), connectTimeoutMs)

        val out = DataOutputStream(socket.getOutputStream())
        val `in` = DataInputStream(socket.getInputStream())

        // 1. Initial Handshake: Version 5, 1 Method, Method 0x00 (NO AUTH)
        out.write(byteArrayOf(0x05, 0x01, 0x00))
        out.flush()

        val serverVer = `in`.readUnsignedByte()
        val selectedMethod = `in`.readUnsignedByte()
        if (serverVer != 0x05 || selectedMethod != 0x00) {
            socket.close()
            throw IOException("SOCKS5 authentication failed or version mismatch: ver=$serverVer, method=$selectedMethod")
        }

        // 2. Connect Request with Domain Name (ATYP 0x03) to prevent local DNS leak
        val hostBytes = targetHost.toByteArray(StandardCharsets.US_ASCII)
        require(hostBytes.size <= 255) { "Host length cannot exceed 255 bytes: $targetHost" }

        val req = ByteBuffer.allocate(7 + hostBytes.size)
        req.put(0x05.toByte()) // VER
        req.put(0x01.toByte()) // CMD = CONNECT
        req.put(0x00.toByte()) // RSV
        req.put(0x03.toByte()) // ATYP = DOMAINNAME
        req.put(hostBytes.size.toByte())
        req.put(hostBytes)
        req.putShort(targetPort.toShort())

        out.write(req.array())
        out.flush()

        // 3. Connect Reply
        val repVer = `in`.readUnsignedByte()
        val repCode = `in`.readUnsignedByte()
        `in`.readUnsignedByte() // RSV
        val atyp = `in`.readUnsignedByte()

        if (repVer != 0x05 || repCode != 0x00) {
            socket.close()
            throw IOException("SOCKS5 connect failed: code=$repCode (server=$proxyHost:$proxyPort, target=$targetHost:$targetPort)")
        }

        // Read bound address and port
        readBoundAddress(`in`, atyp)
        `in`.readUnsignedShort() // Bound port

        return socket
    }

    /**
     * Establishes a UDP association with the SOCKS5 proxy according to RFC 1928 section 6.
     * Keeps a TCP control socket open and returns a [Socks5UdpAssociation] for sending/receiving datagrams.
     */
    fun createUdpAssociation(): Socks5UdpAssociation {
        val controlSocket = Socket()
        controlSocket.soTimeout = 0 // Keep-alive socket
        controlSocket.connect(InetSocketAddress(proxyHost, proxyPort), connectTimeoutMs)

        val out = DataOutputStream(controlSocket.getOutputStream())
        val `in` = DataInputStream(controlSocket.getInputStream())

        // 1. Handshake
        out.write(byteArrayOf(0x05, 0x01, 0x00))
        out.flush()

        val serverVer = `in`.readUnsignedByte()
        val selectedMethod = `in`.readUnsignedByte()
        if (serverVer != 0x05 || selectedMethod != 0x00) {
            controlSocket.close()
            throw IOException("SOCKS5 handshake failed: ver=$serverVer, method=$selectedMethod")
        }

        // 2. Request UDP ASSOCIATE (CMD 0x03)
        // Client specifies 0.0.0.0:0 as DST.ADDR/PORT
        out.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        out.flush()

        // 3. Response
        val repVer = `in`.readUnsignedByte()
        val repCode = `in`.readUnsignedByte()
        `in`.readUnsignedByte() // RSV
        val atyp = `in`.readUnsignedByte()

        if (repVer != 0x05 || repCode != 0x00) {
            controlSocket.close()
            if (repCode == 0x07 || repCode == 0x01) {
                throw Socks5CommandNotSupportedException(
                    replyCode = repCode,
                    message = "SOCKS5 UDP ASSOCIATE (CMD 0x03) rejected with code 0x%02X (Command not supported by Tor daemon)".format(repCode)
                )
            }
            throw IOException("SOCKS5 UDP ASSOCIATE rejected with code $repCode")
        }

        val bndAddr = readBoundAddress(`in`, atyp)
        val bndPort = `in`.readUnsignedShort()

        // If relay reports 0.0.0.0, use the proxy IP address that accepted the TCP connection
        val relayIp = if (bndAddr.isAnyLocalAddress || bndAddr.hostAddress == "0.0.0.0") {
            controlSocket.inetAddress
        } else {
            bndAddr
        }

        val relayEndpoint = InetSocketAddress(relayIp, bndPort)
        val udpSocket = DatagramSocket().apply { reuseAddress = true }

        return Socks5UdpAssociation(controlSocket, udpSocket, relayEndpoint)
    }

    private fun readBoundAddress(`in`: DataInputStream, atyp: Int): InetAddress {
        return when (atyp) {
            0x01 -> { // IPv4
                val addrBytes = ByteArray(4)
                `in`.readFully(addrBytes)
                InetAddress.getByAddress(addrBytes)
            }
            0x03 -> { // Domain name
                val len = `in`.readUnsignedByte()
                val domainBytes = ByteArray(len)
                `in`.readFully(domainBytes)
                val domain = String(domainBytes, StandardCharsets.US_ASCII)
                try {
                    InetAddress.getByName(domain)
                } catch (_: Exception) {
                    InetAddress.getByName("127.0.0.1")
                }
            }
            0x04 -> { // IPv6
                val addrBytes = ByteArray(16)
                `in`.readFully(addrBytes)
                InetAddress.getByAddress(addrBytes)
            }
            else -> throw IOException("Unsupported SOCKS5 address type: $atyp")
        }
    }

    /**
     * Active UDP association channel maintaining the SOCKS5 TCP control connection
     * and encapsulating/decapsulating RFC 1928 UDP datagrams.
     */
    class Socks5UdpAssociation(
        private val controlSocket: Socket,
        val localDatagramSocket: DatagramSocket,
        val relayEndpoint: InetSocketAddress
    ) : Closeable {

        @Volatile
        var isClosed: Boolean = false
            private set

        /**
         * Sends a datagram through the SOCKS5 UDP relay to the specified target.
         * Appends RFC 1928 UDP header.
         */
        fun send(data: ByteArray, target: InetSocketAddress) {
            if (isClosed) throw IOException("SOCKS5 UDP association is closed")

            val header = buildHeader(target)
            val packetData = ByteArray(header.size + data.size)
            System.arraycopy(header, 0, packetData, 0, header.size)
            System.arraycopy(data, 0, packetData, header.size, data.size)

            val packet = DatagramPacket(packetData, packetData.size, relayEndpoint)
            localDatagramSocket.send(packet)
        }

        /**
         * Sends a datagram with domain-name destination (ATYP 0x03), preventing DNS leaks.
         */
        fun sendDomain(data: ByteArray, targetHost: String, targetPort: Int) {
            if (isClosed) throw IOException("SOCKS5 UDP association is closed")

            val hostBytes = targetHost.toByteArray(StandardCharsets.US_ASCII)
            val header = ByteBuffer.allocate(7 + hostBytes.size)
            header.putShort(0.toShort()) // RSV
            header.put(0.toByte())       // FRAG
            header.put(0x03.toByte())    // ATYP = DOMAINNAME
            header.put(hostBytes.size.toByte())
            header.put(hostBytes)
            header.putShort(targetPort.toShort())

            val headerBytes = header.array()
            val packetData = ByteArray(headerBytes.size + data.size)
            System.arraycopy(headerBytes, 0, packetData, 0, headerBytes.size)
            System.arraycopy(data, 0, packetData, headerBytes.size, data.size)

            val packet = DatagramPacket(packetData, packetData.size, relayEndpoint)
            localDatagramSocket.send(packet)
        }

        /**
         * Receives a datagram from the SOCKS5 UDP relay and decapsulates the RFC 1928 header.
         */
        fun receive(buffer: ByteArray = ByteArray(4096)): Socks5UdpPacket? {
            if (isClosed) return null
            val packet = DatagramPacket(buffer, buffer.size)
            localDatagramSocket.receive(packet)

            val length = packet.length
            if (length < 10) return null // Minimum header size is 10 for IPv4

            val bb = ByteBuffer.wrap(packet.data, 0, length)
            bb.short // RSV
            bb.get() // FRAG
            val atyp = bb.get().toInt() and 0xFF

            val senderAddress: InetSocketAddress = when (atyp) {
                0x01 -> { // IPv4
                    val ip = ByteArray(4)
                    bb.get(ip)
                    val port = bb.short.toInt() and 0xFFFF
                    InetSocketAddress(InetAddress.getByAddress(ip), port)
                }
                0x03 -> { // Domain name
                    val domainLen = bb.get().toInt() and 0xFF
                    val domainBytes = ByteArray(domainLen)
                    bb.get(domainBytes)
                    val port = bb.short.toInt() and 0xFFFF
                    val host = String(domainBytes, StandardCharsets.US_ASCII)
                    InetSocketAddress.createUnresolved(host, port)
                }
                0x04 -> { // IPv6
                    val ip = ByteArray(16)
                    bb.get(ip)
                    val port = bb.short.toInt() and 0xFFFF
                    InetSocketAddress(InetAddress.getByAddress(ip), port)
                }
                else -> return null
            }

            val payloadOffset = bb.position()
            val payloadLen = length - payloadOffset
            val payload = ByteArray(payloadLen)
            System.arraycopy(packet.data, payloadOffset, payload, 0, payloadLen)

            return Socks5UdpPacket(payload, senderAddress)
        }

        private fun buildHeader(target: InetSocketAddress): ByteArray {
            return if (target.isUnresolved) {
                val hostBytes = target.hostName.toByteArray(StandardCharsets.US_ASCII)
                val bb = ByteBuffer.allocate(7 + hostBytes.size)
                bb.putShort(0.toShort()) // RSV
                bb.put(0.toByte())       // FRAG
                bb.put(0x03.toByte())    // ATYP = DOMAINNAME
                bb.put(hostBytes.size.toByte())
                bb.put(hostBytes)
                bb.putShort(target.port.toShort())
                bb.array()
            } else {
                val ip = target.address.address
                val bb = ByteBuffer.allocate(4 + ip.size + 2)
                bb.putShort(0.toShort()) // RSV
                bb.put(0.toByte())       // FRAG
                bb.put(if (ip.size == 4) 0x01.toByte() else 0x04.toByte())
                bb.put(ip)
                bb.putShort(target.port.toShort())
                bb.array()
            }
        }

        override fun close() {
            if (isClosed) return
            isClosed = true
            try {
                controlSocket.close()
            } catch (_: Exception) {
            }
            try {
                localDatagramSocket.close()
            } catch (_: Exception) {
            }
        }
    }
}
