package org.pqchat.dht.network.tor

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress

/**
 * Tunneling client for routing BEP 44 KRPC messages over streaming TCP SOCKS5 connections.
 *
 * Standard Tor daemons (including Orbot and libtor.so) do not support SOCKS5 UDP ASSOCIATE (RFC 1928 CMD 0x03).
 * When UDP ASSOCIATE is rejected, this client tunnels KRPC queries to nodes supporting TCP/Onion relays
 * using length-prefixed framing:
 *   [4 bytes Length (Big-Endian UInt32)] + [Bencoded KRPC bytes]
 *
 * This guarantees zero UDP packet leakage to the clearnet while maintaining compatibility with
 * Tor's SOCKS5 TCP-only stream architecture.
 */
class TorTcpTunnelClient(
    val socks5Client: Socks5Client,
    private val defaultTimeoutMs: Long = 8000L
) {
    /**
     * Sends a length-prefixed KRPC message over a TCP stream via SOCKS5 proxy
     * and reads the length-prefixed response.
     *
     * @param target Target node socket address (can be unresolved domain to prevent DNS leaks)
     * @param queryBytes Bencoded KRPC query payload
     * @param timeoutMs Timeout in milliseconds for connection and response
     * @return Bencoded KRPC response bytes
     */
    fun sendQuery(
        target: InetSocketAddress,
        queryBytes: ByteArray,
        timeoutMs: Long = defaultTimeoutMs
    ): ByteArray {
        val targetHost = if (target.isUnresolved) target.hostName else target.address.hostAddress
        val targetPort = target.port

        val socket = socks5Client.connectTcp(targetHost, targetPort)
        socket.soTimeout = timeoutMs.toInt().coerceAtLeast(1000)

        return try {
            val out = DataOutputStream(socket.getOutputStream())
            val `in` = DataInputStream(socket.getInputStream())

            // 1. Send length-prefixed frame (4 bytes big-endian length + payload)
            out.writeInt(queryBytes.size)
            out.write(queryBytes)
            out.flush()

            // 2. Read length-prefixed response frame
            val respLen = `in`.readInt()
            if (respLen <= 0 || respLen > 65536) {
                throw IOException("Invalid KRPC TCP response frame length: $respLen")
            }
            val respData = ByteArray(respLen)
            `in`.readFully(respData)
            respData
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }
}
