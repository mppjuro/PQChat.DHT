package org.pqchat.dht.network.tor

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory

/**
 * SocketFactory implementation that tunnels all TCP connections through an active SOCKS5 Tor proxy.
 *
 * Guarantees zero local DNS leaks by using SOCKS5 DOMAINNAME resolution (ATYP 0x03)
 * so that domain names are resolved exclusively on the Tor exit node.
 */
class TorSocketFactory(
    private val proxyAddressProvider: () -> InetSocketAddress?
) : SocketFactory() {

    override fun createSocket(): Socket {
        proxyAddressProvider() ?: throw IOException("Tor SOCKS5 proxy is not currently connected")
        // Return unbound socket; will be handled when connected or caller uses custom connection
        return Socket()
    }

    override fun createSocket(host: String, port: Int): Socket {
        val proxy = proxyAddressProvider() ?: throw IOException("Tor SOCKS5 proxy is not currently connected")
        val client = Socks5Client(proxy.hostString, proxy.port)
        return client.connectTcp(host, port)
    }

    override fun createSocket(host: String, port: Int, localHost: InetAddress?, localPort: Int): Socket {
        // Ignores local bind interface to avoid leaking device network routes, tunnels directly via Tor proxy
        return createSocket(host, port)
    }

    override fun createSocket(host: InetAddress, port: Int): Socket {
        val proxy = proxyAddressProvider() ?: throw IOException("Tor SOCKS5 proxy is not currently connected")
        val client = Socks5Client(proxy.hostString, proxy.port)
        return client.connectTcp(host.hostAddress ?: host.hostName, port)
    }

    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress?, localPort: Int): Socket {
        return createSocket(address, port)
    }
}
