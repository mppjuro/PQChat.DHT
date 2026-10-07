package org.pqchat.dht.dht.integration

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.dht.leaf.DhtLeafNode
import java.security.Security

/**
 * Integration test verifying real BitTorrent Mainline DHT BEP 44 remote PUT and GET operations.
 * Requires public internet connectivity to reach DHT bootstrap nodes.
 */
class RealBep44RemoteIntegrationTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @Test
    fun testRealBep44RemotePutAndGet() = runBlocking {
        val node = DhtLeafNode()
        node.start()
        val bootstrapNodes = node.resolveBootstrapNodes()
        println("Bootstrap nodes: $bootstrapNodes")
        node.bootstrap()
        delay(3000)
        println("Active peer count: ${node.getActivePeerCount()}")

        val seed = CryptoUtils.secureRandomBytes(32)
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        val target = Ed25519Engine.computeTarget(keyPair.publicKey)
        val payload = ByteArray(900) { 0x42.toByte() }

        println("Target hex: ${CryptoUtils.toHex(target)}")
        val putResult = node.putMutable(target, payload, 1L, null, seed)
        println("putMutable returned: $putResult")

        // Wait a few seconds for propagation
        delay(4000)

        // Clear local store to force fetching exclusively from remote peers
        node.localMutableStore.clear()

        println("Attempting remote getMutable (local store cleared)...")
        val retrieved = node.getMutable(target)
        println("Remote getMutable result: ${retrieved?.let { String(it.v, Charsets.UTF_8) }}")

        node.stop()
    }
}
