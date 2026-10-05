package org.pqchat.dht.traffic

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.dht.leaf.DhtLeafNode
import kotlin.math.ln

/**
 * Poisson Process Cover Traffic Generator (Chaffing).
 *
 * Intervals delta_t follow an exponential distribution:
 * delta_t = - (1 / lambda) * ln(U), where U ~ Uniform(0, 1)
 *
 * Masks transmission patterns so external observers cannot distinguish
 * between real conversations and background noise.
 */
class PoissonTrafficGenerator(
    private val dhtLeafNode: DhtLeafNode,
    private val lambda: Double = 1.0 / 480.0 // average once every 8 minutes (480s)
) {
    data class CoverEvent(
        val timestamp: Long,
        val targetHex: String,
        val intervalSeconds: Double
    )

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val _eventFlow = MutableSharedFlow<CoverEvent>(replay = 50)
    val eventFlow: SharedFlow<CoverEvent> = _eventFlow.asSharedFlow()

    @Volatile
    private var isRunning = false

    /**
     * Compute next Poisson interval delta_t in milliseconds.
     */
    fun computeNextIntervalMs(currentLambda: Double = lambda): Long {
        val u = CryptoUtils.secureRandom.nextDouble().coerceIn(1e-10, 1.0 - 1e-10)
        val deltaSeconds = -(1.0 / currentLambda) * ln(u)
        return (deltaSeconds * 1000.0).toLong().coerceAtLeast(1000L)
    }

    fun start() {
        if (isRunning) return
        isRunning = true

        scope.launch {
            while (isRunning) {
                val delayMs = computeNextIntervalMs()
                delay(delayMs)
                if (!isRunning) break

                try {
                    val dummySeed = CryptoUtils.secureRandomBytes(32)
                    val dummyTarget = CryptoUtils.sha1(dummySeed)
                    dhtLeafNode.sendCoverTrafficDummy()

                    _eventFlow.emit(
                        CoverEvent(
                            timestamp = System.currentTimeMillis(),
                            targetHex = CryptoUtils.toHex(dummyTarget),
                            intervalSeconds = delayMs / 1000.0
                        )
                    )
                } catch (_: Exception) {}
            }
        }
    }

    fun stop() {
        isRunning = false
        scope.cancel()
    }
}
