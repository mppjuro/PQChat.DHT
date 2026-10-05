package org.pqchat.dht.protocol

import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.crypto.HkdfSha512
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Dual Unidirectional KDF Ratchet & Key Hopping Engine.
 *
 * For each step i:
 * Entropy_i = HKDF-Expand(ChainKey^i, "step" || i, 128)
 * - Bytes 0..31: MsgKey_i (AES-256-GCM symmetric key)
 * - Bytes 32..63: EdSeed_i (Ed25519 deterministic key pair pk_i, sk_i)
 * - Bytes 64..127: ChainKey^{i+1} (Next chain state)
 * - DHT Address: Target_i = SHA-1(pk_i)
 */
object RatchetChain {

    const val CHAIN_KEY_SIZE = 64
    const val MSG_KEY_SIZE = 32
    const val ED_SEED_SIZE = 32
    const val TOTAL_ENTROPY_SIZE = 128

    data class SlotParameters(
        val counter: Int,
        val msgKey: ByteArray,
        val edPrivateKeySeed: ByteArray,
        val edPublicKey: ByteArray,
        val target: ByteArray,
        val nextChainKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is SlotParameters) return false
            return counter == other.counter &&
                    msgKey.contentEquals(other.msgKey) &&
                    edPrivateKeySeed.contentEquals(other.edPrivateKeySeed) &&
                    edPublicKey.contentEquals(other.edPublicKey) &&
                    target.contentEquals(other.target) &&
                    nextChainKey.contentEquals(other.nextChainKey)
        }

        override fun hashCode(): Int {
            var result = counter
            result = 31 * result + msgKey.contentHashCode()
            result = 31 * result + edPrivateKeySeed.contentHashCode()
            result = 31 * result + edPublicKey.contentHashCode()
            result = 31 * result + target.contentHashCode()
            result = 31 * result + nextChainKey.contentHashCode()
            return result
        }
    }

    /**
     * Build info bytes for HKDF-Expand: "step" || i (as 32-bit big-endian integer)
     */
    private fun buildStepInfo(counter: Int): ByteArray {
        val buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
        buffer.put("step".toByteArray(Charsets.UTF_8))
        buffer.putInt(counter)
        return buffer.array()
    }

    /**
     * Derives slot parameters for step i from the current ChainKey.
     */
    fun deriveSlot(chainKey: ByteArray, counter: Int): SlotParameters {
        require(chainKey.size == CHAIN_KEY_SIZE) {
            "Invalid ChainKey size: ${chainKey.size}, expected $CHAIN_KEY_SIZE"
        }

        val info = buildStepInfo(counter)
        val entropy = HkdfSha512.expand(chainKey, info, TOTAL_ENTROPY_SIZE)

        val msgKey = entropy.copyOfRange(0, 32)
        val edSeed = entropy.copyOfRange(32, 64)
        val nextChainKey = entropy.copyOfRange(64, 128)

        val edKeyPair = Ed25519Engine.generateKeyPairFromSeed(edSeed)
        val target = Ed25519Engine.computeTarget(edKeyPair.publicKey)

        return SlotParameters(
            counter = counter,
            msgKey = msgKey,
            edPrivateKeySeed = edSeed,
            edPublicKey = edKeyPair.publicKey,
            target = target,
            nextChainKey = nextChainKey
        )
    }

    /**
     * Computes slots in a lookahead window [fromCounter, fromCounter + windowSize].
     * Useful for checking out-of-order slots on receiver side.
     */
    fun computeLookaheadSlots(
        startChainKey: ByteArray,
        startCounter: Int,
        windowSize: Int = 4
    ): List<SlotParameters> {
        val slots = ArrayList<SlotParameters>(windowSize + 1)
        var currentChain = startChainKey
        var currentCounter = startCounter

        for (k in 0..windowSize) {
            val slot = deriveSlot(currentChain, currentCounter)
            slots.add(slot)
            currentChain = slot.nextChainKey
            currentCounter++
        }

        return slots
    }

    /**
     * Injects a new post-quantum shared secret SS_rekey into the current ChainKey:
     * ChainKey = HKDF-Extract(ChainKey, SS_rekey)
     */
    fun injectRekeySecret(currentChainKey: ByteArray, ssRekey: ByteArray): ByteArray {
        require(currentChainKey.size == CHAIN_KEY_SIZE)
        require(ssRekey.size == 32)

        return HkdfSha512.extract(currentChainKey, ssRekey)
    }
}
