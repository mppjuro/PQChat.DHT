package org.pqchat.dht.protocol

import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.HybridKemEngine
import java.util.Arrays

object RekeyCoordinator {

    const val REKEY_INTERVAL = 50

    data class PendingRekeyOffer(
        val epoch: Long,
        val skNew: ByteArray, // 1664 B: 1632 B ML-KEM sk + 32 B X25519 sk
        val pkNew: ByteArray, // 832 B: 800 B ML-KEM pk + 32 B X25519 pk
        val createdAt: Long = System.currentTimeMillis()
    ) {
        fun destroy() {
            Arrays.fill(skNew, 0.toByte())
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PendingRekeyOffer) return false
            return epoch == other.epoch &&
                    skNew.contentEquals(other.skNew) &&
                    pkNew.contentEquals(other.pkNew) &&
                    createdAt == other.createdAt
        }

        override fun hashCode(): Int {
            var result = epoch.hashCode()
            result = 31 * result + skNew.contentHashCode()
            result = 31 * result + pkNew.contentHashCode()
            result = 31 * result + createdAt.hashCode()
            return result
        }
    }

    /**
     * Checks if current sender counter qualifies for initiating a rekey offer.
     */
    fun shouldOfferRekey(counterOut: Int): Boolean {
        return counterOut > 0 && (counterOut % REKEY_INTERVAL == 0)
    }

    /**
     * Sender generates Hybrid (ML-KEM-512 + X25519) key pair and builds Type 0x03 Offer frame.
     */
    fun createRekeyOffer(
        epoch: Long,
        seqNum: Int,
        ackNum: Int,
        msgKey: ByteArray,
        target: ByteArray,
        direction: String
    ): Pair<PendingRekeyOffer, ByteArray> {
        val hybridPair = HybridKemEngine.generateKeyPair()

        val skNew = ByteArray(1632 + 32)
        System.arraycopy(hybridPair.mlKemPrivateKey, 0, skNew, 0, 1632)
        System.arraycopy(hybridPair.x25519PrivateKey, 0, skNew, 1632, 32)
        val pkNew = hybridPair.combinedPublicKey // 832 bytes

        // Zero original key pair fields
        hybridPair.wipe()

        val plaintext = BinaryFrameCodec.encodeRekeyOffer(
            seqNum = seqNum,
            ackNum = ackNum,
            timestampUTC = System.currentTimeMillis(),
            rekeyEpoch = epoch,
            hybridPublicKey = pkNew
        )

        val frame = BinaryFrameCodec.packAeadFrame(msgKey, plaintext, target, direction)

        val pending = PendingRekeyOffer(
            epoch = epoch,
            skNew = skNew,
            pkNew = pkNew
        )

        return Pair(pending, frame)
    }

    /**
     * Receiver processes Type 0x03 Offer, encapsulates SS_rekey, and builds Type 0x04 Response frame.
     * Returns (SS_rekey, frame).
     */
    fun processOfferAndCreateResponse(
        offer: BinaryFrameCodec.DecodedPayload.RekeyOffer,
        reverseSeqNum: Int,
        reverseAckNum: Int,
        reverseMsgKey: ByteArray,
        reverseTarget: ByteArray,
        direction: String
    ): Pair<ByteArray, ByteArray> {
        // 1. Encapsulate SS_rekey against sender's hybrid pk_new (832 bytes)
        val encResult = HybridKemEngine.encapsulate(offer.hybridPublicKey)
        val ssRekey = encResult.sharedSecret.copyOf()
        val ctNew = encResult.combinedCiphertext // 800 bytes
        encResult.wipe()

        // 2. Build Type 0x04 Response frame for reverse channel
        val plaintext = BinaryFrameCodec.encodeRekeyResponse(
            seqNum = reverseSeqNum,
            ackNum = reverseAckNum,
            timestampUTC = System.currentTimeMillis(),
            rekeyEpoch = offer.rekeyEpoch,
            hybridCiphertext = ctNew
        )

        val frame = BinaryFrameCodec.packAeadFrame(reverseMsgKey, plaintext, reverseTarget, direction)

        return Pair(ssRekey, frame)
    }

    /**
     * Sender processes Type 0x04 Response from reverse channel.
     * Decapsulates SS_rekey and destroys ephemeral sk_new.
     */
    fun processResponse(
        response: BinaryFrameCodec.DecodedPayload.RekeyResponse,
        pendingOffer: PendingRekeyOffer
    ): ByteArray {
        require(response.rekeyEpoch == pendingOffer.epoch) {
            "Rekey epoch mismatch: expected ${pendingOffer.epoch}, got ${response.rekeyEpoch}"
        }

        require(pendingOffer.skNew.size == 1664) {
            "Invalid pending offer private key size: ${pendingOffer.skNew.size}, expected 1664 bytes"
        }

        val mlKemSk = pendingOffer.skNew.copyOfRange(0, 1632)
        val x25519Sk = pendingOffer.skNew.copyOfRange(1632, 1664)

        val ssRekey = HybridKemEngine.decapsulate(
            mlKemPrivateKey = mlKemSk,
            x25519PrivateKey = x25519Sk,
            combinedCiphertext = response.hybridCiphertext
        )

        mlKemSk.fill(0)
        x25519Sk.fill(0)
        pendingOffer.destroy() // wipes pendingOffer.skNew

        return ssRekey
    }
}
