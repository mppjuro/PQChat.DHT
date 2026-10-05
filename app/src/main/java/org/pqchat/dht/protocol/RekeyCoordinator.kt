package org.pqchat.dht.protocol

import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.MLKemEngine
import java.util.Arrays

object RekeyCoordinator {

    const val REKEY_INTERVAL = 50

    data class PendingRekeyOffer(
        val epoch: Long,
        val skNew: ByteArray,
        val pkNew: ByteArray,
        val createdAt: Long = System.currentTimeMillis()
    ) {
        fun destroy() {
            Arrays.fill(skNew, 0.toByte())
        }
    }

    /**
     * Checks if current sender counter qualifies for initiating a rekey offer.
     */
    fun shouldOfferRekey(counterOut: Int): Boolean {
        return counterOut > 0 && (counterOut % REKEY_INTERVAL == 0)
    }

    /**
     * Sender generates ML-KEM-512 key pair and builds Type 0x03 Offer frame.
     */
    fun createRekeyOffer(
        epoch: Long,
        seqNum: Int,
        ackNum: Int,
        msgKey: ByteArray
    ): Pair<PendingRekeyOffer, ByteArray> {
        val kemPair = MLKemEngine.generateKeyPair()

        val plaintext972 = BinaryFrameCodec.encodeRekeyOffer(
            seqNum = seqNum,
            ackNum = ackNum,
            timestampUTC = System.currentTimeMillis(),
            rekeyEpoch = epoch,
            mlKemPublicKey = kemPair.publicKey
        )

        val frame1000 = BinaryFrameCodec.packAeadFrame(msgKey, plaintext972)

        val pending = PendingRekeyOffer(
            epoch = epoch,
            skNew = kemPair.privateKey,
            pkNew = kemPair.publicKey
        )

        return Pair(pending, frame1000)
    }

    /**
     * Receiver processes Type 0x03 Offer, encapsulates SS_rekey, and builds Type 0x04 Response frame.
     * Returns (SS_rekey, frame1000).
     */
    fun processOfferAndCreateResponse(
        offer: BinaryFrameCodec.DecodedPayload.RekeyOffer,
        reverseSeqNum: Int,
        reverseAckNum: Int,
        reverseMsgKey: ByteArray
    ): Pair<ByteArray, ByteArray> {
        // 1. Encapsulate SS_rekey against sender's pk_new
        val (ssRekey, ctNew) = MLKemEngine.encapsulate(offer.mlKemPublicKey)

        // 2. Build Type 0x04 Response frame for reverse channel
        val plaintext972 = BinaryFrameCodec.encodeRekeyResponse(
            seqNum = reverseSeqNum,
            ackNum = reverseAckNum,
            timestampUTC = System.currentTimeMillis(),
            rekeyEpoch = offer.rekeyEpoch,
            mlKemCiphertext = ctNew
        )

        val frame1000 = BinaryFrameCodec.packAeadFrame(reverseMsgKey, plaintext972)

        return Pair(ssRekey, frame1000)
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

        val ssRekey = MLKemEngine.decapsulate(pendingOffer.skNew, response.mlKemCiphertext)
        pendingOffer.destroy()

        return ssRekey
    }
}
