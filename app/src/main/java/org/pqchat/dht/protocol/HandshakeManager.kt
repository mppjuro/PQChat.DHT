package org.pqchat.dht.protocol

import org.pqchat.dht.crypto.*
import java.util.Arrays

object HandshakeManager {

    const val QR_DATA_SIZE = 832 // 800 bytes pk_A + 32 bytes Seed_init
    private val RENDEZVOUS_INFO = "handshake_rendezvous".toByteArray(Charsets.UTF_8)
    private val HS_ENC_INFO = "hs_enc".toByteArray(Charsets.UTF_8)
    private val HS_ED_INFO = "hs_ed25519".toByteArray(Charsets.UTF_8)

    data class AliceInitResult(
        val qrBytes: ByteArray,
        val skA: ByteArray,
        val pkA: ByteArray,
        val seedInit: ByteArray,
        val target0: ByteArray
    ) {
        fun destroySensitiveKeys() {
            Arrays.fill(skA, 0.toByte())
        }
    }

    data class BobHandshakeResult(
        val frame1000: ByteArray,
        val target0: ByteArray,
        val edPrivateKeySeed: ByteArray,
        val chainKeyAtoB: ByteArray,
        val chainKeyBtoA: ByteArray
    )

    data class EstablishedSession(
        val chainKeyOut: ByteArray, // 64 bytes
        val chainKeyIn: ByteArray,  // 64 bytes
        val counterOut: Int = 0,
        val counterIn: Int = 0
    )

    /**
     * Step 1 (Alice): Generates ML-KEM-512 key pair and random 32-byte seed.
     * Returns 832-byte QR payload (800B pk + 32B seed).
     */
    fun aliceCreateHandshake(): AliceInitResult {
        val kemPair = MLKemEngine.generateKeyPair()
        val seedInit = CryptoUtils.secureRandomBytes(32)

        val qrBytes = ByteArray(QR_DATA_SIZE)
        System.arraycopy(kemPair.publicKey, 0, qrBytes, 0, MLKemEngine.PUBLIC_KEY_SIZE)
        System.arraycopy(seedInit, 0, qrBytes, MLKemEngine.PUBLIC_KEY_SIZE, 32)

        val target0 = computeTarget0(seedInit)

        return AliceInitResult(
            qrBytes = qrBytes,
            skA = kemPair.privateKey,
            pkA = kemPair.publicKey,
            seedInit = seedInit,
            target0 = target0
        )
    }

    /**
     * Compute Target_0 = SHA-1(HMAC-SHA512(Seed_init, "handshake_rendezvous"))
     */
    fun computeTarget0(seedInit: ByteArray): ByteArray {
        val hmac = CryptoUtils.hmacSha512(seedInit, RENDEZVOUS_INFO)
        return CryptoUtils.sha1(hmac)
    }

    /**
     * Step 2 (Bob): Scans 832-byte QR code from Alice, encapsulates ML-KEM shared secret,
     * creates 1000-byte Type 0x01 BEP 44 frame to PUT to DHT at Target_0.
     */
    fun bobProcessQr(qrBytes: ByteArray): BobHandshakeResult {
        require(qrBytes.size == QR_DATA_SIZE) { "Invalid QR code data size: ${qrBytes.size}, expected $QR_DATA_SIZE" }

        val pkA = qrBytes.copyOfRange(0, MLKemEngine.PUBLIC_KEY_SIZE)
        val seedInit = qrBytes.copyOfRange(MLKemEngine.PUBLIC_KEY_SIZE, QR_DATA_SIZE)

        // 1. Encapsulate post-quantum shared secret
        val (ssInit, ctB) = MLKemEngine.encapsulate(pkA)

        // 2. Compute Target_0
        val target0 = computeTarget0(seedInit)

        // 3. Derive symmetric encryption key for the handshake frame
        // Uses Seed_init so Alice can decrypt the frame to retrieve ct_B
        val kHs = HkdfSha512.derive(null, seedInit, HS_ENC_INFO, 32)

        // 4. Derive ephemeral Ed25519 key pair for DHT BEP 44
        val edSeed = HkdfSha512.derive(null, seedInit, HS_ED_INFO, 32)

        // 5. Build Type 0x01 Handshake Finalize frame
        val salt = CryptoUtils.secureRandomBytes(32)
        val plaintext972 = BinaryFrameCodec.encodeHandshakeFinalize(
            seqNum = 0,
            ackNum = 0,
            timestampUTC = System.currentTimeMillis(),
            mlKemCiphertext = ctB,
            saltParameter = salt
        )
        val frame1000 = BinaryFrameCodec.packAeadFrame(kHs, plaintext972)

        // 6. Derive working KDF chains:
        // ChainKey_{A->B} = HKDF-Expand(SS_init, "AliceToBob", 64)
        // ChainKey_{B->A} = HKDF-Expand(SS_init, "BobToAlice", 64)
        val chainAtoB = HkdfSha512.expand(ssInit, "AliceToBob".toByteArray(Charsets.UTF_8), 64)
        val chainBtoA = HkdfSha512.expand(ssInit, "BobToAlice".toByteArray(Charsets.UTF_8), 64)

        // For Bob:
        // Outgoing chain: B->A
        // Incoming chain: A->B
        return BobHandshakeResult(
            frame1000 = frame1000,
            target0 = target0,
            edPrivateKeySeed = edSeed,
            chainKeyAtoB = chainAtoB,
            chainKeyBtoA = chainBtoA
        )
    }

    /**
     * Step 3 (Alice): On receiving Type 0x01 frame from Target_0:
     * Decrypts frame, decapsulates ct_B to recover SS_init, derives chains, destroys sk_A.
     */
    fun aliceFinalize(
        skA: ByteArray,
        seedInit: ByteArray,
        frame1000: ByteArray
    ): EstablishedSession {
        val kHs = HkdfSha512.derive(null, seedInit, HS_ENC_INFO, 32)
        val frameMsg = BinaryFrameCodec.unpackAeadFrame(kHs, frame1000)

        require(frameMsg.msgType == BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE) {
            "Expected Handshake Finalize message (0x01), got 0x%02X".format(frameMsg.msgType)
        }

        val handshakePayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.HandshakeFinalize

        // Decapsulate SS_init using Alice's ML-KEM private key
        val ssInit = MLKemEngine.decapsulate(skA, handshakePayload.mlKemCiphertext)

        // Wipe Alice's ephemeral private key from memory
        Arrays.fill(skA, 0.toByte())

        // Derive working chains
        val chainAtoB = HkdfSha512.expand(ssInit, "AliceToBob".toByteArray(Charsets.UTF_8), 64)
        val chainBtoA = HkdfSha512.expand(ssInit, "BobToAlice".toByteArray(Charsets.UTF_8), 64)

        // For Alice:
        // Outgoing chain: A->B
        // Incoming chain: B->A
        return EstablishedSession(
            chainKeyOut = chainAtoB,
            chainKeyIn = chainBtoA,
            counterOut = 0,
            counterIn = 0
        )
    }
}
