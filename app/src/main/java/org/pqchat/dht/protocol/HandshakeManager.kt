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
        val frame: ByteArray,
        val target0: ByteArray,
        val edPrivateKeySeed: ByteArray,
        val chainKeyAtoB: ByteArray,
        val chainKeyBtoA: ByteArray,
        val sas: String = "",
        val fingerprint: String = ""
    ) {
        @Deprecated("Use frame instead", ReplaceWith("frame"))
        val frame1000: ByteArray get() = frame
    }

    data class EstablishedSession(
        val chainKeyOut: ByteArray, // 64 bytes
        val chainKeyIn: ByteArray,  // 64 bytes
        val counterOut: Int = 0,
        val counterIn: Int = 0,
        val sas: String = "",
        val fingerprint: String = ""
    )

    fun buildTranscript(
        pkA: ByteArray,
        ctB: ByteArray,
        seedInit: ByteArray,
        salt: ByteArray
    ): ByteArray {
        val buffer = java.nio.ByteBuffer.allocate(pkA.size + ctB.size + seedInit.size + salt.size)
        buffer.put(pkA)
        buffer.put(ctB)
        buffer.put(seedInit)
        buffer.put(salt)
        return buffer.array()
    }

    fun computeConfirmationTag(masterKey: ByteArray): ByteArray {
        return HkdfSha512.expand(masterKey, "KeyConfirmationBob".toByteArray(Charsets.UTF_8), 32)
    }

    /**
     * Computes a 6-digit Short Authentication String (SAS).
     * Users can compare this code out-of-band to detect any eavesdropper who saw the QR code
     * and attempted to race/overwrite Target_0 on the DHT.
     */
    fun computeSas(masterKey: ByteArray): String {
        val sasBytes = HkdfSha512.expand(masterKey, "PQChat_SAS_v1".toByteArray(Charsets.UTF_8), 4)
        val num = java.nio.ByteBuffer.wrap(sasBytes).order(java.nio.ByteOrder.BIG_ENDIAN).int and 0x7FFFFFFF
        val code = num % 1000000
        return "%06d".format(code)
    }

    /**
     * Computes a formatted hex fingerprint of the negotiated session.
     */
    fun computeFingerprint(masterKey: ByteArray): String {
        val fpBytes = HkdfSha512.expand(masterKey, "PQChat_Fingerprint_v1".toByteArray(Charsets.UTF_8), 16)
        return CryptoUtils.toHex(fpBytes).chunked(4).joinToString(":")
    }

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
     * binds transcript (pkA, ctB, seedInit, salt), generates key confirmation tag,
     * and creates Type 0x01 BEP 44 frame with AAD to PUT to DHT at Target_0.
     */
    fun bobProcessQr(qrBytes: ByteArray): BobHandshakeResult {
        require(qrBytes.size == QR_DATA_SIZE) { "Invalid QR code data size: ${qrBytes.size}, expected $QR_DATA_SIZE" }

        val pkA = qrBytes.copyOfRange(0, MLKemEngine.PUBLIC_KEY_SIZE)
        val seedInit = qrBytes.copyOfRange(MLKemEngine.PUBLIC_KEY_SIZE, QR_DATA_SIZE)

        // 1. Encapsulate post-quantum shared secret
        val (ssInit, ctB) = MLKemEngine.encapsulate(pkA)

        // 2. Compute Target_0
        val target0 = computeTarget0(seedInit)

        // 3. Derive symmetric encryption key and Ed25519 seed for the handshake frame
        val kHs = HkdfSha512.derive(null, seedInit, HS_ENC_INFO, 32)
        val edSeed = HkdfSha512.derive(null, seedInit, HS_ED_INFO, 32)

        // 4. Generate salt and bind transcript: (pkA, ctB, seedInit, salt)
        val salt = CryptoUtils.secureRandomBytes(32)
        val transcript = buildTranscript(pkA, ctB, seedInit, salt)
        val transcriptHash = CryptoUtils.sha512(transcript)

        // 5. HKDF-Extract using salt and ssInit, then expand with transcriptHash
        val prk = HkdfSha512.extract(salt, ssInit)
        val label = "PQChat_MasterKey_Transcript".toByteArray(Charsets.UTF_8)
        val info = ByteArray(label.size + transcriptHash.size)
        System.arraycopy(label, 0, info, 0, label.size)
        System.arraycopy(transcriptHash, 0, info, label.size, transcriptHash.size)
        val masterKey = HkdfSha512.expand(prk, info, 64)

        // 6. Compute key confirmation tag
        val confirmationTag = computeConfirmationTag(masterKey)

        // 7. Build Type 0x01 Handshake Finalize frame with confirmation tag and AAD (target0, 0x01, "BobToAlice")
        val plaintext = BinaryFrameCodec.encodeHandshakeFinalize(
            seqNum = 0,
            ackNum = 0,
            timestampUTC = System.currentTimeMillis(),
            mlKemCiphertext = ctB,
            saltParameter = salt,
            confirmationTag = confirmationTag
        )
        val frame = BinaryFrameCodec.packAeadFrame(
            key = kHs,
            plaintext = plaintext,
            target = target0,
            direction = "BobToAlice"
        )

        // 8. Derive working KDF chains:
        val chainAtoB = HkdfSha512.expand(masterKey, "AliceToBob".toByteArray(Charsets.UTF_8), 64)
        val chainBtoA = HkdfSha512.expand(masterKey, "BobToAlice".toByteArray(Charsets.UTF_8), 64)
        val sas = computeSas(masterKey)
        val fingerprint = computeFingerprint(masterKey)

        // For Bob:
        // Outgoing chain: B->A
        // Incoming chain: A->B
        return BobHandshakeResult(
            frame = frame,
            target0 = target0,
            edPrivateKeySeed = edSeed,
            chainKeyAtoB = chainAtoB,
            chainKeyBtoA = chainBtoA,
            sas = sas,
            fingerprint = fingerprint
        )
    }

    /**
     * Step 3 (Alice): On receiving Type 0x01 frame from Target_0:
     * Decrypts frame with AAD, decapsulates ct_B to recover SS_init,
     * binds transcript, verifies Key Confirmation tag.
     * Only on verified confirmation is sk_A securely wiped and session established.
     */
    fun aliceFinalize(
        skA: ByteArray,
        pkA: ByteArray,
        seedInit: ByteArray,
        frame: ByteArray
    ): EstablishedSession {
        val target0 = computeTarget0(seedInit)
        val kHs = HkdfSha512.derive(null, seedInit, HS_ENC_INFO, 32)
        val frameMsg = BinaryFrameCodec.unpackAeadFrame(
            key = kHs,
            frame = frame,
            target = target0,
            direction = "BobToAlice",
            expectedType = BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE
        )

        require(frameMsg.msgType == BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE) {
            "Expected Handshake Finalize message (0x01), got 0x%02X".format(frameMsg.msgType)
        }

        val handshakePayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.HandshakeFinalize

        // Decapsulate SS_init using Alice's ML-KEM private key
        val ssInit = MLKemEngine.decapsulate(skA, handshakePayload.mlKemCiphertext)

        // Bind transcript: (pkA, ctB, seedInit, salt)
        val transcript = buildTranscript(pkA, handshakePayload.mlKemCiphertext, seedInit, handshakePayload.saltParameter)
        val transcriptHash = CryptoUtils.sha512(transcript)
        val prk = HkdfSha512.extract(handshakePayload.saltParameter, ssInit)
        val label = "PQChat_MasterKey_Transcript".toByteArray(Charsets.UTF_8)
        val info = ByteArray(label.size + transcriptHash.size)
        System.arraycopy(label, 0, info, 0, label.size)
        System.arraycopy(transcriptHash, 0, info, label.size, transcriptHash.size)
        val masterKey = HkdfSha512.expand(prk, info, 64)

        // Verify Key Confirmation Tag: protects against ML-KEM implicit rejection silent desync
        val expectedConfirmationTag = computeConfirmationTag(masterKey)
        if (!java.security.MessageDigest.isEqual(handshakePayload.confirmationTag, expectedConfirmationTag)) {
            // DO NOT wipe skA on failure: allows Alice to keep waiting for legitimate Bob packet
            throw SecurityException("ML-KEM key confirmation failed: invalid ciphertext or desync detected")
        }

        // Wipe Alice's ephemeral private key ONLY after verified key confirmation
        Arrays.fill(skA, 0.toByte())

        // Derive working chains
        val chainAtoB = HkdfSha512.expand(masterKey, "AliceToBob".toByteArray(Charsets.UTF_8), 64)
        val chainBtoA = HkdfSha512.expand(masterKey, "BobToAlice".toByteArray(Charsets.UTF_8), 64)
        val sas = computeSas(masterKey)
        val fingerprint = computeFingerprint(masterKey)

        // For Alice:
        // Outgoing chain: A->B
        // Incoming chain: B->A
        return EstablishedSession(
            chainKeyOut = chainAtoB,
            chainKeyIn = chainBtoA,
            counterOut = 0,
            counterIn = 0,
            sas = sas,
            fingerprint = fingerprint
        )
    }

    /**
     * Backward-compatible overload extracting pkA directly from skA.
     */
    fun aliceFinalize(
        skA: ByteArray,
        seedInit: ByteArray,
        frame: ByteArray
    ): EstablishedSession {
        val pkA = MLKemEngine.extractPublicKey(skA)
        return aliceFinalize(skA, pkA, seedInit, frame)
    }
}
