package org.pqchat.dht.protocol

import org.pqchat.dht.crypto.*
import java.util.Arrays

object HandshakeManager {

    const val QR_DATA_SIZE = 864 // 832 bytes combinedPublicKey + 32 bytes Seed_init
    private val RENDEZVOUS_INFO = "handshake_rendezvous".toByteArray(Charsets.UTF_8)
    private val HS_ENC_INFO = "hs_enc".toByteArray(Charsets.UTF_8)
    private val HS_ED_INFO = "hs_ed25519".toByteArray(Charsets.UTF_8)

    data class AliceInitResult(
        val qrBytes: ByteArray,
        val skA: ByteArray,      // Combined private keys (1632 B ML-KEM + 32 B X25519 = 1664 B)
        val pkA: ByteArray,      // Combined public key (800 B ML-KEM + 32 B X25519 = 832 B)
        val seedInit: ByteArray, // 32 bytes
        val target0: ByteArray
    ) {
        val mlKemPrivateKey: ByteArray get() = if (skA.size >= 1632) skA.copyOfRange(0, 1632) else skA
        val x25519PrivateKey: ByteArray get() = if (skA.size >= 1664) skA.copyOfRange(1632, 1664) else ByteArray(0)

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
     * Computes the cryptographic anti-grinding commitment over the handshake transcript.
     * Binds the initiator's Seed_init, ephemeral ML-KEM + X25519 public key, Bob's hybrid ciphertext, and salt.
     */
    fun computeAntiGrindCommitment(seedInit: ByteArray, transcript: ByteArray): ByteArray {
        val label = "PQChat_AntiGrind_v2".toByteArray(Charsets.UTF_8)
        val data = ByteArray(label.size + seedInit.size + transcript.size)
        var offset = 0
        System.arraycopy(label, 0, data, offset, label.size)
        offset += label.size
        System.arraycopy(seedInit, 0, data, offset, seedInit.size)
        offset += seedInit.size
        System.arraycopy(transcript, 0, data, offset, transcript.size)
        return CryptoUtils.sha256(data)
    }

    /**
     * Computes an 8-digit Short Authentication String (SAS) in the format "XXXX-XXXX".
     *
     * Anti-grinding Commitment & Entropy:
     * - Derives from masterKey and the anti-grinding commitment bound to the complete handshake transcript.
     * - Provides 10^8 (~26.6 bits) search space against offline or active grinding.
     * - Any tampering with transcript, KEM ciphertext, salt, or QR seed results in an entirely different SAS.
     */
    fun computeSas(masterKey: ByteArray, commitment: ByteArray? = null): String {
        val label = "PQChat_SAS_v2_AntiGrind".toByteArray(Charsets.UTF_8)
        val info = if (commitment != null) {
            val combined = ByteArray(label.size + commitment.size)
            System.arraycopy(label, 0, combined, 0, label.size)
            System.arraycopy(commitment, 0, combined, label.size, commitment.size)
            combined
        } else {
            label
        }
        val sasBytes = HkdfSha512.expand(masterKey, info, 8)
        val buffer = java.nio.ByteBuffer.wrap(sasBytes).order(java.nio.ByteOrder.BIG_ENDIAN)
        val part1 = (buffer.int and 0x7FFFFFFF) % 10000
        val part2 = (buffer.int and 0x7FFFFFFF) % 10000
        return "%04d-%04d".format(part1, part2)
    }

    /**
     * Computes a formatted hex fingerprint of the negotiated session.
     */
    fun computeFingerprint(masterKey: ByteArray): String {
        val fpBytes = HkdfSha512.expand(masterKey, "PQChat_Fingerprint_v1".toByteArray(Charsets.UTF_8), 16)
        return CryptoUtils.toHex(fpBytes).chunked(4).joinToString(":")
    }

    /**
     * Step 1 (Alice): Generates Hybrid ML-KEM-512 + X25519 key pair and random 32-byte seed.
     * Returns 864-byte QR payload (832B combined pk + 32B seed).
     */
    fun aliceCreateHandshake(): AliceInitResult {
        val hybridPair = HybridKemEngine.generateKeyPair()
        val seedInit = CryptoUtils.secureRandomBytes(32)

        val combinedPk = hybridPair.combinedPublicKey
        val qrBytes = ByteArray(QR_DATA_SIZE)
        System.arraycopy(combinedPk, 0, qrBytes, 0, HybridKemEngine.HYBRID_PUBLIC_KEY_SIZE)
        System.arraycopy(seedInit, 0, qrBytes, HybridKemEngine.HYBRID_PUBLIC_KEY_SIZE, 32)

        val target0 = computeTarget0(seedInit)

        val skA = ByteArray(1632 + 32)
        System.arraycopy(hybridPair.mlKemPrivateKey, 0, skA, 0, 1632)
        System.arraycopy(hybridPair.x25519PrivateKey, 0, skA, 1632, 32)

        // Zero original key pair fields
        hybridPair.wipe()

        return AliceInitResult(
            qrBytes = qrBytes,
            skA = skA,
            pkA = combinedPk,
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
     * Step 2 (Bob): Scans 864-byte QR code from Alice, encapsulates hybrid shared secret,
     * binds transcript (pkA, ctB, seedInit, salt), generates key confirmation tag,
     * and creates Type 0x01 BEP 44 frame with AAD to PUT to DHT at Target_0.
     */
    fun bobProcessQr(qrBytes: ByteArray): BobHandshakeResult {
        require(qrBytes.size == QR_DATA_SIZE) { "Invalid QR code data size: ${qrBytes.size}, expected $QR_DATA_SIZE" }

        val pkA = qrBytes.copyOfRange(0, HybridKemEngine.HYBRID_PUBLIC_KEY_SIZE)
        val seedInit = qrBytes.copyOfRange(HybridKemEngine.HYBRID_PUBLIC_KEY_SIZE, QR_DATA_SIZE)

        // 1. Encapsulate hybrid post-quantum + classical shared secret
        val encResult = HybridKemEngine.encapsulate(pkA)
        val ssInit = encResult.sharedSecret.copyOf()
        val ctB = encResult.combinedCiphertext
        encResult.wipe()

        // 2. Compute Target_0
        val target0 = computeTarget0(seedInit)

        // 3. Derive symmetric encryption key and Ed25519 seed for the handshake frame
        val kHs = HkdfSha512.derive(null, seedInit, HS_ENC_INFO, 32)
        val edSeed = HkdfSha512.derive(null, seedInit, HS_ED_INFO, 32)

        // 4. Generate salt (24 B per T1_SALT_SIZE) and bind transcript: (pkA, ctB, seedInit, salt)
        val salt = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T1_SALT_SIZE)
        val transcript = buildTranscript(pkA, ctB, seedInit, salt)
        val transcriptHash = CryptoUtils.sha512(transcript)

        // 5. HKDF-Extract using salt and ssInit, then expand with transcriptHash
        val prk = HkdfSha512.extract(salt, ssInit)
        val label = "PQChat_MasterKey_Transcript".toByteArray(Charsets.UTF_8)
        val info = ByteArray(label.size + transcriptHash.size)
        System.arraycopy(label, 0, info, 0, label.size)
        System.arraycopy(transcriptHash, 0, info, label.size, transcriptHash.size)
        val masterKey = HkdfSha512.expand(prk, info, 64)

        // Zero sensitive ephemeral ssInit
        ssInit.fill(0)

        // 6. Compute key confirmation tag
        val confirmationTag = computeConfirmationTag(masterKey)

        // 7. Build Type 0x01 Handshake Finalize frame with confirmation tag and AAD (target0, 0x01, "BobToAlice")
        val plaintext = BinaryFrameCodec.encodeHandshakeFinalize(
            seqNum = 0,
            ackNum = 0,
            timestampUTC = System.currentTimeMillis(),
            hybridCiphertext = ctB,
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
        val antiGrindCommitment = computeAntiGrindCommitment(seedInit, transcript)
        val sas = computeSas(masterKey, antiGrindCommitment)
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
     * Decrypts frame with AAD, decapsulates ct_B to recover SS_init using hybrid private keys,
     * binds transcript, verifies Key Confirmation tag.
     * Only on verified confirmation are ephemeral private keys securely wiped and session established.
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
            direction = "BobToAlice"
        )

        require(frameMsg.msgType == BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE) {
            "Expected Handshake Finalize message (0x01), got 0x%02X".format(frameMsg.msgType)
        }

        val handshakePayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.HandshakeFinalize

        require(skA.size == 1664) {
            "Invalid private key parameters for hybrid decapsulation: skA size must be 1664 (got ${skA.size})"
        }
        val mlKemSk = skA.copyOfRange(0, 1632)
        val x25519Sk = skA.copyOfRange(1632, 1664)

        // Decapsulate SS_init using Alice's hybrid private keys (ML-KEM-512 + X25519)
        val ssInit = HybridKemEngine.decapsulate(
            mlKemPrivateKey = mlKemSk,
            x25519PrivateKey = x25519Sk,
            combinedCiphertext = handshakePayload.hybridCiphertext
        )

        // Bind transcript: (pkA, ctB, seedInit, salt)
        val transcript = buildTranscript(pkA, handshakePayload.hybridCiphertext, seedInit, handshakePayload.saltParameter)
        val transcriptHash = CryptoUtils.sha512(transcript)
        val prk = HkdfSha512.extract(handshakePayload.saltParameter, ssInit)
        val label = "PQChat_MasterKey_Transcript".toByteArray(Charsets.UTF_8)
        val info = ByteArray(label.size + transcriptHash.size)
        System.arraycopy(label, 0, info, 0, label.size)
        System.arraycopy(transcriptHash, 0, info, label.size, transcriptHash.size)
        val masterKey = HkdfSha512.expand(prk, info, 64)

        // Verify Key Confirmation Tag: protects against ML-KEM/Hybrid implicit rejection silent desync
        val expectedConfirmationTag = computeConfirmationTag(masterKey)
        if (!java.security.MessageDigest.isEqual(handshakePayload.confirmationTag, expectedConfirmationTag)) {
            // DO NOT wipe skA on failure: allows Alice to keep waiting for legitimate Bob packet
            mlKemSk.fill(0)
            x25519Sk.fill(0)
            ssInit.fill(0)
            throw SecurityException("ML-KEM/Hybrid key confirmation failed: invalid ciphertext or desync detected")
        }

        // Wipe Alice's ephemeral private keys ONLY after verified key confirmation
        Arrays.fill(skA, 0.toByte())
        mlKemSk.fill(0)
        x25519Sk.fill(0)
        ssInit.fill(0)

        // Derive working chains
        val chainAtoB = HkdfSha512.expand(masterKey, "AliceToBob".toByteArray(Charsets.UTF_8), 64)
        val chainBtoA = HkdfSha512.expand(masterKey, "BobToAlice".toByteArray(Charsets.UTF_8), 64)
        val antiGrindCommitment = computeAntiGrindCommitment(seedInit, transcript)
        val sas = computeSas(masterKey, antiGrindCommitment)
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

    fun extractCombinedPublicKey(skA: ByteArray): ByteArray {
        require(skA.size == 1664) {
            "Cannot extract combined public key without full hybrid private key (1664 bytes, was ${skA.size})"
        }
        val mlKemSk = skA.copyOfRange(0, 1632)
        val x25519Sk = skA.copyOfRange(1632, 1664)

        val mlKemPk = MLKemEngine.extractPublicKey(mlKemSk)
        val xKeyGenParams = org.bouncycastle.crypto.params.X25519PrivateKeyParameters(x25519Sk, 0)
        val x25519Pk = (xKeyGenParams.generatePublicKey() as org.bouncycastle.crypto.params.X25519PublicKeyParameters).encoded

        val combinedPk = ByteArray(HybridKemEngine.HYBRID_PUBLIC_KEY_SIZE)
        System.arraycopy(mlKemPk, 0, combinedPk, 0, 800)
        System.arraycopy(x25519Pk, 0, combinedPk, 800, 32)

        mlKemSk.fill(0)
        x25519Sk.fill(0)
        return combinedPk
    }

    /**
     * Backward-compatible overload extracting combined pkA directly from hybrid skA.
     */
    fun aliceFinalize(
        skA: ByteArray,
        seedInit: ByteArray,
        frame: ByteArray
    ): EstablishedSession {
        val pkA = extractCombinedPublicKey(skA)
        return aliceFinalize(skA, pkA, seedInit, frame)
    }
}
