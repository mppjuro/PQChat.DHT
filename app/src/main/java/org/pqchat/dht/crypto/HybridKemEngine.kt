package org.pqchat.dht.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom

/**
 * Hybrid Key Encapsulation Mechanism combining ML-KEM-512 (FIPS 203) with classical X25519 ECDH (RFC 7748).
 * Provides dual-defense (IND-CCA2 post-quantum + classical elliptic curve security)
 * behind a negotiable protocol version.
 */
object HybridKemEngine {

    enum class ProtocolVersion(val wireId: Byte) {
        V1_MLKEM_ONLY(0x01),
        V2_HYBRID_X25519_MLKEM(0x02);

        companion object {
            fun fromWireId(id: Byte): ProtocolVersion = when (id) {
                0x01.toByte() -> V1_MLKEM_ONLY
                0x02.toByte() -> V2_HYBRID_X25519_MLKEM
                else -> throw IllegalArgumentException("Unknown protocol version wire ID: 0x%02X".format(id))
            }
        }
    }

    const val X25519_PUBLIC_KEY_SIZE = 32
    const val X25519_PRIVATE_KEY_SIZE = 32
    const val X25519_SHARED_SECRET_SIZE = 32

    const val HYBRID_PUBLIC_KEY_SIZE = MLKemEngine.PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE // 800 + 32 = 832
    const val HYBRID_CIPHERTEXT_SIZE = MLKemEngine.CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE // 768 + 32 = 800
    const val SHARED_SECRET_SIZE = 32

    private val HYBRID_KDF_INFO = "Hybrid_X25519_MLKEM512_v2".toByteArray(Charsets.UTF_8)

    data class HybridKeyPair(
        val mlKemPublicKey: ByteArray,
        val mlKemPrivateKey: ByteArray,
        val x25519PublicKey: ByteArray,
        val x25519PrivateKey: ByteArray
    ) {
        val combinedPublicKey: ByteArray by lazy {
            val combined = ByteArray(HYBRID_PUBLIC_KEY_SIZE)
            System.arraycopy(mlKemPublicKey, 0, combined, 0, MLKemEngine.PUBLIC_KEY_SIZE)
            System.arraycopy(x25519PublicKey, 0, combined, MLKemEngine.PUBLIC_KEY_SIZE, X25519_PUBLIC_KEY_SIZE)
            combined
        }

        fun wipe() {
            mlKemPrivateKey.fill(0)
            x25519PrivateKey.fill(0)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is HybridKeyPair) return false
            return mlKemPublicKey.contentEquals(other.mlKemPublicKey) &&
                    mlKemPrivateKey.contentEquals(other.mlKemPrivateKey) &&
                    x25519PublicKey.contentEquals(other.x25519PublicKey) &&
                    x25519PrivateKey.contentEquals(other.x25519PrivateKey)
        }

        override fun hashCode(): Int {
            var result = mlKemPublicKey.contentHashCode()
            result = 31 * result + mlKemPrivateKey.contentHashCode()
            result = 31 * result + x25519PublicKey.contentHashCode()
            result = 31 * result + x25519PrivateKey.contentHashCode()
            return result
        }
    }

    data class HybridEncapsulationResult(
        val sharedSecret: ByteArray,       // 32 bytes
        val combinedCiphertext: ByteArray  // 800 bytes: ML-KEM ct (768) + X25519 eph pk (32)
    ) {
        fun wipe() {
            sharedSecret.fill(0)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is HybridEncapsulationResult) return false
            return sharedSecret.contentEquals(other.sharedSecret) &&
                    combinedCiphertext.contentEquals(other.combinedCiphertext)
        }

        override fun hashCode(): Int {
            var result = sharedSecret.contentHashCode()
            result = 31 * result + combinedCiphertext.contentHashCode()
            return result
        }
    }

    /**
     * Generates a combined (ML-KEM-512 + X25519) key pair.
     */
    fun generateKeyPair(random: SecureRandom = CryptoUtils.secureRandom): HybridKeyPair {
        val kemPair = MLKemEngine.generateKeyPair(random)

        val xKeyGen = X25519KeyPairGenerator()
        xKeyGen.init(X25519KeyGenerationParameters(random))
        val xPair = xKeyGen.generateKeyPair()

        val xPub = (xPair.public as X25519PublicKeyParameters).encoded
        val xPriv = (xPair.private as X25519PrivateKeyParameters).encoded

        return HybridKeyPair(
            mlKemPublicKey = kemPair.publicKey,
            mlKemPrivateKey = kemPair.privateKey,
            x25519PublicKey = xPub,
            x25519PrivateKey = xPriv
        )
    }

    /**
     * Encapsulates a shared secret against a combined recipient public key (832 bytes: 800B ML-KEM + 32B X25519).
     */
    fun encapsulate(
        combinedPublicKey: ByteArray,
        random: SecureRandom = CryptoUtils.secureRandom
    ): HybridEncapsulationResult {
        require(combinedPublicKey.size == HYBRID_PUBLIC_KEY_SIZE) {
            "Invalid hybrid public key size: ${combinedPublicKey.size}, expected $HYBRID_PUBLIC_KEY_SIZE"
        }

        val mlKemPk = combinedPublicKey.copyOfRange(0, MLKemEngine.PUBLIC_KEY_SIZE)
        val x25519PkBytes = combinedPublicKey.copyOfRange(MLKemEngine.PUBLIC_KEY_SIZE, HYBRID_PUBLIC_KEY_SIZE)

        // 1. Post-quantum encapsulation
        val mlKemResult = MLKemEngine.encapsulate(mlKemPk, random)
        val ssKem = mlKemResult.sharedSecret
        val ctKem = mlKemResult.ciphertext

        // 2. Classical X25519 ephemeral key agreement
        val xKeyGen = X25519KeyPairGenerator()
        xKeyGen.init(X25519KeyGenerationParameters(random))
        val ephPair = xKeyGen.generateKeyPair()
        val ephPub = (ephPair.public as X25519PublicKeyParameters).encoded
        val ephPriv = ephPair.private as X25519PrivateKeyParameters

        val recipientXPub = X25519PublicKeyParameters(x25519PkBytes, 0)
        val agreement = X25519Agreement()
        agreement.init(ephPriv)
        val ssEcdh = ByteArray(X25519_SHARED_SECRET_SIZE)
        agreement.calculateAgreement(recipientXPub, ssEcdh, 0)

        // 3. Combine secrets via HKDF: salt = ssEcdh, IKM = ssKem
        val combinedSecret = HkdfSha512.derive(
            salt = ssEcdh,
            ikm = ssKem,
            info = HYBRID_KDF_INFO,
            length = SHARED_SECRET_SIZE
        )

        // Zero ephemeral secrets
        ssKem.fill(0)
        ssEcdh.fill(0)

        // 4. Combined ciphertext: 768B ML-KEM ct + 32B X25519 ephemeral pk
        val combinedCt = ByteArray(HYBRID_CIPHERTEXT_SIZE)
        System.arraycopy(ctKem, 0, combinedCt, 0, MLKemEngine.CIPHERTEXT_SIZE)
        System.arraycopy(ephPub, 0, combinedCt, MLKemEngine.CIPHERTEXT_SIZE, X25519_PUBLIC_KEY_SIZE)

        return HybridEncapsulationResult(
            sharedSecret = combinedSecret,
            combinedCiphertext = combinedCt
        )
    }

    /**
     * Decapsulates combined ciphertext (800 bytes) using recipient's private keys.
     */
    fun decapsulate(
        mlKemPrivateKey: ByteArray,
        x25519PrivateKey: ByteArray,
        combinedCiphertext: ByteArray
    ): ByteArray {
        require(combinedCiphertext.size == HYBRID_CIPHERTEXT_SIZE) {
            "Invalid hybrid ciphertext size: ${combinedCiphertext.size}, expected $HYBRID_CIPHERTEXT_SIZE"
        }

        val ctKem = combinedCiphertext.copyOfRange(0, MLKemEngine.CIPHERTEXT_SIZE)
        val ephXPubBytes = combinedCiphertext.copyOfRange(MLKemEngine.CIPHERTEXT_SIZE, HYBRID_CIPHERTEXT_SIZE)

        // 1. Decapsulate ML-KEM
        val ssKem = MLKemEngine.decapsulate(mlKemPrivateKey, ctKem)

        // 2. Classical X25519 agreement
        val recipientPriv = X25519PrivateKeyParameters(x25519PrivateKey, 0)
        val ephXPub = X25519PublicKeyParameters(ephXPubBytes, 0)
        val agreement = X25519Agreement()
        agreement.init(recipientPriv)
        val ssEcdh = ByteArray(X25519_SHARED_SECRET_SIZE)
        agreement.calculateAgreement(ephXPub, ssEcdh, 0)

        // 3. Combine secrets
        val combinedSecret = HkdfSha512.derive(
            salt = ssEcdh,
            ikm = ssKem,
            info = HYBRID_KDF_INFO,
            length = SHARED_SECRET_SIZE
        )

        // Zero ephemeral secrets
        ssKem.fill(0)
        ssEcdh.fill(0)

        return combinedSecret
    }
}
