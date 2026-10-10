package org.pqchat.dht.crypto

import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.SecureRandom

/**
 * ML-KEM-512 (FIPS 203) Post-Quantum Cryptographic Engine.
 *
 * Parameters:
 * - Public Key (pk): 800 bytes
 * - Ciphertext (ct): 768 bytes
 * - Shared Secret (SS): 32 bytes
 */
object MLKemEngine {
    const val PUBLIC_KEY_SIZE = 800
    const val CIPHERTEXT_SIZE = 768
    const val SHARED_SECRET_SIZE = 32

    data class KeyPair(
        val publicKey: ByteArray,
        val privateKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is KeyPair) return false
            return publicKey.contentEquals(other.publicKey) && privateKey.contentEquals(other.privateKey)
        }

        override fun hashCode(): Int {
            var result = publicKey.contentHashCode()
            result = 31 * result + privateKey.contentHashCode()
            return result
        }
    }

    data class EncapsulationResult(
        val sharedSecret: ByteArray, // 32 bytes
        val ciphertext: ByteArray    // 768 bytes
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is EncapsulationResult) return false
            return sharedSecret.contentEquals(other.sharedSecret) && ciphertext.contentEquals(other.ciphertext)
        }

        override fun hashCode(): Int {
            var result = sharedSecret.contentHashCode()
            result = 31 * result + ciphertext.contentHashCode()
            return result
        }
    }

    /**
     * Generates a new ML-KEM-512 (FIPS 203) key pair (pk = 800B).
     */
    fun generateKeyPair(random: SecureRandom = CryptoUtils.secureRandom): KeyPair {
        val keyGenParams = MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_512)
        val generator = MLKEMKeyPairGenerator()
        generator.init(keyGenParams)
        val pair = generator.generateKeyPair()

        val pub = pair.public as MLKEMPublicKeyParameters
        val priv = pair.private as MLKEMPrivateKeyParameters

        val pkBytes = pub.encoded
        val skBytes = priv.encoded

        require(pkBytes.size == PUBLIC_KEY_SIZE) {
            "ML-KEM-512 public key size mismatch: ${pkBytes.size}, expected $PUBLIC_KEY_SIZE"
        }

        return KeyPair(pkBytes, skBytes)
    }

    /**
     * Encapsulates a random 32-byte shared secret against the recipient's public key (800B).
     * Returns (SS, ct).
     */
    fun encapsulate(
        recipientPublicKeyBytes: ByteArray,
        random: SecureRandom = CryptoUtils.secureRandom
    ): EncapsulationResult {
        require(recipientPublicKeyBytes.size == PUBLIC_KEY_SIZE) {
            "Invalid public key size: ${recipientPublicKeyBytes.size}, expected $PUBLIC_KEY_SIZE"
        }

        val pubParams = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_512, recipientPublicKeyBytes)
        val kemGen = MLKEMGenerator(random)
        val secEnc = kemGen.generateEncapsulated(pubParams)

        val sharedSecret = secEnc.secret
        val ciphertext = secEnc.encapsulation

        require(sharedSecret.size == SHARED_SECRET_SIZE) { "Invalid shared secret size" }
        require(ciphertext.size == CIPHERTEXT_SIZE) { "Invalid ciphertext size: ${ciphertext.size}, expected $CIPHERTEXT_SIZE" }

        return EncapsulationResult(sharedSecret, ciphertext)
    }

    /**
     * Decapsulates the ciphertext (768B) using the recipient's private key.
     * Returns the 32-byte shared secret.
     */
    fun decapsulate(privateKeyBytes: ByteArray, ciphertext: ByteArray): ByteArray {
        require(ciphertext.size == CIPHERTEXT_SIZE) {
            "Invalid ciphertext size: ${ciphertext.size}, expected $CIPHERTEXT_SIZE"
        }

        val privParams = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_512, privateKeyBytes)
        val kemExt = MLKEMExtractor(privParams)
        val secret = kemExt.extractSecret(ciphertext)

        require(secret.size == SHARED_SECRET_SIZE) { "Invalid shared secret size" }
        return secret
    }

    /**
     * Extracts the 800-byte public key embedded within the ML-KEM-512 private key.
     */
    fun extractPublicKey(privateKeyBytes: ByteArray): ByteArray {
        val privParams = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_512, privateKeyBytes)
        val pk = privParams.publicKey
        require(pk.size == PUBLIC_KEY_SIZE) {
            "Extracted public key size mismatch: ${pk.size}, expected $PUBLIC_KEY_SIZE"
        }
        return pk
    }
}

