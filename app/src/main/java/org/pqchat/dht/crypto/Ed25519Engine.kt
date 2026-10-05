package org.pqchat.dht.crypto

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

object Ed25519Engine {
    const val SEED_SIZE = 32
    const val PUBLIC_KEY_SIZE = 32
    const val SIGNATURE_SIZE = 64

    data class KeyPair(
        val seed: ByteArray,
        val publicKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is KeyPair) return false
            return seed.contentEquals(other.seed) && publicKey.contentEquals(other.publicKey)
        }

        override fun hashCode(): Int {
            var result = seed.contentHashCode()
            result = 31 * result + publicKey.contentHashCode()
            return result
        }
    }

    /**
     * Generates a deterministic Ed25519 key pair from a 32-byte seed.
     */
    fun generateKeyPairFromSeed(seed: ByteArray): KeyPair {
        require(seed.size == SEED_SIZE) { "Invalid Ed25519 seed size: ${seed.size}, expected $SEED_SIZE" }
        val privParams = Ed25519PrivateKeyParameters(seed, 0)
        val pubParams = privParams.generatePublicKey()
        return KeyPair(seed.copyOf(), pubParams.encoded)
    }

    /**
     * Generates an ephemeral Ed25519 key pair using SecureRandom.
     */
    fun generateEphemeralKeyPair(): KeyPair {
        val seed = CryptoUtils.secureRandomBytes(SEED_SIZE)
        return generateKeyPairFromSeed(seed)
    }

    /**
     * Signs data using the Ed25519 private key seed.
     * Returns a 64-byte signature.
     */
    fun sign(privateKeySeed: ByteArray, data: ByteArray): ByteArray {
        require(privateKeySeed.size == SEED_SIZE) { "Invalid private key seed size" }
        val privParams = Ed25519PrivateKeyParameters(privateKeySeed, 0)
        val signer = Ed25519Signer()
        signer.init(true, privParams)
        signer.update(data, 0, data.size)
        return signer.generateSignature()
    }

    /**
     * Verifies an Ed25519 signature.
     */
    fun verify(publicKeyBytes: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        if (publicKeyBytes.size != PUBLIC_KEY_SIZE || signature.size != SIGNATURE_SIZE) {
            return false
        }
        return try {
            val pubParams = Ed25519PublicKeyParameters(publicKeyBytes, 0)
            val signer = Ed25519Signer()
            signer.init(false, pubParams)
            signer.update(data, 0, data.size)
            signer.verifySignature(signature)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Computes the DHT Target address: Target = SHA-1(pk) in 20 bytes.
     */
    fun computeTarget(publicKeyBytes: ByteArray): ByteArray {
        require(publicKeyBytes.size == PUBLIC_KEY_SIZE) { "Invalid public key size" }
        return CryptoUtils.sha1(publicKeyBytes)
    }
}
