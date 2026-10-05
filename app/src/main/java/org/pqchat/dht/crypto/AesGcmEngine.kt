package org.pqchat.dht.crypto

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object AesGcmEngine {
    private const val ALGORITHM = "AES/GCM/NoPadding"
    private const val TAG_LENGTH_BITS = 128 // 16 bytes
    const val KEY_SIZE_BYTES = 32
    const val IV_SIZE_BYTES = 12
    const val TAG_SIZE_BYTES = 16

    /**
     * Encrypts plaintext using AES-256-GCM.
     * Returns a Pair of (tag: 16 bytes, ciphertext: plaintext.size bytes).
     */
    fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        plaintext: ByteArray,
        associatedData: ByteArray? = null
    ): Pair<ByteArray, ByteArray> {
        require(key.size == KEY_SIZE_BYTES) { "Invalid key size: ${key.size}, expected $KEY_SIZE_BYTES" }
        require(iv.size == IV_SIZE_BYTES) { "Invalid IV size: ${iv.size}, expected $IV_SIZE_BYTES" }

        val cipher = Cipher.getInstance(ALGORITHM)
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        associatedData?.let { cipher.updateAAD(it) }

        // Java GCM appends the 16-byte tag to the ciphertext
        val encryptedWithTag = cipher.doFinal(plaintext)
        val ciphertextLen = encryptedWithTag.size - TAG_SIZE_BYTES
        require(ciphertextLen == plaintext.size) { "Ciphertext size mismatch" }

        val ciphertext = ByteArray(ciphertextLen)
        val tag = ByteArray(TAG_SIZE_BYTES)

        System.arraycopy(encryptedWithTag, 0, ciphertext, 0, ciphertextLen)
        System.arraycopy(encryptedWithTag, ciphertextLen, tag, 0, TAG_SIZE_BYTES)

        return Pair(tag, ciphertext)
    }

    /**
     * Decrypts ciphertext with authentication tag.
     */
    fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        tag: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray? = null
    ): ByteArray {
        require(key.size == KEY_SIZE_BYTES) { "Invalid key size: ${key.size}, expected $KEY_SIZE_BYTES" }
        require(iv.size == IV_SIZE_BYTES) { "Invalid IV size: ${iv.size}, expected $IV_SIZE_BYTES" }
        require(tag.size == TAG_SIZE_BYTES) { "Invalid Tag size: ${tag.size}, expected $TAG_SIZE_BYTES" }

        val cipher = Cipher.getInstance(ALGORITHM)
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

        associatedData?.let { cipher.updateAAD(it) }

        // Combine ciphertext and tag for Java Cipher
        val encryptedWithTag = ByteArray(ciphertext.size + tag.size)
        System.arraycopy(ciphertext, 0, encryptedWithTag, 0, ciphertext.size)
        System.arraycopy(tag, 0, encryptedWithTag, ciphertext.size, tag.size)

        return cipher.doFinal(encryptedWithTag)
    }
}
