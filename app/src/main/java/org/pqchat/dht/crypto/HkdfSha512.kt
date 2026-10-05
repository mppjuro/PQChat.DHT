package org.pqchat.dht.crypto

import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF using HMAC-SHA-512 (RFC 5869).
 * Used for Symmetric Ratchet and key derivation.
 */
object HkdfSha512 {
    private const val HASH_LEN = 64 // SHA-512 outputs 64 bytes

    /**
     * HKDF-Extract(salt, IKM) -> PRK (64 bytes)
     */
    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val effectiveSalt = if (salt == null || salt.isEmpty()) {
            ByteArray(HASH_LEN) // all zeroes
        } else {
            salt
        }
        return CryptoUtils.hmacSha512(effectiveSalt, ikm)
    }

    /**
     * HKDF-Expand(PRK, info, L) -> OKM (L bytes)
     */
    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length <= 255 * HASH_LEN) { "Length too long: $length > ${255 * HASH_LEN}" }
        require(length > 0) { "Length must be positive" }

        val n = (length + HASH_LEN - 1) / HASH_LEN
        val okm = ByteArray(length)
        var offset = 0

        val mac = Mac.getInstance("HmacSHA512")
        val key = SecretKeySpec(prk, "HmacSHA512")
        mac.init(key)

        var t = ByteArray(0)
        for (i in 1..n) {
            mac.reset()
            if (t.isNotEmpty()) {
                mac.update(t)
            }
            if (info.isNotEmpty()) {
                mac.update(info)
            }
            mac.update(i.toByte())
            t = mac.doFinal()

            val toCopy = minOf(HASH_LEN, length - offset)
            System.arraycopy(t, 0, okm, offset, toCopy)
            offset += toCopy
        }

        return okm
    }

    /**
     * One-shot HKDF: Extract then Expand.
     */
    fun derive(salt: ByteArray?, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = extract(salt, ikm)
        return expand(prk, info, length)
    }
}
