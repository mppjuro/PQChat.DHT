package org.pqchat.dht.dht.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import org.pqchat.dht.crypto.KeystoreCrypto
import java.security.GeneralSecurityException
import javax.crypto.spec.SecretKeySpec

/**
 * Official Jazzer fuzz target for [KeystoreCrypto] MAGIC_ROW_BOUND / MAGIC_ROW_BOUND_V2 parsers
 * and fail-closed AES-GCM decryption.
 */
object KeystoreCryptoFuzzTarget {

    private val FUZZ_MASTER_KEY = SecretKeySpec(
        ByteArray(32) { ((it * 19 + 5) and 0xFF).toByte() },
        "AES"
    )
    private val TEST_AAD = "messages+row-1+textContent".toByteArray(Charsets.UTF_8)

    private fun ensureTestKey() {
        KeystoreCrypto.setTestSecretKey(FUZZ_MASTER_KEY)
    }

    @JvmStatic
    fun fuzzerTestOneInput(input: ByteArray) {
        ensureTestKey()

        // 1. Direct fuzzing of all decryption entry points
        try {
            KeystoreCrypto.decryptRowBoundV2(input, "messages", "row-1", "textContent")
        } catch (_: IllegalArgumentException) {
        } catch (_: GeneralSecurityException) {
        } catch (_: IllegalStateException) {
        }

        try {
            KeystoreCrypto.decryptWithRowMetadata(input)
        } catch (_: IllegalArgumentException) {
        } catch (_: GeneralSecurityException) {
        } catch (_: IllegalStateException) {
        }

        try {
            KeystoreCrypto.decrypt(input, TEST_AAD)
        } catch (_: IllegalArgumentException) {
        } catch (_: GeneralSecurityException) {
        } catch (_: IllegalStateException) {
        }

        // 2. Force MAGIC_ROW_BOUND_V2 (0x52) and v1 (0x51) prefixes to exercise header parsers
        if (input.isNotEmpty()) {
            val v2Forced = input.copyOf()
            v2Forced[0] = KeystoreCrypto.MAGIC_ROW_BOUND_V2
            try {
                KeystoreCrypto.decryptWithRowMetadata(v2Forced)
            } catch (_: IllegalArgumentException) {
            } catch (_: GeneralSecurityException) {
            } catch (_: IllegalStateException) {
            }

            val v1Forced = input.copyOf()
            v1Forced[0] = KeystoreCrypto.MAGIC_ROW_BOUND
            try {
                KeystoreCrypto.decryptWithRowMetadata(v1Forced)
            } catch (_: IllegalArgumentException) {
            } catch (_: GeneralSecurityException) {
            } catch (_: IllegalStateException) {
            }

            // 3. Round-trip encrypt + tamper fail-closed check
            val encrypted = KeystoreCrypto.encrypt(input, "messages", "row-1", "textContent")
            if (encrypted != null && encrypted.isNotEmpty()) {
                val dec = KeystoreCrypto.decryptRowBoundV2(encrypted, "messages", "row-1", "textContent")
                check(dec.plaintext.contentEquals(input)) { "KeystoreCrypto round-trip mismatch" }

                val tampered = encrypted.copyOf()
                val tamperIdx = (input[0].toInt() and 0xFF) % tampered.size
                tampered[tamperIdx] = (tampered[tamperIdx].toInt() xor 0x01).toByte()
                var rejected = false
                try {
                    KeystoreCrypto.decryptRowBoundV2(tampered, "messages", "row-1", "textContent")
                } catch (_: IllegalArgumentException) {
                    rejected = true
                } catch (_: GeneralSecurityException) {
                    rejected = true
                } catch (_: IllegalStateException) {
                    rejected = true
                }
                check(rejected) { "Tampered MAGIC_ROW_BOUND_V2 ciphertext was accepted!" }
            }
        }
    }

    @JvmStatic
    fun fuzzerTestOneInput(data: FuzzedDataProvider) {
        fuzzerTestOneInput(data.consumeRemainingAsBytes())
    }
}
