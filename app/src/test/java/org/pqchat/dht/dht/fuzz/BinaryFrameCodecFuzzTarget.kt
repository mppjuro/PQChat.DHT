package org.pqchat.dht.dht.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.pqchat.dht.crypto.AesGcmEngine
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.protocol.CoverAckProtocol
import java.security.GeneralSecurityException
import java.security.Security

/**
 * Official Jazzer fuzz target for [BinaryFrameCodec] (frame types 0x01..0x0C) and [CoverAckProtocol].
 * Exercises both untrusted raw wire frames and authenticated-inner frames so fuzzing penetrates
 * past AES-256-GCM directly into header, Deflate bounded-decompression, and base-3329 parsers.
 */
object BinaryFrameCodecFuzzTarget {

    private val FUZZ_KEY = ByteArray(AesGcmEngine.KEY_SIZE_BYTES) { ((it * 29 + 7) and 0xFF).toByte() }
    private val FUZZ_TARGET = ByteArray(20) { ((it * 13 + 3) and 0xFF).toByte() }
    private val KNOWN_TYPES = byteArrayOf(
        BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE,
        BinaryFrameCodec.TYPE_TEXT_MESSAGE,
        BinaryFrameCodec.TYPE_REKEY_OFFER,
        BinaryFrameCodec.TYPE_REKEY_RESPONSE,
        BinaryFrameCodec.TYPE_CHUNK_DATA,
        BinaryFrameCodec.TYPE_GROUP_CONTROL,
        BinaryFrameCodec.TYPE_REACTION,
        BinaryFrameCodec.TYPE_LOCATION_PIN,
        BinaryFrameCodec.TYPE_VOICE_NOTE,
        BinaryFrameCodec.TYPE_GROUP_POLL,
        BinaryFrameCodec.TYPE_SAFETY_CANARY,
        BinaryFrameCodec.TYPE_COMPRESSED_MICRO_DOC
    )

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @JvmStatic
    fun fuzzerTestOneInput(input: ByteArray) {
        val aad = BinaryFrameCodec.buildAad(FUZZ_TARGET, "AliceToBob")

        // 1. Raw wire frame path (any length / malformed AEAD frame)
        try {
            BinaryFrameCodec.unpackAeadFrame(FUZZ_KEY, input, aad)
        } catch (_: IllegalArgumentException) {
        } catch (_: IllegalStateException) {
        } catch (_: GeneralSecurityException) {
        }

        // 2. CoverAckProtocol wire path
        try {
            CoverAckProtocol.parseAckPayload(FUZZ_KEY, input, "msg-fuzz", expectedSeqNum = null)
        } catch (_: IllegalArgumentException) {
        } catch (_: IllegalStateException) {
        } catch (_: GeneralSecurityException) {
        }

        if (input.isEmpty()) return

        // 3. Authenticated-inner path: wrap mutated inner bytes inside valid AES-256-GCM framing
        //    to exercise every inner message parser (0x01..0x0C), Deflate inflation, and base-3329 unpacking.
        val innerPlaintext = ByteArray(BinaryFrameCodec.CIPHERTEXT_SIZE)
        val copyLen = minOf(input.size, innerPlaintext.size)
        System.arraycopy(input, 0, innerPlaintext, 0, copyLen)

        // Probe exact first byte first
        wrapAndUnpack(innerPlaintext, aad)

        // Map first byte across all valid message types 0x01..0x0C
        innerPlaintext[0] = KNOWN_TYPES[(input[0].toInt() and 0xFF) % KNOWN_TYPES.size]
        wrapAndUnpack(innerPlaintext, aad)
    }

    private fun wrapAndUnpack(innerPlaintext: ByteArray, aad: ByteArray) {
        val iv = ByteArray(BinaryFrameCodec.IV_SIZE) { i -> ((innerPlaintext[i % innerPlaintext.size].toInt() xor i) and 0xFF).toByte() }
        val (tag, ct) = AesGcmEngine.encrypt(FUZZ_KEY, iv, innerPlaintext, aad)
        val frame = ByteArray(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)
        System.arraycopy(iv, 0, frame, 0, BinaryFrameCodec.IV_SIZE)
        System.arraycopy(tag, 0, frame, BinaryFrameCodec.IV_SIZE, BinaryFrameCodec.TAG_SIZE)
        System.arraycopy(ct, 0, frame, BinaryFrameCodec.IV_SIZE + BinaryFrameCodec.TAG_SIZE, BinaryFrameCodec.CIPHERTEXT_SIZE)

        try {
            BinaryFrameCodec.unpackAeadFrame(FUZZ_KEY, frame, aad)
        } catch (_: IllegalArgumentException) {
        } catch (_: IllegalStateException) {
        } catch (_: GeneralSecurityException) {
        }
    }

    @JvmStatic
    fun fuzzerTestOneInput(data: FuzzedDataProvider) {
        fuzzerTestOneInput(data.consumeRemainingAsBytes())
    }
}
