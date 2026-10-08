package org.pqchat.dht.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder

object BinaryFrameCodec {
    /**
     * BEP 44 hard limit for the bencoded 'v' field (including bencode string length prefix "len:...").
     */
    const val MAX_DHT_VALUE_BYTES = 1000

    /**
     * Maximum binary frame payload size to guarantee that Bencode.encode(frame) <= MAX_DHT_VALUE_BYTES.
     * For 900 bytes: "900:" (4 bytes) + 900 bytes = 904 bytes <= 1000 bytes.
     */
    const val MAX_FRAME_PAYLOAD_BYTES = 900

    const val TOTAL_FRAME_SIZE = MAX_FRAME_PAYLOAD_BYTES
    const val IV_SIZE = 12
    const val TAG_SIZE = 16
    const val CIPHERTEXT_SIZE = MAX_FRAME_PAYLOAD_BYTES - IV_SIZE - TAG_SIZE // 872
    const val INNER_HEADER_SIZE = 13
    const val INNER_PAYLOAD_SIZE = CIPHERTEXT_SIZE - INNER_HEADER_SIZE // 859

    const val TYPE_HANDSHAKE_FINALIZE: Byte = 0x01
    const val TYPE_TEXT_MESSAGE: Byte = 0x02
    const val TYPE_REKEY_OFFER: Byte = 0x03
    const val TYPE_REKEY_RESPONSE: Byte = 0x04
    const val TYPE_CHUNK_DATA: Byte = 0x05

    // Type 0x01 limits (768 + 32 + 32 = 832 <= 859)
    const val T1_CIPHERTEXT_SIZE = 768
    const val T1_SALT_SIZE = 32
    const val T1_CONFIRMATION_TAG_SIZE = 32
    const val T1_PADDING_SIZE = 27 // 859 - 832

    // Type 0x02 limits
    const val T2_MAX_TEXT_SIZE = 857 // 859 - 2

    // Type 0x03 limits (800 + 4 = 804 <= 859)
    const val T3_PUBLIC_KEY_SIZE = 800
    const val T3_PADDING_SIZE = 55 // 859 - 804

    // Type 0x04 limits (768 + 4 = 772 <= 859)
    const val T4_CIPHERTEXT_SIZE = 768
    const val T4_PADDING_SIZE = 87 // 859 - 772

    // Type 0x05 limits
    const val T5_TRANSFER_ID_SIZE = 16
    const val T5_MAX_CHUNK_SIZE = 837 // 859 - 22

    sealed class DecodedPayload {
        data class HandshakeFinalize(
            val mlKemCiphertext: ByteArray,
            val saltParameter: ByteArray,
            val confirmationTag: ByteArray = ByteArray(T1_CONFIRMATION_TAG_SIZE)
        ) : DecodedPayload() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is HandshakeFinalize) return false
                return mlKemCiphertext.contentEquals(other.mlKemCiphertext) &&
                        saltParameter.contentEquals(other.saltParameter) &&
                        confirmationTag.contentEquals(other.confirmationTag)
            }
            override fun hashCode(): Int {
                var result = mlKemCiphertext.contentHashCode()
                result = 31 * result + saltParameter.contentHashCode()
                result = 31 * result + confirmationTag.contentHashCode()
                return result
            }
        }

        data class TextMessage(
            val text: String
        ) : DecodedPayload()

        data class RekeyOffer(
            val rekeyEpoch: Long,
            val mlKemPublicKey: ByteArray
        ) : DecodedPayload() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is RekeyOffer) return false
                return rekeyEpoch == other.rekeyEpoch &&
                        mlKemPublicKey.contentEquals(other.mlKemPublicKey)
            }
            override fun hashCode(): Int =
                31 * rekeyEpoch.hashCode() + mlKemPublicKey.contentHashCode()
        }

        data class RekeyResponse(
            val rekeyEpoch: Long,
            val mlKemCiphertext: ByteArray
        ) : DecodedPayload() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is RekeyResponse) return false
                return rekeyEpoch == other.rekeyEpoch &&
                        mlKemCiphertext.contentEquals(other.mlKemCiphertext)
            }
            override fun hashCode(): Int =
                31 * rekeyEpoch.hashCode() + mlKemCiphertext.contentHashCode()
        }

        data class ChunkData(
            val transferId: ByteArray,
            val chunkIndex: Int,
            val totalChunks: Int,
            val data: ByteArray
        ) : DecodedPayload() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is ChunkData) return false
                return transferId.contentEquals(other.transferId) &&
                        chunkIndex == other.chunkIndex &&
                        totalChunks == other.totalChunks &&
                        data.contentEquals(other.data)
            }
            override fun hashCode(): Int {
                var result = transferId.contentHashCode()
                result = 31 * result + chunkIndex
                result = 31 * result + totalChunks
                result = 31 * result + data.contentHashCode()
                return result
            }
        }
    }

    data class FrameMessage(
        val msgType: Byte,
        val seqNum: Int,
        val ackNum: Int,
        val timestampUTC: Long,
        val payload: DecodedPayload
    )

    // ==========================================
    // ENCODING / PACKING
    // ==========================================

    fun encodeHandshakeFinalize(
        seqNum: Int,
        ackNum: Int,
        timestampUTC: Long,
        mlKemCiphertext: ByteArray,
        saltParameter: ByteArray,
        confirmationTag: ByteArray = ByteArray(T1_CONFIRMATION_TAG_SIZE)
    ): ByteArray {
        require(mlKemCiphertext.size == T1_CIPHERTEXT_SIZE)
        require(saltParameter.size == T1_SALT_SIZE)
        require(confirmationTag.size == T1_CONFIRMATION_TAG_SIZE)

        val buffer = ByteBuffer.allocate(INNER_PAYLOAD_SIZE)
        buffer.put(mlKemCiphertext)
        buffer.put(saltParameter)
        buffer.put(confirmationTag)
        buffer.put(CryptoUtils.secureRandomBytes(T1_PADDING_SIZE))

        return packPlaintext(TYPE_HANDSHAKE_FINALIZE, seqNum, ackNum, timestampUTC, buffer.array())
    }

    fun encodeTextMessage(
        seqNum: Int,
        ackNum: Int,
        timestampUTC: Long,
        text: String
    ): ByteArray {
        val textBytes = text.toByteArray(Charsets.UTF_8)
        require(textBytes.size <= T2_MAX_TEXT_SIZE) {
            "Text exceeds maximum size of $T2_MAX_TEXT_SIZE bytes (was ${textBytes.size})"
        }

        val buffer = ByteBuffer.allocate(INNER_PAYLOAD_SIZE).order(ByteOrder.BIG_ENDIAN)
        buffer.putShort(textBytes.size.toShort())
        buffer.put(textBytes)
        val paddingNeeded = T2_MAX_TEXT_SIZE - textBytes.size
        if (paddingNeeded > 0) {
            buffer.put(CryptoUtils.secureRandomBytes(paddingNeeded))
        }

        return packPlaintext(TYPE_TEXT_MESSAGE, seqNum, ackNum, timestampUTC, buffer.array())
    }

    fun encodeRekeyOffer(
        seqNum: Int,
        ackNum: Int,
        timestampUTC: Long,
        rekeyEpoch: Long,
        mlKemPublicKey: ByteArray
    ): ByteArray {
        require(mlKemPublicKey.size == T3_PUBLIC_KEY_SIZE)

        val buffer = ByteBuffer.allocate(INNER_PAYLOAD_SIZE).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(rekeyEpoch.toInt())
        buffer.put(mlKemPublicKey)
        buffer.put(CryptoUtils.secureRandomBytes(T3_PADDING_SIZE))

        return packPlaintext(TYPE_REKEY_OFFER, seqNum, ackNum, timestampUTC, buffer.array())
    }

    fun encodeRekeyResponse(
        seqNum: Int,
        ackNum: Int,
        timestampUTC: Long,
        rekeyEpoch: Long,
        mlKemCiphertext: ByteArray
    ): ByteArray {
        require(mlKemCiphertext.size == T4_CIPHERTEXT_SIZE)

        val buffer = ByteBuffer.allocate(INNER_PAYLOAD_SIZE).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(rekeyEpoch.toInt())
        buffer.put(mlKemCiphertext)
        buffer.put(CryptoUtils.secureRandomBytes(T4_PADDING_SIZE))

        return packPlaintext(TYPE_REKEY_RESPONSE, seqNum, ackNum, timestampUTC, buffer.array())
    }

    fun encodeChunkData(
        seqNum: Int,
        ackNum: Int,
        timestampUTC: Long,
        transferId: ByteArray,
        chunkIndex: Int,
        totalChunks: Int,
        chunkData: ByteArray
    ): ByteArray {
        require(transferId.size == T5_TRANSFER_ID_SIZE)
        require(chunkData.size <= T5_MAX_CHUNK_SIZE)

        val buffer = ByteBuffer.allocate(INNER_PAYLOAD_SIZE).order(ByteOrder.BIG_ENDIAN)
        buffer.put(transferId)
        buffer.putShort(chunkIndex.toShort())
        buffer.putShort(totalChunks.toShort())
        buffer.putShort(chunkData.size.toShort())
        buffer.put(chunkData)
        val paddingNeeded = T5_MAX_CHUNK_SIZE - chunkData.size
        if (paddingNeeded > 0) {
            buffer.put(CryptoUtils.secureRandomBytes(paddingNeeded))
        }

        return packPlaintext(TYPE_CHUNK_DATA, seqNum, ackNum, timestampUTC, buffer.array())
    }

    private fun packPlaintext(
        msgType: Byte,
        seqNum: Int,
        ackNum: Int,
        timestampUTC: Long,
        payloadBytes: ByteArray
    ): ByteArray {
        require(payloadBytes.size == INNER_PAYLOAD_SIZE)

        val buffer = ByteBuffer.allocate(CIPHERTEXT_SIZE).order(ByteOrder.BIG_ENDIAN)
        buffer.put(msgType)
        buffer.putShort(seqNum.toShort())
        buffer.putShort(ackNum.toShort())
        buffer.putLong(timestampUTC)
        buffer.put(payloadBytes)

        val plaintext = buffer.array()
        require(plaintext.size == CIPHERTEXT_SIZE)
        return plaintext
    }

    // ==========================================
    // AEAD ENVELOPE (Creates exactly MAX_FRAME_PAYLOAD_BYTES)
    // ==========================================

    fun buildAad(target: ByteArray, msgType: Byte, direction: String): ByteArray {
        val dirBytes = direction.toByteArray(Charsets.UTF_8)
        val buffer = ByteBuffer.allocate(target.size + 1 + dirBytes.size)
        buffer.put(target)
        buffer.put(msgType)
        buffer.put(dirBytes)
        return buffer.array()
    }

    fun packAeadFrame(
        key: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray? = null
    ): ByteArray {
        require(plaintext.size == CIPHERTEXT_SIZE)
        val iv = CryptoUtils.secureRandomBytes(IV_SIZE)
        val (tag, ciphertext) = AesGcmEngine.encrypt(key, iv, plaintext, aad)

        val frame = ByteArray(MAX_FRAME_PAYLOAD_BYTES)
        System.arraycopy(iv, 0, frame, 0, IV_SIZE)
        System.arraycopy(tag, 0, frame, IV_SIZE, TAG_SIZE)
        System.arraycopy(ciphertext, 0, frame, IV_SIZE + TAG_SIZE, CIPHERTEXT_SIZE)

        require(frame.size == MAX_FRAME_PAYLOAD_BYTES)
        return frame
    }

    fun packAeadFrame(
        key: ByteArray,
        plaintext: ByteArray,
        target: ByteArray,
        direction: String
    ): ByteArray {
        val msgType = plaintext[0]
        val aad = buildAad(target, msgType, direction)
        return packAeadFrame(key, plaintext, aad)
    }

    fun unpackAeadFrame(
        key: ByteArray,
        frame: ByteArray,
        aad: ByteArray? = null
    ): FrameMessage {
        require(frame.size == MAX_FRAME_PAYLOAD_BYTES) {
            "Invalid frame size: ${frame.size}, expected $MAX_FRAME_PAYLOAD_BYTES"
        }

        val iv = ByteArray(IV_SIZE)
        val tag = ByteArray(TAG_SIZE)
        val ciphertext = ByteArray(CIPHERTEXT_SIZE)

        System.arraycopy(frame, 0, iv, 0, IV_SIZE)
        System.arraycopy(frame, IV_SIZE, tag, 0, TAG_SIZE)
        System.arraycopy(frame, IV_SIZE + TAG_SIZE, ciphertext, 0, CIPHERTEXT_SIZE)

        val plaintext = AesGcmEngine.decrypt(key, iv, tag, ciphertext, aad)
        require(plaintext.size == CIPHERTEXT_SIZE)

        val buffer = ByteBuffer.wrap(plaintext).order(ByteOrder.BIG_ENDIAN)
        val msgType = buffer.get()
        val seqNum = buffer.short.toInt() and 0xFFFF
        val ackNum = buffer.short.toInt() and 0xFFFF
        val timestampUTC = buffer.long

        val payload = when (msgType) {
            TYPE_HANDSHAKE_FINALIZE -> {
                val ct = ByteArray(T1_CIPHERTEXT_SIZE)
                val salt = ByteArray(T1_SALT_SIZE)
                val confTag = ByteArray(T1_CONFIRMATION_TAG_SIZE)
                buffer.get(ct)
                buffer.get(salt)
                buffer.get(confTag)
                DecodedPayload.HandshakeFinalize(ct, salt, confTag)
            }
            TYPE_TEXT_MESSAGE -> {
                val len = buffer.short.toInt() and 0xFFFF
                require(len <= T2_MAX_TEXT_SIZE) { "Text length $len exceeds $T2_MAX_TEXT_SIZE" }
                val textBytes = ByteArray(len)
                buffer.get(textBytes)
                DecodedPayload.TextMessage(String(textBytes, Charsets.UTF_8))
            }
            TYPE_REKEY_OFFER -> {
                val epoch = buffer.int.toLong() and 0xFFFFFFFFL
                val pk = ByteArray(T3_PUBLIC_KEY_SIZE)
                buffer.get(pk)
                DecodedPayload.RekeyOffer(epoch, pk)
            }
            TYPE_REKEY_RESPONSE -> {
                val epoch = buffer.int.toLong() and 0xFFFFFFFFL
                val ct = ByteArray(T4_CIPHERTEXT_SIZE)
                buffer.get(ct)
                DecodedPayload.RekeyResponse(epoch, ct)
            }
            TYPE_CHUNK_DATA -> {
                val transferId = ByteArray(T5_TRANSFER_ID_SIZE)
                buffer.get(transferId)
                val chunkIndex = buffer.short.toInt() and 0xFFFF
                val totalChunks = buffer.short.toInt() and 0xFFFF
                val chunkLen = buffer.short.toInt() and 0xFFFF
                require(chunkLen <= T5_MAX_CHUNK_SIZE) { "Chunk length $chunkLen exceeds $T5_MAX_CHUNK_SIZE" }
                val data = ByteArray(chunkLen)
                buffer.get(data)
                DecodedPayload.ChunkData(transferId, chunkIndex, totalChunks, data)
            }
            else -> throw IllegalArgumentException("Unknown message type: 0x%02X".format(msgType))
        }

        return FrameMessage(msgType, seqNum, ackNum, timestampUTC, payload)
    }

    fun unpackAeadFrame(
        key: ByteArray,
        frame: ByteArray,
        target: ByteArray,
        direction: String,
        expectedType: Byte? = null
    ): FrameMessage {
        val candidateDirections = if (direction == "AliceToBob") {
            listOf("AliceToBob", "BobToAlice")
        } else if (direction == "BobToAlice") {
            listOf("BobToAlice", "AliceToBob")
        } else {
            listOf(direction)
        }

        if (expectedType != null) {
            for (dir in candidateDirections) {
                try {
                    val aad = buildAad(target, expectedType, dir)
                    return unpackAeadFrame(key, frame, aad)
                } catch (_: Exception) {}
            }
            try {
                return unpackAeadFrame(key, frame, null)
            } catch (_: Exception) {}
            throw IllegalArgumentException("Failed to decrypt frame with expectedType 0x%02X and target".format(expectedType))
        }

        val candidateTypes = byteArrayOf(
            TYPE_TEXT_MESSAGE,
            TYPE_CHUNK_DATA,
            TYPE_REKEY_OFFER,
            TYPE_REKEY_RESPONSE,
            TYPE_HANDSHAKE_FINALIZE
        )
        var lastException: Exception? = null
        for (dir in candidateDirections) {
            for (candidate in candidateTypes) {
                try {
                    val aad = buildAad(target, candidate, dir)
                    val msg = unpackAeadFrame(key, frame, aad)
                    if (msg.msgType == candidate) {
                        return msg
                    }
                } catch (e: Exception) {
                    lastException = e
                }
            }
        }
        try {
            return unpackAeadFrame(key, frame, null)
        } catch (_: Exception) {}

        throw lastException ?: IllegalArgumentException("Failed to decrypt frame with AAD ($direction, target)")
    }
}
