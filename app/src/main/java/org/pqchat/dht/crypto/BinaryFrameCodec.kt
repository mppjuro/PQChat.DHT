package org.pqchat.dht.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder

object BinaryFrameCodec {
    const val TOTAL_FRAME_SIZE = 1000
    const val IV_SIZE = 12
    const val TAG_SIZE = 16
    const val CIPHERTEXT_SIZE = 972
    const val INNER_HEADER_SIZE = 13
    const val INNER_PAYLOAD_SIZE = 959 // 972 - 13

    const val TYPE_HANDSHAKE_FINALIZE: Byte = 0x01
    const val TYPE_TEXT_MESSAGE: Byte = 0x02
    const val TYPE_REKEY_OFFER: Byte = 0x03
    const val TYPE_REKEY_RESPONSE: Byte = 0x04
    const val TYPE_CHUNK_DATA: Byte = 0x05

    // Type 0x01 limits
    const val T1_CIPHERTEXT_SIZE = 768
    const val T1_SALT_SIZE = 32
    const val T1_PADDING_SIZE = 159

    // Type 0x02 limits
    const val T2_MAX_TEXT_SIZE = 957

    // Type 0x03 limits
    const val T3_PUBLIC_KEY_SIZE = 800
    const val T3_PADDING_SIZE = 155

    // Type 0x04 limits
    const val T4_CIPHERTEXT_SIZE = 768
    const val T4_PADDING_SIZE = 187

    // Type 0x05 limits
    const val T5_TRANSFER_ID_SIZE = 16
    const val T5_MAX_CHUNK_SIZE = 937

    sealed class DecodedPayload {
        data class HandshakeFinalize(
            val mlKemCiphertext: ByteArray,
            val saltParameter: ByteArray
        ) : DecodedPayload() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is HandshakeFinalize) return false
                return mlKemCiphertext.contentEquals(other.mlKemCiphertext) &&
                        saltParameter.contentEquals(other.saltParameter)
            }
            override fun hashCode(): Int =
                31 * mlKemCiphertext.contentHashCode() + saltParameter.contentHashCode()
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
        saltParameter: ByteArray
    ): ByteArray {
        require(mlKemCiphertext.size == T1_CIPHERTEXT_SIZE)
        require(saltParameter.size == T1_SALT_SIZE)

        val buffer = ByteBuffer.allocate(INNER_PAYLOAD_SIZE)
        buffer.put(mlKemCiphertext)
        buffer.put(saltParameter)
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
    // AEAD ENVELOPE (Creates exactly 1000B)
    // ==========================================

    fun packAeadFrame(key: ByteArray, plaintext972: ByteArray): ByteArray {
        require(plaintext972.size == CIPHERTEXT_SIZE)
        val iv = CryptoUtils.secureRandomBytes(IV_SIZE)
        val (tag, ciphertext) = AesGcmEngine.encrypt(key, iv, plaintext972)

        val frame = ByteArray(TOTAL_FRAME_SIZE)
        System.arraycopy(iv, 0, frame, 0, IV_SIZE)
        System.arraycopy(tag, 0, frame, IV_SIZE, TAG_SIZE)
        System.arraycopy(ciphertext, 0, frame, IV_SIZE + TAG_SIZE, CIPHERTEXT_SIZE)

        require(frame.size == TOTAL_FRAME_SIZE)
        return frame
    }

    fun unpackAeadFrame(key: ByteArray, frame1000: ByteArray): FrameMessage {
        require(frame1000.size == TOTAL_FRAME_SIZE) {
            "Invalid frame size: ${frame1000.size}, expected $TOTAL_FRAME_SIZE"
        }

        val iv = ByteArray(IV_SIZE)
        val tag = ByteArray(TAG_SIZE)
        val ciphertext = ByteArray(CIPHERTEXT_SIZE)

        System.arraycopy(frame1000, 0, iv, 0, IV_SIZE)
        System.arraycopy(frame1000, IV_SIZE, tag, 0, TAG_SIZE)
        System.arraycopy(frame1000, IV_SIZE + TAG_SIZE, ciphertext, 0, CIPHERTEXT_SIZE)

        val plaintext = AesGcmEngine.decrypt(key, iv, tag, ciphertext)
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
                buffer.get(ct)
                buffer.get(salt)
                DecodedPayload.HandshakeFinalize(ct, salt)
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
}
