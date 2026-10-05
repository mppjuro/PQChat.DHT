package org.pqchat.dht.protocol

import org.pqchat.dht.crypto.*
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Handles large binary payloads (such as PNG images or documents)
 * by splitting them into 900-byte chunks and deriving deterministic sub-keys.
 */
object ChunkingEngine {

    const val CHUNK_SIZE = 800 // bytes per segment
    val PNG_MAGIC = byteArrayOf(0x89.toByte(), 0x50.toByte(), 0x4E.toByte(), 0x47.toByte())

    data class ChunkItem(
        val transferId: ByteArray,
        val chunkIndex: Int,
        val totalChunks: Int,
        val target: ByteArray,
        val edPrivateKeySeed: ByteArray,
        val frame1000: ByteArray
    )

    /**
     * Splits data into 900-byte chunks and encodes each into a 1000-byte Type 0x05 frame.
     */
    fun splitData(
        data: ByteArray,
        currentEdSeed: ByteArray,
        currentMsgKey: ByteArray,
        seqNum: Int,
        ackNum: Int,
        transferId: ByteArray = CryptoUtils.secureRandomBytes(16)
    ): List<ChunkItem> {
        val totalChunks = (data.size + CHUNK_SIZE - 1) / CHUNK_SIZE
        val chunks = ArrayList<ChunkItem>(totalChunks)

        for (j in 0 until totalChunks) {
            val offset = j * CHUNK_SIZE
            val len = minOf(CHUNK_SIZE, data.size - offset)
            val chunkBytes = data.copyOfRange(offset, offset + len)

            val subEdSeed = deriveChunkEdSeed(currentEdSeed, transferId, j)
            val subKeyPair = Ed25519Engine.generateKeyPairFromSeed(subEdSeed)
            val subTarget = Ed25519Engine.computeTarget(subKeyPair.publicKey)

            val subMsgKey = deriveChunkMsgKey(currentMsgKey, j)

            // Encode into 1000-byte AEAD frame
            val plaintext972 = BinaryFrameCodec.encodeChunkData(
                seqNum = seqNum,
                ackNum = ackNum,
                timestampUTC = System.currentTimeMillis(),
                transferId = transferId,
                chunkIndex = j,
                totalChunks = totalChunks,
                chunkData = chunkBytes
            )
            val frame1000 = BinaryFrameCodec.packAeadFrame(subMsgKey, plaintext972)

            chunks.add(
                ChunkItem(
                    transferId = transferId,
                    chunkIndex = j,
                    totalChunks = totalChunks,
                    target = subTarget,
                    edPrivateKeySeed = subEdSeed,
                    frame1000 = frame1000
                )
            )
        }

        return chunks
    }

    /**
     * Reassembles chunks into original data.
     */
    fun assembleChunks(chunks: List<BinaryFrameCodec.DecodedPayload.ChunkData>): ByteArray {
        require(chunks.isNotEmpty()) { "Chunks list is empty" }
        val total = chunks[0].totalChunks
        require(chunks.size == total) { "Incomplete chunks: have ${chunks.size}, expected $total" }

        val sorted = chunks.sortedBy { it.chunkIndex }
        val baos = ByteArrayOutputStream()

        for (i in 0 until total) {
            require(sorted[i].chunkIndex == i) { "Missing chunk at index $i" }
            baos.write(sorted[i].data)
        }

        return baos.toByteArray()
    }

    /**
     * Checks if byte array starts with PNG magic bytes.
     */
    fun isPngImage(data: ByteArray): Boolean {
        if (data.size < 4) return false
        return data[0] == PNG_MAGIC[0] &&
                data[1] == PNG_MAGIC[1] &&
                data[2] == PNG_MAGIC[2] &&
                data[3] == PNG_MAGIC[3]
    }

    fun deriveChunkEdSeed(baseEdSeed: ByteArray, transferId: ByteArray, chunkIndex: Int): ByteArray {
        if (chunkIndex == 0) return baseEdSeed
        val buffer = ByteBuffer.allocate(5 + 16 + 4).order(ByteOrder.BIG_ENDIAN)
        buffer.put("chunk".toByteArray(Charsets.UTF_8))
        buffer.put(transferId)
        buffer.putInt(chunkIndex)

        val hmac64 = CryptoUtils.hmacSha512(baseEdSeed, buffer.array())
        return hmac64.copyOfRange(0, 32)
    }

    fun deriveChunkMsgKey(baseMsgKey: ByteArray, chunkIndex: Int): ByteArray {
        if (chunkIndex == 0) return baseMsgKey
        val buffer = ByteBuffer.allocate(9 + 4).order(ByteOrder.BIG_ENDIAN)
        buffer.put("chunk_key".toByteArray(Charsets.UTF_8))
        buffer.putInt(chunkIndex)

        return HkdfSha512.expand(baseMsgKey, buffer.array(), 32)
    }
}
