package org.pqchat.dht.protocol

import org.pqchat.dht.crypto.AesGcmEngine
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Protocol for Cover-Traffic ACK (confirmations hidden inside network noise).
 *
 * An ephemeral DHT slot is calculated as:
 *   Seed = HMAC-SHA256(ratchetKey, "ACK" + msg_id)
 *   Target_ACK = SHA-1(Ed25519_PublicKey(Seed))
 *
 * The ACK packet is encrypted with AES-256-GCM and padded to exactly
 * BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES (900 bytes), making it completely
 * indistinguishable from Poisson dummy cover traffic to outside observers.
 */
object CoverAckProtocol {
    val ACK_MAGIC = byteArrayOf(0x50.toByte(), 0x51.toByte(), 0x41.toByte(), 0x43.toByte()) // "PQAC"
    val READ_RECEIPT_MAGIC = byteArrayOf(0x50.toByte(), 0x51.toByte(), 0x52.toByte(), 0x52.toByte()) // "PQRR"
    private const val READ_RECEIPT_BLOCK_SIZE = 16 // 4B magic + 4B baseSeq + 8B 64-bit bitmap

    data class ParsedAck(
        val seqNum: Int,
        val timestampUTC: Long,
        val messageId: String,
        val hasReadReceipt: Boolean = false,
        val readBaseSeq: Int = 0,
        val readSeqBitmap: Long = 0L
    ) {
        fun isSeqRead(targetSeqNum: Int): Boolean {
            if (!hasReadReceipt) return false
            val delta = targetSeqNum - readBaseSeq
            if (delta !in 0..63) return false
            return ((readSeqBitmap ushr delta) and 1L) != 0L
        }

        fun extractReadSequenceNumbers(): List<Int> {
            if (!hasReadReceipt || readSeqBitmap == 0L) return emptyList()
            val result = ArrayList<Int>(16)
            for (bit in 0 until 64) {
                if (((readSeqBitmap ushr bit) and 1L) != 0L) {
                    val seq = readBaseSeq.toLong() + bit.toLong()
                    if (seq in 0L..Int.MAX_VALUE.toLong()) {
                        result.add(seq.toInt())
                    }
                }
            }
            return result
        }
    }

    /**
     * Packs a collection of read incoming sequence numbers into a compact `(baseSeq, 64-bit bitmap)` window
     * suitable for zero-overhead embedding inside a Cover ACK frame's unused CSPRNG padding.
     */
    fun buildReadReceiptWindow(readSeqNums: Collection<Int>): Pair<Int, Long>? {
        if (readSeqNums.isEmpty()) return null
        val validSeqs = readSeqNums.filter { it >= 0 }
        if (validSeqs.isEmpty()) return null
        val maxSeq = validSeqs.max()
        val baseSeq = (maxSeq - 63).coerceAtLeast(0)
        var bitmap = 0L
        for (seq in validSeqs) {
            val delta = seq - baseSeq
            if (delta in 0..63) {
                bitmap = bitmap or (1L shl delta)
            }
        }
        return if (bitmap != 0L) Pair(baseSeq, bitmap) else null
    }

    /**
     * Derives a 32-byte Ed25519 seed for the ephemeral ACK slot:
     * HMAC-SHA256(ratchetKey, "ACK" + msg_id)
     */
    fun deriveAckSeed(ratchetKey: ByteArray, messageId: String): ByteArray {
        val data = ("ACK$messageId").toByteArray(Charsets.UTF_8)
        return CryptoUtils.hmacSha256(ratchetKey, data)
    }

    /**
     * Computes the 20-byte BEP 44 DHT Target for the ACK slot.
     */
    fun computeAckTarget(ratchetKey: ByteArray, messageId: String): ByteArray {
        val seed = deriveAckSeed(ratchetKey, messageId)
        var keyPair: Ed25519Engine.KeyPair? = null
        return try {
            keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
            Ed25519Engine.computeTarget(keyPair.publicKey)
        } finally {
            seed.fill(0)
            keyPair?.seed?.fill(0)
        }
    }

    /**
     * Overload accepting integer sequence number.
     */
    fun computeAckTarget(ratchetKey: ByteArray, seqNum: Int): ByteArray =
        computeAckTarget(ratchetKey, seqNum.toString())

    /**
     * Derives symmetric AES-256 key for encrypting/decrypting the ACK token:
     * HMAC-SHA256(ratchetKey, "ACK_AES_" + msg_id)
     */
    fun deriveAckAesKey(ratchetKey: ByteArray, messageId: String): ByteArray {
        val data = ("ACK_AES_$messageId").toByteArray(Charsets.UTF_8)
        return CryptoUtils.hmacSha256(ratchetKey, data)
    }

    /**
     * Creates an encrypted ACK payload of exactly BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES (900 bytes).
     * The plaintext contains magic, seqNum, timestamp, messageId, and random CSPRNG padding.
     */
    fun createAckPayload(
        ratchetKey: ByteArray,
        messageId: String,
        seqNum: Int,
        timestampUTC: Long = BinaryFrameCodec.obfuscateTimestamp(System.currentTimeMillis()),
        readBaseSeq: Int? = null,
        readSeqBitmap: Long = 0L
    ): ByteArray {
        val msgIdBytes = messageId.toByteArray(Charsets.UTF_8)
        require(msgIdBytes.size <= 64) { "messageId exceeds maximum length of 64 bytes" }

        val aesKey = deriveAckAesKey(ratchetKey, messageId)
        val plaintextBytes = ByteArray(BinaryFrameCodec.CIPHERTEXT_SIZE)
        return try {
            val plaintext = ByteBuffer.wrap(plaintextBytes).order(ByteOrder.BIG_ENDIAN)
            plaintext.put(ACK_MAGIC)
            plaintext.putInt(seqNum)
            plaintext.putLong(timestampUTC)
            plaintext.putShort(msgIdBytes.size.toShort())
            plaintext.put(msgIdBytes)

            if (readBaseSeq != null && readSeqBitmap != 0L && plaintext.remaining() >= READ_RECEIPT_BLOCK_SIZE) {
                plaintext.put(READ_RECEIPT_MAGIC)
                plaintext.putInt(readBaseSeq)
                plaintext.putLong(readSeqBitmap)
            }

            val paddingSize = BinaryFrameCodec.CIPHERTEXT_SIZE - plaintext.position()
            if (paddingSize > 0) {
                val noise = CryptoUtils.secureRandomBytes(paddingSize)
                if ((readBaseSeq == null || readSeqBitmap == 0L) && noise.size >= READ_RECEIPT_MAGIC.size) {
                    val prefixMatchesMagic = (0 until READ_RECEIPT_MAGIC.size).all { i -> noise[i] == READ_RECEIPT_MAGIC[i] }
                    if (prefixMatchesMagic) {
                        noise[0] = (noise[0].toInt() xor 0xFF).toByte()
                    }
                }
                plaintext.put(noise)
            }

            val ackTarget = computeAckTarget(ratchetKey, messageId)
            val aad = BinaryFrameCodec.buildAad(ackTarget, "ACK")
            BinaryFrameCodec.packAeadFrame(aesKey, plaintextBytes, aad)
        } finally {
            aesKey.fill(0)
            plaintextBytes.fill(0)
        }
    }

    /**
     * Decrypts, authenticates, and parses the ACK payload including any embedded zero-overhead
     * read receipt bitmap (`readBaseSeq` + 64-bit `readSeqBitmap`). Returns null if invalid.
     */
    fun parseAckPayload(
        ratchetKey: ByteArray,
        frame: ByteArray,
        expectedMessageId: String,
        expectedSeqNum: Int? = null
    ): ParsedAck? {
        if (frame.size != BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES) return null
        val aesKey = deriveAckAesKey(ratchetKey, expectedMessageId)
        var plaintextBytes: ByteArray? = null
        return try {
            val iv = ByteArray(BinaryFrameCodec.IV_SIZE)
            val tag = ByteArray(BinaryFrameCodec.TAG_SIZE)
            val ciphertext = ByteArray(BinaryFrameCodec.CIPHERTEXT_SIZE)

            System.arraycopy(frame, 0, iv, 0, BinaryFrameCodec.IV_SIZE)
            System.arraycopy(frame, BinaryFrameCodec.IV_SIZE, tag, 0, BinaryFrameCodec.TAG_SIZE)
            System.arraycopy(frame, BinaryFrameCodec.IV_SIZE + BinaryFrameCodec.TAG_SIZE, ciphertext, 0, BinaryFrameCodec.CIPHERTEXT_SIZE)

            val ackTarget = computeAckTarget(ratchetKey, expectedMessageId)
            val aad = BinaryFrameCodec.buildAad(ackTarget, "ACK")

            plaintextBytes = try {
                AesGcmEngine.decrypt(aesKey, iv, tag, ciphertext, aad)
            } catch (_: Exception) {
                return null
            }

            if (plaintextBytes.size != BinaryFrameCodec.CIPHERTEXT_SIZE) return null

            val buf = ByteBuffer.wrap(plaintextBytes).order(ByteOrder.BIG_ENDIAN)
            val magic = ByteArray(ACK_MAGIC.size)
            buf.get(magic)
            if (!CryptoUtils.constantTimeEquals(magic, ACK_MAGIC)) return null

            val seq = buf.int
            if (expectedSeqNum != null && seq != expectedSeqNum) return null

            val ts = buf.long
            if (ts <= 0) return null

            val msgIdLen = buf.short.toInt() and 0xFFFF
            if (msgIdLen <= 0 || msgIdLen > 64 || msgIdLen > buf.remaining()) return null

            val msgIdBytes = ByteArray(msgIdLen)
            buf.get(msgIdBytes)
            val parsedMsgId = String(msgIdBytes, Charsets.UTF_8)
            if (parsedMsgId != expectedMessageId) return null

            var hasReadReceipt = false
            var parsedReadBaseSeq = 0
            var parsedReadBitmap = 0L
            if (buf.remaining() >= READ_RECEIPT_BLOCK_SIZE) {
                val receiptMagic = ByteArray(READ_RECEIPT_MAGIC.size)
                buf.get(receiptMagic)
                if (CryptoUtils.constantTimeEquals(receiptMagic, READ_RECEIPT_MAGIC)) {
                    parsedReadBaseSeq = buf.int
                    parsedReadBitmap = buf.long
                    hasReadReceipt = parsedReadBitmap != 0L
                }
            }

            ParsedAck(
                seqNum = seq,
                timestampUTC = ts,
                messageId = parsedMsgId,
                hasReadReceipt = hasReadReceipt,
                readBaseSeq = parsedReadBaseSeq,
                readSeqBitmap = parsedReadBitmap
            )
        } finally {
            aesKey.fill(0)
            plaintextBytes?.fill(0)
        }
    }

    /**
     * Decrypts and verifies the ACK payload. Returns true if valid ACK for expectedMessageId.
     */
    fun verifyAckPayload(
        ratchetKey: ByteArray,
        frame: ByteArray,
        expectedMessageId: String,
        expectedSeqNum: Int? = null
    ): Boolean = parseAckPayload(ratchetKey, frame, expectedMessageId, expectedSeqNum) != null
}
