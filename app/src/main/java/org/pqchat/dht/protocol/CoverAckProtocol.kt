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
        val keyPair = Ed25519Engine.generateKeyPairFromSeed(seed)
        return Ed25519Engine.computeTarget(keyPair.publicKey)
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
        timestampUTC: Long = System.currentTimeMillis()
    ): ByteArray {
        val aesKey = deriveAckAesKey(ratchetKey, messageId)
        val msgIdBytes = messageId.toByteArray(Charsets.UTF_8)
        require(msgIdBytes.size <= 64) { "messageId exceeds maximum length of 64 bytes" }

        val plaintext = ByteBuffer.allocate(BinaryFrameCodec.CIPHERTEXT_SIZE).order(ByteOrder.BIG_ENDIAN)
        plaintext.put(ACK_MAGIC)
        plaintext.putInt(seqNum)
        plaintext.putLong(timestampUTC)
        plaintext.putShort(msgIdBytes.size.toShort())
        plaintext.put(msgIdBytes)

        val paddingSize = BinaryFrameCodec.CIPHERTEXT_SIZE - plaintext.position()
        if (paddingSize > 0) {
            plaintext.put(CryptoUtils.secureRandomBytes(paddingSize))
        }

        return BinaryFrameCodec.packAeadFrame(aesKey, plaintext.array())
    }

    /**
     * Decrypts and verifies the ACK payload. Returns true if valid ACK for expectedMessageId.
     */
    fun verifyAckPayload(
        ratchetKey: ByteArray,
        frame: ByteArray,
        expectedMessageId: String,
        expectedSeqNum: Int? = null
    ): Boolean {
        if (frame.size != BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES) return false
        val aesKey = deriveAckAesKey(ratchetKey, expectedMessageId)

        val iv = ByteArray(BinaryFrameCodec.IV_SIZE)
        val tag = ByteArray(BinaryFrameCodec.TAG_SIZE)
        val ciphertext = ByteArray(BinaryFrameCodec.CIPHERTEXT_SIZE)

        System.arraycopy(frame, 0, iv, 0, BinaryFrameCodec.IV_SIZE)
        System.arraycopy(frame, BinaryFrameCodec.IV_SIZE, tag, 0, BinaryFrameCodec.TAG_SIZE)
        System.arraycopy(frame, BinaryFrameCodec.IV_SIZE + BinaryFrameCodec.TAG_SIZE, ciphertext, 0, BinaryFrameCodec.CIPHERTEXT_SIZE)

        val plaintextBytes = try {
            AesGcmEngine.decrypt(aesKey, iv, tag, ciphertext, null)
        } catch (_: Exception) {
            return false
        }

        if (plaintextBytes.size != BinaryFrameCodec.CIPHERTEXT_SIZE) return false

        val buf = ByteBuffer.wrap(plaintextBytes).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(ACK_MAGIC.size)
        buf.get(magic)
        if (!CryptoUtils.constantTimeEquals(magic, ACK_MAGIC)) return false

        val seq = buf.int
        if (expectedSeqNum != null && seq != expectedSeqNum) return false

        val ts = buf.long
        if (ts <= 0) return false

        val msgIdLen = buf.short.toInt() and 0xFFFF
        if (msgIdLen <= 0 || msgIdLen > 64 || msgIdLen > buf.remaining()) return false

        val msgIdBytes = ByteArray(msgIdLen)
        buf.get(msgIdBytes)
        val parsedMsgId = String(msgIdBytes, Charsets.UTF_8)

        return parsedMsgId == expectedMessageId
    }
}
