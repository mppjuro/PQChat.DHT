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
    const val TYPE_GROUP_CONTROL: Byte = 0x06

    const val GROUP_SUBTYPE_INVITE: Byte = 0x01
    const val GROUP_SUBTYPE_REKEY: Byte = 0x02
    const val GROUP_SUBTYPE_LEAVE: Byte = 0x03
    const val GROUP_REKEY_MESSAGE_INTERVAL = 50

    // Type 0x01 limits: Hybrid ct (800 B: 768 B ML-KEM + 32 B X25519) + Salt (24 B) + Tag (32 B) = 856 <= 859
    const val T1_CIPHERTEXT_SIZE = HybridKemEngine.HYBRID_CIPHERTEXT_SIZE // 800
    const val T1_SALT_SIZE = 24
    const val T1_CONFIRMATION_TAG_SIZE = 32
    const val T1_PADDING_SIZE = 3 // 859 - 856

    // Type 0x02 limits
    const val T2_MAX_TEXT_SIZE = 857 // 859 - 2

    // Type 0x03 limits: Combined pk (832 B: 800 B ML-KEM + 32 B X25519) + RekeyEpoch (4 B) = 836 <= 859
    const val T3_PUBLIC_KEY_SIZE = HybridKemEngine.HYBRID_PUBLIC_KEY_SIZE // 832
    const val T3_PADDING_SIZE = 23 // 859 - 836

    // Type 0x04 limits: Hybrid ct (800 B: 768 B ML-KEM + 32 B X25519) + RekeyEpoch (4 B) = 804 <= 859
    const val T4_CIPHERTEXT_SIZE = HybridKemEngine.HYBRID_CIPHERTEXT_SIZE // 800
    const val T4_PADDING_SIZE = 55 // 859 - 804

    // Type 0x05 limits
    const val T5_TRANSFER_ID_SIZE = 16
    const val T5_MAX_CHUNK_SIZE = 837 // 859 - 22

    sealed class DecodedPayload {
        data class HandshakeFinalize(
            val hybridCiphertext: ByteArray,
            val saltParameter: ByteArray,
            val confirmationTag: ByteArray = ByteArray(T1_CONFIRMATION_TAG_SIZE)
        ) : DecodedPayload() {
            // Backward-compatible alias
            val mlKemCiphertext: ByteArray get() = hybridCiphertext

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is HandshakeFinalize) return false
                return hybridCiphertext.contentEquals(other.hybridCiphertext) &&
                        saltParameter.contentEquals(other.saltParameter) &&
                        confirmationTag.contentEquals(other.confirmationTag)
            }
            override fun hashCode(): Int {
                var result = hybridCiphertext.contentHashCode()
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
            val hybridPublicKey: ByteArray
        ) : DecodedPayload() {
            // Backward-compatible alias
            val mlKemPublicKey: ByteArray get() = hybridPublicKey

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is RekeyOffer) return false
                return rekeyEpoch == other.rekeyEpoch &&
                        hybridPublicKey.contentEquals(other.hybridPublicKey)
            }
            override fun hashCode(): Int =
                31 * rekeyEpoch.hashCode() + hybridPublicKey.contentHashCode()
        }

        data class RekeyResponse(
            val rekeyEpoch: Long,
            val hybridCiphertext: ByteArray
        ) : DecodedPayload() {
            // Backward-compatible alias
            val mlKemCiphertext: ByteArray get() = hybridCiphertext

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is RekeyResponse) return false
                return rekeyEpoch == other.rekeyEpoch &&
                        hybridCiphertext.contentEquals(other.hybridCiphertext)
            }
            override fun hashCode(): Int =
                31 * rekeyEpoch.hashCode() + hybridCiphertext.contentHashCode()
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

        data class GroupMemberSummary(
            val memberId: ByteArray,
            val memberName: String
        ) {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is GroupMemberSummary) return false
                return memberId.contentEquals(other.memberId) && memberName == other.memberName
            }
            override fun hashCode(): Int = 31 * memberId.contentHashCode() + memberName.hashCode()
        }

        data class GroupControl(
            val controlSubType: Byte,
            val groupId: ByteArray,
            val groupEpoch: Long,
            val senderMemberId: ByteArray,
            val senderGroupChainKey: ByteArray,
            val currentCounter: Long,
            val groupName: String,
            val members: List<GroupMemberSummary> = emptyList()
        ) : DecodedPayload() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is GroupControl) return false
                return controlSubType == other.controlSubType &&
                        groupId.contentEquals(other.groupId) &&
                        groupEpoch == other.groupEpoch &&
                        senderMemberId.contentEquals(other.senderMemberId) &&
                        senderGroupChainKey.contentEquals(other.senderGroupChainKey) &&
                        currentCounter == other.currentCounter &&
                        groupName == other.groupName &&
                        members == other.members
            }
            override fun hashCode(): Int {
                var result = controlSubType.toInt()
                result = 31 * result + groupId.contentHashCode()
                result = 31 * result + groupEpoch.hashCode()
                result = 31 * result + senderMemberId.contentHashCode()
                result = 31 * result + senderGroupChainKey.contentHashCode()
                result = 31 * result + currentCounter.hashCode()
                result = 31 * result + groupName.hashCode()
                result = 31 * result + members.hashCode()
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
    ) {
        val last_received_seq: Int get() = ackNum
        val lastReceivedSeq: Int get() = ackNum
    }

    // ==========================================
    // ENCODING / PACKING
    // ==========================================

    fun encodeHandshakeFinalize(
        seqNum: Int,
        ackNum: Int,
        timestampUTC: Long,
        hybridCiphertext: ByteArray,
        saltParameter: ByteArray,
        confirmationTag: ByteArray = ByteArray(T1_CONFIRMATION_TAG_SIZE)
    ): ByteArray {
        require(hybridCiphertext.size == T1_CIPHERTEXT_SIZE)
        require(saltParameter.size == T1_SALT_SIZE)
        require(confirmationTag.size == T1_CONFIRMATION_TAG_SIZE)

        val buffer = ByteBuffer.allocate(INNER_PAYLOAD_SIZE)
        buffer.put(hybridCiphertext)
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
        hybridPublicKey: ByteArray
    ): ByteArray {
        require(hybridPublicKey.size == T3_PUBLIC_KEY_SIZE)

        val buffer = ByteBuffer.allocate(INNER_PAYLOAD_SIZE).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(rekeyEpoch.toInt())
        buffer.put(hybridPublicKey)
        buffer.put(CryptoUtils.secureRandomBytes(T3_PADDING_SIZE))

        return packPlaintext(TYPE_REKEY_OFFER, seqNum, ackNum, timestampUTC, buffer.array())
    }

    fun encodeRekeyResponse(
        seqNum: Int,
        ackNum: Int,
        timestampUTC: Long,
        rekeyEpoch: Long,
        hybridCiphertext: ByteArray
    ): ByteArray {
        require(hybridCiphertext.size == T4_CIPHERTEXT_SIZE)

        val buffer = ByteBuffer.allocate(INNER_PAYLOAD_SIZE).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(rekeyEpoch.toInt())
        buffer.put(hybridCiphertext)
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

    fun encodeGroupControl(
        seqNum: Int,
        ackNum: Int,
        timestampUTC: Long,
        controlSubType: Byte,
        groupId: ByteArray,
        groupEpoch: Long,
        senderMemberId: ByteArray,
        senderGroupChainKey: ByteArray,
        currentCounter: Long,
        groupName: String,
        members: List<DecodedPayload.GroupMemberSummary> = emptyList()
    ): ByteArray {
        require(groupId.size == 16) { "groupId must be 16 bytes" }
        require(senderMemberId.size == 16) { "senderMemberId must be 16 bytes" }
        require(senderGroupChainKey.size == 64) { "senderGroupChainKey must be 64 bytes" }

        val nameBytes = groupName.toByteArray(Charsets.UTF_8).let {
            if (it.size > 64) it.copyOf(64) else it
        }

        val buffer = ByteBuffer.allocate(INNER_PAYLOAD_SIZE).order(ByteOrder.BIG_ENDIAN)
        buffer.put(controlSubType)
        buffer.put(groupId)
        buffer.putInt(groupEpoch.toInt())
        buffer.put(senderMemberId)
        buffer.put(senderGroupChainKey)
        buffer.putInt(currentCounter.toInt())
        buffer.putShort(nameBytes.size.toShort())
        buffer.put(nameBytes)

        buffer.putShort(members.size.toShort())
        for (m in members) {
            val mNameBytes = m.memberName.toByteArray(Charsets.UTF_8).let {
                if (it.size > 32) it.copyOf(32) else it
            }
            val required = 16 + 1 + mNameBytes.size
            if (buffer.remaining() < required) break
            buffer.put(m.memberId.let { if (it.size == 16) it else it.copyOf(16) })
            buffer.put(mNameBytes.size.toByte())
            buffer.put(mNameBytes)
        }

        val paddingNeeded = INNER_PAYLOAD_SIZE - buffer.position()
        if (paddingNeeded > 0) {
            buffer.put(CryptoUtils.secureRandomBytes(paddingNeeded))
        }

        return packPlaintext(TYPE_GROUP_CONTROL, seqNum, ackNum, timestampUTC, buffer.array())
    }

    fun encodeGroupRekey(
        seqNum: Int,
        ackNum: Int,
        timestampUTC: Long,
        groupId: ByteArray,
        groupEpoch: Long,
        senderMemberId: ByteArray,
        senderGroupChainKey: ByteArray,
        currentCounter: Long,
        groupName: String = ""
    ): ByteArray = encodeGroupControl(
        seqNum = seqNum,
        ackNum = ackNum,
        timestampUTC = timestampUTC,
        controlSubType = GROUP_SUBTYPE_REKEY,
        groupId = groupId,
        groupEpoch = groupEpoch,
        senderMemberId = senderMemberId,
        senderGroupChainKey = senderGroupChainKey,
        currentCounter = currentCounter,
        groupName = groupName,
        members = emptyList()
    )

    fun encodeGroupLeave(
        seqNum: Int,
        ackNum: Int,
        timestampUTC: Long,
        groupId: ByteArray,
        groupEpoch: Long,
        senderMemberId: ByteArray,
        groupName: String = ""
    ): ByteArray = encodeGroupControl(
        seqNum = seqNum,
        ackNum = ackNum,
        timestampUTC = timestampUTC,
        controlSubType = GROUP_SUBTYPE_LEAVE,
        groupId = groupId,
        groupEpoch = groupEpoch,
        senderMemberId = senderMemberId,
        senderGroupChainKey = ByteArray(64),
        currentCounter = 0L,
        groupName = groupName,
        members = emptyList()
    )

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

    fun buildAad(target: ByteArray, direction: String): ByteArray {
        val dirBytes = direction.toByteArray(Charsets.UTF_8)
        val aad = ByteArray(target.size + dirBytes.size)
        System.arraycopy(target, 0, aad, 0, target.size)
        System.arraycopy(dirBytes, 0, aad, target.size, dirBytes.size)
        return aad
    }

    fun packAeadFrame(
        key: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray
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
        val aad = buildAad(target, direction)
        return packAeadFrame(key, plaintext, aad)
    }

    fun unpackAeadFrame(
        key: ByteArray,
        frame: ByteArray,
        aad: ByteArray
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

        try {
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
                TYPE_GROUP_CONTROL -> {
                    val subType = buffer.get()
                    val gId = ByteArray(16)
                    buffer.get(gId)
                    val epoch = buffer.int.toLong() and 0xFFFFFFFFL
                    val sMemberId = ByteArray(16)
                    buffer.get(sMemberId)
                    val sChainKey = ByteArray(64)
                    buffer.get(sChainKey)
                    val curCounter = buffer.int.toLong() and 0xFFFFFFFFL
                    val nameLen = buffer.short.toInt() and 0xFFFF
                    require(nameLen in 0..64 && nameLen <= buffer.remaining()) { "Invalid group name length: $nameLen" }
                    val nameBytes = ByteArray(nameLen)
                    buffer.get(nameBytes)
                    val gName = String(nameBytes, Charsets.UTF_8)
                    val mCount = buffer.short.toInt() and 0xFFFF
                    require(mCount <= 64) { "Member count $mCount exceeds maximum allowed 64" }
                    val memberList = mutableListOf<DecodedPayload.GroupMemberSummary>()
                    for (i in 0 until mCount) {
                        if (buffer.remaining() < 17) break
                        val mId = ByteArray(16)
                        buffer.get(mId)
                        val mNameLen = buffer.get().toInt() and 0xFF
                        val actualLen = minOf(mNameLen, buffer.remaining())
                        val mNameBytes = ByteArray(actualLen)
                        buffer.get(mNameBytes)
                        memberList.add(DecodedPayload.GroupMemberSummary(mId, String(mNameBytes, Charsets.UTF_8)))
                    }
                    DecodedPayload.GroupControl(
                        controlSubType = subType,
                        groupId = gId,
                        groupEpoch = epoch,
                        senderMemberId = sMemberId,
                        senderGroupChainKey = sChainKey,
                        currentCounter = curCounter,
                        groupName = gName,
                        members = memberList
                    )
                }
                else -> throw IllegalArgumentException("Unknown message type: 0x%02X".format(msgType))
            }

            return FrameMessage(msgType, seqNum, ackNum, timestampUTC, payload)
        } finally {
            plaintext.fill(0)
            ciphertext.fill(0)
            iv.fill(0)
            tag.fill(0)
        }
    }

    fun unpackAeadFrame(
        key: ByteArray,
        frame: ByteArray,
        target: ByteArray,
        direction: String
    ): FrameMessage {
        val aad = buildAad(target, direction)
        return unpackAeadFrame(key, frame, aad)
    }

    fun buildGroupAad(target: ByteArray, groupId: ByteArray, senderMemberId: ByteArray): ByteArray {
        val aad = ByteArray(target.size + groupId.size + senderMemberId.size)
        System.arraycopy(target, 0, aad, 0, target.size)
        System.arraycopy(groupId, 0, aad, target.size, groupId.size)
        System.arraycopy(senderMemberId, 0, aad, target.size + groupId.size, senderMemberId.size)
        return aad
    }

    fun packGroupAeadFrame(
        key: ByteArray,
        plaintext: ByteArray,
        target: ByteArray,
        groupId: ByteArray,
        senderMemberId: ByteArray
    ): ByteArray {
        val aad = buildGroupAad(target, groupId, senderMemberId)
        return packAeadFrame(key, plaintext, aad)
    }

    fun unpackGroupAeadFrame(
        key: ByteArray,
        frame: ByteArray,
        target: ByteArray,
        groupId: ByteArray,
        senderMemberId: ByteArray
    ): FrameMessage {
        val aad = buildGroupAad(target, groupId, senderMemberId)
        return unpackAeadFrame(key, frame, aad)
    }

    /**
     * Creates a constant-size tombstone payload (exactly [MAX_FRAME_PAYLOAD_BYTES] of CSPRNG noise).
     * Overwriting the ephemeral transmission slot with an identical 900-byte frame under seq + 1
     * destroys the original ciphertext on DHT storage nodes while preventing traffic analysis:
     * outside observers cannot distinguish tombstone overwrites from normal PUT updates or chaffing.
     */
    fun createTombstonePayload(): ByteArray {
        return CryptoUtils.secureRandomBytes(MAX_FRAME_PAYLOAD_BYTES)
    }
}
