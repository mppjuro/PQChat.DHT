package org.pqchat.dht.protocol

import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.crypto.HkdfSha512
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Dual Unidirectional KDF Ratchet & Key Hopping Engine.
 *
 * For each step i:
 * Entropy_i = HKDF-Expand(ChainKey^i, "step" || i, 128)
 * - Bytes 0..31: MsgKey_i (AES-256-GCM symmetric key)
 * - Bytes 32..63: EdSeed_i (Ed25519 deterministic key pair pk_i, sk_i)
 * - Bytes 64..127: ChainKey^{i+1} (Next chain state)
 * - DHT Address: Target_i = SHA-1(pk_i)
 */
object RatchetChain {

    const val CHAIN_KEY_SIZE = 64
    const val MSG_KEY_SIZE = 32
    const val ED_SEED_SIZE = 32
    const val TOTAL_ENTROPY_SIZE = 128

    data class SlotParameters(
        val counter: Int,
        val msgKey: ByteArray,
        val edPrivateKeySeed: ByteArray,
        val edPublicKey: ByteArray,
        val target: ByteArray,
        val nextChainKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is SlotParameters) return false
            return counter == other.counter &&
                    msgKey.contentEquals(other.msgKey) &&
                    edPrivateKeySeed.contentEquals(other.edPrivateKeySeed) &&
                    edPublicKey.contentEquals(other.edPublicKey) &&
                    target.contentEquals(other.target) &&
                    nextChainKey.contentEquals(other.nextChainKey)
        }

        override fun hashCode(): Int {
            var result = counter
            result = 31 * result + msgKey.contentHashCode()
            result = 31 * result + edPrivateKeySeed.contentHashCode()
            result = 31 * result + edPublicKey.contentHashCode()
            result = 31 * result + target.contentHashCode()
            result = 31 * result + nextChainKey.contentHashCode()
            return result
        }
    }

    /**
     * Build info bytes for HKDF-Expand: "step" || i (as 32-bit big-endian integer)
     */
    private fun buildStepInfo(counter: Int): ByteArray {
        val buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
        buffer.put("step".toByteArray(Charsets.UTF_8))
        buffer.putInt(counter)
        return buffer.array()
    }

    /**
     * Derives slot parameters for step i from the current ChainKey.
     */
    fun deriveSlot(chainKey: ByteArray, counter: Int): SlotParameters {
        require(chainKey.size == CHAIN_KEY_SIZE) {
            "Invalid ChainKey size: ${chainKey.size}, expected $CHAIN_KEY_SIZE"
        }

        val info = buildStepInfo(counter)
        val entropy = HkdfSha512.expand(chainKey, info, TOTAL_ENTROPY_SIZE)

        val msgKey = entropy.copyOfRange(0, 32)
        val edSeed = entropy.copyOfRange(32, 64)
        val nextChainKey = entropy.copyOfRange(64, 128)

        val edKeyPair = Ed25519Engine.generateKeyPairFromSeed(edSeed)
        val target = Ed25519Engine.computeTarget(edKeyPair.publicKey)

        return SlotParameters(
            counter = counter,
            msgKey = msgKey,
            edPrivateKeySeed = edSeed,
            edPublicKey = edKeyPair.publicKey,
            target = target,
            nextChainKey = nextChainKey
        )
    }

    /**
     * Computes slots in a lookahead window [fromCounter, fromCounter + windowSize].
     * Useful for checking out-of-order slots on receiver side.
     */
    fun computeLookaheadSlots(
        startChainKey: ByteArray,
        startCounter: Int,
        windowSize: Int = 4
    ): List<SlotParameters> {
        val slots = ArrayList<SlotParameters>(windowSize + 1)
        var currentChain = startChainKey
        var currentCounter = startCounter

        for (k in 0..windowSize) {
            val slot = deriveSlot(currentChain, currentCounter)
            slots.add(slot)
            currentChain = slot.nextChainKey
            currentCounter++
        }

        return slots
    }

    /**
     * Injects a new post-quantum shared secret SS_rekey into the current ChainKey:
     * ChainKey = HKDF-Extract(ChainKey, SS_rekey)
     */
    fun injectRekeySecret(currentChainKey: ByteArray, ssRekey: ByteArray): ByteArray {
        require(currentChainKey.size == CHAIN_KEY_SIZE)
        require(ssRekey.size == 32)

        return HkdfSha512.extract(currentChainKey, ssRekey)
    }

    /**
     * Computes in advance the next expected incoming DHT rendezvous address:
     * nextExpectedTarget = SHA-1(pk_in)
     * derived deterministically from the recipient's incoming chain key and counter.
     */
    fun getNextExpectedTarget(chainKeyIn: ByteArray, counterIn: Int): ByteArray {
        val slot = deriveSlot(chainKeyIn, counterIn)
        return slot.target
    }

    fun deriveSlot(chainKey: org.pqchat.dht.data.db.EncryptedBlob, counter: Int): SlotParameters =
        deriveSlot(chainKey.raw, counter)

    fun computeLookaheadSlots(
        startChainKey: org.pqchat.dht.data.db.EncryptedBlob,
        startCounter: Int,
        windowSize: Int = 4
    ): List<SlotParameters> = computeLookaheadSlots(startChainKey.raw, startCounter, windowSize)

    fun injectRekeySecret(currentChainKey: org.pqchat.dht.data.db.EncryptedBlob, ssRekey: ByteArray): ByteArray =
        injectRekeySecret(currentChainKey.raw, ssRekey)

    fun getNextExpectedTarget(chainKeyIn: org.pqchat.dht.data.db.EncryptedBlob, counterIn: Int): ByteArray =
        getNextExpectedTarget(chainKeyIn.raw, counterIn)

    /**
     * Build info bytes for HKDF-Expand with group target context:
     * "group_target:" || groupId || counter || memberId.
     * Ensures strict mathematical independence of DHT targets and encryption keys across
     * all group members, eliminating Group Follower Correlation and Tombstone Collisions.
     *
     * Uzasadnienie: Same-target dla wszystkich członków umożliwia obserwatorowi DHT
     * skorelowanie N odbiorców przez równoległe GET-y na ten sam slot, łamiąc tajność
     * celu komunikacji grupowej.
     */
    fun buildGroupTargetInfo(
        groupId: ByteArray,
        counter: Int,
        memberId: ByteArray
    ): ByteArray {
        val prefix = "group_target:".toByteArray(Charsets.UTF_8)
        val gId = if (groupId.size == 16) groupId else groupId.copyOf(16)
        val mId = if (memberId.size == 16) memberId else memberId.copyOf(16)
        val buffer = ByteBuffer.allocate(prefix.size + 16 + 4 + 16).order(ByteOrder.BIG_ENDIAN)
        buffer.put(prefix)
        buffer.put(gId)
        buffer.putInt(counter)
        buffer.put(mId)
        return buffer.array()
    }

    fun buildGroupTargetInfo(
        groupId: String,
        counter: Int,
        memberId: String
    ): ByteArray = buildGroupTargetInfo(uuidStringToBytes(groupId), counter, uuidStringToBytes(memberId))

    /**
     * Backward-compatible helper retaining 4-tuple signature while using "group_target:" context.
     */
    fun buildGroupRecipientInfo(
        groupId: ByteArray,
        senderMemberId: ByteArray,
        recipientMemberId: ByteArray,
        seqNum: Int
    ): ByteArray {
        return buildGroupTargetInfo(groupId, seqNum, recipientMemberId)
    }

    /**
     * Derives an individual, indexed recipient slot for a group message.
     * Context: "group_target:" || groupId || counter || memberId.
     *
     * The sender's ratchet chain advances via base step (counter), yielding nextChainKey.
     * The recipient-specific target, Ed25519 seed, and msgKey are derived via HKDF-Expand
     * with context "group_target:" || groupId || counter || memberId. This guarantees that:
     * 1. No two members poll the same DHT Target (eliminates Group Follower Correlation).
     * 2. When a member fetches their message, they can safely write a 900B tombstone without
     *    affecting any other member's slot.
     */
    fun deriveGroupRecipientSlot(
        chainKey: ByteArray,
        counter: Int,
        groupId: ByteArray,
        memberId: ByteArray
    ): SlotParameters {
        require(chainKey.size == CHAIN_KEY_SIZE) {
            "Invalid ChainKey size: ${chainKey.size}, expected $CHAIN_KEY_SIZE"
        }

        // Base step to advance the ratchet chain for the sender
        val baseInfo = buildStepInfo(counter)
        val baseEntropy = HkdfSha512.expand(chainKey, baseInfo, TOTAL_ENTROPY_SIZE)
        val nextChainKey = baseEntropy.copyOfRange(64, 128)
        baseEntropy.fill(0)

        // Recipient-specific derivation: context "group_target:" || groupId || counter || memberId
        val recipientInfo = buildGroupTargetInfo(groupId, counter, memberId)
        val recipientEntropy = HkdfSha512.expand(chainKey, recipientInfo, 64)

        val msgKey = recipientEntropy.copyOfRange(0, 32)
        val edSeed = recipientEntropy.copyOfRange(32, 64)
        recipientEntropy.fill(0)

        val edKeyPair = Ed25519Engine.generateKeyPairFromSeed(edSeed)
        val target = Ed25519Engine.computeTarget(edKeyPair.publicKey)

        return SlotParameters(
            counter = counter,
            msgKey = msgKey,
            edPrivateKeySeed = edSeed,
            edPublicKey = edKeyPair.publicKey,
            target = target,
            nextChainKey = nextChainKey
        )
    }

    fun deriveGroupRecipientSlot(
        chainKey: ByteArray,
        counter: Int,
        groupId: ByteArray,
        senderMemberId: ByteArray,
        recipientMemberId: ByteArray
    ): SlotParameters = deriveGroupRecipientSlot(chainKey, counter, groupId, recipientMemberId)

    fun deriveGroupRecipientSlot(
        chainKey: org.pqchat.dht.data.db.EncryptedBlob,
        counter: Int,
        groupId: ByteArray,
        memberId: ByteArray
    ): SlotParameters = deriveGroupRecipientSlot(chainKey.raw, counter, groupId, memberId)

    fun deriveGroupRecipientSlot(
        chainKey: org.pqchat.dht.data.db.EncryptedBlob,
        counter: Int,
        groupId: ByteArray,
        senderMemberId: ByteArray,
        recipientMemberId: ByteArray
    ): SlotParameters = deriveGroupRecipientSlot(chainKey.raw, counter, groupId, recipientMemberId)

    fun uuidStringToBytes(idStr: String): ByteArray {
        return try {
            val u = java.util.UUID.fromString(idStr)
            val bb = java.nio.ByteBuffer.allocate(16).order(java.nio.ByteOrder.BIG_ENDIAN)
            bb.putLong(u.mostSignificantBits)
            bb.putLong(u.leastSignificantBits)
            bb.array()
        } catch (_: Throwable) {
            CryptoUtils.sha256(idStr.toByteArray(Charsets.UTF_8)).copyOf(16)
        }
    }

    fun deriveGroupRecipientSlot(
        chainKey: ByteArray,
        counter: Int,
        groupId: String,
        memberId: String
    ): SlotParameters = deriveGroupRecipientSlot(
        chainKey,
        counter,
        uuidStringToBytes(groupId),
        uuidStringToBytes(memberId)
    )

    fun deriveGroupRecipientSlot(
        chainKey: ByteArray,
        counter: Int,
        groupId: String,
        senderMemberId: String,
        recipientMemberId: String
    ): SlotParameters = deriveGroupRecipientSlot(
        chainKey,
        counter,
        uuidStringToBytes(groupId),
        uuidStringToBytes(recipientMemberId)
    )

    fun deriveGroupRecipientSlot(
        chainKey: org.pqchat.dht.data.db.EncryptedBlob,
        counter: Int,
        groupId: String,
        memberId: String
    ): SlotParameters = deriveGroupRecipientSlot(
        chainKey.raw,
        counter,
        uuidStringToBytes(groupId),
        uuidStringToBytes(memberId)
    )

    fun deriveGroupRecipientSlot(
        chainKey: org.pqchat.dht.data.db.EncryptedBlob,
        counter: Int,
        groupId: String,
        senderMemberId: String,
        recipientMemberId: String
    ): SlotParameters = deriveGroupRecipientSlot(
        chainKey.raw,
        counter,
        uuidStringToBytes(groupId),
        uuidStringToBytes(recipientMemberId)
    )

    fun deriveGroupMemberTargetEntropy(
        chainKey: ByteArray,
        counter: Int,
        groupId: ByteArray,
        memberId: ByteArray
    ): ByteArray {
        val recipientInfo = buildGroupTargetInfo(groupId, counter, memberId)
        return HkdfSha512.expand(chainKey, recipientInfo, 32)
    }

    fun deriveGroupMemberTarget(
        chainKey: ByteArray,
        counter: Int,
        groupId: ByteArray,
        memberId: ByteArray
    ): ByteArray = deriveGroupRecipientSlot(chainKey, counter, groupId, memberId).target

    fun deriveGroupMemberTarget(
        chainKey: ByteArray,
        counter: Int,
        groupId: String,
        memberId: String
    ): ByteArray = deriveGroupRecipientSlot(chainKey, counter, groupId, memberId).target
}
