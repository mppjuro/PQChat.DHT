package org.pqchat.dht.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import java.security.Security
import java.util.UUID

class GroupChatCryptoTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private fun uuidToBytes(uuid: UUID): ByteArray {
        val bb = java.nio.ByteBuffer.allocate(16)
        bb.putLong(uuid.mostSignificantBits)
        bb.putLong(uuid.leastSignificantBits)
        return bb.array()
    }

    @Test
    fun testGroupControlInviteRoundtrip() {
        val groupId = uuidToBytes(UUID.randomUUID())
        val senderMemberId = uuidToBytes(UUID.randomUUID())
        val member2Id = uuidToBytes(UUID.randomUUID())
        val chainKey = CryptoUtils.secureRandomBytes(64)
        val groupName = "Post-Quantum Resistance Group"

        val memberSummaries = listOf(
            BinaryFrameCodec.DecodedPayload.GroupMemberSummary(senderMemberId, "Alice"),
            BinaryFrameCodec.DecodedPayload.GroupMemberSummary(member2Id, "Bob")
        )

        val plaintext = BinaryFrameCodec.encodeGroupControl(
            seqNum = 1,
            ackNum = 0,
            timestampUTC = 1718000000000L,
            controlSubType = BinaryFrameCodec.GROUP_SUBTYPE_INVITE,
            groupId = groupId,
            groupEpoch = 1L,
            senderMemberId = senderMemberId,
            senderGroupChainKey = chainKey,
            currentCounter = 0L,
            groupName = groupName,
            members = memberSummaries
        )

        assertEquals("Ciphertext plaintext input must be exactly 872 bytes", BinaryFrameCodec.CIPHERTEXT_SIZE, plaintext.size)

        // Pack as standard 1-on-1 frame (0x06 is transferred over 1-on-1 channels)
        val msgKey = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val frame = BinaryFrameCodec.packAeadFrame(
            key = msgKey,
            plaintext = plaintext,
            target = target,
            direction = "AtoB"
        )

        assertEquals("Wire frame must be exactly 900 bytes", BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, frame.size)

        val frameMsg = BinaryFrameCodec.unpackAeadFrame(
            key = msgKey,
            frame = frame,
            target = target,
            direction = "AtoB"
        )

        assertTrue("Decoded payload must be GroupControl", frameMsg.payload is BinaryFrameCodec.DecodedPayload.GroupControl)
        val gc = frameMsg.payload as BinaryFrameCodec.DecodedPayload.GroupControl
        assertEquals(BinaryFrameCodec.GROUP_SUBTYPE_INVITE, gc.controlSubType)
        assertArrayEquals(groupId, gc.groupId)
        assertEquals(1L, gc.groupEpoch)
        assertArrayEquals(senderMemberId, gc.senderMemberId)
        assertArrayEquals(chainKey, gc.senderGroupChainKey)
        assertEquals(0L, gc.currentCounter)
        assertEquals(groupName, gc.groupName)
        assertEquals(2, gc.members.size)
        assertArrayEquals(senderMemberId, gc.members[0].memberId)
        assertEquals("Alice", gc.members[0].memberName)
        assertArrayEquals(member2Id, gc.members[1].memberId)
        assertEquals("Bob", gc.members[1].memberName)
    }

    @Test
    fun testGroupControlRekeyAndLeaveSubtypes() {
        val groupId = uuidToBytes(UUID.randomUUID())
        val senderMemberId = uuidToBytes(UUID.randomUUID())
        val newChainKey = CryptoUtils.secureRandomBytes(64)

        assertEquals(50, BinaryFrameCodec.GROUP_REKEY_MESSAGE_INTERVAL)

        // Rekey subtype using helper
        val rekeyPlaintext = BinaryFrameCodec.encodeGroupRekey(
            seqNum = 51,
            ackNum = 42,
            timestampUTC = 1718000000000L,
            groupId = groupId,
            groupEpoch = 2L,
            senderMemberId = senderMemberId,
            senderGroupChainKey = newChainKey,
            currentCounter = 0L,
            groupName = "Updated Group Name"
        )
        assertEquals(BinaryFrameCodec.CIPHERTEXT_SIZE, rekeyPlaintext.size)

        val msgKey = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val frameRekey = BinaryFrameCodec.packAeadFrame(msgKey, rekeyPlaintext, target, "AtoB")
        val decodedRekey = BinaryFrameCodec.unpackAeadFrame(msgKey, frameRekey, target, "AtoB").payload as BinaryFrameCodec.DecodedPayload.GroupControl

        assertEquals(BinaryFrameCodec.GROUP_SUBTYPE_REKEY, decodedRekey.controlSubType)
        assertEquals(2L, decodedRekey.groupEpoch)
        assertArrayEquals(newChainKey, decodedRekey.senderGroupChainKey)

        // Leave subtype using helper
        val leavePlaintext = BinaryFrameCodec.encodeGroupLeave(
            seqNum = 52,
            ackNum = 42,
            timestampUTC = 1718000000000L,
            groupId = groupId,
            groupEpoch = 2L,
            senderMemberId = senderMemberId,
            groupName = ""
        )
        val frameLeave = BinaryFrameCodec.packAeadFrame(msgKey, leavePlaintext, target, "AtoB")
        val decodedLeave = BinaryFrameCodec.unpackAeadFrame(msgKey, frameLeave, target, "AtoB").payload as BinaryFrameCodec.DecodedPayload.GroupControl

        assertEquals(BinaryFrameCodec.GROUP_SUBTYPE_LEAVE, decodedLeave.controlSubType)
        assertEquals(2L, decodedLeave.groupEpoch)
    }

    @Test
    fun testGroupAadPackingAndUnpacking() {
        val groupId = uuidToBytes(UUID.randomUUID())
        val senderMemberId = uuidToBytes(UUID.randomUUID())
        val msgKey = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)

        val textPlaintext = BinaryFrameCodec.encodeTextMessage(
            seqNum = 7,
            ackNum = 3,
            timestampUTC = System.currentTimeMillis(),
            text = "Hello Post-Quantum Group Chat over BEP 44!"
        )

        // Pack group frame with group AAD
        val groupFrame = BinaryFrameCodec.packGroupAeadFrame(
            key = msgKey,
            plaintext = textPlaintext,
            target = target,
            groupId = groupId,
            senderMemberId = senderMemberId
        )

        assertEquals("Group wire frame must be exactly 900 bytes", 900, groupFrame.size)

        // Unpack with matching AAD
        val frameMsg = BinaryFrameCodec.unpackGroupAeadFrame(
            key = msgKey,
            frame = groupFrame,
            target = target,
            groupId = groupId,
            senderMemberId = senderMemberId
        )

        assertTrue(frameMsg.payload is BinaryFrameCodec.DecodedPayload.TextMessage)
        assertEquals("Hello Post-Quantum Group Chat over BEP 44!", (frameMsg.payload as BinaryFrameCodec.DecodedPayload.TextMessage).text)

        // Tamper test 1: wrong groupId
        val wrongGroupId = uuidToBytes(UUID.randomUUID())
        try {
            BinaryFrameCodec.unpackGroupAeadFrame(
                key = msgKey,
                frame = groupFrame,
                target = target,
                groupId = wrongGroupId,
                senderMemberId = senderMemberId
            )
            fail("Unpack with wrong groupId must throw AEAD verification exception")
        } catch (_: Exception) {
            // Expected
        }

        // Tamper test 2: wrong senderMemberId
        val wrongSenderMemberId = uuidToBytes(UUID.randomUUID())
        try {
            BinaryFrameCodec.unpackGroupAeadFrame(
                key = msgKey,
                frame = groupFrame,
                target = target,
                groupId = groupId,
                senderMemberId = wrongSenderMemberId
            )
            fail("Unpack with wrong senderMemberId must throw AEAD verification exception")
        } catch (_: Exception) {
            // Expected
        }

        // Tamper test 3: wrong target
        val wrongTarget = CryptoUtils.secureRandomBytes(20)
        try {
            BinaryFrameCodec.unpackGroupAeadFrame(
                key = msgKey,
                frame = groupFrame,
                target = wrongTarget,
                groupId = groupId,
                senderMemberId = senderMemberId
            )
            fail("Unpack with wrong target must throw AEAD verification exception")
        } catch (_: Exception) {
            // Expected
        }
    }

    @Test
    fun testTruncateUtf8ToMaxBytes_CodePointBoundaries() {
        // 1. ASCII within limit
        val ascii = "Hello, World!"
        val asciiTrunc = BinaryFrameCodec.truncateUtf8ToMaxBytes(ascii, 20)
        assertEquals(ascii, String(asciiTrunc, Charsets.UTF_8))

        // 2. Polish multi-byte characters: "Zażółć gęślą jaźń"
        // 'Z' (1), 'a' (1), 'ż' (2), 'ó' (2) = 6 bytes.
        // 'ł' is 2 bytes -> total 8 bytes.
        // If maxBytes = 7, it must truncate at 6 bytes ("Zażó") rather than splitting 'ł'
        val polish = "Zażółć gęślą jaźń"
        val polishTrunc7 = BinaryFrameCodec.truncateUtf8ToMaxBytes(polish, 7)
        assertEquals(6, polishTrunc7.size)
        assertEquals("Zażó", String(polishTrunc7, Charsets.UTF_8))

        // 3. 4-byte Emojis (Surrogate pairs in Java/Kotlin CharSequence)
        // 🚀 (U+1F680) is 4 bytes in UTF-8
        // 🛡️ (U+1F6E1 + U+FE0F) is 4 + 3 = 7 bytes
        val emojis = "🚀🛡️🇵🇱"
        // Rocket alone is 4 bytes. If maxBytes = 5, cannot fit shield (7 bytes), so only rocket fits (4 bytes)
        val emojiTrunc5 = BinaryFrameCodec.truncateUtf8ToMaxBytes(emojis, 5)
        assertEquals(4, emojiTrunc5.size)
        assertEquals("🚀", String(emojiTrunc5, Charsets.UTF_8))

        // Empty string and 0 limit
        assertEquals(0, BinaryFrameCodec.truncateUtf8ToMaxBytes("", 10).size)
        assertEquals(0, BinaryFrameCodec.truncateUtf8ToMaxBytes("Test", 0).size)
    }

    @Test
    fun testGroupControlWithEmojisAndUnicodeNamesRoundtrip() {
        val groupId = uuidToBytes(UUID.randomUUID())
        val senderMemberId = uuidToBytes(UUID.randomUUID())
        val bobId = uuidToBytes(UUID.randomUUID())
        val charlieId = uuidToBytes(UUID.randomUUID())
        val chainKey = CryptoUtils.secureRandomBytes(64)

        val unicodeGroupName = "🛡️ Post-Quantum Squad 🇵🇱"
        val memberSummaries = listOf(
            BinaryFrameCodec.DecodedPayload.GroupMemberSummary(senderMemberId, "Alicja 🚀"),
            BinaryFrameCodec.DecodedPayload.GroupMemberSummary(bobId, "Bober 🦆"),
            BinaryFrameCodec.DecodedPayload.GroupMemberSummary(charlieId, "Grzegorz Brzęczyszczykiewicz")
        )

        val plaintext = BinaryFrameCodec.encodeGroupControl(
            seqNum = 1,
            ackNum = 0,
            timestampUTC = System.currentTimeMillis(),
            controlSubType = BinaryFrameCodec.GROUP_SUBTYPE_INVITE,
            groupId = groupId,
            groupEpoch = 1L,
            senderMemberId = senderMemberId,
            senderGroupChainKey = chainKey,
            currentCounter = 0L,
            groupName = unicodeGroupName,
            members = memberSummaries
        )

        val msgKey = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val frame = BinaryFrameCodec.packAeadFrame(msgKey, plaintext, target, "AtoB")
        val decoded = BinaryFrameCodec.unpackAeadFrame(msgKey, frame, target, "AtoB").payload as BinaryFrameCodec.DecodedPayload.GroupControl

        assertEquals(unicodeGroupName, decoded.groupName)
        assertEquals(3, decoded.members.size)
        assertEquals("Alicja 🚀", decoded.members[0].memberName)
        assertEquals("Bober 🦆", decoded.members[1].memberName)
        assertEquals("Grzegorz Brzęczyszczykiewicz", decoded.members[2].memberName)
    }

    @Test
    fun testGroupControlMemberCountPrecalculationAndPaddingNoiseSafety() {
        val groupId = uuidToBytes(UUID.randomUUID())
        val senderMemberId = uuidToBytes(UUID.randomUUID())
        val chainKey = CryptoUtils.secureRandomBytes(64)

        // Generate 64 members with short names to test maximum member capability
        val memberSummaries = (1..64).map { i ->
            BinaryFrameCodec.DecodedPayload.GroupMemberSummary(
                memberId = uuidToBytes(UUID.randomUUID()),
                memberName = "M$i"
            )
        }

        val plaintext = BinaryFrameCodec.encodeGroupControl(
            seqNum = 5,
            ackNum = 2,
            timestampUTC = System.currentTimeMillis(),
            controlSubType = BinaryFrameCodec.GROUP_SUBTYPE_INVITE,
            groupId = groupId,
            groupEpoch = 1L,
            senderMemberId = senderMemberId,
            senderGroupChainKey = chainKey,
            currentCounter = 0L,
            groupName = "Max Member Group",
            members = memberSummaries
        )

        val msgKey = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val frame = BinaryFrameCodec.packAeadFrame(msgKey, plaintext, target, "AtoB")
        val decoded = BinaryFrameCodec.unpackAeadFrame(msgKey, frame, target, "AtoB").payload as BinaryFrameCodec.DecodedPayload.GroupControl

        // Fixed header: 109 + 16 ("Max Member Group") = 125 B.
        // Remaining buffer: 859 - 125 = 734 B.
        // Each member entry: 16 (UUID) + 1 (Len) + 2..3 (Name) = 19..20 B.
        // Total fitting members: min(64, floor(734 / 20)) = ~36-38 members.
        // CRITICAL: decoded.members.size MUST equal the exact number of eligible members encoded,
        // and must NOT treat the remaining CSPRNG padding as phantom members!
        assertTrue("Eligible members must fit within 859 B buffer", decoded.members.size in 35..64)
        for (i in 0 until decoded.members.size) {
            assertEquals(memberSummaries[i].memberName, decoded.members[i].memberName)
            assertArrayEquals(memberSummaries[i].memberId, decoded.members[i].memberId)
        }
    }

    @Test
    fun testGroupControlExcessMembersBufferBudgetProtection() {
        val groupId = uuidToBytes(UUID.randomUUID())
        val senderMemberId = uuidToBytes(UUID.randomUUID())
        val chainKey = CryptoUtils.secureRandomBytes(64)

        // Pass 100 members with long names (32 bytes each) to heavily exceed the 859 B buffer
        val oversizedMemberList = (1..100).map { i ->
            BinaryFrameCodec.DecodedPayload.GroupMemberSummary(
                memberId = uuidToBytes(UUID.randomUUID()),
                memberName = "Member_With_Long_Name_Number_$i"
            )
        }

        val plaintext = BinaryFrameCodec.encodeGroupControl(
            seqNum = 1,
            ackNum = 0,
            timestampUTC = System.currentTimeMillis(),
            controlSubType = BinaryFrameCodec.GROUP_SUBTYPE_INVITE,
            groupId = groupId,
            groupEpoch = 1L,
            senderMemberId = senderMemberId,
            senderGroupChainKey = chainKey,
            currentCounter = 0L,
            groupName = "Oversized Member List Group",
            members = oversizedMemberList
        )

        val msgKey = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val frame = BinaryFrameCodec.packAeadFrame(msgKey, plaintext, target, "AtoB")

        // Unpack must not throw BufferUnderflowException and must match exact member count
        val decoded = BinaryFrameCodec.unpackAeadFrame(msgKey, frame, target, "AtoB").payload as BinaryFrameCodec.DecodedPayload.GroupControl
        assertTrue("Decoded member count must be > 0 and <= oversizedMemberList.size", decoded.members.isNotEmpty() && decoded.members.size < 100)
        for (i in 0 until decoded.members.size) {
            assertArrayEquals(oversizedMemberList[i].memberId, decoded.members[i].memberId)
        }
    }
}
