package org.pqchat.dht.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.dht.bencode.Bencode
import java.security.Security
import java.util.UUID
import javax.crypto.AEADBadTagException

class BinaryFrameCodecPollAndCanaryTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupProviders() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @Test
    fun testGroupPollCreateEncodeDecodeAndExact900BytesWireSize() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val groupId = CryptoUtils.secureRandomBytes(16)
        val senderMemberId = CryptoUtils.secureRandomBytes(16)

        val pollId = CryptoUtils.secureRandomBytes(16)
        val expTs = System.currentTimeMillis() + 86400_000L
        val question = "Which post-quantum algorithm is your favorite for key exchange?"
        val options = listOf("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "Classic McEliece")

        // 1. Encode inner payload
        val innerPayload = BinaryFrameCodec.encodeGroupPollCreate(
            seqNum = 42,
            ackNum = 0,
            timestampUTC = 1771900000000L,
            pollId = pollId,
            expirationTimestamp = expTs,
            flags = BinaryFrameCodec.POLL_FLAG_MULTI_CHOICE,
            question = question,
            options = options
        )

        assertEquals(
            "Inner payload must be exactly CIPHERTEXT_SIZE (872 bytes)",
            BinaryFrameCodec.CIPHERTEXT_SIZE,
            innerPayload.size
        )

        // 2. Pack with Group AAD (Target || GroupID || SenderMemberID)
        val frame = BinaryFrameCodec.packGroupAeadFrame(
            key = key,
            plaintext = innerPayload,
            target = target,
            groupId = groupId,
            senderMemberId = senderMemberId
        )

        assertEquals(
            "Total wire frame must be exactly 900 bytes",
            BinaryFrameCodec.TOTAL_FRAME_SIZE,
            frame.size
        )

        // 3. BEP 44 compliance check
        val bencoded = Bencode.encode(frame)
        assertEquals(
            "Bencoded frame must be exactly 904 bytes (4 bytes '900:' prefix + 900 bytes payload)",
            904,
            bencoded.size
        )

        // 4. Unpack with Group AAD
        val decoded = BinaryFrameCodec.unpackGroupAeadFrame(
            key = key,
            frame = frame,
            target = target,
            groupId = groupId,
            senderMemberId = senderMemberId
        )

        assertEquals(BinaryFrameCodec.TYPE_GROUP_POLL, decoded.msgType)
        assertEquals(42, decoded.seqNum)
        assertEquals(0, decoded.ackNum)
        assertEquals(1771900000000L, decoded.timestampUTC)

        assertTrue(decoded.payload is BinaryFrameCodec.DecodedPayload.GroupPollCreate)
        val poll = decoded.payload as BinaryFrameCodec.DecodedPayload.GroupPollCreate
        assertEquals(BinaryFrameCodec.POLL_SUBTYPE_CREATE, poll.pollSubType)
        assertArrayEquals(pollId, poll.pollId)
        assertEquals(expTs, poll.expirationTimestamp)
        assertEquals(BinaryFrameCodec.POLL_FLAG_MULTI_CHOICE, poll.flags)
        assertTrue(poll.isMultiChoice)
        assertEquals(question, poll.question)
        assertEquals(options.size, poll.options.size)
        assertEquals(options, poll.options)
    }

    @Test
    fun testGroupPollVoteEncodeDecodeAndAeadBinding() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val groupId = CryptoUtils.secureRandomBytes(16)
        val senderMemberId = CryptoUtils.secureRandomBytes(16)
        val forgedSenderId = CryptoUtils.secureRandomBytes(16)

        val pollId = CryptoUtils.secureRandomBytes(16)
        val voteTs = System.currentTimeMillis()
        val bitmask = 0x05 // options 0 and 2

        // 1. Encode inner vote payload
        val innerPayload = BinaryFrameCodec.encodeGroupPollVote(
            seqNum = 43,
            ackNum = 12,
            timestampUTC = voteTs,
            pollId = pollId,
            selectedOptionsBitmask = bitmask,
            voteTimestamp = voteTs
        )

        assertEquals(BinaryFrameCodec.CIPHERTEXT_SIZE, innerPayload.size)

        // 2. Pack with legitimate Group AAD
        val frame = BinaryFrameCodec.packGroupAeadFrame(
            key = key,
            plaintext = innerPayload,
            target = target,
            groupId = groupId,
            senderMemberId = senderMemberId
        )
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, frame.size)

        // 3. Successful decode with matching AAD
        val decoded = BinaryFrameCodec.unpackGroupAeadFrame(
            key = key,
            frame = frame,
            target = target,
            groupId = groupId,
            senderMemberId = senderMemberId
        )
        assertEquals(BinaryFrameCodec.TYPE_GROUP_POLL, decoded.msgType)
        assertTrue(decoded.payload is BinaryFrameCodec.DecodedPayload.GroupPollVote)
        val vote = decoded.payload as BinaryFrameCodec.DecodedPayload.GroupPollVote
        assertEquals(BinaryFrameCodec.POLL_SUBTYPE_VOTE, vote.pollSubType)
        assertArrayEquals(pollId, vote.pollId)
        assertEquals(bitmask, vote.selectedOptionsBitmask and 0xFF)
        assertEquals(voteTs, vote.voteTimestamp)

        // 4. Verification that forged SenderMemberID is rejected by Group AAD
        try {
            BinaryFrameCodec.unpackGroupAeadFrame(
                key = key,
                frame = frame,
                target = target,
                groupId = groupId,
                senderMemberId = forgedSenderId // Spoofed sender
            )
            fail("Expected AEADBadTagException when Group AAD senderMemberId is tampered with")
        } catch (_: AEADBadTagException) {
            // Success: AEAD tag authentication prevented identity spoofing
        }
    }

    @Test
    fun testSafetyCanaryRoundtripAllReasonsAndExactSize() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "A_TO_B"

        val reasons = listOf(
            BinaryFrameCodec.CANARY_REASON_DEAD_MAN_TIMEOUT,
            BinaryFrameCodec.CANARY_REASON_DURESS_PIN,
            BinaryFrameCodec.CANARY_REASON_MANUAL_SOS
        )

        for (reason in reasons) {
            val canaryId = CryptoUtils.secureRandomBytes(16)
            val triggerTs = 1771950000000L
            val lat = 52.2297
            val lon = 21.0122
            val note = "Emergency canary alarm for reason code: $reason"

            val plaintext = BinaryFrameCodec.encodeSafetyCanary(
                seqNum = 100,
                ackNum = 50,
                timestampUTC = triggerTs,
                triggerReason = reason,
                canaryId = canaryId,
                triggerTimestamp = triggerTs,
                latitude = lat,
                longitude = lon,
                note = note
            )

            assertEquals(
                "Plaintext size before AEAD must be 872 bytes",
                BinaryFrameCodec.CIPHERTEXT_SIZE,
                plaintext.size
            )

            val frame = BinaryFrameCodec.packAeadFrame(key, plaintext, target, direction)
            assertEquals(
                "Wire size must be 900 bytes",
                BinaryFrameCodec.TOTAL_FRAME_SIZE,
                frame.size
            )

            val bencoded = Bencode.encode(frame)
            assertEquals("Bencoded size must be 904 bytes", 904, bencoded.size)

            val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
            assertEquals(BinaryFrameCodec.TYPE_SAFETY_CANARY, decoded.msgType)
            assertEquals(100, decoded.seqNum)
            assertEquals(50, decoded.ackNum)

            assertTrue(decoded.payload is BinaryFrameCodec.DecodedPayload.SafetyCanary)
            val canary = decoded.payload as BinaryFrameCodec.DecodedPayload.SafetyCanary
            assertEquals(reason, canary.triggerReason)
            assertArrayEquals(canaryId, canary.canaryId)
            assertEquals(triggerTs, canary.triggerTimestamp)
            assertEquals(lat, canary.latitude, 0.00001)
            assertEquals(lon, canary.longitude, 0.00001)
            assertEquals(note, canary.note)
        }
    }

    @Test
    fun testGroupPollCreateMaxOptionsAndQuestionLimits() {
        val pollId = CryptoUtils.secureRandomBytes(16)
        val expTs = System.currentTimeMillis() + 3600_000L

        // Exactly 8 options (max allowed)
        val options = (1..8).map { "Option $it with some descriptive text" }
        val longQuestion = "A".repeat(200) // max question size

        val payload = BinaryFrameCodec.encodeGroupPollCreate(
            seqNum = 1,
            ackNum = 0,
            timestampUTC = System.currentTimeMillis(),
            pollId = pollId,
            expirationTimestamp = expTs,
            flags = 0,
            question = longQuestion,
            options = options
        )
        assertEquals(BinaryFrameCodec.CIPHERTEXT_SIZE, payload.size)

        // Attempting > 8 options must throw IllegalArgumentException
        val tooManyOptions = (1..9).map { "Option $it" }
        try {
            BinaryFrameCodec.encodeGroupPollCreate(
                seqNum = 1,
                ackNum = 0,
                timestampUTC = System.currentTimeMillis(),
                pollId = pollId,
                expirationTimestamp = expTs,
                flags = 0,
                question = "Too many options?",
                options = tooManyOptions
            )
            fail("Expected IllegalArgumentException for option count > 8")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }
}
