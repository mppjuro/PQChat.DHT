package org.pqchat.dht.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.dht.bencode.Bencode
import org.pqchat.dht.media.voice.VoiceCodec
import java.security.Security
import javax.crypto.AEADBadTagException
import kotlin.math.log2

class VoiceNoteFrameTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupProviders() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @Test
    fun testVoiceNoteSingleFrameRoundtripAndExactSize() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"

        val clipId = 0x1122334455667788L
        val durationMs = 5250
        val voiceData = CryptoUtils.secureRandomBytes(BinaryFrameCodec.T9_MAX_VOICE_SIZE) // 840 bytes

        // 1. Encode inner payload
        val innerPayload = BinaryFrameCodec.encodeVoiceNote(
            seqNum = 10,
            ackNum = 5,
            timestampUTC = 1771800000000L,
            voiceClipId = clipId,
            segmentIndex = 0,
            totalSegments = 1,
            durationMs = durationMs,
            codecMode = VoiceCodec.CODEC_MODE_LPC10_COMPACT,
            voiceBytes = voiceData,
            ephemeralTtlSeconds = 0L
        )

        assertEquals(
            "Inner ciphertext payload must be exactly CIPHERTEXT_SIZE (872 bytes)",
            BinaryFrameCodec.CIPHERTEXT_SIZE,
            innerPayload.size
        )

        // 2. Pack into AEAD frame (IV 12 B + Tag 16 B + Ciphertext 872 B = 900 B)
        val frame = BinaryFrameCodec.packAeadFrame(key, innerPayload, target, direction)
        assertEquals(
            "Total BEP 44 wire frame must be exactly 900 bytes",
            BinaryFrameCodec.TOTAL_FRAME_SIZE,
            frame.size
        )

        // 3. BEP 44 Compliance check: Bencode encoding size must be exactly 904 bytes (<= 1000 B limit)
        val bencoded = Bencode.encode(frame)
        assertEquals(
            "Bencoded BEP 44 frame must be 904 bytes (4 bytes '900:' prefix + 900 bytes data)",
            904,
            bencoded.size
        )

        // 4. Unpack and verify decoded fields
        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        assertEquals(BinaryFrameCodec.TYPE_VOICE_NOTE, decoded.msgType)
        assertEquals(10, decoded.seqNum)
        assertEquals(5, decoded.ackNum)
        assertEquals(1771800000000L, decoded.timestampUTC)

        assertTrue(decoded.payload is BinaryFrameCodec.DecodedPayload.VoiceNote)
        val voicePayload = decoded.payload as BinaryFrameCodec.DecodedPayload.VoiceNote
        assertEquals(clipId, voicePayload.voiceClipId)
        assertEquals(0, voicePayload.segmentIndex)
        assertEquals(1, voicePayload.totalSegments)
        assertEquals(durationMs, voicePayload.durationMs)
        assertEquals(VoiceCodec.CODEC_MODE_LPC10_COMPACT, voicePayload.codecMode)
        assertEquals(0L, voicePayload.ephemeralTtlSeconds)
        assertArrayEquals(voiceData, voicePayload.voiceBytes)
    }

    @Test
    fun testVoiceNoteMultiFrameSegmentRoundtrip() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "BobToAlice"

        val clipId = 0x6655443322110099L
        val seg0Data = CryptoUtils.secureRandomBytes(840)
        val seg1Data = CryptoUtils.secureRandomBytes(840)
        val seg2Data = CryptoUtils.secureRandomBytes(420) // Final segment with fewer bytes

        val segments = listOf(
            Triple(0, 5250, seg0Data),
            Triple(1, 5250, seg1Data),
            Triple(2, 2625, seg2Data)
        )

        for ((idx, dur, data) in segments) {
            val innerPayload = BinaryFrameCodec.encodeVoiceNote(
                seqNum = 20 + idx,
                ackNum = 15,
                timestampUTC = 1771800100000L + idx * 1000L,
                voiceClipId = clipId,
                segmentIndex = idx,
                totalSegments = 3,
                durationMs = dur,
                codecMode = VoiceCodec.CODEC_MODE_LPC10_COMPACT,
                voiceBytes = data,
                ephemeralTtlSeconds = 600L
            )
            assertEquals(BinaryFrameCodec.CIPHERTEXT_SIZE, innerPayload.size)

            val frame = BinaryFrameCodec.packAeadFrame(key, innerPayload, target, direction)
            assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, frame.size)

            val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
            assertTrue(decoded.payload is BinaryFrameCodec.DecodedPayload.VoiceNote)
            val vn = decoded.payload as BinaryFrameCodec.DecodedPayload.VoiceNote
            assertEquals(clipId, vn.voiceClipId)
            assertEquals(idx, vn.segmentIndex)
            assertEquals(3, vn.totalSegments)
            assertEquals(dur, vn.durationMs)
            assertEquals(600L, vn.ephemeralTtlSeconds)
            assertArrayEquals(data, vn.voiceBytes)
        }
    }

    @Test
    fun testVoiceNoteValidationLimits() {
        val validBytes = ByteArray(100)

        // 1. Voice data size > 840
        assertThrows(IllegalArgumentException::class.java) {
            BinaryFrameCodec.encodeVoiceNote(
                seqNum = 1,
                ackNum = 1,
                timestampUTC = 1000L,
                voiceClipId = 1L,
                segmentIndex = 0,
                totalSegments = 1,
                durationMs = 100,
                codecMode = 1,
                voiceBytes = ByteArray(BinaryFrameCodec.T9_MAX_VOICE_SIZE + 1)
            )
        }

        // 2. segmentIndex >= totalSegments
        assertThrows(IllegalArgumentException::class.java) {
            BinaryFrameCodec.encodeVoiceNote(
                seqNum = 1,
                ackNum = 1,
                timestampUTC = 1000L,
                voiceClipId = 1L,
                segmentIndex = 2,
                totalSegments = 2,
                durationMs = 100,
                codecMode = 1,
                voiceBytes = validBytes
            )
        }

        // 3. totalSegments > 3
        assertThrows(IllegalArgumentException::class.java) {
            BinaryFrameCodec.encodeVoiceNote(
                seqNum = 1,
                ackNum = 1,
                timestampUTC = 1000L,
                voiceClipId = 1L,
                segmentIndex = 0,
                totalSegments = 4,
                durationMs = 100,
                codecMode = 1,
                voiceBytes = validBytes
            )
        }

        // 4. segmentIndex < 0
        assertThrows(IllegalArgumentException::class.java) {
            BinaryFrameCodec.encodeVoiceNote(
                seqNum = 1,
                ackNum = 1,
                timestampUTC = 1000L,
                voiceClipId = 1L,
                segmentIndex = -1,
                totalSegments = 1,
                durationMs = 100,
                codecMode = 1,
                voiceBytes = validBytes
            )
        }
    }

    @Test
    fun testCorruptCiphertextThrowsAeadBadTagException() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"

        val innerPayload = BinaryFrameCodec.encodeVoiceNote(
            seqNum = 1,
            ackNum = 0,
            timestampUTC = 1000L,
            voiceClipId = 42L,
            segmentIndex = 0,
            totalSegments = 1,
            durationMs = 1000,
            codecMode = 1,
            voiceBytes = ByteArray(160)
        )

        val frame = BinaryFrameCodec.packAeadFrame(key, innerPayload, target, direction)

        // Corrupt single byte in tag (index 15)
        frame[15] = (frame[15].toInt() xor 0x01).toByte()

        assertThrows(AEADBadTagException::class.java) {
            BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        }
    }

    @Test
    fun testVoiceNotePaddingHighEntropy() {
        // Short voice payload: 40 bytes out of 840. The remaining 800 bytes must be CSPRNG noise.
        val shortVoice = ByteArray(40) { 0x00 } // Silence/zeroes
        val innerPayload = BinaryFrameCodec.encodeVoiceNote(
            seqNum = 1,
            ackNum = 0,
            timestampUTC = 1000L,
            voiceClipId = 12345L,
            segmentIndex = 0,
            totalSegments = 1,
            durationMs = 250,
            codecMode = 1,
            voiceBytes = shortVoice
        )

        // Skip 13 bytes header + 19 bytes voice note header + 40 bytes data = 72 bytes.
        // Remaining 800 bytes should be high-entropy padding.
        val padding = innerPayload.copyOfRange(72, innerPayload.size)
        assertEquals(800, padding.size)

        val counts = IntArray(256)
        for (b in padding) {
            counts[b.toInt() and 0xFF]++
        }

        var entropy = 0.0
        val total = padding.size.toDouble()
        for (c in counts) {
            if (c > 0) {
                val p = c / total
                entropy -= p * (log2(p))
            }
        }

        // CSPRNG noise over 800 bytes should have Shannon entropy > 7.5 bits/byte (max 8.0)
        assertTrue("Padding entropy must be >= 7.5 bits/byte, got $entropy", entropy >= 7.5)
    }
}
