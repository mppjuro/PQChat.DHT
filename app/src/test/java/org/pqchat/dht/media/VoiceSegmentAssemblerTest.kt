package org.pqchat.dht.media

import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.media.voice.VoiceCodec
import org.pqchat.dht.media.voice.VoiceSegmentAssembler

class VoiceSegmentAssemblerTest {

    @Test
    fun testSingleFrameFastPathReturnsImmediately() {
        val assembler = VoiceSegmentAssembler()
        val clipId = 123456789L
        val data = ByteArray(400) { (it and 0xFF).toByte() }

        val frame = BinaryFrameCodec.DecodedPayload.VoiceNote(
            voiceClipId = clipId,
            segmentIndex = 0,
            totalSegments = 1,
            durationMs = 2500,
            codecMode = VoiceCodec.CODEC_MODE_LPC10_COMPACT,
            voiceData = data,
            ephemeralTtlSeconds = 120L
        )

        val assembled = assembler.ingest(frame)
        assertNotNull("Single frame must assemble immediately", assembled)
        assertEquals(clipId, assembled!!.voiceClipId)
        assertEquals(1, assembled.totalSegments)
        assertEquals(2500, assembled.totalDurationMs)
        assertEquals(VoiceCodec.CODEC_MODE_LPC10_COMPACT, assembled.codecMode)
        assertEquals(120L, assembled.ephemeralTtlSeconds)
        assertArrayEquals(data, assembled.voiceBytes)
    }

    @Test
    fun testTwoSegmentsInOrderAssembly() {
        val assembler = VoiceSegmentAssembler()
        val clipId = 987654321L
        val seg0 = ByteArray(840) { 0x11 }
        val seg1 = ByteArray(420) { 0x22 }

        val frame0 = BinaryFrameCodec.DecodedPayload.VoiceNote(
            voiceClipId = clipId,
            segmentIndex = 0,
            totalSegments = 2,
            durationMs = 5250,
            codecMode = VoiceCodec.CODEC_MODE_LPC10_COMPACT,
            voiceData = seg0,
            ephemeralTtlSeconds = 300L
        )

        val frame1 = BinaryFrameCodec.DecodedPayload.VoiceNote(
            voiceClipId = clipId,
            segmentIndex = 1,
            totalSegments = 2,
            durationMs = 2625,
            codecMode = VoiceCodec.CODEC_MODE_LPC10_COMPACT,
            voiceData = seg1,
            ephemeralTtlSeconds = 300L
        )

        val result0 = assembler.ingest(frame0)
        assertNull("First segment of two must return null", result0)

        val result1 = assembler.ingest(frame1)
        assertNotNull("Second segment must complete assembly", result1)

        assertEquals(clipId, result1!!.voiceClipId)
        assertEquals(2, result1.totalSegments)
        assertEquals(7875, result1.totalDurationMs)
        assertEquals(VoiceCodec.CODEC_MODE_LPC10_COMPACT, result1.codecMode)
        assertEquals(300L, result1.ephemeralTtlSeconds)
        assertEquals(1260, result1.voiceBytes.size)

        // Verify ordering: first 840 bytes must be 0x11, next 420 must be 0x22
        val expected = ByteArray(1260)
        System.arraycopy(seg0, 0, expected, 0, 840)
        System.arraycopy(seg1, 0, expected, 840, 420)
        assertArrayEquals(expected, result1.voiceBytes)
    }

    @Test
    fun testThreeSegmentsOutOfOrderAssembly() {
        val assembler = VoiceSegmentAssembler()
        val clipId = 4455667788L
        val seg0 = ByteArray(840) { 0x00 }
        val seg1 = ByteArray(840) { 0x01 }
        val seg2 = ByteArray(840) { 0x02 }

        val f0 = BinaryFrameCodec.DecodedPayload.VoiceNote(clipId, 0, 3, 5250, VoiceCodec.CODEC_MODE_LPC10_COMPACT, seg0, 0L)
        val f1 = BinaryFrameCodec.DecodedPayload.VoiceNote(clipId, 1, 3, 5250, VoiceCodec.CODEC_MODE_LPC10_COMPACT, seg1, 0L)
        val f2 = BinaryFrameCodec.DecodedPayload.VoiceNote(clipId, 2, 3, 5250, VoiceCodec.CODEC_MODE_LPC10_COMPACT, seg2, 0L)

        // Arrival order: segment 2, then segment 0, then segment 1
        assertNull(assembler.ingest(f2))
        assertNull(assembler.ingest(f0))
        val assembled = assembler.ingest(f1)

        assertNotNull("Assembly must succeed upon arrival of final segment", assembled)
        assertEquals(3, assembled!!.totalSegments)
        assertEquals(15750, assembled.totalDurationMs)
        assertEquals(2520, assembled.voiceBytes.size)

        // Verify segments are concatenated strictly in ascending order: 0, 1, 2
        for (i in 0 until 840) assertEquals(0x00.toByte(), assembled.voiceBytes[i])
        for (i in 840 until 1680) assertEquals(0x01.toByte(), assembled.voiceBytes[i])
        for (i in 1680 until 2520) assertEquals(0x02.toByte(), assembled.voiceBytes[i])
    }

    @Test
    fun testInvalidSegmentIndicesIgnored() {
        val assembler = VoiceSegmentAssembler()
        val clipId = 111L

        val invalidNegative = BinaryFrameCodec.DecodedPayload.VoiceNote(
            clipId, -1, 2, 1000, 1, ByteArray(100), 0L
        )
        assertNull(assembler.ingest(invalidNegative))

        val invalidOutOfBounds = BinaryFrameCodec.DecodedPayload.VoiceNote(
            clipId, 2, 2, 1000, 1, ByteArray(100), 0L
        )
        assertNull(assembler.ingest(invalidOutOfBounds))
    }

    @Test
    fun testIndependentClipIsolation() {
        val assembler = VoiceSegmentAssembler()
        val clipA = 1001L
        val clipB = 2002L

        val fa0 = BinaryFrameCodec.DecodedPayload.VoiceNote(clipA, 0, 2, 5000, 1, ByteArray(500) { 0xAA.toByte() }, 0L)
        val fb0 = BinaryFrameCodec.DecodedPayload.VoiceNote(clipB, 0, 2, 3000, 1, ByteArray(300) { 0xBB.toByte() }, 0L)
        val fb1 = BinaryFrameCodec.DecodedPayload.VoiceNote(clipB, 1, 2, 3000, 1, ByteArray(300) { 0xBC.toByte() }, 0L)
        val fa1 = BinaryFrameCodec.DecodedPayload.VoiceNote(clipA, 1, 2, 5000, 1, ByteArray(500) { 0xAB.toByte() }, 0L)

        assertNull(assembler.ingest(fa0))
        assertNull(assembler.ingest(fb0))

        val resB = assembler.ingest(fb1)
        assertNotNull(resB)
        assertEquals(clipB, resB!!.voiceClipId)
        assertEquals(6000, resB.totalDurationMs)

        val resA = assembler.ingest(fa1)
        assertNotNull(resA)
        assertEquals(clipA, resA!!.voiceClipId)
        assertEquals(10000, resA.totalDurationMs)
    }

    @Test
    fun testExpirationCleanupRemovesStaleClips() {
        val shortTtlAssembler = VoiceSegmentAssembler(clipExpirationMs = 10L)
        val clipId = 555L

        val f0 = BinaryFrameCodec.DecodedPayload.VoiceNote(clipId, 0, 2, 5000, 1, ByteArray(500), 0L)
        assertNull(shortTtlAssembler.ingest(f0))

        // Wait past 10ms expiration
        Thread.sleep(25L)

        // Ingest another clip to trigger cleanExpiredClips
        val anotherClip = 999L
        val fOther = BinaryFrameCodec.DecodedPayload.VoiceNote(anotherClip, 0, 1, 1000, 1, ByteArray(100), 0L)
        assertNotNull(shortTtlAssembler.ingest(fOther))

        // Now if segment 1 of the expired clip arrives, it starts fresh with 1 segment, but total is 2, so it won't assemble
        val f1 = BinaryFrameCodec.DecodedPayload.VoiceNote(clipId, 1, 2, 5000, 1, ByteArray(500), 0L)
        val res = shortTtlAssembler.ingest(f1)
        assertNull("Expired clip buffer was cleared, single segment 1 cannot assemble without segment 0", res)
    }
}
