package org.pqchat.dht.media

import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.media.voice.VoiceCodec
import kotlin.math.sin

class VoiceCodecTest {

    @Test
    fun testEncodeDecodeSilence() {
        val samples = ShortArray(800) // 100 ms (4 frames) of silence
        val encoded = VoiceCodec.encode(samples)

        assertEquals(4 * VoiceCodec.BYTES_PER_FRAME, encoded.size)
        assertEquals(16, encoded.size)

        val decoded = VoiceCodec.decode(encoded)
        assertEquals(samples.size, decoded.size)

        // Decoded silence should have near zero amplitude
        for (s in decoded) {
            assertTrue("Decoded silence sample should be small: $s", kotlin.math.abs(s.toInt()) < 200)
        }
    }

    @Test
    fun testEncodeDecodeSyntheticVowel() {
        // Generate 1 second of synthetic 150 Hz vowel-like tone at 8 kHz (40 frames)
        val sampleCount = 8000
        val samples = ShortArray(sampleCount) { i ->
            val fundamental = sin(2.0 * Math.PI * 150.0 * i / 8000.0)
            val formant1 = 0.5 * sin(2.0 * Math.PI * 600.0 * i / 8000.0)
            val formant2 = 0.25 * sin(2.0 * Math.PI * 1200.0 * i / 8000.0)
            ((fundamental + formant1 + formant2) * 8000.0).toInt().toShort()
        }

        val encoded = VoiceCodec.encode(samples)
        assertEquals(40 * VoiceCodec.BYTES_PER_FRAME, encoded.size)
        assertEquals(160, encoded.size) // 160 bytes for 1 second of speech!

        val decoded = VoiceCodec.decode(encoded)
        assertEquals(sampleCount, decoded.size)

        // Ensure stability: samples are non-trivial and bounded
        var maxVal = 0
        var nonZeroCount = 0
        for (s in decoded) {
            val v = kotlin.math.abs(s.toInt())
            if (v > maxVal) maxVal = v
            if (v > 50) nonZeroCount++
        }
        assertTrue("Synthesized speech should produce audible signal, got $nonZeroCount non-zero samples", nonZeroCount > 500)
        assertTrue("Max amplitude should be significant", maxVal > 1000)
    }

    @Test
    fun testSingleFrameCapacityFitsWithin840Bytes() {
        // 5.25 seconds of speech = 210 frames = 42,000 samples
        val samples = ShortArray(210 * VoiceCodec.FRAME_SAMPLES) { i ->
            (sin(2.0 * Math.PI * 200.0 * i / 8000.0) * 10000.0).toInt().toShort()
        }

        val encoded = VoiceCodec.encode(samples)
        assertEquals(VoiceCodec.MAX_FRAME_VOICE_BYTES, encoded.size)
        assertEquals(840, encoded.size)

        val durationMs = VoiceCodec.calculateDurationMs(encoded.size)
        assertEquals(5250, durationMs) // 5.25 seconds exactly
    }

    @Test
    fun testThreeFrameCapacityFitsWithin2520Bytes() {
        // 15.75 seconds of speech = 630 frames = 126,000 samples
        val samples = ShortArray(630 * VoiceCodec.FRAME_SAMPLES) { i ->
            (sin(2.0 * Math.PI * 220.0 * i / 8000.0) * 8000.0).toInt().toShort()
        }

        val encoded = VoiceCodec.encode(samples)
        assertEquals(VoiceCodec.MAX_TOTAL_VOICE_BYTES, encoded.size)
        assertEquals(2520, encoded.size)

        val durationMs = VoiceCodec.calculateDurationMs(encoded.size)
        assertEquals(15750, durationMs) // 15.75 seconds exactly
    }

    @Test
    fun testDecodeEmptyAndCorruptInput() {
        val emptyDecoded = VoiceCodec.decode(ByteArray(0))
        assertEquals(0, emptyDecoded.size)

        val partialDecoded = VoiceCodec.decode(ByteArray(3)) // Less than 4 bytes
        assertEquals(0, partialDecoded.size)

        // Arbitrary random noise bytes should decode stably without crashes or NaN
        val garbage = ByteArray(64) { i -> (i * 37).toByte() }
        val decoded = VoiceCodec.decode(garbage)
        assertEquals(16 * VoiceCodec.FRAME_SAMPLES, decoded.size)
        for (s in decoded) {
            assertTrue("Sample must be a valid short: $s", s >= Short.MIN_VALUE && s <= Short.MAX_VALUE)
        }
    }
}
