package org.pqchat.dht.media.voice

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.cos
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.sqrt

/**
 * Ultra-Low-Bitrate Parametric Speech Codec for PQChat DHT Push-To-Talk Voice Notes.
 *
 * Implements a lightweight, pure Kotlin parametric vocoder (LPC-10 / Codec2-inspired)
 * operating at 8000 Hz mono 16-bit PCM.
 *
 * Sizing & Bitrate Specification:
 * - Sampling Rate: 8000 Hz, mono, 16-bit PCM.
 * - Frame Duration: 25 ms (200 samples per frame).
 * - Encoded Frame Size: 4 bytes (32 bits).
 * - Bitrate: 1280 bps (160 bytes / second of speech).
 * - Maximum Single BEP 44 Frame (900 B): 840 B voice payload = 210 frames = 5.25 seconds.
 * - Maximum 3 BEP 44 Frames: 2520 B voice payload = 630 frames = 15.75 seconds.
 *
 * Frame Bit Allocation (32 bits = 4 bytes):
 * - Bit 31: Voiced/Unvoiced flag (1 bit: 1 = voiced, 0 = unvoiced)
 * - Bits 24..30: Pitch Period (7 bits: lag 20..147 samples, ~54 Hz - 400 Hz)
 * - Bits 19..23: RMS Gain Level (5 bits: 32 logarithmic levels)
 * - Bits 15..18: Reflection coefficient k1 (4 bits: 16 levels)
 * - Bits 11..14: Reflection coefficient k2 (4 bits: 16 levels)
 * - Bits 8..10: Reflection coefficient k3 (3 bits: 8 levels)
 * - Bits 5..7: Reflection coefficient k4 (3 bits: 8 levels)
 * - Bits 3..4: Reflection coefficient k5 (2 bits: 4 levels)
 * - Bits 1..2: Reflection coefficient k6 (2 bits: 4 levels)
 * - Bit 0: Reflection coefficient k7 (1 bit: 2 levels)
 */
object VoiceCodec {

    const val SAMPLE_RATE = 8000
    const val FRAME_SAMPLES = 200 // 25 ms at 8 kHz
    const val BYTES_PER_FRAME = 4
    const val BYTES_PER_SECOND = 160 // 40 frames/sec * 4 bytes
    const val BITS_PER_SECOND = 1280

    const val MAX_FRAME_VOICE_BYTES = 840 // Fits in 1 BEP 44 frame (859 B inner - 19 B header)
    const val MAX_VOICE_NOTE_SEGMENTS = 3
    const val MAX_TOTAL_VOICE_BYTES = MAX_FRAME_VOICE_BYTES * MAX_VOICE_NOTE_SEGMENTS // 2520 B (~15.75s)

    const val CODEC_MODE_LPC_8K_1280: Byte = 0x01
    const val CODEC_MODE_LPC10_COMPACT: Byte = CODEC_MODE_LPC_8K_1280
    const val FRAME_SIZE = FRAME_SAMPLES

    private const val PREEMPH_COEFF = 0.9375
    private const val LPC_ORDER = 7
    private const val MIN_PITCH_LAG = 20 // 400 Hz
    private const val MAX_PITCH_LAG = 147 // ~54 Hz

    // Hamming window for 200 samples
    private val HAMMING_WINDOW = DoubleArray(FRAME_SAMPLES) { n ->
        0.54 - 0.46 * cos(2.0 * Math.PI * n / (FRAME_SAMPLES - 1))
    }

    // Quantization codebooks for reflection coefficients (bounded strictly in (-1, 1) for stability)
    private val K1_TABLE = doubleArrayOf(
        -0.92, -0.80, -0.68, -0.56, -0.44, -0.32, -0.20, -0.08,
        0.08, 0.20, 0.32, 0.44, 0.56, 0.68, 0.80, 0.92
    )
    private val K2_TABLE = doubleArrayOf(
        -0.90, -0.78, -0.66, -0.54, -0.42, -0.30, -0.18, -0.06,
        0.06, 0.18, 0.30, 0.42, 0.54, 0.66, 0.78, 0.90
    )
    private val K3_TABLE = doubleArrayOf(-0.80, -0.57, -0.34, -0.11, 0.11, 0.34, 0.57, 0.80)
    private val K4_TABLE = doubleArrayOf(-0.75, -0.53, -0.32, -0.10, 0.10, 0.32, 0.53, 0.75)
    private val K5_TABLE = doubleArrayOf(-0.60, -0.20, 0.20, 0.60)
    private val K6_TABLE = doubleArrayOf(-0.50, -0.16, 0.16, 0.50)
    private val K7_TABLE = doubleArrayOf(-0.30, 0.30)

    // Gain quantization (32 levels covering ~50 dB dynamic range)
    private val GAIN_TABLE = DoubleArray(32) { i ->
        if (i == 0) 0.0 else 25.0 * exp(i * ln(18000.0 / 25.0) / 31.0)
    }

    /**
     * Encodes 8 kHz mono 16-bit PCM audio into a compressed parametric byte stream (1280 bps).
     *
     * @param pcm16 Array of 16-bit PCM samples.
     * @return Compressed byte array (length will be a multiple of 4 bytes).
     */
    fun encode(pcm16: ShortArray): ByteArray {
        if (pcm16.isEmpty()) return ByteArray(0)

        val totalFrames = pcm16.size / FRAME_SAMPLES
        if (totalFrames == 0) return ByteArray(0)

        val output = ByteBuffer.allocate(totalFrames * BYTES_PER_FRAME).order(ByteOrder.BIG_ENDIAN)

        var preemphState = 0.0
        val windowed = DoubleArray(FRAME_SAMPLES)
        val r = DoubleArray(LPC_ORDER + 1)
        val k = DoubleArray(LPC_ORDER)
        val a = DoubleArray(LPC_ORDER)

        for (frameIdx in 0 until totalFrames) {
            val offset = frameIdx * FRAME_SAMPLES

            // 1. RMS Energy
            var sumSq = 0.0
            for (i in 0 until FRAME_SAMPLES) {
                val s = pcm16[offset + i].toDouble()
                sumSq += s * s
            }
            val rms = sqrt(sumSq / FRAME_SAMPLES)

            // Quantize gain
            val gainIdx = quantizeGain(rms)

            // 2. Pre-emphasis & Windowing
            for (i in 0 until FRAME_SAMPLES) {
                val s = pcm16[offset + i].toDouble()
                val pre = s - PREEMPH_COEFF * preemphState
                preemphState = s
                windowed[i] = pre * HAMMING_WINDOW[i]
            }

            // 3. Autocorrelation for LPC
            for (lag in 0..LPC_ORDER) {
                var sum = 0.0
                for (n in 0 until FRAME_SAMPLES - lag) {
                    sum += windowed[n] * windowed[n + lag]
                }
                r[lag] = sum
            }

            // 4. Levinson-Durbin Recursion for Reflection Coefficients
            levinsonDurbin(r, k, a)

            // 5. Pitch & Voicing Estimation
            var bestPitchLag = 0
            var maxAutoCorr = 0.0
            val maxSearchLag = MAX_PITCH_LAG.coerceAtMost(FRAME_SAMPLES - 1)
            for (lag in MIN_PITCH_LAG..maxSearchLag) {
                var sum = 0.0
                for (n in 0 until FRAME_SAMPLES - lag) {
                    sum += windowed[n] * windowed[n + lag]
                }
                if (sum > maxAutoCorr) {
                    maxAutoCorr = sum
                    bestPitchLag = lag
                }
            }

            val r0 = if (r[0] > 1e-4) r[0] else 1e-4
            val normAutoCorr = maxAutoCorr / r0
            val isVoiced = (normAutoCorr > 0.35 && rms > 80.0)

            val pitchIdx = if (isVoiced && bestPitchLag >= MIN_PITCH_LAG) {
                (bestPitchLag - MIN_PITCH_LAG).coerceIn(0, 127)
            } else {
                0
            }

            // 6. Quantize Reflection Coefficients
            val qK1 = quantizeToTable(k[0], K1_TABLE)
            val qK2 = quantizeToTable(k[1], K2_TABLE)
            val qK3 = quantizeToTable(k[2], K3_TABLE)
            val qK4 = quantizeToTable(k[3], K4_TABLE)
            val qK5 = quantizeToTable(k[4], K5_TABLE)
            val qK6 = quantizeToTable(k[5], K6_TABLE)
            val qK7 = quantizeToTable(k[6], K7_TABLE)

            // 7. Pack into 32-bit Frame Integer
            var packed = 0
            if (isVoiced) {
                packed = packed or (1 shl 31)
            }
            packed = packed or ((pitchIdx and 0x7F) shl 24)
            packed = packed or ((gainIdx and 0x1F) shl 19)
            packed = packed or ((qK1 and 0x0F) shl 15)
            packed = packed or ((qK2 and 0x0F) shl 11)
            packed = packed or ((qK3 and 0x07) shl 8)
            packed = packed or ((qK4 and 0x07) shl 5)
            packed = packed or ((qK5 and 0x03) shl 3)
            packed = packed or ((qK6 and 0x03) shl 1)
            packed = packed or (qK7 and 0x01)

            output.putInt(packed)
        }

        return output.array()
    }

    /**
     * Decodes a compressed parametric byte stream into 8 kHz mono 16-bit PCM samples.
     *
     * @param compressedBytes Compressed byte array.
     * @return Decoded 16-bit PCM audio samples.
     */
    fun decode(compressedBytes: ByteArray): ShortArray {
        if (compressedBytes.size < BYTES_PER_FRAME) return ShortArray(0)

        val totalFrames = compressedBytes.size / BYTES_PER_FRAME
        val output = ShortArray(totalFrames * FRAME_SAMPLES)
        val buffer = ByteBuffer.wrap(compressedBytes).order(ByteOrder.BIG_ENDIAN)

        val latticeState = DoubleArray(LPC_ORDER)
        var deemphState = 0.0
        var pitchPhase = 0
        var noiseSeed = 123456789L

        for (frameIdx in 0 until totalFrames) {
            val packed = buffer.int

            val isVoiced = (packed ushr 31) and 0x01 != 0
            val pitchIdx = (packed ushr 24) and 0x7F
            val gainIdx = (packed ushr 19) and 0x1F
            val qK1 = (packed ushr 15) and 0x0F
            val qK2 = (packed ushr 11) and 0x0F
            val qK3 = (packed ushr 8) and 0x07
            val qK4 = (packed ushr 5) and 0x07
            val qK5 = (packed ushr 3) and 0x03
            val qK6 = (packed ushr 1) and 0x03
            val qK7 = packed and 0x01

            val pitchPeriod = MIN_PITCH_LAG + pitchIdx
            val gain = GAIN_TABLE[gainIdx]

            val k = doubleArrayOf(
                K1_TABLE[qK1],
                K2_TABLE[qK2],
                K3_TABLE[qK3],
                K4_TABLE[qK4],
                K5_TABLE[qK5],
                K6_TABLE[qK6],
                K7_TABLE[qK7]
            )

            val frameOffset = frameIdx * FRAME_SAMPLES

            for (n in 0 until FRAME_SAMPLES) {
                // Generate excitation
                val excitation: Double = if (!isVoiced || gain == 0.0) {
                    // White noise excitation
                    noiseSeed = (noiseSeed * 6364136223846793005L + 1442695040888963407L)
                    val rnd = ((noiseSeed ushr 33).toInt() - 1073741824).toDouble() / 1073741824.0
                    rnd * gain * 1.5
                } else {
                    // Periodic glottal pulse excitation
                    pitchPhase++
                    if (pitchPhase >= pitchPeriod) {
                        pitchPhase = 0
                    }
                    val pulseDuration = (pitchPeriod / 4).coerceIn(4, 16)
                    val pulse = if (pitchPhase < pulseDuration) {
                        0.5 * (1.0 - cos(2.0 * Math.PI * pitchPhase / pulseDuration))
                    } else {
                        0.0
                    }
                    pulse * gain * sqrt(pitchPeriod.toDouble())
                }

                // Lattice synthesis filter (strictly stable)
                var forward = excitation
                for (i in LPC_ORDER - 1 downTo 0) {
                    forward -= k[i] * latticeState[i]
                }
                for (i in LPC_ORDER - 1 downTo 1) {
                    latticeState[i] = latticeState[i - 1] + k[i - 1] * forward
                }
                latticeState[0] = forward

                // De-emphasis filter: y[n] = x[n] + PREEMPH * y[n-1]
                deemphState = forward + PREEMPH_COEFF * deemphState

                // Clamp to 16-bit signed integer
                val sample = deemphState.toInt().coerceIn(-32768, 32767).toShort()
                output[frameOffset + n] = sample
            }
        }

        return output
    }

    /**
     * Calculates duration in milliseconds from compressed bytes count.
     */
    fun calculateDurationMs(compressedByteCount: Int): Int {
        val frames = compressedByteCount / BYTES_PER_FRAME
        return frames * 25 // 25 ms per frame
    }

    /**
     * Calculates maximum compressed bytes for a given duration.
     */
    fun calculateMaxBytesForDuration(durationMs: Int): Int {
        val frames = (durationMs + 24) / 25
        return frames * BYTES_PER_FRAME
    }

    private fun quantizeGain(rms: Double): Int {
        if (rms <= 15.0) return 0
        var bestIdx = 1
        var minDiff = Double.MAX_VALUE
        for (i in 1 until GAIN_TABLE.size) {
            val diff = kotlin.math.abs(GAIN_TABLE[i] - rms)
            if (diff < minDiff) {
                minDiff = diff
                bestIdx = i
            }
        }
        return bestIdx
    }

    private fun quantizeToTable(value: Double, table: DoubleArray): Int {
        var bestIdx = 0
        var minDiff = Double.MAX_VALUE
        for (i in table.indices) {
            val diff = kotlin.math.abs(table[i] - value)
            if (diff < minDiff) {
                minDiff = diff
                bestIdx = i
            }
        }
        return bestIdx
    }

    private fun levinsonDurbin(r: DoubleArray, k: DoubleArray, a: DoubleArray) {
        var error = r[0]
        if (error <= 1e-6) {
            for (i in 0 until LPC_ORDER) {
                k[i] = 0.0
                a[i] = 0.0
            }
            return
        }

        val aPrev = DoubleArray(LPC_ORDER)

        for (i in 1..LPC_ORDER) {
            var sum = 0.0
            for (j in 1 until i) {
                sum += aPrev[j - 1] * r[i - j]
            }

            val ki = -(r[i] + sum) / error
            val clampedKi = ki.coerceIn(-0.95, 0.95)
            k[i - 1] = clampedKi

            a[i - 1] = clampedKi
            for (j in 1 until i) {
                a[j - 1] = aPrev[j - 1] + clampedKi * aPrev[i - j - 1]
            }

            error *= (1.0 - clampedKi * clampedKi)
            if (error <= 1e-6) error = 1e-6

            System.arraycopy(a, 0, aPrev, 0, i)
        }
    }
}
