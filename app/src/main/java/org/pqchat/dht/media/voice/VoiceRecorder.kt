package org.pqchat.dht.media.voice

import android.annotation.SuppressLint
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import kotlinx.coroutines.*
import org.pqchat.dht.crypto.BinaryFrameCodec
import java.io.ByteArrayOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.sqrt

/**
 * Push-To-Talk voice recorder for ultra-low-bitrate micro-voice notes.
 * Records 8 kHz mono 16-bit PCM and strictly enforces BEP 44 frame limits (1 frame = 840 B, 3 frames = 2520 B).
 */
class VoiceRecorder(
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
) {
    companion object {
        /**
         * Enables deterministic 8 kHz synthetic PCM-16 capture for headless CI emulators
         * running with `-noaudio` or instrumented UI tests without physical microphone hardware.
         */
        @Volatile
        var isSyntheticAudioTestMode: Boolean = false
    }

    private val isRecording = AtomicBoolean(false)
    private var recordJob: Job? = null
    private var audioRecord: AudioRecord? = null
    private val sampleBuffer = mutableListOf<Short>()
    private val bufferLock = Any()

    data class RecordingResult(
        val pcm16Samples: ShortArray,
        val durationMs: Int,
        val estimatedCompressedBytes: Int,
        val framesCount: Int
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RecordingResult) return false
            return durationMs == other.durationMs &&
                    estimatedCompressedBytes == other.estimatedCompressedBytes &&
                    framesCount == other.framesCount &&
                    pcm16Samples.contentEquals(other.pcm16Samples)
        }

        override fun hashCode(): Int {
            var result = pcm16Samples.contentHashCode()
            result = 31 * result + durationMs
            result = 31 * result + estimatedCompressedBytes
            result = 31 * result + framesCount
            return result
        }
    }

    fun isRecordingNow(): Boolean = isRecording.get()

    /**
     * Starts recording audio.
     * @param maxFrames Maximum DHT BEP 44 frames allowed (1 or 3).
     * @param onAmplitude Callback with normalized audio amplitude (0.0 to 1.0) for UI waveforms.
     * @param onProgress Callback with duration in ms, estimated compressed byte count, and DHT frame count.
     * @param onAutoStop Callback triggered if recording hits maxFrames limit.
     */
    @SuppressLint("MissingPermission")
    fun startRecording(
        maxFrames: Int = 3,
        onAmplitude: ((Float) -> Unit)? = null,
        onProgress: ((durationMs: Int, bytesCount: Int, framesCount: Int) -> Unit)? = null,
        onAutoStop: ((RecordingResult) -> Unit)? = null
    ): Boolean {
        if (!isRecording.compareAndSet(false, true)) {
            return false
        }

        synchronized(bufferLock) {
            sampleBuffer.clear()
        }

        val clampedMaxFrames = maxFrames.coerceIn(1, 3)
        val maxCompressedBytes = clampedMaxFrames * BinaryFrameCodec.T9_MAX_VOICE_SIZE // 840 or 2520
        val maxSpeechFrames = maxCompressedBytes / VoiceCodec.BYTES_PER_FRAME // 210 or 630
        val maxSamples = maxSpeechFrames * VoiceCodec.FRAME_SIZE // 42,000 or 126,000 samples

        val usingSyntheticStream = isSyntheticAudioTestMode
        if (!usingSyntheticStream) {
            val minBufferSize = try {
                AudioRecord.getMinBufferSize(
                    VoiceCodec.SAMPLE_RATE,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT
                )
            } catch (_: Throwable) {
                AudioRecord.ERROR_BAD_VALUE
            }
            val bufferSize = max(minBufferSize, VoiceCodec.FRAME_SIZE * 2)
            try {
                audioRecord = AudioRecord(
                    MediaRecorder.AudioSource.MIC,
                    VoiceCodec.SAMPLE_RATE,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT,
                    bufferSize
                )
                if (audioRecord?.state != AudioRecord.STATE_INITIALIZED) {
                    audioRecord?.release()
                    audioRecord = null
                    isRecording.set(false)
                    return false
                }
                audioRecord?.startRecording()
            } catch (_: Throwable) {
                audioRecord?.release()
                audioRecord = null
                isRecording.set(false)
                return false
            }
        } else {
            // Seed 500 ms (20 speech frames = 4000 samples = 80 B LPC-10) immediately
            // so short automated taps produce valid voice notes without high-frequency UI storms.
            val seedFrames = 20
            val seedSampleCount = seedFrames * VoiceCodec.FRAME_SIZE
            synchronized(bufferLock) {
                for (i in 0 until seedSampleCount) {
                    val phase = (2.0 * Math.PI * 440.0 * i) / VoiceCodec.SAMPLE_RATE
                    sampleBuffer.add((kotlin.math.sin(phase) * 9000.0).toInt().toShort())
                }
            }
            onAmplitude?.invoke(0.28f)
            onProgress?.invoke(
                seedFrames * 25,
                seedFrames * VoiceCodec.BYTES_PER_FRAME,
                1
            )
        }

        val uiCallbackIntervalMs = if (usingSyntheticStream) 1250L else 120L

        recordJob = scope.launch(kotlinx.coroutines.Dispatchers.IO) {
            val readBuffer = ShortArray(VoiceCodec.FRAME_SIZE)
            var reachedLimit = false
            var syntheticSampleCursor = 20 * VoiceCodec.FRAME_SIZE
            var lastUiCallbackMs = System.currentTimeMillis()

            while (isActive && isRecording.get() && !reachedLimit) {
                var sumSquare = 0.0
                var samplesAdded = 0
                if (usingSyntheticStream) {
                    // Pace synthetic capture at 250 ms (10 speech frames at 25 ms/frame = real-time 8 kHz)
                    delay(250)
                    if (!isActive || !isRecording.get()) break
                    val framesPerTick = 10
                    synchronized(bufferLock) {
                        for (f in 0 until framesPerTick) {
                            if (sampleBuffer.size >= maxSamples) {
                                reachedLimit = true
                                break
                            }
                            for (i in 0 until VoiceCodec.FRAME_SIZE) {
                                val t = syntheticSampleCursor++
                                val carrier = kotlin.math.sin(2.0 * Math.PI * 440.0 * t / VoiceCodec.SAMPLE_RATE)
                                val overtone = 0.35 * kotlin.math.sin(2.0 * Math.PI * 880.0 * t / VoiceCodec.SAMPLE_RATE)
                                val s = ((carrier + overtone) * 8000.0).toInt().toShort()
                                sampleBuffer.add(s)
                                sumSquare += (s * s).toDouble()
                                samplesAdded++
                                if (sampleBuffer.size >= maxSamples) {
                                    reachedLimit = true
                                    break
                                }
                            }
                        }
                    }
                } else {
                    val readCount = audioRecord?.read(readBuffer, 0, readBuffer.size) ?: -1
                    if (readCount > 0) {
                        synchronized(bufferLock) {
                            for (i in 0 until readCount) {
                                val s = readBuffer[i]
                                sampleBuffer.add(s)
                                sumSquare += (s * s).toDouble()
                                samplesAdded++
                                if (sampleBuffer.size >= maxSamples) {
                                    reachedLimit = true
                                    break
                                }
                            }
                        }
                    } else {
                        delay(10)
                    }
                }

                if (samplesAdded > 0) {
                    val nowMs = System.currentTimeMillis()
                    if (reachedLimit || (nowMs - lastUiCallbackMs) >= uiCallbackIntervalMs) {
                        lastUiCallbackMs = nowMs
                        val rms = sqrt(sumSquare / samplesAdded)
                        val normalizedAmp = (rms / 32768.0).toFloat().coerceIn(0f, 1f)
                        onAmplitude?.invoke(normalizedAmp)

                        val currentSamples = synchronized(bufferLock) { sampleBuffer.size }
                        val currentDurationMs = (currentSamples * 1000L / VoiceCodec.SAMPLE_RATE).toInt()
                        val speechFrames = (currentSamples + VoiceCodec.FRAME_SIZE - 1) / VoiceCodec.FRAME_SIZE
                        val bytesCount = speechFrames * VoiceCodec.BYTES_PER_FRAME
                        val dhtFrames = ((bytesCount + BinaryFrameCodec.T9_MAX_VOICE_SIZE - 1) / BinaryFrameCodec.T9_MAX_VOICE_SIZE).coerceIn(1, 3)

                        onProgress?.invoke(currentDurationMs, bytesCount, dhtFrames)
                    }

                    if (reachedLimit) {
                        break
                    }
                }
            }

            if (reachedLimit && isRecording.get()) {
                val result = stopInternal(cancelRecordJob = false)
                if (result != null) {
                    onAutoStop?.invoke(result)
                }
            }
        }

        return true
    }

    /**
     * Stops recording and returns the recorded PCM-16 audio.
     */
    fun stop(): RecordingResult? {
        if (!isRecording.get()) return null
        return stopInternal(cancelRecordJob = true)
    }

    /**
     * Cancels recording without returning any data.
     */
    fun cancel() {
        isRecording.set(false)
        recordJob?.cancel()
        recordJob = null
        try {
            audioRecord?.stop()
            audioRecord?.release()
        } catch (_: Throwable) {}
        audioRecord = null
        synchronized(bufferLock) {
            sampleBuffer.clear()
        }
    }

    private fun stopInternal(cancelRecordJob: Boolean): RecordingResult? {
        isRecording.set(false)
        if (cancelRecordJob) {
            recordJob?.cancel()
        }
        recordJob = null
        try {
            audioRecord?.stop()
            audioRecord?.release()
        } catch (_: Throwable) {}
        audioRecord = null

        val samples: ShortArray
        synchronized(bufferLock) {
            samples = sampleBuffer.toShortArray()
            sampleBuffer.clear()
        }

        if (samples.isEmpty()) return null

        val durationMs = (samples.size * 1000L / VoiceCodec.SAMPLE_RATE).toInt()
        val speechFrames = (samples.size + VoiceCodec.FRAME_SIZE - 1) / VoiceCodec.FRAME_SIZE
        val bytesCount = speechFrames * VoiceCodec.BYTES_PER_FRAME
        val dhtFrames = ((bytesCount + BinaryFrameCodec.T9_MAX_VOICE_SIZE - 1) / BinaryFrameCodec.T9_MAX_VOICE_SIZE).coerceIn(1, 3)

        return RecordingResult(
            pcm16Samples = samples,
            durationMs = durationMs,
            estimatedCompressedBytes = bytesCount,
            framesCount = dhtFrames
        )
    }
}
