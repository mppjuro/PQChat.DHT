package org.pqchat.dht.media.voice

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import kotlinx.coroutines.*
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.max

/**
 * Audio playback player for ultra-low-bitrate micro-voice notes.
 * Decodes compressed vocoder bytes into 8 kHz mono 16-bit PCM and streams to AudioTrack.
 */
class VoicePlayer(
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
) {
    private val isPlayingState = AtomicBoolean(false)
    private var playJob: Job? = null
    private var audioTrack: AudioTrack? = null

    fun isPlaying(): Boolean = isPlayingState.get()

    /**
     * Plays compressed voice bytes.
     * @param voiceBytes Compressed vocoder bytes (LPC-10 / Codec2-inspired stream).
     * @param onProgress Callback with normalized playback progress (0.0 to 1.0).
     * @param onCompletion Callback invoked when playback finishes or is stopped.
     */
    fun play(
        voiceBytes: ByteArray,
        onProgress: ((Float) -> Unit)? = null,
        onCompletion: (() -> Unit)? = null
    ) {
        stop()

        if (voiceBytes.isEmpty()) {
            onCompletion?.invoke()
            return
        }

        isPlayingState.set(true)

        playJob = scope.launch {
            val pcmSamples = VoiceCodec.decode(voiceBytes)
            if (pcmSamples.isEmpty()) {
                isPlayingState.set(false)
                withContext(Dispatchers.Main) {
                    onCompletion?.invoke()
                }
                return@launch
            }

            val minBufferSize = AudioTrack.getMinBufferSize(
                VoiceCodec.SAMPLE_RATE,
                AudioFormat.CHANNEL_OUT_MONO,
                AudioFormat.ENCODING_PCM_16BIT
            )
            val bufferSize = max(minBufferSize, VoiceCodec.FRAME_SIZE * 2)

            val track = try {
                AudioTrack.Builder()
                    .setAudioAttributes(
                        AudioAttributes.Builder()
                            .setUsage(AudioAttributes.USAGE_MEDIA)
                            .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                            .build()
                    )
                    .setAudioFormat(
                        AudioFormat.Builder()
                            .setSampleRate(VoiceCodec.SAMPLE_RATE)
                            .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                            .build()
                    )
                    .setBufferSizeInBytes(bufferSize)
                    .setTransferMode(AudioTrack.MODE_STREAM)
                    .build()
            } catch (_: Throwable) {
                null
            }

            if (track == null || track.state != AudioTrack.STATE_INITIALIZED) {
                track?.release()
                isPlayingState.set(false)
                withContext(Dispatchers.Main) {
                    onCompletion?.invoke()
                }
                return@launch
            }

            audioTrack = track
            try {
                track.play()
                val chunkSize = VoiceCodec.FRAME_SIZE
                var offset = 0
                val total = pcmSamples.size

                while (isActive && isPlayingState.get() && offset < total) {
                    val count = (total - offset).coerceAtMost(chunkSize)
                    val written = track.write(pcmSamples, offset, count)
                    if (written > 0) {
                        offset += written
                        val progress = (offset.toFloat() / total.toFloat()).coerceIn(0f, 1f)
                        withContext(Dispatchers.Main) {
                            onProgress?.invoke(progress)
                        }
                    } else {
                        delay(10)
                    }
                }
            } catch (_: Throwable) {
                // Audio track interrupted or error
            } finally {
                try {
                    track.stop()
                    track.release()
                } catch (_: Throwable) {}
                audioTrack = null
                isPlayingState.set(false)
                withContext(Dispatchers.Main) {
                    onProgress?.invoke(1f)
                    onCompletion?.invoke()
                }
            }
        }
    }

    /**
     * Stops current playback immediately.
     */
    fun stop() {
        isPlayingState.set(false)
        playJob?.cancel()
        playJob = null
        try {
            audioTrack?.pause()
            audioTrack?.flush()
            audioTrack?.stop()
            audioTrack?.release()
        } catch (_: Throwable) {}
        audioTrack = null
    }
}
