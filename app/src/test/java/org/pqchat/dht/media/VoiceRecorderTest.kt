package org.pqchat.dht.media

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.pqchat.dht.media.voice.VoiceCodec
import org.pqchat.dht.media.voice.VoiceRecorder
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Unit tests for [VoiceRecorder] synthetic capture mode and callback pacing.
 */
class VoiceRecorderTest {

    @After
    fun tearDown() {
        VoiceRecorder.isSyntheticAudioTestMode = false
    }

    @Test
    fun testSyntheticModeSeedsAudioAndThrottlesUiCallbacksOnStop() = runBlocking {
        VoiceRecorder.isSyntheticAudioTestMode = true
        val recorder = VoiceRecorder()
        val amplitudeCount = AtomicInteger(0)
        val progressCount = AtomicInteger(0)
        val lastBytes = AtomicInteger(0)

        val started = recorder.startRecording(
            maxFrames = 3,
            onAmplitude = { amplitudeCount.incrementAndGet() },
            onProgress = { _, bytes, _ ->
                progressCount.incrementAndGet()
                lastBytes.set(bytes)
            }
        )
        assertTrue("Synthetic mode recording must start", started)
        assertTrue("Initial seed must report non-zero compressed bytes immediately", lastBytes.get() >= 80)

        delay(350L)
        val result = recorder.stop()
        assertNotNull("Stopping synthetic recording must return PCM samples", result)
        assertTrue("Seeded synthetic sample buffer must contain at least 4000 samples", result!!.pcm16Samples.size >= 4000)
        assertTrue("Duration must be at least 500 ms", result.durationMs >= 500)
        assertTrue(
            "UI callbacks must stay throttled instead of 50Hz bursts (got amp=${amplitudeCount.get()}, prog=${progressCount.get()})",
            amplitudeCount.get() <= 4 && progressCount.get() <= 4
        )

        val encoded = VoiceCodec.encode(result.pcm16Samples)
        assertTrue("Encoded LPC-10 voice bytes must be non-empty", encoded.isNotEmpty())
    }

    @Test
    fun testSyntheticModeAutoStopForwardsRecordingResult() = runBlocking {
        VoiceRecorder.isSyntheticAudioTestMode = true
        val recorder = VoiceRecorder()
        val autoStoppedResult = AtomicReference<VoiceRecorder.RecordingResult?>(null)

        val started = recorder.startRecording(
            maxFrames = 1,
            onAutoStop = { result -> autoStoppedResult.set(result) }
        )
        assertTrue("Synthetic mode recording must start", started)

        val deadlineMs = System.currentTimeMillis() + 8_000L
        while (System.currentTimeMillis() < deadlineMs && autoStoppedResult.get() == null) {
            delay(100L)
        }

        val result = autoStoppedResult.get()
        assertNotNull("Auto-stop must deliver RecordingResult to caller", result)
        assertEquals("Single-frame budget must report framesCount=1", 1, result!!.framesCount)
        assertTrue("Auto-stopped recording must fill single-frame sample budget", result.pcm16Samples.size >= 42_000)
    }
}
