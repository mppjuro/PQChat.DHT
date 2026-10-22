package org.pqchat.dht.media.voice

import org.pqchat.dht.crypto.BinaryFrameCodec
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe assembler for multi-frame BEP 44 Push-To-Talk micro-voice notes (TYPE_VOICE_NOTE = 0x09).
 * Single-frame notes (totalSegments = 1) complete immediately.
 * Multi-frame notes (2 or 3 segments) buffer incoming segments until all are received,
 * then assemble them in ascending segment index order (0..totalSegments-1).
 */
class VoiceSegmentAssembler(
    private val clipExpirationMs: Long = 15 * 60 * 1000L // 15 minutes
) {

    data class AssembledVoiceNote(
        val voiceClipId: Long,
        val totalSegments: Int,
        val totalDurationMs: Int,
        val codecMode: Byte,
        val ephemeralTtlSeconds: Long,
        val voiceBytes: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is AssembledVoiceNote) return false
            return voiceClipId == other.voiceClipId &&
                    totalSegments == other.totalSegments &&
                    totalDurationMs == other.totalDurationMs &&
                    codecMode == other.codecMode &&
                    ephemeralTtlSeconds == other.ephemeralTtlSeconds &&
                    voiceBytes.contentEquals(other.voiceBytes)
        }

        override fun hashCode(): Int {
            var result = voiceClipId.hashCode()
            result = 31 * result + totalSegments
            result = 31 * result + totalDurationMs
            result = 31 * result + codecMode.toInt()
            result = 31 * result + ephemeralTtlSeconds.hashCode()
            result = 31 * result + voiceBytes.contentHashCode()
            return result
        }
    }

    private data class SegmentEntry(
        val durationMs: Int,
        val data: ByteArray
    )

    private data class ClipBuffer(
        val voiceClipId: Long,
        val totalSegments: Int,
        val codecMode: Byte,
        val ephemeralTtlSeconds: Long,
        val createdAt: Long = System.currentTimeMillis(),
        val segments: MutableMap<Int, SegmentEntry> = mutableMapOf()
    )

    private val clipBuffers = ConcurrentHashMap<Long, ClipBuffer>()

    /**
     * Ingests a decoded voice note frame.
     * @return AssembledVoiceNote if all segments have been received, or null if waiting for more segments.
     */
    fun ingest(voiceNote: BinaryFrameCodec.DecodedPayload.VoiceNote): AssembledVoiceNote? {
        val total = voiceNote.totalSegments.coerceIn(1, 3)
        val index = voiceNote.segmentIndex

        if (index < 0 || index >= total) {
            return null // Invalid segment index
        }

        // Fast path: single-frame voice note
        if (total == 1) {
            return AssembledVoiceNote(
                voiceClipId = voiceNote.voiceClipId,
                totalSegments = 1,
                totalDurationMs = voiceNote.durationMs,
                codecMode = voiceNote.codecMode,
                ephemeralTtlSeconds = voiceNote.ephemeralTtlSeconds,
                voiceBytes = voiceNote.voiceBytes
            )
        }

        cleanExpiredClips()

        val buffer = clipBuffers.compute(voiceNote.voiceClipId) { _, existing ->
            val buf = existing ?: ClipBuffer(
                voiceClipId = voiceNote.voiceClipId,
                totalSegments = total,
                codecMode = voiceNote.codecMode,
                ephemeralTtlSeconds = voiceNote.ephemeralTtlSeconds
            )
            synchronized(buf) {
                buf.segments[index] = SegmentEntry(voiceNote.durationMs, voiceNote.voiceBytes)
            }
            buf
        } ?: return null

        synchronized(buffer) {
            if (buffer.segments.size == buffer.totalSegments) {
                // All segments received!
                clipBuffers.remove(voiceNote.voiceClipId)
                val out = ByteArrayOutputStream()
                var sumDuration = 0
                for (i in 0 until buffer.totalSegments) {
                    val seg = buffer.segments[i] ?: return null
                    out.write(seg.data)
                    sumDuration += seg.durationMs
                }
                return AssembledVoiceNote(
                    voiceClipId = buffer.voiceClipId,
                    totalSegments = buffer.totalSegments,
                    totalDurationMs = sumDuration,
                    codecMode = buffer.codecMode,
                    ephemeralTtlSeconds = buffer.ephemeralTtlSeconds,
                    voiceBytes = out.toByteArray()
                )
            }
        }

        return null
    }

    fun clear() {
        clipBuffers.clear()
    }

    private fun cleanExpiredClips() {
        val now = System.currentTimeMillis()
        val iterator = clipBuffers.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.createdAt > clipExpirationMs) {
                iterator.remove()
            }
        }
    }
}
