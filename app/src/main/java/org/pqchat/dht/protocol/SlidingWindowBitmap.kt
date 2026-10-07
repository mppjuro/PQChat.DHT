package org.pqchat.dht.protocol

/**
 * Sliding Window Replay Protection and Out-Of-Order Tracking Bitmap.
 *
 * Tracks received sequence numbers in a sliding window of size [windowSizeBits] (default 1024 bits = 128 bytes).
 * - Sequence numbers older than [windowBase] are considered already received.
 * - Out-of-order sequence numbers inside [windowBase .. windowBase + windowSizeBits - 1] are marked as received.
 * - As contiguous sequence numbers starting from [windowBase] are received, the window slides forward.
 */
class SlidingWindowBitmap(
    var windowBase: Int = 0,
    val windowSizeBits: Int = 1024,
    byteArray: ByteArray? = null
) {
    val bitmap: ByteArray = if (byteArray != null && byteArray.size == windowSizeBits / 8) {
        byteArray.copyOf()
    } else {
        ByteArray(windowSizeBits / 8)
    }

    /**
     * Checks if [seqNum] has already been received.
     */
    fun isReceived(seqNum: Int): Boolean {
        if (seqNum < windowBase) return true
        val offset = seqNum - windowBase
        if (offset >= windowSizeBits) return false
        val byteIndex = offset / 8
        val bitIndex = offset % 8
        return (bitmap[byteIndex].toInt() and (1 shl bitIndex)) != 0
    }

    /**
     * Marks [seqNum] as received.
     * Returns true if newly marked, or false if already received or out-of-window.
     */
    fun markReceived(seqNum: Int): Boolean {
        if (seqNum < windowBase) return false
        val offset = seqNum - windowBase
        if (offset >= windowSizeBits) return false

        val byteIndex = offset / 8
        val bitIndex = offset % 8
        if ((bitmap[byteIndex].toInt() and (1 shl bitIndex)) != 0) {
            return false // Already received
        }

        bitmap[byteIndex] = (bitmap[byteIndex].toInt() or (1 shl bitIndex)).toByte()
        advanceWindow()
        return true
    }

    private fun advanceWindow() {
        while (isBitSet(0)) {
            shiftDownByOneBit()
            windowBase++
        }
    }

    private fun isBitSet(bitOffset: Int): Boolean {
        val byteIndex = bitOffset / 8
        val bitIndex = bitOffset % 8
        return (bitmap[byteIndex].toInt() and (1 shl bitIndex)) != 0
    }

    private fun shiftDownByOneBit() {
        for (i in 0 until bitmap.size) {
            val currentByte = bitmap[i].toInt() and 0xFF
            val nextByte = if (i + 1 < bitmap.size) bitmap[i + 1].toInt() and 0xFF else 0
            val shifted = (currentByte ushr 1) or ((nextByte and 0x01) shl 7)
            bitmap[i] = shifted.toByte()
        }
    }

    fun toByteArray(): ByteArray = bitmap.copyOf()
}
