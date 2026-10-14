package org.pqchat.dht.ui.util

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.net.Uri
import android.util.Base64
import com.google.zxing.*
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.util.EnumMap

object QrCodeUtil {

    val MULTIPART_MAGIC = byteArrayOf('P'.code.toByte(), 'Q'.code.toByte(), 'Q'.code.toByte(), 'R'.code.toByte())
    const val MULTIPART_MAGIC_STR = "PQQR"

    fun base64Encode(data: ByteArray): String {
        return try {
            Base64.encodeToString(data, Base64.NO_WRAP)
        } catch (_: Throwable) {
            java.util.Base64.getEncoder().encodeToString(data)
        }
    }

    fun base64Decode(data: String): ByteArray {
        val clean = data.trim()
        return try {
            Base64.decode(clean, Base64.DEFAULT)
        } catch (_: Throwable) {
            java.util.Base64.getDecoder().decode(clean)
        }
    }

    /**
     * Generates a Bitmap containing the QR code for binary data.
     */
    fun generateQrBitmap(data: ByteArray, size: Int = 600): Bitmap {
        val base64Data = base64Encode(data)
        val hints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java)
        hints[EncodeHintType.ERROR_CORRECTION] = ErrorCorrectionLevel.L
        hints[EncodeHintType.MARGIN] = 1

        val bitMatrix = QRCodeWriter().encode(
            base64Data,
            BarcodeFormat.QR_CODE,
            size,
            size,
            hints
        )

        val width = bitMatrix.width
        val height = bitMatrix.height
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)

        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (bitMatrix.get(x, y)) Color.BLACK else Color.WHITE)
            }
        }

        return bitmap
    }

    /**
     * Decodes Base64 QR string into raw bytes.
     */
    fun decodeQrString(qrString: String): ByteArray {
        return base64Decode(qrString)
    }

    /**
     * 16-bit CRC (CCITT polynomial 0x1021, init 0xFFFF) for verifying full payload reassembly.
     */
    fun computeCrc16(data: ByteArray): Int {
        var crc = 0xFFFF
        for (b in data) {
            crc = crc xor ((b.toInt() and 0xFF) shl 8)
            for (i in 0 until 8) {
                crc = if ((crc and 0x8000) != 0) {
                    ((crc shl 1) xor 0x1021) and 0xFFFF
                } else {
                    (crc shl 1) and 0xFFFF
                }
            }
        }
        return crc and 0xFFFF
    }

    data class MultipartFrame(
        val frameIndex: Int,
        val totalFrames: Int,
        val crc16: Int,
        val chunk: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is MultipartFrame) return false
            return frameIndex == other.frameIndex &&
                    totalFrames == other.totalFrames &&
                    crc16 == other.crc16 &&
                    chunk.contentEquals(other.chunk)
        }

        override fun hashCode(): Int {
            var result = frameIndex
            result = 31 * result + totalFrames
            result = 31 * result + crc16
            result = 31 * result + chunk.contentHashCode()
            return result
        }
    }

    /**
     * Splits binary handshake payload into multipart frames (e.g. 4 frames of ~220 bytes each).
     */
    fun splitIntoMultipartFrames(
        payload: ByteArray,
        totalFrames: Int = 4
    ): List<MultipartFrame> {
        require(totalFrames in 2..64) { "totalFrames must be between 2 and 64 (got $totalFrames)" }
        require(payload.isNotEmpty()) { "Payload cannot be empty" }

        val crc = computeCrc16(payload)
        val chunkSize = (payload.size + totalFrames - 1) / totalFrames
        val frames = ArrayList<MultipartFrame>(totalFrames)

        var offset = 0
        for (index in 0 until totalFrames) {
            val remaining = (payload.size - offset).coerceAtLeast(0)
            val currentChunkSize = minOf(chunkSize, remaining)
            val chunk = payload.copyOfRange(offset, offset + currentChunkSize)
            frames.add(
                MultipartFrame(
                    frameIndex = index,
                    totalFrames = totalFrames,
                    crc16 = crc,
                    chunk = chunk
                )
            )
            offset += currentChunkSize
        }
        return frames
    }

    /**
     * Serializes a multipart frame into binary:
     * [0..3]: Magic "PQQR" (0x50, 0x51, 0x51, 0x52)
     * [4]: frameIndex (UInt8)
     * [5]: totalFrames (UInt8)
     * [6..7]: crc16 (UInt16 Big-Endian)
     * [8..end]: chunk bytes
     */
    fun encodeFrame(frame: MultipartFrame): ByteArray {
        val result = ByteArray(8 + frame.chunk.size)
        result[0] = MULTIPART_MAGIC[0]
        result[1] = MULTIPART_MAGIC[1]
        result[2] = MULTIPART_MAGIC[2]
        result[3] = MULTIPART_MAGIC[3]
        result[4] = frame.frameIndex.toByte()
        result[5] = frame.totalFrames.toByte()
        result[6] = ((frame.crc16 ushr 8) and 0xFF).toByte()
        result[7] = (frame.crc16 and 0xFF).toByte()
        System.arraycopy(frame.chunk, 0, result, 8, frame.chunk.size)
        return result
    }

    /**
     * Formats frame as a human-readable / standard text format:
     * "PQQR:<frameIndex>:<totalFrames>:<crcHex>:<base64Chunk>"
     */
    fun encodeFrameToString(frame: MultipartFrame): String {
        val crcHex = String.format(java.util.Locale.US, "%04X", frame.crc16)
        val base64Chunk = base64Encode(frame.chunk)
        return "$MULTIPART_MAGIC_STR:${frame.frameIndex}:${frame.totalFrames}:$crcHex:$base64Chunk"
    }

    /**
     * Parses a scanned QR text payload into a MultipartFrame if it matches the format.
     * Returns null if text is a single static QR payload (e.g. standard Base64).
     */
    fun parseMultipartFrame(raw: String): MultipartFrame? {
        val clean = raw.trim()
        if (clean.isBlank()) return null

        // 1. Text format: "PQQR:<index>:<total>:<crcHex>:<base64Chunk>"
        if (clean.startsWith("$MULTIPART_MAGIC_STR:")) {
            val parts = clean.split(":")
            if (parts.size >= 5) {
                val index = parts[1].toIntOrNull() ?: return null
                val total = parts[2].toIntOrNull() ?: return null
                val crc = parts[3].toIntOrNull(16) ?: return null
                val chunk = try {
                    base64Decode(parts[4])
                } catch (_: Exception) {
                    return null
                }
                if (total in 2..64 && index in 0 until total) {
                    return MultipartFrame(index, total, crc, chunk)
                }
            }
        }

        // 2. Binary format encoded in Base64
        return try {
            val bytes = base64Decode(clean)
            if (bytes.size >= 8 &&
                bytes[0] == MULTIPART_MAGIC[0] &&
                bytes[1] == MULTIPART_MAGIC[1] &&
                bytes[2] == MULTIPART_MAGIC[2] &&
                bytes[3] == MULTIPART_MAGIC[3]
            ) {
                val index = bytes[4].toInt() and 0xFF
                val total = bytes[5].toInt() and 0xFF
                val crc = ((bytes[6].toInt() and 0xFF) shl 8) or (bytes[7].toInt() and 0xFF)
                if (total in 2..64 && index in 0 until total) {
                    val chunk = bytes.copyOfRange(8, bytes.size)
                    MultipartFrame(index, total, crc, chunk)
                } else {
                    null
                }
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Generates a list of Bitmaps for each multipart frame of the handshake payload.
     */
    fun generateMultipartQrBitmaps(
        payload: ByteArray,
        totalFrames: Int = 4,
        size: Int = 600
    ): List<Bitmap> {
        val frames = splitIntoMultipartFrames(payload, totalFrames)
        return frames.map { frame ->
            val frameBytes = encodeFrame(frame)
            generateQrBitmap(frameBytes, size)
        }
    }

    /**
     * Buffer that reassembles animated multipart QR frames received in any order.
     * Compatible with single static QR codes.
     */
    class MultipartQrAssembler {
        private val receivedFrames = mutableMapOf<Int, ByteArray>()
        private var expectedTotal: Int? = null
        private var expectedCrc: Int? = null

        sealed class AssembleResult {
            object SingleStatic : AssembleResult()
            data class Progress(val scannedCount: Int, val totalCount: Int) : AssembleResult()
            data class Complete(
                val payload: ByteArray,
                val rawBase64: String,
                val scannedCount: Int,
                val totalCount: Int
            ) : AssembleResult() {
                override fun equals(other: Any?): Boolean {
                    if (this === other) return true
                    if (other !is Complete) return false
                    return scannedCount == other.scannedCount &&
                            totalCount == other.totalCount &&
                            rawBase64 == other.rawBase64 &&
                            payload.contentEquals(other.payload)
                }

                override fun hashCode(): Int {
                    var result = payload.contentHashCode()
                    result = 31 * result + rawBase64.hashCode()
                    result = 31 * result + scannedCount
                    result = 31 * result + totalCount
                    return result
                }
            }
            data class Error(val message: String) : AssembleResult()
        }

        @Synchronized
        fun processScan(qrText: String): AssembleResult {
            val frame = parseMultipartFrame(qrText)
            if (frame == null) {
                // Not a multipart frame -> It's a single static QR!
                return AssembleResult.SingleStatic
            }

            // If sequence changes (new CRC or total frames count), reset buffer
            if (expectedTotal == null || expectedCrc == null) {
                expectedTotal = frame.totalFrames
                expectedCrc = frame.crc16
            } else if (frame.totalFrames != expectedTotal || frame.crc16 != expectedCrc) {
                receivedFrames.clear()
                expectedTotal = frame.totalFrames
                expectedCrc = frame.crc16
            }

            receivedFrames[frame.frameIndex] = frame.chunk

            val total = expectedTotal ?: frame.totalFrames
            if (receivedFrames.size == total) {
                // Reassemble in exact frame order 0 until total
                val totalBytes = (0 until total).sumOf { receivedFrames[it]?.size ?: 0 }
                val assembled = ByteArray(totalBytes)
                var offset = 0
                for (i in 0 until total) {
                    val chunk = receivedFrames[i] ?: return AssembleResult.Error("Missing frame $i")
                    System.arraycopy(chunk, 0, assembled, offset, chunk.size)
                    offset += chunk.size
                }

                // Verify CRC16 of the full assembled payload
                val actualCrc = computeCrc16(assembled)
                if (actualCrc != expectedCrc) {
                    receivedFrames.clear()
                    expectedTotal = null
                    expectedCrc = null
                    return AssembleResult.Error("CRC16 mismatch: expected $expectedCrc, got $actualCrc")
                }

                val rawBase64 = base64Encode(assembled)
                return AssembleResult.Complete(
                    payload = assembled,
                    rawBase64 = rawBase64,
                    scannedCount = total,
                    totalCount = total
                )
            } else {
                return AssembleResult.Progress(
                    scannedCount = receivedFrames.size,
                    totalCount = total
                )
            }
        }

        @Synchronized
        fun reset() {
            receivedFrames.clear()
            expectedTotal = null
            expectedCrc = null
        }

        val scannedCount: Int get() = receivedFrames.size
        val totalCount: Int get() = expectedTotal ?: 0
    }

    /**
     * Decodes a QR code payload from a given Bitmap image (e.g. from gallery or file).
     * Employs multiple scanning strategies (full image, white-card auto-detection,
     * upper-middle screenshot cropping, and scaled passes) to reliably handle
     * both raw QR images and full-screen phone screenshots.
     */
    fun decodeQrFromBitmap(bitmap: Bitmap): String? {
        val safeBitmap = if (bitmap.config == Bitmap.Config.HARDWARE) {
            bitmap.copy(Bitmap.Config.ARGB_8888, false) ?: bitmap
        } else {
            bitmap
        }

        val width = safeBitmap.width
        val height = safeBitmap.height
        android.util.Log.d("QrCodeUtil", "Attempting QR decode on bitmap ${width}x${height}")

        val intArray = IntArray(width * height)
        safeBitmap.getPixels(intArray, 0, width, 0, 0, width, height)

        val fullSource = RGBLuminanceSource(width, height, intArray)
        val reader = MultiFormatReader().apply {
            setHints(
                mapOf(
                    DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                    DecodeHintType.TRY_HARDER to true
                )
            )
        }

        fun trySource(source: LuminanceSource, label: String): String? {
            // 1. HybridBinarizer
            try {
                reader.reset()
                val res = reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
                if (!res.isNullOrBlank()) {
                    android.util.Log.d("QrCodeUtil", "QR decode success with HybridBinarizer on $label")
                    return res
                }
            } catch (_: Exception) {}

            // 2. GlobalHistogramBinarizer
            try {
                reader.reset()
                val res = reader.decodeWithState(BinaryBitmap(GlobalHistogramBinarizer(source))).text
                if (!res.isNullOrBlank()) {
                    android.util.Log.d("QrCodeUtil", "QR decode success with GlobalHistogramBinarizer on $label")
                    return res
                }
            } catch (_: Exception) {}

            // 3. Inverted HybridBinarizer
            try {
                reader.reset()
                val res = reader.decodeWithState(BinaryBitmap(HybridBinarizer(source.invert()))).text
                if (!res.isNullOrBlank()) {
                    android.util.Log.d("QrCodeUtil", "QR decode success with Inverted HybridBinarizer on $label")
                    return res
                }
            } catch (_: Exception) {}

            // 4. Inverted GlobalHistogramBinarizer
            try {
                reader.reset()
                val res = reader.decodeWithState(BinaryBitmap(GlobalHistogramBinarizer(source.invert()))).text
                if (!res.isNullOrBlank()) {
                    android.util.Log.d("QrCodeUtil", "QR decode success with Inverted GlobalHistogramBinarizer on $label")
                    return res
                }
            } catch (_: Exception) {}

            return null
        }

        // Strategy A: Full image
        trySource(fullSource, "Full Image")?.let { return it }

        // Strategy B: White card bounding box detection (for dark theme app screenshots)
        try {
            var minX = width
            var maxX = 0
            var minY = height
            var maxY = 0
            var whitePixelsCount = 0

            val step = if (width > 1000) 4 else 2
            for (y in 0 until height step step) {
                for (x in 0 until width step step) {
                    val pixel = intArray[y * width + x]
                    val r = (pixel shr 16) and 0xFF
                    val g = (pixel shr 8) and 0xFF
                    val b = pixel and 0xFF
                    if (r > 180 && g > 180 && b > 180) {
                        if (x < minX) minX = x
                        if (x > maxX) maxX = x
                        if (y < minY) minY = y
                        if (y > maxY) maxY = y
                        whitePixelsCount++
                    }
                }
            }

            if (whitePixelsCount > 200 && maxX > minX + 150 && maxY > minY + 150) {
                val pad = 12
                val cropX = (minX - pad).coerceAtLeast(0)
                val cropY = (minY - pad).coerceAtLeast(0)
                val cropW = (maxX - minX + 2 * pad).coerceAtMost(width - cropX)
                val cropH = (maxY - minY + 2 * pad).coerceAtMost(height - cropY)

                if (cropW > 100 && cropH > 100) {
                    val cardCrop = fullSource.crop(cropX, cropY, cropW, cropH)
                    trySource(cardCrop, "White-Card Bounding Box ($cropW x $cropH)")?.let { return it }

                    // Also try scaled versions of the cropped card (e.g. 600x600, 800x800)
                    try {
                        val cardBmp = Bitmap.createBitmap(safeBitmap, cropX, cropY, cropW, cropH)
                        for (targetSize in listOf(600, 800)) {
                            val scaledCard = Bitmap.createScaledBitmap(cardBmp, targetSize, targetSize, true)
                            val cardPixels = IntArray(targetSize * targetSize)
                            scaledCard.getPixels(cardPixels, 0, targetSize, 0, 0, targetSize, targetSize)
                            val scaledSource = RGBLuminanceSource(targetSize, targetSize, cardPixels)
                            trySource(scaledSource, "Scaled Card ${targetSize}x${targetSize}")?.let { return it }
                        }
                    } catch (e: Exception) {
                        android.util.Log.w("QrCodeUtil", "Scaled card attempt failed: ${e.message}")
                    }
                }
            }
        } catch (e: Exception) {
            android.util.Log.w("QrCodeUtil", "White-card detection failed: ${e.message}")
        }

        // Strategy C: If screenshot (aspect ratio > 1.2), crop specific screen bands
        if (height > width * 1.2f) {
            // HandshakeScreen QR Card area (centered around Y: 35% - 75%, X: 10% - 90%)
            val screenCrops = listOf(
                "Handshake QR Center (35%-75%)" to Triple((width * 0.10f).toInt(), (height * 0.35f).toInt(), Pair((width * 0.80f).toInt(), (height * 0.40f).toInt())),
                "Handshake QR Extended (30%-80%)" to Triple((width * 0.05f).toInt(), (height * 0.30f).toInt(), Pair((width * 0.90f).toInt(), (height * 0.50f).toInt())),
                "Middle Screen (20%-80%)" to Triple(0, (height * 0.20f).toInt(), Pair(width, (height * 0.60f).toInt())),
                "Upper-Middle Screen (15%-65%)" to Triple(0, (height * 0.15f).toInt(), Pair(width, (height * 0.50f).toInt()))
            )

            for ((label, rect) in screenCrops) {
                try {
                    val (cropX, cropY, size) = rect
                    val (cropW, cropH) = size
                    val clampedX = cropX.coerceIn(0, width - 1)
                    val clampedY = cropY.coerceIn(0, height - 1)
                    val clampedW = cropW.coerceAtMost(width - clampedX)
                    val clampedH = cropH.coerceAtMost(height - clampedY)

                    if (clampedW > 100 && clampedH > 100) {
                        val cropped = fullSource.crop(clampedX, clampedY, clampedW, clampedH)
                        trySource(cropped, label)?.let { return it }

                        // Try scaled 600x600 for the center crop
                        if (label.startsWith("Handshake QR")) {
                            val cropBmp = Bitmap.createBitmap(safeBitmap, clampedX, clampedY, clampedW, clampedH)
                            val scaledCrop = Bitmap.createScaledBitmap(cropBmp, 600, 600, true)
                            val p = IntArray(360000)
                            scaledCrop.getPixels(p, 0, 600, 0, 0, 600, 600)
                            trySource(RGBLuminanceSource(600, 600, p), "$label Scaled 600x600")?.let { return it }
                        }
                    }
                } catch (e: Exception) {
                    android.util.Log.w("QrCodeUtil", "Screen crop $label failed: ${e.message}")
                }
            }
        }

        // Strategy D: Downscaled pass if original is high-res (e.g. > 800px)
        if (width > 800 || height > 800) {
            try {
                for (targetW in listOf(600, 800)) {
                    val targetH = (height * (targetW.toFloat() / width)).toInt()
                    val scaledBitmap = Bitmap.createScaledBitmap(safeBitmap, targetW, targetH, true)
                    val scaledPixels = IntArray(targetW * targetH)
                    scaledBitmap.getPixels(scaledPixels, 0, targetW, 0, 0, targetW, targetH)
                    val scaledSource = RGBLuminanceSource(targetW, targetH, scaledPixels)
                    trySource(scaledSource, "Downscaled ${targetW}px")?.let { return it }
                }
            } catch (e: Exception) {
                android.util.Log.w("QrCodeUtil", "Downscaled decode failed: ${e.message}")
            }
        }

        android.util.Log.w("QrCodeUtil", "All QR decode strategies failed for bitmap ${width}x${height}")
        return null
    }

    /**
     * Loads a Bitmap from a content Uri and extracts the QR code payload text.
     */
    fun decodeQrFromUri(context: Context, uri: Uri): String? {
        return try {
            val options = BitmapFactory.Options().apply {
                inPreferredConfig = Bitmap.Config.ARGB_8888
            }
            val inputStream = context.contentResolver.openInputStream(uri) ?: return null
            val decodedBitmap = BitmapFactory.decodeStream(inputStream, null, options)
            inputStream.close()
            if (decodedBitmap != null) {
                val nonHardwareBitmap = if (decodedBitmap.config == Bitmap.Config.HARDWARE) {
                    decodedBitmap.copy(Bitmap.Config.ARGB_8888, false) ?: decodedBitmap
                } else {
                    decodedBitmap
                }
                decodeQrFromBitmap(nonHardwareBitmap)
            } else {
                null
            }
        } catch (e: Exception) {
            android.util.Log.e("QrCodeUtil", "Error reading URI: ${e.message}", e)
            null
        }
    }
}

