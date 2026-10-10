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

    /**
     * Generates a Bitmap containing the QR code for binary data.
     */
    fun generateQrBitmap(data: ByteArray, size: Int = 600): Bitmap {
        val base64Data = Base64.encodeToString(data, Base64.NO_WRAP)
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
        val clean = qrString.trim()
        return Base64.decode(clean, Base64.DEFAULT)
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

