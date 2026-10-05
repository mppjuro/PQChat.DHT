package org.pqchat.dht.ui.util

import android.graphics.Bitmap
import android.graphics.Color
import android.util.Base64
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
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
                bitmap.setPixel(x, y, if (bitMatrix.get(x, y)) Color.WHITE else Color.BLACK)
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
}
