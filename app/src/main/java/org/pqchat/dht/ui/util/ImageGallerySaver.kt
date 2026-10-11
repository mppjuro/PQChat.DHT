package org.pqchat.dht.ui.util

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File
import java.io.FileOutputStream

object ImageGallerySaver {

    /**
     * Saves an image byte array (e.g. PNG) into the device's public photo gallery.
     * Compatible with modern Android Scoped Storage (API 29+) as well as legacy storage.
     */
    fun saveImageToGallery(
        context: Context,
        imageBytes: ByteArray,
        filenamePrefix: String = "PQChat"
    ): Boolean {
        if (imageBytes.isEmpty()) return false
        val timestamp = System.currentTimeMillis()
        val filename = "${filenamePrefix}_$timestamp.png"

        return try {
            val resolver = context.contentResolver
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, filename)
                    put(MediaStore.MediaColumns.MIME_TYPE, "image/png")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/PQChat")
                    put(MediaStore.MediaColumns.IS_PENDING, 1)
                }
                val uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues) ?: return false

                val writeSuccessful = resolver.openOutputStream(uri)?.use { out ->
                    out.write(imageBytes)
                    out.flush()
                    true
                } ?: false

                if (writeSuccessful) {
                    contentValues.clear()
                    contentValues.put(MediaStore.MediaColumns.IS_PENDING, 0)
                    resolver.update(uri, contentValues, null, null)
                    true
                } else {
                    resolver.delete(uri, null, null)
                    false
                }
            } else {
                val picturesDir = File(
                    Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES),
                    "PQChat"
                )
                if (!picturesDir.exists()) {
                    picturesDir.mkdirs()
                }
                val file = File(picturesDir, filename)
                FileOutputStream(file).use { out ->
                    out.write(imageBytes)
                    out.flush()
                }
                android.media.MediaScannerConnection.scanFile(
                    context,
                    arrayOf(file.absolutePath),
                    arrayOf("image/png"),
                    null
                )
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}
