package org.pqchat.dht.media

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.PriorityQueue
import java.util.zip.CRC32
import java.util.zip.Deflater

/**
 * High-performance PNG8 (Indexed 8-bit color) encoder and compressor for DHT block transfers.
 *
 * Implements Median-Cut color quantization, perceptual RGB distance matching,
 * fast 15-bit color lookup caching, scanline generation, and RFC 1950 zlib Deflate.
 */
object Png8Compressor {

    val PNG_MAGIC = byteArrayOf(
        0x89.toByte(), 0x50.toByte(), 0x4E.toByte(), 0x47.toByte(),
        0x0D.toByte(), 0x0A.toByte(), 0x1A.toByte(), 0x0A.toByte()
    )

    private val CHUNK_IHDR = "IHDR".toByteArray(Charsets.US_ASCII)
    private val CHUNK_PLTE = "PLTE".toByteArray(Charsets.US_ASCII)
    private val CHUNK_TRNS = "tRNS".toByteArray(Charsets.US_ASCII)
    private val CHUNK_IDAT = "IDAT".toByteArray(Charsets.US_ASCII)
    private val CHUNK_IEND = "IEND".toByteArray(Charsets.US_ASCII)

    /**
     * Color bin for histogram gathering before median cut.
     */
    private class ColorBin(
        val r: Int,
        val g: Int,
        val b: Int,
        var count: Int
    )

    /**
     * Box representing a subspace in RGB color space for Median Cut.
     */
    private class ColorBox(val items: MutableList<ColorBin>) {
        var minR = 255; var maxR = 0
        var minG = 255; var maxG = 0
        var minB = 255; var maxB = 0
        var totalCount = 0L

        init {
            recompute()
        }

        fun recompute() {
            minR = 255; maxR = 0
            minG = 255; maxG = 0
            minB = 255; maxB = 0
            totalCount = 0L
            for (item in items) {
                if (item.r < minR) minR = item.r
                if (item.r > maxR) maxR = item.r
                if (item.g < minG) minG = item.g
                if (item.g > maxG) maxG = item.g
                if (item.b < minB) minB = item.b
                if (item.b > maxB) maxB = item.b
                totalCount += item.count
            }
        }

        val rangeR: Int get() = maxR - minR
        val rangeG: Int get() = maxG - minG
        val rangeB: Int get() = maxB - minB
        val maxRange: Int get() = maxOf(rangeR, rangeG, rangeB)
    }

    /**
     * Encodes raw ARGB pixels into a valid PNG8 (Color Type 3 - Indexed Color) binary.
     * Pure Kotlin/JVM logic with zero Android framework dependencies.
     *
     * @param width Image width in pixels
     * @param height Image height in pixels
     * @param argbPixels Array of ARGB_8888 formatted integer pixels
     * @param maxColors Number of colors in palette (2..256)
     * @return Full PNG8 byte array including signature, IHDR, PLTE, optional tRNS, IDAT and IEND
     */
    fun encodePng8(
        width: Int,
        height: Int,
        argbPixels: IntArray,
        maxColors: Int = 128
    ): ByteArray {
        require(width > 0 && height > 0) { "Width and height must be positive" }
        require(argbPixels.size >= width * height) { "Pixel array size does not match width * height" }
        val targetColors = maxColors.coerceIn(2, 256)

        // 1. Separate transparent pixels and build color histogram
        var hasTransparency = false
        val binsMap = HashMap<Int, ColorBin>(1024)

        for (i in 0 until (width * height)) {
            val p = argbPixels[i]
            val a = (p ushr 24) and 0xFF
            if (a < 32) {
                hasTransparency = true
                continue
            }
            val r = (p ushr 16) and 0xFF
            val g = (p ushr 8) and 0xFF
            val b = p and 0xFF

            // 5-bit RGB quantization for histogram binning
            val key = ((r shr 3) shl 10) or ((g shr 3) shl 5) or (b shr 3)
            val bin = binsMap[key]
            if (bin != null) {
                bin.count++
            } else {
                binsMap[key] = ColorBin(r, g, b, 1)
            }
        }

        val colorBudget = if (hasTransparency) targetColors - 1 else targetColors
        val paletteList = ArrayList<IntArray>()

        if (hasTransparency) {
            // Index 0 reserved for transparency
            paletteList.add(intArrayOf(0, 0, 0))
        }

        if (binsMap.isEmpty()) {
            // Completely transparent or blank
            paletteList.add(intArrayOf(0, 0, 0))
        } else if (binsMap.size <= colorBudget) {
            // Colors fit within budget directly
            for (bin in binsMap.values) {
                paletteList.add(intArrayOf(bin.r, bin.g, bin.b))
            }
        } else {
            // Run Median Cut quantization
            val queue = PriorityQueue<ColorBox>(compareByDescending { it.maxRange })
            queue.add(ColorBox(binsMap.values.toMutableList()))

            while (queue.size < colorBudget) {
                val box = queue.poll() ?: break
                if (box.maxRange == 0 || box.items.size <= 1) {
                    queue.add(box)
                    break
                }

                // Pick axis with largest spread
                when {
                    box.rangeR >= box.rangeG && box.rangeR >= box.rangeB -> {
                        box.items.sortBy { it.r }
                    }
                    box.rangeG >= box.rangeB -> {
                        box.items.sortBy { it.g }
                    }
                    else -> {
                        box.items.sortBy { it.b }
                    }
                }

                // Weighted median split
                val halfCount = box.totalCount / 2
                var acc = 0L
                var splitIdx = 1
                for (j in box.items.indices) {
                    acc += box.items[j].count
                    if (acc >= halfCount) {
                        splitIdx = j
                        break
                    }
                }
                splitIdx = splitIdx.coerceIn(1, box.items.size - 1)

                val items1 = box.items.subList(0, splitIdx).toMutableList()
                val items2 = box.items.subList(splitIdx, box.items.size).toMutableList()

                queue.add(ColorBox(items1))
                queue.add(ColorBox(items2))
            }

            for (box in queue) {
                var sumR = 0L
                var sumG = 0L
                var sumB = 0L
                for (it in box.items) {
                    sumR += it.r.toLong() * it.count
                    sumG += it.g.toLong() * it.count
                    sumB += it.b.toLong() * it.count
                }
                val avgR = (sumR / box.totalCount).toInt().coerceIn(0, 255)
                val avgG = (sumG / box.totalCount).toInt().coerceIn(0, 255)
                val avgB = (sumB / box.totalCount).toInt().coerceIn(0, 255)
                paletteList.add(intArrayOf(avgR, avgG, avgB))
            }
        }

        // Final palette array (K <= 256 entries)
        val palette = paletteList.toTypedArray()
        val startIndexForOpaque = if (hasTransparency) 1 else 0

        // 2. Fast 15-bit color lookup cache
        val colorCache = IntArray(32768) { -1 }

        // 3. Map pixels to palette indices & build uncompressed scanlines
        // Each scanline: [FilterByte = 0, idx0, idx1, ..., idx_{width-1}]
        val scanlines = ByteArray(height * (width + 1))

        for (y in 0 until height) {
            val rowOffset = y * (width + 1)
            scanlines[rowOffset] = 0 // Filter None

            for (x in 0 until width) {
                val p = argbPixels[y * width + x]
                val a = (p ushr 24) and 0xFF
                if (hasTransparency && a < 32) {
                    scanlines[rowOffset + 1 + x] = 0 // Transparent index
                    continue
                }

                val r = (p ushr 16) and 0xFF
                val g = (p ushr 8) and 0xFF
                val b = p and 0xFF

                val key = ((r shr 3) shl 10) or ((g shr 3) shl 5) or (b shr 3)
                var idx = colorCache[key]
                if (idx == -1) {
                    var bestDist = Long.MAX_VALUE
                    var bestIdx = startIndexForOpaque
                    for (pi in startIndexForOpaque until palette.size) {
                        val pr = palette[pi][0]
                        val pg = palette[pi][1]
                        val pb = palette[pi][2]
                        val dr = r - pr
                        val dg = g - pg
                        val db = b - pb
                        // Weighted Euclidean perceptual distance
                        val dist = 2L * dr * dr + 4L * dg * dg + 3L * db * db
                        if (dist < bestDist) {
                            bestDist = dist
                            bestIdx = pi
                            if (dist == 0L) break
                        }
                    }
                    idx = bestIdx
                    colorCache[key] = idx
                }

                scanlines[rowOffset + 1 + x] = idx.toByte()
            }
        }

        // 4. Deflate compress scanlines (zlib stream)
        val deflater = Deflater(Deflater.BEST_COMPRESSION)
        deflater.setInput(scanlines)
        deflater.finish()

        val idatBaos = ByteArrayOutputStream(scanlines.size / 2)
        val defBuffer = ByteArray(16384)
        while (!deflater.finished()) {
            val count = deflater.deflate(defBuffer)
            idatBaos.write(defBuffer, 0, count)
        }
        deflater.end()
        val idatData = idatBaos.toByteArray()

        // 5. Build PNG Chunks
        val pngOut = ByteArrayOutputStream(idatData.size + 1024)
        val dos = DataOutputStream(pngOut)

        // Signature
        dos.write(PNG_MAGIC)

        // IHDR Chunk (13 bytes)
        val ihdrBytes = ByteArray(13)
        ihdrBytes[0] = (width ushr 24).toByte()
        ihdrBytes[1] = (width ushr 16).toByte()
        ihdrBytes[2] = (width ushr 8).toByte()
        ihdrBytes[3] = width.toByte()
        ihdrBytes[4] = (height ushr 24).toByte()
        ihdrBytes[5] = (height ushr 16).toByte()
        ihdrBytes[6] = (height ushr 8).toByte()
        ihdrBytes[7] = height.toByte()
        ihdrBytes[8] = 8.toByte()  // Bit depth 8
        ihdrBytes[9] = 3.toByte()  // Color type 3: Indexed-color
        ihdrBytes[10] = 0.toByte() // Compression 0: Deflate
        ihdrBytes[11] = 0.toByte() // Filter 0
        ihdrBytes[12] = 0.toByte() // Interlace 0
        writeChunk(dos, CHUNK_IHDR, ihdrBytes)

        // PLTE Chunk (3 bytes per color entry)
        val plteBytes = ByteArray(palette.size * 3)
        for (i in palette.indices) {
            plteBytes[i * 3] = palette[i][0].toByte()
            plteBytes[i * 3 + 1] = palette[i][1].toByte()
            plteBytes[i * 3 + 2] = palette[i][2].toByte()
        }
        writeChunk(dos, CHUNK_PLTE, plteBytes)

        // tRNS Chunk (if transparency was present, index 0 is transparent)
        if (hasTransparency) {
            writeChunk(dos, CHUNK_TRNS, byteArrayOf(0.toByte()))
        }

        // IDAT Chunk
        writeChunk(dos, CHUNK_IDAT, idatData)

        // IEND Chunk
        writeChunk(dos, CHUNK_IEND, ByteArray(0))

        dos.flush()
        return pngOut.toByteArray()
    }

    private fun writeChunk(dos: DataOutputStream, type: ByteArray, data: ByteArray) {
        dos.writeInt(data.size)
        dos.write(type)
        dos.write(data)

        val crc = CRC32()
        crc.update(type)
        crc.update(data)
        dos.writeInt(crc.value.toInt())
    }

    /**
     * Resizes the Bitmap so that its longest edge does not exceed [maxEdge],
     * quantizes colors to [maxColors], and encodes to PNG8 format.
     */
    fun compressBitmapToPng8(
        bitmap: Bitmap,
        maxEdge: Int = 1000,
        maxColors: Int = 128
    ): ByteArray {
        val origW = bitmap.width
        val origH = bitmap.height
        val maxDim = maxOf(origW, origH)

        val scaled = if (maxEdge > 0 && maxDim > maxEdge) {
            val scale = maxEdge.toFloat() / maxDim
            val targetW = (origW * scale).toInt().coerceAtLeast(1)
            val targetH = (origH * scale).toInt().coerceAtLeast(1)
            Bitmap.createScaledBitmap(bitmap, targetW, targetH, true)
        } else {
            bitmap
        }

        val w = scaled.width
        val h = scaled.height
        val pixels = IntArray(w * h)
        scaled.getPixels(pixels, 0, w, 0, 0, w, h)

        return encodePng8(w, h, pixels, maxColors)
    }

    /**
     * Decodes [rawBytes] into a Bitmap, resizes to [maxEdge],
     * quantizes to [maxColors], and encodes as PNG8.
     * Falls back to original [rawBytes] if decoding fails.
     */
    fun compressToPng8(
        rawBytes: ByteArray,
        maxEdge: Int = 1000,
        maxColors: Int = 128
    ): ByteArray {
        return try {
            val bitmap = BitmapFactory.decodeByteArray(rawBytes, 0, rawBytes.size)
            if (bitmap != null) {
                compressBitmapToPng8(bitmap, maxEdge, maxColors)
            } else {
                rawBytes
            }
        } catch (_: Exception) {
            rawBytes
        }
    }
}
