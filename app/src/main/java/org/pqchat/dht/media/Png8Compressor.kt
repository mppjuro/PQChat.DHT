package org.pqchat.dht.media

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.PriorityQueue
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.Inflater

/**
 * High-performance PNG8 (Indexed 8-bit color) encoder and compressor for DHT block transfers.
 *
 * Implements Median-Cut color quantization, perceptual RGB distance matching,
 * fast 15-bit color lookup caching, scanline generation, RFC 1950 zlib Deflate,
 * and post-quantization LSB steganography for metadata-free handshake exchange.
 */
object Png8Compressor {

    val PNG_MAGIC = byteArrayOf(
        0x89.toByte(), 0x50.toByte(), 0x4E.toByte(), 0x47.toByte(),
        0x0D.toByte(), 0x0A.toByte(), 0x1A.toByte(), 0x0A.toByte()
    )

    val STEG_MAGIC = byteArrayOf(0x50.toByte(), 0x51.toByte(), 0x53.toByte(), 0x54.toByte()) // "PQST"
    const val STEG_HEADER_OVERHEAD = 10 // 4B magic ("PQST") + 2B length UInt16 + 4B CRC32

    private val CHUNK_IHDR = "IHDR".toByteArray(Charsets.US_ASCII)
    private val CHUNK_PLTE = "PLTE".toByteArray(Charsets.US_ASCII)
    private val CHUNK_TRNS = "tRNS".toByteArray(Charsets.US_ASCII)
    private val CHUNK_IDAT = "IDAT".toByteArray(Charsets.US_ASCII)
    private val CHUNK_IEND = "IEND".toByteArray(Charsets.US_ASCII)

    /**
     * Packs an arbitrary binary payload into a self-authenticating steganographic envelope:
     * [0..3]: Magic "PQST" (4 bytes)
     * [4..5]: Payload length (2 bytes UInt16 Big-Endian)
     * [6..5+len]: Payload (len bytes)
     * [6+len..9+len]: CRC32 checksum over (Magic + Length + Payload) (4 bytes Big-Endian)
     */
    fun packStegoEnvelope(payload: ByteArray): ByteArray {
        require(payload.isNotEmpty()) { "Steganography payload cannot be empty" }
        require(payload.size <= 65535) { "Steganography payload exceeds maximum UInt16 size (65535 bytes)" }

        val len = payload.size
        val out = ByteArray(STEG_HEADER_OVERHEAD + len)
        out[0] = STEG_MAGIC[0]
        out[1] = STEG_MAGIC[1]
        out[2] = STEG_MAGIC[2]
        out[3] = STEG_MAGIC[3]
        out[4] = ((len ushr 8) and 0xFF).toByte()
        out[5] = (len and 0xFF).toByte()
        System.arraycopy(payload, 0, out, 6, len)

        val crc = CRC32()
        crc.update(out, 0, 6 + len)
        val crcVal = crc.value.toInt()
        out[6 + len] = ((crcVal ushr 24) and 0xFF).toByte()
        out[7 + len] = ((crcVal ushr 16) and 0xFF).toByte()
        out[8 + len] = ((crcVal ushr 8) and 0xFF).toByte()
        out[9 + len] = (crcVal and 0xFF).toByte()
        return out
    }

    /**
     * Unpacks and verifies a steganographic envelope. Returns the payload or null if invalid/corrupt.
     */
    fun unpackStegoEnvelope(envelope: ByteArray): ByteArray? {
        if (envelope.size < STEG_HEADER_OVERHEAD) return null
        if (envelope[0] != STEG_MAGIC[0] ||
            envelope[1] != STEG_MAGIC[1] ||
            envelope[2] != STEG_MAGIC[2] ||
            envelope[3] != STEG_MAGIC[3]
        ) {
            return null
        }
        val len = ((envelope[4].toInt() and 0xFF) shl 8) or (envelope[5].toInt() and 0xFF)
        if (len < 0 || envelope.size < STEG_HEADER_OVERHEAD + len) return null

        val expectedCrc = (
            ((envelope[6 + len].toInt() and 0xFF) shl 24) or
            ((envelope[7 + len].toInt() and 0xFF) shl 16) or
            ((envelope[8 + len].toInt() and 0xFF) shl 8) or
            (envelope[9 + len].toInt() and 0xFF)
        )

        val crc = CRC32()
        crc.update(envelope, 0, 6 + len)
        val actualCrc = crc.value.toInt()
        if (actualCrc != expectedCrc) return null

        val payload = ByteArray(len)
        System.arraycopy(envelope, 6, payload, 0, len)
        return payload
    }

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
        maxColors: Int = 128,
        stegoPayload: ByteArray? = null
    ): ByteArray {
        require(width > 0 && height > 0) { "Width and height must be positive" }
        require(argbPixels.size >= width * height) { "Pixel array size does not match width * height" }
        val targetColors = maxColors.coerceIn(2, 256)

        val stegoEnvelope = stegoPayload?.let { packStegoEnvelope(it) }
        val totalStegoBits = stegoEnvelope?.let { it.size * 8 } ?: 0
        if (totalStegoBits > 0) {
            require(width * height >= totalStegoBits) {
                "Carrier image has insufficient capacity (${width * height} pixels), but steganography requires at least $totalStegoBits pixels"
            }
        }

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

        val startIndexForOpaque = if (hasTransparency) 1 else 0

        // If steganography is active, ensure we have both even and odd indices for opaque colors
        if (stegoEnvelope != null) {
            val hasEvenOpaque = (startIndexForOpaque until paletteList.size).any { (it and 1) == 0 }
            val hasOddOpaque = (startIndexForOpaque until paletteList.size).any { (it and 1) == 1 }
            if (!hasEvenOpaque || !hasOddOpaque) {
                val refColor = if (paletteList.isNotEmpty()) paletteList.last() else intArrayOf(0, 0, 0)
                val perturbed = intArrayOf(
                    refColor[0],
                    refColor[1],
                    (refColor[2] xor 1).coerceIn(0, 255)
                )
                paletteList.add(perturbed)
            }
        }

        // Final palette array (K <= 256 entries)
        val palette = paletteList.toTypedArray()

        // 2. Fast 15-bit color lookup cache
        val colorCache = IntArray(32768) { -1 }

        // 3. Map pixels to palette indices & build uncompressed scanlines
        // Each scanline: [FilterByte = 0, idx0, idx1, ..., idx_{width-1}]
        val scanlines = ByteArray(height * (width + 1))
        var stegoBitIndex = 0

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

                val targetParity: Int? = if (stegoEnvelope != null && stegoBitIndex < totalStegoBits) {
                    val byteIdx = stegoBitIndex / 8
                    val bitInByte = 7 - (stegoBitIndex % 8)
                    val bit = (stegoEnvelope[byteIdx].toInt() ushr bitInByte) and 1
                    stegoBitIndex++
                    bit
                } else {
                    null
                }

                val idx: Int = if (targetParity != null) {
                    // Steganographic LSB modulation: select closest color with matching parity
                    var bestDist = Long.MAX_VALUE
                    var bestIdx = -1
                    for (pi in startIndexForOpaque until palette.size) {
                        if ((pi and 1) == targetParity) {
                            val pr = palette[pi][0]
                            val pg = palette[pi][1]
                            val pb = palette[pi][2]
                            val dr = r - pr
                            val dg = g - pg
                            val db = b - pb
                            val dist = 2L * dr * dr + 4L * dg * dg + 3L * db * db
                            if (dist < bestDist) {
                                bestDist = dist
                                bestIdx = pi
                                if (dist == 0L) break
                            }
                        }
                    }
                    if (bestIdx != -1) bestIdx else (startIndexForOpaque or targetParity).coerceIn(startIndexForOpaque, palette.size - 1)
                } else {
                    val key = ((r shr 3) shl 10) or ((g shr 3) shl 5) or (b shr 3)
                    var cachedIdx = colorCache[key]
                    if (cachedIdx == -1) {
                        var bestDist = Long.MAX_VALUE
                        var bestIdx = startIndexForOpaque
                        for (pi in startIndexForOpaque until palette.size) {
                            val pr = palette[pi][0]
                            val pg = palette[pi][1]
                            val pb = palette[pi][2]
                            val dr = r - pr
                            val dg = g - pg
                            val db = b - pb
                            val dist = 2L * dr * dr + 4L * dg * dg + 3L * db * db
                            if (dist < bestDist) {
                                bestDist = dist
                                bestIdx = pi
                                if (dist == 0L) break
                            }
                        }
                        cachedIdx = bestIdx
                        colorCache[key] = cachedIdx
                    }
                    cachedIdx
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

    /**
     * Extracts and authenticates an embedded steganographic payload from raw PNG8 file bytes.
     * Pure Kotlin logic with zero Android dependencies.
     *
     * @param pngBytes Raw PNG file bytes
     * @return Decoded payload ByteArray or null if no valid steganographic carrier is found
     */
    fun extractStegoFromPng8(pngBytes: ByteArray): ByteArray? {
        if (pngBytes.size < 8) return null
        for (i in 0 until 8) {
            if (pngBytes[i] != PNG_MAGIC[i]) return null
        }

        var offset = 8
        var width = 0
        var height = 0
        val idatBaos = ByteArrayOutputStream()

        while (offset + 8 <= pngBytes.size) {
            val chunkLen = (
                ((pngBytes[offset].toInt() and 0xFF) shl 24) or
                ((pngBytes[offset + 1].toInt() and 0xFF) shl 16) or
                ((pngBytes[offset + 2].toInt() and 0xFF) shl 8) or
                (pngBytes[offset + 3].toInt() and 0xFF)
            )
            if (chunkLen < 0 || offset + 8 + chunkLen + 4 > pngBytes.size) break
            val typeStr = String(pngBytes, offset + 4, 4, Charsets.US_ASCII)
            val dataOffset = offset + 8

            when (typeStr) {
                "IHDR" -> {
                    if (chunkLen >= 8) {
                        width = (
                            ((pngBytes[dataOffset].toInt() and 0xFF) shl 24) or
                            ((pngBytes[dataOffset + 1].toInt() and 0xFF) shl 16) or
                            ((pngBytes[dataOffset + 2].toInt() and 0xFF) shl 8) or
                            (pngBytes[dataOffset + 3].toInt() and 0xFF)
                        )
                        height = (
                            ((pngBytes[dataOffset + 4].toInt() and 0xFF) shl 24) or
                            ((pngBytes[dataOffset + 5].toInt() and 0xFF) shl 16) or
                            ((pngBytes[dataOffset + 6].toInt() and 0xFF) shl 8) or
                            (pngBytes[dataOffset + 7].toInt() and 0xFF)
                        )
                    }
                }
                "IDAT" -> {
                    idatBaos.write(pngBytes, dataOffset, chunkLen)
                }
                "IEND" -> {
                    break
                }
            }
            offset += 8 + chunkLen + 4 // chunk header (8) + data + crc (4)
        }

        if (width <= 0 || height <= 0 || idatBaos.size() == 0) return null

        val idatBytes = idatBaos.toByteArray()
        val inflater = Inflater()
        inflater.setInput(idatBytes)
        val scanlinesBaos = ByteArrayOutputStream(height * (width + 1))
        val buffer = ByteArray(16384)
        try {
            while (!inflater.finished()) {
                val count = inflater.inflate(buffer)
                if (count == 0 && inflater.needsInput()) break
                scanlinesBaos.write(buffer, 0, count)
            }
        } catch (_: Exception) {
            return null
        } finally {
            inflater.end()
        }

        val scanlines = scanlinesBaos.toByteArray()
        val expectedScanlinesLen = height * (width + 1)
        if (scanlines.size < expectedScanlinesLen) return null

        val totalPixels = width * height
        if (totalPixels < STEG_HEADER_OVERHEAD * 8) return null

        // Extract bits row by row, skipping filter bytes at start of each line
        val bits = ArrayList<Int>(minOf(totalPixels, 65536 * 8))
        for (y in 0 until height) {
            val rowOffset = y * (width + 1)
            for (x in 0 until width) {
                val idxByte = scanlines[rowOffset + 1 + x].toInt() and 0xFF
                bits.add(idxByte and 1)
            }
        }

        // Fast reject check: first 4 bytes (32 bits) must match STEG_MAGIC
        if (bits.size < 32) return null
        val magic = ByteArray(4)
        for (b in 0 until 4) {
            var byteVal = 0
            for (k in 0 until 8) {
                byteVal = (byteVal shl 1) or bits[b * 8 + k]
            }
            magic[b] = byteVal.toByte()
        }
        if (magic[0] != STEG_MAGIC[0] ||
            magic[1] != STEG_MAGIC[1] ||
            magic[2] != STEG_MAGIC[2] ||
            magic[3] != STEG_MAGIC[3]
        ) {
            return null
        }

        // Read payload length (bytes 4..5)
        if (bits.size < 48) return null
        var lenVal = 0
        for (k in 0 until 16) {
            lenVal = (lenVal shl 1) or bits[32 + k]
        }
        if (lenVal <= 0 || lenVal > 65535) return null

        val totalBytes = STEG_HEADER_OVERHEAD + lenVal
        if (bits.size < totalBytes * 8) return null

        val envelope = ByteArray(totalBytes)
        envelope[0] = magic[0]
        envelope[1] = magic[1]
        envelope[2] = magic[2]
        envelope[3] = magic[3]
        envelope[4] = ((lenVal ushr 8) and 0xFF).toByte()
        envelope[5] = (lenVal and 0xFF).toByte()

        for (b in 6 until totalBytes) {
            var byteVal = 0
            for (k in 0 until 8) {
                byteVal = (byteVal shl 1) or bits[b * 8 + k]
            }
            envelope[b] = byteVal.toByte()
        }

        return unpackStegoEnvelope(envelope)
    }

    /**
     * Embeds arbitrary payload into the LSB of the Blue channel of an ARGB pixel buffer.
     */
    fun embedInArgbPixels(width: Int, height: Int, argbPixels: IntArray, payload: ByteArray): IntArray {
        val envelope = packStegoEnvelope(payload)
        val totalBits = envelope.size * 8
        require(width * height >= totalBits) {
            "Pixel array capacity (${width * height}) is smaller than required bits ($totalBits)"
        }

        val result = argbPixels.copyOf()
        for (i in 0 until totalBits) {
            val byteIdx = i / 8
            val bitInByte = 7 - (i % 8)
            val bit = (envelope[byteIdx].toInt() ushr bitInByte) and 1
            val orig = result[i]
            result[i] = (orig and 0xFFFFFFFE.toInt()) or bit
        }
        return result
    }

    /**
     * Extracts and authenticates an embedded payload from the LSB of the Blue channel of ARGB pixels.
     */
    fun extractFromArgbPixels(width: Int, height: Int, argbPixels: IntArray): ByteArray? {
        val totalPixels = minOf(width * height, argbPixels.size)
        if (totalPixels < STEG_HEADER_OVERHEAD * 8) return null

        // Read first 6 bytes (48 bits) to inspect magic & length
        val headerBytes = ByteArray(6)
        for (b in 0 until 6) {
            var byteVal = 0
            for (k in 0 until 8) {
                val bit = argbPixels[b * 8 + k] and 1
                byteVal = (byteVal shl 1) or bit
            }
            headerBytes[b] = byteVal.toByte()
        }

        if (headerBytes[0] != STEG_MAGIC[0] ||
            headerBytes[1] != STEG_MAGIC[1] ||
            headerBytes[2] != STEG_MAGIC[2] ||
            headerBytes[3] != STEG_MAGIC[3]
        ) {
            return null
        }

        val len = ((headerBytes[4].toInt() and 0xFF) shl 8) or (headerBytes[5].toInt() and 0xFF)
        if (len <= 0 || len > 65535) return null
        val totalBytes = STEG_HEADER_OVERHEAD + len
        if (totalPixels < totalBytes * 8) return null

        val envelope = ByteArray(totalBytes)
        System.arraycopy(headerBytes, 0, envelope, 0, 6)
        for (b in 6 until totalBytes) {
            var byteVal = 0
            for (k in 0 until 8) {
                val bit = argbPixels[b * 8 + k] and 1
                byteVal = (byteVal shl 1) or bit
            }
            envelope[b] = byteVal.toByte()
        }

        return unpackStegoEnvelope(envelope)
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
     * quantizes colors to [maxColors], and encodes to PNG8 format with optional steganographic payload.
     */
    fun compressBitmapToPng8(
        bitmap: Bitmap,
        maxEdge: Int = 1000,
        maxColors: Int = 128,
        stegoPayload: ByteArray? = null
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

        return encodePng8(w, h, pixels, maxColors, stegoPayload)
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

    /**
     * Embeds [stegoPayload] inside [rawImageBytes] by decoding into a Bitmap and encoding to PNG8.
     */
    fun embedStegoInPng(
        rawImageBytes: ByteArray,
        stegoPayload: ByteArray,
        maxEdge: Int = 1000,
        maxColors: Int = 128
    ): ByteArray {
        val bitmap = BitmapFactory.decodeByteArray(rawImageBytes, 0, rawImageBytes.size)
            ?: throw IllegalArgumentException("Could not decode carrier image bytes")
        return compressBitmapToPng8(bitmap, maxEdge, maxColors, stegoPayload)
    }
}
