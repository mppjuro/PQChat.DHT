package org.pqchat.dht.media

import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.data.settings.DefaultImageCompression
import org.pqchat.dht.protocol.ChunkingEngine
import java.nio.ByteBuffer
import java.nio.ByteOrder

class Png8CompressorTest {

    @Test
    fun testPng8SignatureAndMagicBytes() {
        val width = 10
        val height = 10
        val pixels = IntArray(width * height) { 0xFF00FF00.toInt() } // Opaque Green

        val png = Png8Compressor.encodePng8(width, height, pixels, maxColors = 16)

        assertNotNull(png)
        assertTrue(png.size > 8)

        // Check 8-byte PNG magic signature
        for (i in 0 until 8) {
            assertEquals("Magic byte at index $i mismatch", Png8Compressor.PNG_MAGIC[i], png[i])
        }

        // Verify compatibility with ChunkingEngine.isPngImage
        assertTrue("Must be recognized as PNG by ChunkingEngine", ChunkingEngine.isPngImage(png))
    }

    @Test
    fun testIhdrChunkStructure() {
        val width = 120
        val height = 80
        val pixels = IntArray(width * height) { 0xFFFF0000.toInt() } // Opaque Red

        val png = Png8Compressor.encodePng8(width, height, pixels, maxColors = 64)

        val buffer = ByteBuffer.wrap(png).order(ByteOrder.BIG_ENDIAN)

        // Skip 8-byte PNG signature
        buffer.position(8)

        // IHDR Chunk: length (4 bytes), type (4 bytes: "IHDR")
        val ihdrLength = buffer.int
        assertEquals(13, ihdrLength)

        val ihdrType = ByteArray(4)
        buffer.get(ihdrType)
        assertEquals("IHDR", String(ihdrType, Charsets.US_ASCII))

        val encodedWidth = buffer.int
        val encodedHeight = buffer.int
        val bitDepth = buffer.get().toInt() and 0xFF
        val colorType = buffer.get().toInt() and 0xFF
        val compressionMethod = buffer.get().toInt() and 0xFF
        val filterMethod = buffer.get().toInt() and 0xFF
        val interlaceMethod = buffer.get().toInt() and 0xFF

        assertEquals(120, encodedWidth)
        assertEquals(80, encodedHeight)
        assertEquals("Bit depth must be 8 for PNG8", 8, bitDepth)
        assertEquals("Color type must be 3 (Indexed color) for PNG8", 3, colorType)
        assertEquals(0, compressionMethod)
        assertEquals(0, filterMethod)
        assertEquals(0, interlaceMethod)
    }

    @Test
    fun testPlteChunkAndColorQuantizationBudget() {
        val width = 50
        val height = 50
        val totalPixels = width * height
        val pixels = IntArray(totalPixels)

        // Generate gradient with many distinct colors
        for (y in 0 until height) {
            for (x in 0 until width) {
                val r = (x * 5) and 0xFF
                val g = (y * 5) and 0xFF
                val b = ((x + y) * 2) and 0xFF
                pixels[y * width + x] = (0xFF shl 24) or (r shl 16) or (g shl 8) or b
            }
        }

        // Encode with 16 colors
        val png16 = Png8Compressor.encodePng8(width, height, pixels, maxColors = 16)
        val paletteSize16 = extractPlteEntryCount(png16)
        assertTrue("Palette size for maxColors=16 must be <= 16", paletteSize16 <= 16)

        // Encode with 64 colors
        val png64 = Png8Compressor.encodePng8(width, height, pixels, maxColors = 64)
        val paletteSize64 = extractPlteEntryCount(png64)
        assertTrue("Palette size for maxColors=64 must be <= 64", paletteSize64 <= 64)

        // Encode with 256 colors
        val png256 = Png8Compressor.encodePng8(width, height, pixels, maxColors = 256)
        val paletteSize256 = extractPlteEntryCount(png256)
        assertTrue("Palette size for maxColors=256 must be <= 256", paletteSize256 <= 256)

        // Noticeably fewer colors compress to fewer bytes or equal
        assertTrue(png16.size <= png256.size)
    }

    @Test
    fun testTransparencyGeneratesTrnsChunk() {
        val width = 20
        val height = 20
        val pixels = IntArray(width * height)

        for (i in pixels.indices) {
            if (i % 2 == 0) {
                pixels[i] = 0x00000000 // Fully transparent
            } else {
                pixels[i] = 0xFF0000FF.toInt() // Opaque Blue
            }
        }

        val png = Png8Compressor.encodePng8(width, height, pixels, maxColors = 32)
        assertTrue(hasChunk(png, "tRNS"))
    }

    @Test
    fun testIdatAndIendPresence() {
        val width = 16
        val height = 16
        val pixels = IntArray(width * height) { 0xFF123456.toInt() }

        val png = Png8Compressor.encodePng8(width, height, pixels, maxColors = 8)

        assertTrue("Must contain IDAT chunk", hasChunk(png, "IDAT"))
        assertTrue("Must contain IEND chunk", hasChunk(png, "IEND"))

        // End of file must terminate with IEND
        val last12Bytes = png.copyOfRange(png.size - 12, png.size)
        val typeBytes = last12Bytes.copyOfRange(4, 8)
        assertEquals("IEND", String(typeBytes, Charsets.US_ASCII))
    }

    @Test
    fun testSettingsManagerImageCompressionDefaultsAndClamping() {
        val settings = AppSettingsManager(null)

        // Default values
        assertEquals(DefaultImageCompression.DEFAULT_MAX_EDGE, settings.imageMaxEdge.value)
        assertEquals(1000, settings.imageMaxEdge.value)

        assertEquals(DefaultImageCompression.DEFAULT_COLOR_COUNT, settings.imageColorCount.value)
        assertEquals(128, settings.imageColorCount.value)

        // Max edge setter and clamping
        settings.setImageMaxEdge(800)
        assertEquals(800, settings.imageMaxEdge.value)

        settings.setImageMaxEdge(100) // Below MIN_MAX_EDGE (400)
        assertEquals(400, settings.imageMaxEdge.value)

        settings.setImageMaxEdge(3000) // Above MAX_MAX_EDGE (1600)
        assertEquals(1600, settings.imageMaxEdge.value)

        // Color count setter and clamping
        settings.setImageColorCount(64)
        assertEquals(64, settings.imageColorCount.value)

        settings.setImageColorCount(2) // Below MIN_COLORS (8)
        assertEquals(8, settings.imageColorCount.value)

        settings.setImageColorCount(500) // Above MAX_COLORS (256)
        assertEquals(256, settings.imageColorCount.value)
    }

    private fun extractPlteEntryCount(png: ByteArray): Int {
        val buffer = ByteBuffer.wrap(png).order(ByteOrder.BIG_ENDIAN)
        buffer.position(8) // Skip signature

        while (buffer.remaining() >= 8) {
            val length = buffer.int
            val typeBytes = ByteArray(4)
            buffer.get(typeBytes)
            val type = String(typeBytes, Charsets.US_ASCII)

            if (type == "PLTE") {
                return length / 3
            }

            buffer.position(buffer.position() + length + 4) // Skip data + CRC
        }
        return -1
    }

    private fun hasChunk(png: ByteArray, targetType: String): Boolean {
        val buffer = ByteBuffer.wrap(png).order(ByteOrder.BIG_ENDIAN)
        buffer.position(8)

        while (buffer.remaining() >= 8) {
            val length = buffer.int
            val typeBytes = ByteArray(4)
            buffer.get(typeBytes)
            val type = String(typeBytes, Charsets.US_ASCII)

            if (type == targetType) {
                return true
            }

            buffer.position(buffer.position() + length + 4)
        }
        return false
    }
}
