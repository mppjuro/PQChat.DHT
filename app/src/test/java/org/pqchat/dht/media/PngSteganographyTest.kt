package org.pqchat.dht.media

import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.ui.util.QrCodeUtil

class PngSteganographyTest {

    @Test
    fun testPackAndUnpackStegoEnvelopeValid() {
        val payload = CryptoUtils.secureRandomBytes(864) // Handshake size
        val envelope = Png8Compressor.packStegoEnvelope(payload)

        // Envelope must have 4B magic + 2B length + 864B payload + 4B CRC32 = 874 bytes
        assertEquals(864 + Png8Compressor.STEG_HEADER_OVERHEAD, envelope.size)

        val unpacked = Png8Compressor.unpackStegoEnvelope(envelope)
        assertNotNull("Unpacked payload must not be null", unpacked)
        assertArrayEquals("Unpacked payload must match original", payload, unpacked)
    }

    @Test
    fun testUnpackStegoEnvelopeCorruptedCrcRejected() {
        val payload = CryptoUtils.secureRandomBytes(864)
        val envelope = Png8Compressor.packStegoEnvelope(payload)

        // Corrupt the CRC32 at the end
        envelope[envelope.size - 1] = (envelope[envelope.size - 1].toInt() xor 0xFF).toByte()

        val unpacked = Png8Compressor.unpackStegoEnvelope(envelope)
        assertNull("Corrupted CRC32 must cause unpack to return null", unpacked)
    }

    @Test
    fun testUnpackStegoEnvelopeBadMagicRejected() {
        val payload = CryptoUtils.secureRandomBytes(100)
        val envelope = Png8Compressor.packStegoEnvelope(payload)

        // Corrupt magic header
        envelope[0] = 'X'.code.toByte()

        val unpacked = Png8Compressor.unpackStegoEnvelope(envelope)
        assertNull("Invalid magic header must cause unpack to return null", unpacked)
    }

    @Test
    fun testUnpackStegoEnvelopeTruncatedRejected() {
        val payload = CryptoUtils.secureRandomBytes(100)
        val envelope = Png8Compressor.packStegoEnvelope(payload)

        val truncated = envelope.copyOf(envelope.size - 5)
        val unpacked = Png8Compressor.unpackStegoEnvelope(truncated)
        assertNull("Truncated envelope must return null", unpacked)
    }

    @Test
    fun testStegoCapacityValidation() {
        val payload = CryptoUtils.secureRandomBytes(864) // 864 bytes = 874 enveloped = 6,992 bits
        // A 20x20 image only has 400 pixels < 6,992 bits
        val smallPixels = IntArray(20 * 20) { 0xFF00FF00.toInt() }

        val ex = assertThrows(IllegalArgumentException::class.java) {
            Png8Compressor.encodePng8(20, 20, smallPixels, maxColors = 16, stegoPayload = payload)
        }
        assertTrue("Exception must mention insufficient capacity", ex.message!!.contains("capacity"))
    }

    @Test
    fun testPng8StegoEmbeddingAndExtractionRoundtrip() {
        val width = 200
        val height = 200 // 40,000 pixels > 6,992 bits
        val totalPixels = width * height
        val pixels = IntArray(totalPixels)

        // Create a realistic image pattern with varying color gradients
        for (y in 0 until height) {
            for (x in 0 until width) {
                val r = (x * 7 + y * 3) and 0xFF
                val g = (y * 5 + 40) and 0xFF
                val b = ((x + y) * 2 + 80) and 0xFF
                pixels[y * width + x] = (0xFF shl 24) or (r shl 16) or (g shl 8) or b
            }
        }

        val handshakePayload = CryptoUtils.secureRandomBytes(864)

        // Encode into PNG8 with stego payload
        val pngBytes = Png8Compressor.encodePng8(
            width = width,
            height = height,
            argbPixels = pixels,
            maxColors = 128,
            stegoPayload = handshakePayload
        )

        assertNotNull(pngBytes)
        assertTrue("PNG must start with standard PNG magic", pngBytes.size > 8)
        assertEquals(0x89.toByte(), pngBytes[0])
        assertEquals('P'.code.toByte(), pngBytes[1])
        assertEquals('N'.code.toByte(), pngBytes[2])
        assertEquals('G'.code.toByte(), pngBytes[3])

        // Extract stego payload directly from PNG8 bytes
        val extracted = Png8Compressor.extractStegoFromPng8(pngBytes)
        assertNotNull("Extracted payload must not be null", extracted)
        assertEquals(864, extracted!!.size)
        assertArrayEquals("Extracted handshake payload must exactly match original", handshakePayload, extracted)
    }

    @Test
    fun testNormalPngDoesNotReturnFalsePositiveStego() {
        val width = 100
        val height = 100
        val pixels = IntArray(width * height) { 0xFF336699.toInt() }

        // Encode normal PNG8 without stego payload
        val normalPng = Png8Compressor.encodePng8(width, height, pixels, maxColors = 32, stegoPayload = null)
        val extracted = Png8Compressor.extractStegoFromPng8(normalPng)

        assertNull("Normal non-steganographic image must return null", extracted)
    }

    @Test
    fun testArgbPixelLsbStegoEmbeddingAndExtraction() {
        val width = 150
        val height = 150
        val pixels = IntArray(width * height) { (0xFF shl 24) or (it and 0x00FFFFFF) }
        val secret = CryptoUtils.secureRandomBytes(864)

        val stegoPixels = Png8Compressor.embedInArgbPixels(width, height, pixels, secret)
        assertNotNull(stegoPixels)

        val recovered = Png8Compressor.extractFromArgbPixels(width, height, stegoPixels)
        assertNotNull(recovered)
        assertArrayEquals("Recovered payload from ARGB pixels must match original", secret, recovered)
    }

    @Test
    fun testHarmlessCarrierStegoRoundtripViaQrCodeUtil() {
        val handshakeBytes = CryptoUtils.secureRandomBytes(QrCodeUtil.STEG_HANDSHAKE_PAYLOAD_SIZE)

        // Generate harmless steganographic PNG
        val stegoPng = QrCodeUtil.generateHarmlessStegoPng(handshakeBytes, width = 300, height = 300)
        assertNotNull(stegoPng)

        // Extract using QrCodeUtil.extractHandshakeStego
        val extracted = QrCodeUtil.extractHandshakeStego(stegoPng)
        assertNotNull("Extracted handshake from harmless stego PNG must not be null", extracted)
        assertEquals(864, extracted!!.size)
        assertArrayEquals(handshakeBytes, extracted)
    }
}
