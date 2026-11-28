package org.pqchat.dht.dht.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import org.pqchat.dht.media.Png8Compressor

/**
 * Official Jazzer fuzz target for [Png8Compressor] steganography and PNG8 parser routines.
 * Validates resilience against crafted IHDR dimensions, malformed PNG chunks, IDAT zip-bombs,
 * and corrupted PQST envelopes.
 */
object Png8CompressorFuzzTarget {

    @JvmStatic
    fun fuzzerTestOneInput(input: ByteArray) {
        // 1. Direct PQST envelope decoder
        try {
            Png8Compressor.unpackStegoEnvelope(input)
        } catch (_: IllegalArgumentException) {
        }

        // 2. Raw PNG8 chunk + Inflater steganography extractor
        try {
            Png8Compressor.extractStegoFromPng8(input)
        } catch (_: IllegalArgumentException) {
        }

        // 3. Direct ARGB pixel LSB extractor with fuzzed bounded dimensions
        if (input.size >= 8) {
            val w = ((input[0].toInt() and 0xFF) % 16) + 1
            val h = ((input[1].toInt() and 0xFF) % 16) + 1
            val pixelCount = w * h
            val pixels = IntArray(pixelCount) { idx ->
                val b0 = input[(2 + (idx * 4) % (input.size - 2))].toInt() and 0xFF
                val b1 = input[(2 + (idx * 4 + 1) % (input.size - 2))].toInt() and 0xFF
                val b2 = input[(2 + (idx * 4 + 2) % (input.size - 2))].toInt() and 0xFF
                (0xFF shl 24) or (b0 shl 16) or (b1 shl 8) or b2
            }
            try {
                Png8Compressor.extractFromArgbPixels(w, h, pixels)
            } catch (_: IllegalArgumentException) {
            }

            if (input.size >= 16) {
                val maxColors = ((input[2].toInt() and 0xFF) % 249) + 8
                val stegoSliceLen = ((input[3].toInt() and 0xFF) % minOf(32, input.size)).coerceAtLeast(1)
                val stegoPayload = input.copyOfRange(0, stegoSliceLen)
                try {
                    val png = Png8Compressor.encodePng8(w, h, pixels, maxColors = maxColors, stegoPayload = stegoPayload)
                    Png8Compressor.extractStegoFromPng8(png)
                } catch (_: IllegalArgumentException) {
                }
            }
        }
    }

    @JvmStatic
    fun fuzzerTestOneInput(data: FuzzedDataProvider) {
        fuzzerTestOneInput(data.consumeRemainingAsBytes())
    }
}
