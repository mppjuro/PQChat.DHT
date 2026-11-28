package org.pqchat.dht.dht.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.KeystoreCrypto
import org.pqchat.dht.media.Png8Compressor
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.Security
import java.util.Random
import java.util.zip.Deflater
import javax.crypto.spec.SecretKeySpec

class JazzerFuzzTest {

    companion object {
        @JvmStatic
        @BeforeAll
        fun setupSecurity() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }

        @JvmStatic
        @AfterAll
        fun tearDownSecurity() {
            KeystoreCrypto.resetForTesting()
        }
    }

    @FuzzTest(maxDuration = "3s")
    fun fuzzBencode(data: FuzzedDataProvider) {
        val input = data.consumeRemainingAsBytes()
        BencodeFuzzTarget.fuzzerTestOneInput(input)
    }

    @FuzzTest(maxDuration = "3s")
    fun fuzzKrpcMessage(data: FuzzedDataProvider) {
        val input = data.consumeRemainingAsBytes()
        KrpcMessageFuzzTarget.fuzzerTestOneInput(input)
    }

    @FuzzTest(maxDuration = "3s")
    fun fuzzBinaryFrameCodec(data: FuzzedDataProvider) {
        val input = data.consumeRemainingAsBytes()
        BinaryFrameCodecFuzzTarget.fuzzerTestOneInput(input)
    }

    @FuzzTest(maxDuration = "3s")
    fun fuzzPng8Compressor(data: FuzzedDataProvider) {
        val input = data.consumeRemainingAsBytes()
        Png8CompressorFuzzTarget.fuzzerTestOneInput(input)
    }

    @FuzzTest(maxDuration = "3s")
    fun fuzzKeystoreCrypto(data: FuzzedDataProvider) {
        val input = data.consumeRemainingAsBytes()
        KeystoreCryptoFuzzTarget.fuzzerTestOneInput(input)
    }

    /**
     * High-iteration automated fuzz harness exercising mutated payloads across all 5 parser/codec targets:
     * Bencode, KRPC messages, BinaryFrameCodec (0x01..0x0C + Cover-ACK), Png8Compressor, and KeystoreCrypto.
     */
    @Test
    fun testExtensiveFuzzHarness() {
        val random = Random(42)

        // 1. Bencode & KRPC seed corpus
        val bencodeKrpcSeeds = listOf(
            "i0e".toByteArray(),
            "i42e".toByteArray(),
            "i-42e".toByteArray(),
            "0:".toByteArray(),
            "4:spam".toByteArray(),
            "l4:spami42ee".toByteArray(),
            "d3:bar4:spam3:fooi42ee".toByteArray(),
            "2147483647:".toByteArray(),
            "9999999999999999999999:".toByteArray(),
            "i-0e".toByteArray(),
            "i03e".toByteArray(),
            "i-03e".toByteArray(),
            "ie".toByteArray(),
            "i-e".toByteArray(),
            "i99999999999999999999999999999999e".toByteArray(),
            "04:test".toByteArray(),
            "d1:a1:b1:a1:ce".toByteArray(),
            "d1:b1:x1:a1:ye".toByteArray(),
            "d1:a1:beGARBAGE".toByteArray(),
            ByteArray(100) { 'l'.code.toByte() },
            ByteArray(100) { 'd'.code.toByte() }
        )

        // 2. BinaryFrameCodec inner plaintext seeds (0x01..0x0C + Deflate Zip-Bomb + malformed 0x0C)
        val zipBombBytes = ByteArray(16384) { 'A'.code.toByte() }
        val deflater = Deflater(Deflater.BEST_COMPRESSION).apply {
            setInput(zipBombBytes)
            finish()
        }
        val deflatedBomb = ByteArrayOutputStream().also { baos ->
            val buf = ByteArray(1024)
            while (!deflater.finished()) {
                baos.write(buf, 0, deflater.deflate(buf))
            }
            deflater.end()
        }.toByteArray()

        val zipBombInner = ByteArray(BinaryFrameCodec.CIPHERTEXT_SIZE).also { arr ->
            val buf = ByteBuffer.wrap(arr).order(ByteOrder.BIG_ENDIAN)
            buf.put(BinaryFrameCodec.TYPE_COMPRESSED_MICRO_DOC)
            buf.putShort(1)
            buf.putShort(0)
            buf.putLong(1_700_000_000_000L)
            buf.put(BinaryFrameCodec.MICRO_DOC_SUBTYPE_MARKDOWN)
            buf.put(BinaryFrameCodec.MICRO_DOC_COMPRESSION_DEFLATE)
            buf.putShort(8192)
            buf.putShort(minOf(deflatedBomb.size, 800).toShort())
            buf.putInt(0)
            buf.put(deflatedBomb, 0, minOf(deflatedBomb.size, 800))
        }

        val frameSeeds = listOf(
            ByteArray(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES) { 0x01 },
            ByteArray(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES) { 0x02 },
            zipBombInner,
            ByteArray(64) { BinaryFrameCodec.TYPE_GROUP_CONTROL },
            ByteArray(64) { BinaryFrameCodec.TYPE_GROUP_POLL },
            ByteArray(64) { BinaryFrameCodec.TYPE_SAFETY_CANARY },
            ByteArray(128) { BinaryFrameCodec.TYPE_VOICE_NOTE }
        ) + (0x01..0x0C).map { t ->
            ByteArray(BinaryFrameCodec.CIPHERTEXT_SIZE).also {
                it[0] = t.toByte()
                it[1] = 0
                it[2] = 1
            }
        }

        // 3. Png8Compressor seeds (valid PNG8 with stego, giant-IHDR, corrupted CRC envelope)
        val validPng = Png8Compressor.encodePng8(
            width = 32,
            height = 32,
            argbPixels = IntArray(32 * 32) { idx -> (0xFF shl 24) or ((idx * 17) and 0xFFFFFF) },
            maxColors = 16,
            stegoPayload = "PQChatFuzzSeed".toByteArray()
        )
        val hugeIhdrPng = ByteBuffer.allocate(33).order(ByteOrder.BIG_ENDIAN).apply {
            put(Png8Compressor.PNG_MAGIC)
            putInt(13)
            put("IHDR".toByteArray(Charsets.US_ASCII))
            putInt(65535)
            putInt(65535)
            put(8.toByte())
            put(3.toByte())
            put(0.toByte())
            put(0.toByte())
            put(0.toByte())
            putInt(0)
        }.array()
        val pngSeeds = listOf(
            validPng,
            hugeIhdrPng,
            Png8Compressor.packStegoEnvelope("PQChatEnvelopeSeed".toByteArray()),
            ByteArray(16)
        )

        // 4. KeystoreCrypto seeds (valid v2/v1 headers + truncated headers)
        KeystoreCrypto.setTestSecretKey(SecretKeySpec(ByteArray(32) { ((it * 19 + 5) and 0xFF).toByte() }, "AES"))
        val validV2 = KeystoreCrypto.encrypt("secret-db-text".toByteArray(), "messages", "row-1", "textContent")!!
        val validV1 = KeystoreCrypto.encrypt("secret-v1".toByteArray(), "messages", "row-1")!!
        val keystoreSeeds = listOf(
            validV2,
            validV1,
            byteArrayOf(KeystoreCrypto.MAGIC_ROW_BOUND_V2, 0x7F.toByte(), 0x00, 0x01, 0x05),
            byteArrayOf(KeystoreCrypto.MAGIC_ROW_BOUND, 0x05, 0x61, 0x00, 0x50)
        )

        val allSeeds = bencodeKrpcSeeds + frameSeeds + pngSeeds + keystoreSeeds
        for (seed in allSeeds) {
            BencodeFuzzTarget.fuzzerTestOneInput(seed)
            KrpcMessageFuzzTarget.fuzzerTestOneInput(seed)
            BinaryFrameCodecFuzzTarget.fuzzerTestOneInput(seed)
            Png8CompressorFuzzTarget.fuzzerTestOneInput(seed)
            KeystoreCryptoFuzzTarget.fuzzerTestOneInput(seed)
        }

        // Mutate and fuzz all 5 targets deterministically
        for (i in 0 until 2_500) {
            val baseSeed = allSeeds[random.nextInt(allSeeds.size)]
            val mutated = mutatePayload(baseSeed, random)
            when (i % 5) {
                0 -> BencodeFuzzTarget.fuzzerTestOneInput(mutated)
                1 -> KrpcMessageFuzzTarget.fuzzerTestOneInput(mutated)
                2 -> BinaryFrameCodecFuzzTarget.fuzzerTestOneInput(mutated)
                3 -> Png8CompressorFuzzTarget.fuzzerTestOneInput(mutated)
                else -> KeystoreCryptoFuzzTarget.fuzzerTestOneInput(mutated)
            }
        }
    }

    private fun mutatePayload(seed: ByteArray, random: Random): ByteArray {
        val mode = random.nextInt(6)
        return when (mode) {
            0 -> {
                val len = random.nextInt(1024)
                ByteArray(len).also { random.nextBytes(it) }
            }
            1 -> {
                val copy = seed.copyOf()
                if (copy.isNotEmpty()) {
                    val idx = random.nextInt(copy.size)
                    copy[idx] = (copy[idx].toInt() xor (1 shl random.nextInt(8))).toByte()
                }
                copy
            }
            2 -> {
                if (seed.isEmpty()) seed else seed.copyOf(random.nextInt(seed.size))
            }
            3 -> {
                if (seed.size > 1500) seed else seed + seed
            }
            4 -> {
                val garbage = ByteArray(random.nextInt(64)).also { random.nextBytes(it) }
                seed + garbage
            }
            else -> {
                val delimiters = byteArrayOf('i'.code.toByte(), 'e'.code.toByte(), 'l'.code.toByte(), 'd'.code.toByte(), ':'.code.toByte(), '-'.code.toByte(), '0'.code.toByte())
                val insert = delimiters[random.nextInt(delimiters.size)]
                val idx = if (seed.isEmpty()) 0 else random.nextInt(seed.size)
                seed.copyOfRange(0, idx) + byteArrayOf(insert) + seed.copyOfRange(idx, seed.size)
            }
        }
    }
}
