package org.pqchat.dht.dht.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import org.junit.jupiter.api.Test
import org.pqchat.dht.dht.bencode.Bencode
import org.pqchat.dht.dht.krpc.KrpcMessage
import java.util.Random

class JazzerFuzzTest {

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

    /**
     * High-iteration automated fuzz harness exercising thousands of mutated payloads,
     * boundaries, edge cases, nested structures, allocation attacks, and random bytes.
     */
    @Test
    fun testExtensiveFuzzHarness() {
        val random = Random(42)

        // Seed corpus covering valid and malicious primitives
        val seeds = listOf(
            "i0e".toByteArray(),
            "i42e".toByteArray(),
            "i-42e".toByteArray(),
            "0:".toByteArray(),
            "4:spam".toByteArray(),
            "l4:spami42ee".toByteArray(),
            "d3:bar4:spam3:fooi42ee".toByteArray(),
            // Potential crash triggers
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

        // 1. Run all seeds through both fuzz targets
        for (seed in seeds) {
            BencodeFuzzTarget.fuzzerTestOneInput(seed)
            KrpcMessageFuzzTarget.fuzzerTestOneInput(seed)
        }

        // 2. Generate 10,000 mutated inputs
        for (i in 0 until 10_000) {
            val baseSeed = seeds[random.nextInt(seeds.size)]
            val mutated = mutatePayload(baseSeed, random)
            BencodeFuzzTarget.fuzzerTestOneInput(mutated)
            KrpcMessageFuzzTarget.fuzzerTestOneInput(mutated)
        }
    }

    private fun mutatePayload(seed: ByteArray, random: Random): ByteArray {
        val mode = random.nextInt(6)
        return when (mode) {
            0 -> {
                // Completely random bytes (0 to 1024 bytes)
                val len = random.nextInt(1024)
                ByteArray(len).also { random.nextBytes(it) }
            }
            1 -> {
                // Byte flip / mutation in seed
                val copy = seed.copyOf()
                if (copy.isNotEmpty()) {
                    val idx = random.nextInt(copy.size)
                    copy[idx] = (copy[idx].toInt() xor (1 shl random.nextInt(8))).toByte()
                }
                copy
            }
            2 -> {
                // Truncation
                if (seed.isEmpty()) seed else seed.copyOf(random.nextInt(seed.size))
            }
            3 -> {
                // Repetition / concatenation
                seed + seed + seed
            }
            4 -> {
                // Append random garbage
                val garbage = ByteArray(random.nextInt(64)).also { random.nextBytes(it) }
                seed + garbage
            }
            else -> {
                // Insert random ASCII control/delimiter character
                val delimiters = byteArrayOf('i'.code.toByte(), 'e'.code.toByte(), 'l'.code.toByte(), 'd'.code.toByte(), ':'.code.toByte(), '-'.code.toByte(), '0'.code.toByte())
                val insert = delimiters[random.nextInt(delimiters.size)]
                val idx = if (seed.isEmpty()) 0 else random.nextInt(seed.size)
                seed.copyOfRange(0, idx) + byteArrayOf(insert) + seed.copyOfRange(idx, seed.size)
            }
        }
    }
}
