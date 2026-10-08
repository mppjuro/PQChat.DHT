package org.pqchat.dht.dht.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import org.pqchat.dht.dht.bencode.Bencode
import org.pqchat.dht.dht.bencode.BencodeException

/**
 * Official Jazzer fuzz target for [Bencode.decode] and [Bencode.encode].
 * Can be run via the Jazzer standalone CLI or libFuzzer JVM engine.
 */
object BencodeFuzzTarget {

    /**
     * Standard libFuzzer entry point for raw byte array inputs.
     */
    @JvmStatic
    fun fuzzerTestOneInput(input: ByteArray) {
        try {
            val decoded = Bencode.decode(input)
            // If decoding succeeded, test round-trip encoding and re-decoding
            val reencoded = Bencode.encode(decoded)
            Bencode.decode(reencoded)
        } catch (e: IllegalArgumentException) {
            // Expected and valid behavior for malformed, non-canonical, or unbounded input
        }
        // Any Error, StackOverflowError, OutOfMemoryError, NumberFormatException,
        // ClassCastException, NegativeArraySizeException or IndexOutOfBoundsException
        // will bubble up and signal a security failure to the Jazzer engine!
    }

    /**
     * Jazzer structured entry point using [FuzzedDataProvider].
     */
    @JvmStatic
    fun fuzzerTestOneInput(data: FuzzedDataProvider) {
        val bytes = data.consumeRemainingAsBytes()
        fuzzerTestOneInput(bytes)
    }
}
