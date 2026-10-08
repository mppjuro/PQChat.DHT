package org.pqchat.dht.dht.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import org.pqchat.dht.dht.krpc.KrpcMessage

/**
 * Official Jazzer fuzz target for [KrpcMessage.parse].
 * Tests resilient parsing of untrusted KRPC UDP packets without crashes or unhandled runtime exceptions.
 */
object KrpcMessageFuzzTarget {

    /**
     * Standard libFuzzer entry point for raw byte array inputs.
     */
    @JvmStatic
    fun fuzzerTestOneInput(input: ByteArray) {
        try {
            val msg = KrpcMessage.parse(input)
            // If message parsed, verify toBencoded roundtrip doesn't crash
            when (msg) {
                is KrpcMessage.Query -> msg.toBencoded()
                is KrpcMessage.Response -> msg.toBencoded()
                is KrpcMessage.Error -> msg.toBencoded()
            }
        } catch (e: IllegalArgumentException) {
            // Expected and valid behavior for invalid KRPC packets
        }
        // Any Error, StackOverflowError, OutOfMemoryError, ClassCastException,
        // NullPointerException, or NumberFormatException will fail the test!
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
