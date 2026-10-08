package org.pqchat.dht.dht.bencode

import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.dht.krpc.KrpcMessage
import java.nio.charset.StandardCharsets

class BencodeSecurityTest {

    @Test
    fun testAllocationBombPreventedWithoutOom() {
        // String claiming 2 GB length with only 4 bytes of actual input
        val malicious1 = "2147483647:test".toByteArray(StandardCharsets.US_ASCII)
        val ex1 = assertThrows(IllegalArgumentException::class.java) {
            Bencode.decode(malicious1)
        }
        assertTrue("Must be BencodeException or IllegalArgumentException: ${ex1.message}", ex1.message!!.contains("exceeds"))

        // String length overflow
        val malicious2 = "99999999999999999999:test".toByteArray(StandardCharsets.US_ASCII)
        val ex2 = assertThrows(IllegalArgumentException::class.java) {
            Bencode.decode(malicious2)
        }
        assertNotNull(ex2.message)

        // String claiming 100 KB on stream with 5 bytes
        val malicious3 = "100000:abc".toByteArray(StandardCharsets.US_ASCII)
        val ex3 = assertThrows(IllegalArgumentException::class.java) {
            Bencode.decode(malicious3)
        }
        assertTrue(ex3.message!!.contains("exceeds"))
    }

    @Test
    fun testStackOverflowPreventedOnDeepRecursion() {
        // 500 levels of nested lists
        val deepList = "l".repeat(500) + "e".repeat(500)
        val ex = assertThrows(BencodeException::class.java) {
            Bencode.decode(deepList.toByteArray(StandardCharsets.US_ASCII))
        }
        assertTrue("Must report recursion depth: ${ex.message}", ex.message!!.contains("depth"))
    }

    @Test
    fun testMaxInputSizeEnforced() {
        // 70 KB input (exceeds default 64 KB)
        val hugeInput = ByteArray(70_000)
        val ex = assertThrows(BencodeException::class.java) {
            Bencode.decode(hugeInput)
        }
        assertTrue(ex.message!!.contains("exceeds maximum allowed limit"))
    }

    @Test
    fun testEmptyIntegerRejected() {
        assertThrows(BencodeException::class.java) {
            Bencode.decode("ie".toByteArray())
        }
        assertThrows(BencodeException::class.java) {
            Bencode.decode("i-e".toByteArray())
        }
    }

    @Test
    fun testNegativeZeroRejectedByCanonicity() {
        // BEP 3 explicitly forbids 'i-0e'
        val ex = assertThrows(BencodeException::class.java) {
            Bencode.decode("i-0e".toByteArray())
        }
        assertTrue(ex.message!!.contains("negative zero"))
    }

    @Test
    fun testLeadingZerosInIntegerRejectedByCanonicity() {
        // BEP 3 explicitly forbids leading zeros except i0e
        assertThrows(BencodeException::class.java) {
            Bencode.decode("i03e".toByteArray())
        }
        assertThrows(BencodeException::class.java) {
            Bencode.decode("i00e".toByteArray())
        }
        assertThrows(BencodeException::class.java) {
            Bencode.decode("i-03e".toByteArray())
        }
        // Canonical zero must succeed
        assertEquals(0L, Bencode.decode("i0e".toByteArray()))
    }

    @Test
    fun testIntegerOverflowSafelyCaught() {
        // Long.MAX_VALUE + 1
        val overflow = "i9223372036854775808e".toByteArray()
        val ex = assertThrows(BencodeException::class.java) {
            Bencode.decode(overflow)
        }
        assertTrue(ex.message!!.contains("overflow", ignoreCase = true))

        // Huge digit sequence
        val hugeDigits = "i" + "9".repeat(100) + "e"
        assertThrows(BencodeException::class.java) {
            Bencode.decode(hugeDigits.toByteArray())
        }
    }

    @Test
    fun testNonCanonicalStringLengthLeadingZeros() {
        // BEP 3 forbids leading zeros in string lengths like "03:abc"
        val ex = assertThrows(BencodeException::class.java) {
            Bencode.decode("03:abc".toByteArray())
        }
        assertTrue(ex.message!!.contains("leading zero"))

        // 0: is valid empty string
        val emptyStr = Bencode.decode("0:".toByteArray()) as ByteArray
        assertEquals(0, emptyStr.size)
    }

    @Test
    fun testInvalidCharactersInStringLength() {
        assertThrows(BencodeException::class.java) {
            Bencode.decode("-5:hello".toByteArray())
        }
        assertThrows(BencodeException::class.java) {
            Bencode.decode("12a3:hello".toByteArray())
        }
    }

    @Test
    fun testDictionaryDuplicateKeysRejected() {
        // Dict with duplicate key 'a'
        val dupDict = "d1:a1:x1:a1:ye".toByteArray()
        val ex = assertThrows(BencodeException::class.java) {
            Bencode.decode(dupDict)
        }
        assertTrue(ex.message!!.contains("duplicate key"))
    }

    @Test
    fun testDictionaryUnsortedKeysRejected() {
        // Dict with unsorted keys 'b' then 'a'
        val unsortedDict = "d1:b1:x1:a1:ye".toByteArray()
        val ex = assertThrows(BencodeException::class.java) {
            Bencode.decode(unsortedDict)
        }
        assertTrue(ex.message!!.contains("out of order"))
    }

    @Test
    fun testDictionarySortedKeysAccepted() {
        // Canonical sorted keys 'a' then 'b'
        val sortedDict = "d1:a1:x1:b1:ye".toByteArray()
        val decoded = Bencode.decode(sortedDict) as Map<*, *>
        assertEquals(2, decoded.size)
        assertArrayEquals("x".toByteArray(), decoded["a"] as ByteArray)
        assertArrayEquals("y".toByteArray(), decoded["b"] as ByteArray)
    }

    @Test
    fun testTrailingGarbageRejected() {
        val trailing = "d1:a1:beGARBAGE".toByteArray()
        val ex = assertThrows(BencodeException::class.java) {
            Bencode.decode(trailing)
        }
        assertTrue(ex.message!!.contains("Trailing unparsed bytes"))
    }

    @Test
    fun testValidCanonicalRoundTrip() {
        val original = mapOf(
            "age" to 30L,
            "name" to "Alice",
            "scores" to listOf(100L, 200L, 300L),
            "valid" to 1L
        )
        val encoded = Bencode.encode(original)
        val decoded = Bencode.decode(encoded) as Map<*, *>
        assertEquals(30L, decoded["age"])
        assertArrayEquals("Alice".toByteArray(), decoded["name"] as ByteArray)
        assertEquals(listOf(100L, 200L, 300L), decoded["scores"])
    }

    @Test
    fun testKrpcMessageParseMalformedInputs() {
        // Non-dict root
        assertThrows(IllegalArgumentException::class.java) {
            KrpcMessage.parse("i42e".toByteArray())
        }

        // Missing transaction ID 't'
        assertThrows(IllegalArgumentException::class.java) {
            KrpcMessage.parse("d1:y1:qe".toByteArray())
        }

        // Empty transaction ID 't'
        assertThrows(IllegalArgumentException::class.java) {
            KrpcMessage.parse("d1:t0:1:y1:qe".toByteArray())
        }

        // Missing message type 'y'
        assertThrows(IllegalArgumentException::class.java) {
            KrpcMessage.parse("d1:t2:txe".toByteArray())
        }

        // Query missing 'q'
        assertThrows(IllegalArgumentException::class.java) {
            KrpcMessage.parse("d1:t2:tx1:y1:qe".toByteArray())
        }

        // Query with invalid 'a' (not a dict)
        assertThrows(IllegalArgumentException::class.java) {
            KrpcMessage.parse("d1:a4:fail1:q4:ping1:t2:tx1:y1:qe".toByteArray())
        }

        // Error with non-list 'e'
        assertThrows(IllegalArgumentException::class.java) {
            KrpcMessage.parse("d1:e4:fail1:t2:tx1:y1:ee".toByteArray())
        }

        // Error with incomplete list [201] (missing message)
        assertThrows(IllegalArgumentException::class.java) {
            KrpcMessage.parse("d1:ei201e1:t2:tx1:y1:ee".toByteArray())
        }

        // Valid query parses cleanly
        val validQuery = KrpcMessage.createPingQuery(ByteArray(20) { 1 }, "tx".toByteArray())
        val parsedQuery = KrpcMessage.parse(validQuery.toBencoded()) as KrpcMessage.Query
        assertEquals("ping", parsedQuery.method)
        assertArrayEquals("tx".toByteArray(), parsedQuery.transactionId)

        // Valid error parses cleanly
        val validError = KrpcMessage.Error("tx".toByteArray(), 201, "Generic Error")
        val parsedError = KrpcMessage.parse(validError.toBencoded()) as KrpcMessage.Error
        assertEquals(201, parsedError.code)
        assertEquals("Generic Error", parsedError.message)
    }
}
