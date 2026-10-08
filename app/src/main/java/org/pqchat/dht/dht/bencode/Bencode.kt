package org.pqchat.dht.dht.bencode

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets

/**
 * Exception thrown when parsing invalid, non-canonical, or malicious Bencoded data.
 * Extends [IllegalArgumentException] to maintain compatibility with existing error handlers.
 */
open class BencodeException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

object Bencode {

    /** Default maximum allowable input byte array length (64 KB for UDP datagrams). */
    const val DEFAULT_MAX_INPUT_SIZE: Int = 65_536

    /** Default maximum allowable length of a single byte string (64 KB). */
    const val DEFAULT_MAX_STRING_LENGTH: Int = 65_536

    /** Default maximum recursion depth to prevent StackOverflowError on nested containers. */
    const val DEFAULT_MAX_DEPTH: Int = 32

    /** Default maximum number of elements per list or dictionary to prevent heap exhaustion. */
    const val DEFAULT_MAX_CONTAINER_SIZE: Int = 2048

    /**
     * Decodes bencoded byte array into Any:
     * - Long for integers
     * - ByteArray for byte strings
     * - List<Any> for lists
     * - Map<String, Any> for dictionaries
     *
     * Enforces canonical Bencode rules (BEP 3 & BEP 44):
     * - Input size limit
     * - Recursion depth limit
     * - Single string length limit bounded by available bytes
     * - Integer canonicity (no leading zeros, no -0, overflow checks)
     * - Dictionary key canonicity (raw byte lexicographical ordering, no duplicate keys)
     * - No trailing unparsed bytes
     */
    fun decode(
        bytes: ByteArray,
        maxDepth: Int = DEFAULT_MAX_DEPTH,
        maxStringLength: Int = DEFAULT_MAX_STRING_LENGTH,
        maxInputSize: Int = DEFAULT_MAX_INPUT_SIZE,
        maxContainerSize: Int = DEFAULT_MAX_CONTAINER_SIZE
    ): Any {
        if (bytes.size > maxInputSize) {
            throw BencodeException("Input size (${bytes.size} B) exceeds maximum allowed limit of $maxInputSize B")
        }
        val stream = ByteArrayInputStream(bytes)
        val decoded = decodeStream(
            stream = stream,
            depth = 0,
            maxDepth = maxDepth,
            maxStringLength = maxStringLength,
            maxContainerSize = maxContainerSize
        )
        if (stream.available() > 0) {
            throw BencodeException("Trailing unparsed bytes after bencoded value (${stream.available()} B remaining)")
        }
        return decoded
    }

    private fun decodeStream(
        stream: InputStream,
        depth: Int,
        maxDepth: Int,
        maxStringLength: Int,
        maxContainerSize: Int
    ): Any {
        if (depth > maxDepth) {
            throw BencodeException("Maximum recursion depth exceeded: depth $depth > max $maxDepth")
        }

        val b = stream.read()
        if (b == -1) throw BencodeException("Unexpected EOF in bencoded stream")

        return when (b.toChar()) {
            'i' -> decodeInteger(stream)
            'l' -> decodeList(stream, depth, maxDepth, maxStringLength, maxContainerSize)
            'd' -> decodeDictionary(stream, depth, maxDepth, maxStringLength, maxContainerSize)
            in '0'..'9' -> decodeByteString(stream, b, maxStringLength)
            else -> throw BencodeException("Invalid bencode prefix: '${b.toChar()}' (0x%02X)".format(b))
        }
    }

    /**
     * Decodes canonical bencoded integer: `i<number>e`.
     * Strict canonical checks:
     * - No leading zeros: `i03e` is invalid (only `i0e` allowed).
     * - Negative zero is forbidden: `i-0e` is invalid.
     * - Minus without digits: `i-e` is invalid.
     * - Overflows outside Long.MIN_VALUE..Long.MAX_VALUE are caught and rejected.
     */
    private fun decodeInteger(stream: InputStream): Long {
        val sb = StringBuilder()
        var charCount = 0
        while (true) {
            val b = stream.read()
            if (b == -1) throw BencodeException("Unexpected EOF inside integer")
            val c = b.toChar()
            if (c == 'e') break

            // Maximum digits for a 64-bit signed integer (Long.MIN_VALUE has 20 chars including '-')
            if (++charCount > 21) {
                throw BencodeException("Integer digit sequence exceeds maximum allowable length")
            }
            if (c != '-' && (c < '0' || c > '9')) {
                throw BencodeException("Invalid character in integer: '$c'")
            }
            sb.append(c)
        }

        val str = sb.toString()
        if (str.isEmpty()) throw BencodeException("Empty integer specification 'ie'")
        if (str == "-") throw BencodeException("Invalid integer '-' without digits")
        if (str == "-0") throw BencodeException("Non-canonical integer: negative zero '-0' is forbidden")
        if (str.length > 1 && str.startsWith("0")) {
            throw BencodeException("Non-canonical integer: leading zero in '$str'")
        }
        if (str.length > 2 && str.startsWith("-0")) {
            throw BencodeException("Non-canonical integer: leading zero after minus in '$str'")
        }

        return try {
            str.toLong()
        } catch (e: NumberFormatException) {
            throw BencodeException("Integer overflow: '$str'", e)
        }
    }

    /**
     * Decodes canonical byte string: `<length>:<content>`.
     * Strict canonical checks:
     * - No leading zeros in length: `03:` is invalid (only `0:` allowed for empty string).
     * - Length must be bounded by both [maxStringLength] and stream.available() (prevent allocation bombs).
     * - Length digits cannot overflow integer.
     */
    private fun decodeByteString(stream: InputStream, firstDigit: Int, maxStringLength: Int): ByteArray {
        val sb = StringBuilder()
        val firstChar = firstDigit.toChar()
        sb.append(firstChar)

        var digitCount = 1
        while (true) {
            val b = stream.read()
            if (b == -1) throw BencodeException("Unexpected EOF while reading string length")
            val c = b.toChar()
            if (c == ':') break

            if (c < '0' || c > '9') {
                throw BencodeException("Invalid character in string length: '$c'")
            }
            if (++digitCount > 10) {
                throw BencodeException("String length exceeds maximum integer representation")
            }
            sb.append(c)
        }

        val lenStr = sb.toString()
        if (lenStr.length > 1 && lenStr.startsWith("0")) {
            throw BencodeException("Non-canonical string length: leading zero in '$lenStr'")
        }

        val length = try {
            lenStr.toInt()
        } catch (e: NumberFormatException) {
            throw BencodeException("String length overflow: '$lenStr'", e)
        }

        if (length < 0 || length > maxStringLength) {
            throw BencodeException("String length $length exceeds allowed maximum ($maxStringLength B)")
        }

        val available = stream.available()
        if (length > available) {
            throw BencodeException("String length $length exceeds available input bytes ($available B)")
        }

        val data = ByteArray(length)
        var readTotal = 0
        while (readTotal < length) {
            val count = stream.read(data, readTotal, length - readTotal)
            if (count == -1) {
                throw BencodeException("Unexpected EOF reading byte string data of length $length")
            }
            readTotal += count
        }
        return data
    }

    private fun decodeList(
        stream: InputStream,
        depth: Int,
        maxDepth: Int,
        maxStringLength: Int,
        maxContainerSize: Int
    ): List<Any> {
        val list = ArrayList<Any>()
        while (true) {
            stream.mark(1)
            val b = stream.read()
            if (b == -1) throw BencodeException("Unexpected EOF in list")
            if (b.toChar() == 'e') break
            stream.reset()

            if (list.size >= maxContainerSize) {
                throw BencodeException("List size exceeds maximum allowed elements ($maxContainerSize)")
            }
            list.add(decodeStream(stream, depth + 1, maxDepth, maxStringLength, maxContainerSize))
        }
        return list
    }

    /**
     * Decodes canonical dictionary: `d<key1><val1>...e`.
     * Strict canonical checks (BEP 3 & BEP 44):
     * - Keys MUST be byte strings.
     * - Keys MUST appear in strict lexicographical order based on raw unsigned byte comparison.
     * - Duplicate keys are strictly FORBIDDEN.
     */
    private fun decodeDictionary(
        stream: InputStream,
        depth: Int,
        maxDepth: Int,
        maxStringLength: Int,
        maxContainerSize: Int
    ): Map<String, Any> {
        val map = LinkedHashMap<String, Any>()
        var prevKeyBytes: ByteArray? = null

        while (true) {
            stream.mark(1)
            val b = stream.read()
            if (b == -1) throw BencodeException("Unexpected EOF in dictionary")
            if (b.toChar() == 'e') break
            stream.reset()

            if (map.size >= maxContainerSize) {
                throw BencodeException("Dictionary size exceeds maximum allowed elements ($maxContainerSize)")
            }

            // Key must be a byte string
            val keyPrefix = stream.read()
            if (keyPrefix == -1) throw BencodeException("Unexpected EOF reading dictionary key")
            if (keyPrefix.toChar() !in '0'..'9') {
                throw BencodeException("Dictionary key must be a byte string (got '${keyPrefix.toChar()}')")
            }

            val keyBytes = decodeByteString(stream, keyPrefix, maxStringLength)

            // Validate canonical ordering and uniqueness against previous key
            if (prevKeyBytes != null) {
                val cmp = compareRawBytesUnsigned(prevKeyBytes, keyBytes)
                if (cmp == 0) {
                    val keyName = String(keyBytes, StandardCharsets.UTF_8)
                    throw BencodeException("Non-canonical dictionary: duplicate key '$keyName'")
                }
                if (cmp > 0) {
                    val prevName = String(prevKeyBytes, StandardCharsets.UTF_8)
                    val currName = String(keyBytes, StandardCharsets.UTF_8)
                    throw BencodeException("Non-canonical dictionary: keys out of order ('$prevName' before '$currName')")
                }
            }
            prevKeyBytes = keyBytes

            val key = String(keyBytes, StandardCharsets.UTF_8)
            val value = decodeStream(stream, depth + 1, maxDepth, maxStringLength, maxContainerSize)
            map[key] = value
        }
        return map
    }

    /**
     * Compares two byte arrays lexicographically using unsigned byte values (BEP 3 specification).
     */
    fun compareRawBytesUnsigned(a: ByteArray, b: ByteArray): Int {
        val minLen = minOf(a.size, b.size)
        for (i in 0 until minLen) {
            val aVal = a[i].toInt() and 0xFF
            val bVal = b[i].toInt() and 0xFF
            if (aVal != bVal) return aVal.compareTo(bVal)
        }
        return a.size.compareTo(b.size)
    }

    /**
     * Encodes object into Bencode format.
     */
    fun encode(obj: Any): ByteArray {
        val baos = ByteArrayOutputStream()
        encodeToStream(obj, baos)
        return baos.toByteArray()
    }

    @Suppress("UNCHECKED_CAST")
    private fun encodeToStream(obj: Any, out: ByteArrayOutputStream) {
        when (obj) {
            is Number -> {
                out.write('i'.code)
                out.write(obj.toLong().toString().toByteArray(StandardCharsets.US_ASCII))
                out.write('e'.code)
            }
            is String -> {
                val bytes = obj.toByteArray(StandardCharsets.UTF_8)
                encodeByteString(bytes, out)
            }
            is ByteArray -> {
                encodeByteString(obj, out)
            }
            is List<*> -> {
                out.write('l'.code)
                for (item in obj) {
                    if (item != null) encodeToStream(item, out)
                }
                out.write('e'.code)
            }
            is Map<*, *> -> {
                out.write('d'.code)
                // Keys MUST be sorted lexicographically by raw byte encoding
                val entriesWithBytes = obj.entries.mapNotNull { (k, v) ->
                    if (v == null) null
                    else {
                        val keyBytes = k.toString().toByteArray(StandardCharsets.UTF_8)
                        Triple(keyBytes, k.toString(), v)
                    }
                }.sortedWith { o1, o2 ->
                    compareRawBytesUnsigned(o1.first, o2.first)
                }

                for ((keyBytes, _, value) in entriesWithBytes) {
                    encodeByteString(keyBytes, out)
                    encodeToStream(value, out)
                }
                out.write('e'.code)
            }
            else -> throw IllegalArgumentException("Unsupported type for bencoding: ${obj.javaClass.name}")
        }
    }

    private fun encodeByteString(bytes: ByteArray, out: ByteArrayOutputStream) {
        out.write(bytes.size.toString().toByteArray(StandardCharsets.US_ASCII))
        out.write(':'.code)
        out.write(bytes)
    }

    /**
     * Encodes BEP 44 mutable data payload to sign:
     * Without salt: "3:seqi<seq>e1:v<len>:<v>"
     * With salt: "4:salt<len>:<salt>3:seqi<seq>e1:v<len>:<v>"
     */
    fun encodeBep44SignData(v: ByteArray, seq: Long, salt: ByteArray? = null): ByteArray {
        val out = ByteArrayOutputStream()
        if (salt != null && salt.isNotEmpty()) {
            out.write("4:salt".toByteArray(StandardCharsets.US_ASCII))
            encodeByteString(salt, out)
        }
        out.write("3:seqi".toByteArray(StandardCharsets.US_ASCII))
        out.write(seq.toString().toByteArray(StandardCharsets.US_ASCII))
        out.write("e1:v".toByteArray(StandardCharsets.US_ASCII))
        encodeByteString(v, out)
        return out.toByteArray()
    }
}
