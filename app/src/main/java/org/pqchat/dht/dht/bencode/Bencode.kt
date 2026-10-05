package org.pqchat.dht.dht.bencode

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets

object Bencode {

    /**
     * Decodes bencoded byte array into Any:
     * - Long for integers
     * - ByteArray for byte strings
     * - List<Any> for lists
     * - Map<String, Any> for dictionaries
     */
    fun decode(bytes: ByteArray): Any {
        val stream = ByteArrayInputStream(bytes)
        return decodeStream(stream)
    }

    private fun decodeStream(stream: InputStream): Any {
        val b = stream.read()
        if (b == -1) throw IllegalArgumentException("Unexpected EOF in bencoded stream")

        return when (b.toChar()) {
            'i' -> decodeInteger(stream)
            'l' -> decodeList(stream)
            'd' -> decodeDictionary(stream)
            in '0'..'9' -> decodeByteString(stream, b)
            else -> throw IllegalArgumentException("Invalid bencode prefix: ${b.toChar()} (0x%02X)".format(b))
        }
    }

    private fun decodeInteger(stream: InputStream): Long {
        val sb = StringBuilder()
        while (true) {
            val b = stream.read()
            if (b == -1) throw IllegalArgumentException("Unexpected EOF inside integer")
            if (b.toChar() == 'e') break
            sb.append(b.toChar())
        }
        return sb.toString().toLong()
    }

    private fun decodeByteString(stream: InputStream, firstDigit: Int): ByteArray {
        val sb = StringBuilder()
        sb.append(firstDigit.toChar())
        while (true) {
            val b = stream.read()
            if (b == -1) throw IllegalArgumentException("Unexpected EOF in string length")
            if (b.toChar() == ':') break
            sb.append(b.toChar())
        }
        val length = sb.toString().toInt()
        val data = ByteArray(length)
        var readTotal = 0
        while (readTotal < length) {
            val count = stream.read(data, readTotal, length - readTotal)
            if (count == -1) throw IllegalArgumentException("Unexpected EOF reading byte string data of length $length")
            readTotal += count
        }
        return data
    }

    private fun decodeList(stream: InputStream): List<Any> {
        val list = ArrayList<Any>()
        while (true) {
            stream.mark(1)
            val b = stream.read()
            if (b == -1) throw IllegalArgumentException("Unexpected EOF in list")
            if (b.toChar() == 'e') break
            stream.reset()
            list.add(decodeStream(stream))
        }
        return list
    }

    private fun decodeDictionary(stream: InputStream): Map<String, Any> {
        val map = LinkedHashMap<String, Any>()
        while (true) {
            stream.mark(1)
            val b = stream.read()
            if (b == -1) throw IllegalArgumentException("Unexpected EOF in dictionary")
            if (b.toChar() == 'e') break
            stream.reset()

            // Key is always a string
            val keyBytes = decodeStream(stream) as? ByteArray
                ?: throw IllegalArgumentException("Dictionary key must be a byte string")
            val key = String(keyBytes, StandardCharsets.UTF_8)
            val value = decodeStream(stream)
            map[key] = value
        }
        return map
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
                // Keys MUST be sorted lexicographically
                val sortedKeys = obj.keys.map { it.toString() }.sorted()
                for (key in sortedKeys) {
                    val value = obj[key]
                    if (value != null) {
                        val keyBytes = key.toByteArray(StandardCharsets.UTF_8)
                        encodeByteString(keyBytes, out)
                        encodeToStream(value, out)
                    }
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
