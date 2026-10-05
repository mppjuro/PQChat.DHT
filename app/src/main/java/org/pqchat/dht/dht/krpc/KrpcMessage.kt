package org.pqchat.dht.dht.krpc

import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.dht.bencode.Bencode
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets

sealed class KrpcMessage {
    abstract val transactionId: ByteArray

    data class Query(
        override val transactionId: ByteArray,
        val method: String,
        val arguments: Map<String, Any>,
        val readOnly: Boolean = true
    ) : KrpcMessage() {
        fun toBencoded(): ByteArray {
            val map = LinkedHashMap<String, Any>()
            map["t"] = transactionId
            map["y"] = "q"
            map["q"] = method
            map["a"] = arguments
            if (readOnly) {
                map["ro"] = 1L
            }
            return Bencode.encode(map)
        }
    }

    data class Response(
        override val transactionId: ByteArray,
        val responseData: Map<String, Any>
    ) : KrpcMessage() {
        fun toBencoded(): ByteArray {
            val map = LinkedHashMap<String, Any>()
            map["t"] = transactionId
            map["y"] = "r"
            map["r"] = responseData
            return Bencode.encode(map)
        }
    }

    data class Error(
        override val transactionId: ByteArray,
        val code: Int,
        val message: String
    ) : KrpcMessage() {
        fun toBencoded(): ByteArray {
            val map = LinkedHashMap<String, Any>()
            map["t"] = transactionId
            map["y"] = "e"
            map["e"] = listOf(code.toLong(), message.toByteArray(StandardCharsets.UTF_8))
            return Bencode.encode(map)
        }
    }

    companion object {
        fun parse(bytes: ByteArray): KrpcMessage {
            val decoded = Bencode.decode(bytes) as? Map<*, *>
                ?: throw IllegalArgumentException("KRPC message must be a dictionary")

            val t = (decoded["t"] as? ByteArray)
                ?: throw IllegalArgumentException("Missing transaction ID 't'")

            val yBytes = decoded["y"] as? ByteArray
            val y = yBytes?.let { String(it, StandardCharsets.UTF_8) }
                ?: (decoded["y"] as? String)
                ?: throw IllegalArgumentException("Missing message type 'y'")

            return when (y) {
                "q" -> {
                    val qBytes = decoded["q"] as? ByteArray
                    val q = qBytes?.let { String(it, StandardCharsets.UTF_8) } ?: decoded["q"].toString()
                    @Suppress("UNCHECKED_CAST")
                    val a = (decoded["a"] as? Map<String, Any>) ?: emptyMap()
                    val ro = (decoded["ro"] as? Long) == 1L
                    Query(t, q, a, ro)
                }
                "r" -> {
                    @Suppress("UNCHECKED_CAST")
                    val r = (decoded["r"] as? Map<String, Any>) ?: emptyMap()
                    Response(t, r)
                }
                "e" -> {
                    val e = (decoded["e"] as? List<*>)
                    val code = (e?.getOrNull(0) as? Long)?.toInt() ?: -1
                    val msgBytes = e?.getOrNull(1) as? ByteArray
                    val msg = msgBytes?.let { String(it, StandardCharsets.UTF_8) } ?: e?.getOrNull(1)?.toString() ?: "Unknown error"
                    Error(t, code, msg)
                }
                else -> throw IllegalArgumentException("Unknown KRPC 'y' type: $y")
            }
        }

        // ==========================================
        // Helper factory methods
        // ==========================================

        fun createPingQuery(myNodeId: ByteArray, txId: ByteArray = CryptoUtils.secureRandomBytes(2)): Query {
            val args = mapOf("id" to myNodeId)
            return Query(txId, "ping", args)
        }

        fun createPingResponse(myNodeId: ByteArray, txId: ByteArray): Response {
            return Response(txId, mapOf("id" to myNodeId))
        }

        fun createFindNodeQuery(
            myNodeId: ByteArray,
            targetId: ByteArray,
            txId: ByteArray = CryptoUtils.secureRandomBytes(2)
        ): Query {
            val args = mapOf(
                "id" to myNodeId,
                "target" to targetId
            )
            return Query(txId, "find_node", args)
        }

        fun createBep44GetQuery(
            myNodeId: ByteArray,
            targetSha1: ByteArray,
            txId: ByteArray = CryptoUtils.secureRandomBytes(2),
            seq: Long? = null
        ): Query {
            val args = LinkedHashMap<String, Any>()
            args["id"] = myNodeId
            args["target"] = targetSha1
            if (seq != null) {
                args["seq"] = seq
            }
            return Query(txId, "get", args)
        }

        fun createBep44PutQuery(
            myNodeId: ByteArray,
            token: ByteArray,
            v: ByteArray,
            k: ByteArray,
            sig: ByteArray,
            seq: Long,
            salt: ByteArray? = null,
            cas: Long? = null,
            txId: ByteArray = CryptoUtils.secureRandomBytes(2)
        ): Query {
            val args = LinkedHashMap<String, Any>()
            args["id"] = myNodeId
            args["token"] = token
            args["v"] = v
            args["k"] = k
            args["sig"] = sig
            args["seq"] = seq
            if (salt != null && salt.isNotEmpty()) {
                args["salt"] = salt
            }
            if (cas != null) {
                args["cas"] = cas
            }
            return Query(txId, "put", args)
        }
    }
}
