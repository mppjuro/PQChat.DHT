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
            val decoded = try {
                Bencode.decode(bytes) as? Map<*, *>
            } catch (e: Exception) {
                throw IllegalArgumentException("Malformed bencoded KRPC message: ${e.message}", e)
            } ?: throw IllegalArgumentException("KRPC message must be a dictionary")

            val t = (decoded["t"] as? ByteArray)
                ?: throw IllegalArgumentException("Missing or invalid transaction ID 't'")
            if (t.isEmpty() || t.size > 256) {
                throw IllegalArgumentException("Invalid transaction ID length (${t.size} B)")
            }

            val yBytes = decoded["y"] as? ByteArray
            val y = yBytes?.let { String(it, StandardCharsets.UTF_8) }
                ?: (decoded["y"] as? String)
                ?: throw IllegalArgumentException("Missing or invalid message type 'y'")

            return when (y) {
                "q" -> {
                    val qRaw = decoded["q"]
                    val q = when (qRaw) {
                        is ByteArray -> String(qRaw, StandardCharsets.UTF_8)
                        is String -> qRaw
                        else -> throw IllegalArgumentException("Missing or invalid query method 'q'")
                    }
                    if (q.isEmpty() || q.length > 64) {
                        throw IllegalArgumentException("Invalid query method name '$q'")
                    }

                    val aRaw = decoded["a"]
                    val a = if (aRaw is Map<*, *>) {
                        val safeMap = LinkedHashMap<String, Any>()
                        for ((k, v) in aRaw) {
                            val keyStr = when (k) {
                                is String -> k
                                is ByteArray -> String(k, StandardCharsets.UTF_8)
                                else -> throw IllegalArgumentException("Non-string argument key in query '$q'")
                            }
                            if (v != null) safeMap[keyStr] = v
                        }
                        safeMap
                    } else if (aRaw == null) {
                        emptyMap()
                    } else {
                        throw IllegalArgumentException("Query arguments 'a' must be a dictionary")
                    }

                    val ro = when (val roVal = decoded["ro"]) {
                        is Long -> roVal == 1L
                        is Int -> roVal == 1
                        is Number -> roVal.toLong() == 1L
                        else -> false
                    }
                    Query(t, q, a, ro)
                }
                "r" -> {
                    val rRaw = decoded["r"]
                    val r = if (rRaw is Map<*, *>) {
                        val safeMap = LinkedHashMap<String, Any>()
                        for ((k, v) in rRaw) {
                            val keyStr = when (k) {
                                is String -> k
                                is ByteArray -> String(k, StandardCharsets.UTF_8)
                                else -> throw IllegalArgumentException("Non-string key in response dictionary")
                            }
                            if (v != null) safeMap[keyStr] = v
                        }
                        safeMap
                    } else if (rRaw == null) {
                        emptyMap()
                    } else {
                        throw IllegalArgumentException("Response data 'r' must be a dictionary")
                    }
                    Response(t, r)
                }
                "e" -> {
                    val e = (decoded["e"] as? List<*>)
                        ?: throw IllegalArgumentException("KRPC error element 'e' must be a list")
                    if (e.size < 2) {
                        throw IllegalArgumentException("KRPC error list 'e' must have at least [code, message]")
                    }
                    val code = (e[0] as? Number)?.toInt()
                        ?: throw IllegalArgumentException("KRPC error code must be numeric")
                    val msgBytes = e[1] as? ByteArray
                    val msg = msgBytes?.let { String(it, StandardCharsets.UTF_8) }
                        ?: (e[1] as? String)
                        ?: e[1]?.toString()
                        ?: "Unknown error"
                    Error(t, code, msg)
                }
                else -> throw IllegalArgumentException("Unknown KRPC message type 'y': '$y'")
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
            return Query(txId, "put", args, readOnly = false)
        }
    }
}
