package org.pqchat.dht.protocol

import org.pqchat.dht.crypto.CryptoUtils

/**
 * Payload helper for Type 0x0C Compressed Micro-Doc (Markdown / code notes),
 * stored inside encrypted `MessageEntity.textContent` without altering the Room DB schema.
 */
data class CompressedMicroDocData(
    val title: String,
    val markdownBody: String
) {
    fun toPayloadText(): String {
        val titleHex = CryptoUtils.toHex(title.toByteArray(Charsets.UTF_8))
        val bodyHex = CryptoUtils.toHex(markdownBody.toByteArray(Charsets.UTF_8))
        return "$PREFIX$titleHex:$bodyHex"
    }

    companion object {
        private const val PREFIX = "pqdoc:v1:"

        fun parse(text: String?): CompressedMicroDocData? {
            if (text == null || !text.startsWith(PREFIX)) return null
            val payload = text.removePrefix(PREFIX)
            val sepIdx = payload.indexOf(':')
            if (sepIdx < 0) return null
            val titleHex = payload.substring(0, sepIdx)
            val bodyHex = payload.substring(sepIdx + 1)
            return try {
                val title = String(CryptoUtils.fromHex(titleHex), Charsets.UTF_8)
                val body = String(CryptoUtils.fromHex(bodyHex), Charsets.UTF_8)
                CompressedMicroDocData(title = title, markdownBody = body)
            } catch (_: Exception) {
                null
            }
        }
    }
}

/**
 * Payload helper for Type 0x0C Trusted Contact Introducer cards (`pk_C || Seed_init`),
 * stored inside encrypted `MessageEntity.textContent` without altering the Room DB schema.
 */
data class ContactIntroducerData(
    val introducedName: String,
    val qrPayload: ByteArray
) {
    val fingerprintPreview: String
        get() {
            val hash = CryptoUtils.sha256(qrPayload)
            return CryptoUtils.toHex(hash.copyOfRange(0, 8)).chunked(4).joinToString(":")
        }

    fun toPayloadText(): String {
        val nameHex = CryptoUtils.toHex(introducedName.toByteArray(Charsets.UTF_8))
        val qrHex = CryptoUtils.toHex(qrPayload)
        return "$PREFIX$nameHex:$qrHex"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ContactIntroducerData) return false
        return introducedName == other.introducedName && qrPayload.contentEquals(other.qrPayload)
    }

    override fun hashCode(): Int = 31 * introducedName.hashCode() + qrPayload.contentHashCode()

    companion object {
        private const val PREFIX = "pqintro:v1:"

        fun parse(text: String?): ContactIntroducerData? {
            if (text == null || !text.startsWith(PREFIX)) return null
            val payload = text.removePrefix(PREFIX)
            val sepIdx = payload.indexOf(':')
            if (sepIdx < 0) return null
            val nameHex = payload.substring(0, sepIdx)
            val qrHex = payload.substring(sepIdx + 1)
            return try {
                val name = String(CryptoUtils.fromHex(nameHex), Charsets.UTF_8)
                val qr = CryptoUtils.fromHex(qrHex)
                if (qr.size != HandshakeManager.QR_DATA_SIZE) return null
                ContactIntroducerData(introducedName = name, qrPayload = qr)
            } catch (_: Exception) {
                null
            }
        }
    }
}
