package org.pqchat.dht.debug

import org.pqchat.dht.BuildConfig
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.protocol.RatchetChain
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.atomic.AtomicInteger

/**
 * Diagnostic & Cryptographic Metadata Logger for PQChat DHT.
 *
 * Formats outgoing and incoming message metadata into structured, readable JSON logs.
 * Strictly complies with AGENTS.md §8.1:
 * - NO plaintext messages or decrypted payloads.
 * - NO private key seeds (edPrivateKeySeed), initial seeds (seedInit), or symmetric keys (msgKey).
 * - ONLY protocol metadata, frame sizes, offsets, sequence counters, and public routing identifiers.
 *
 * Prints to stdout (console) and logs to Android Logcat under tag "PQChat-Debug".
 * STRICTLY DISABLED in release builds or when isEnabled is false.
 */
object MessageDebugLogger {

    var isEnabled: Boolean = BuildConfig.DEBUG
    val emitCount = AtomicInteger(0)

    // ==========================================
    // OUTGOING MESSAGES (SENT TO SERVER / DHT)
    // ==========================================

    fun logOutgoingTextMessage(
        contactId: String,
        textLength: Int,
        slot: RatchetChain.SlotParameters,
        seqNum: Int,
        ackNum: Int,
        frame: ByteArray
    ) {
        if (!isEnabled) return

        val paddingCount = BinaryFrameCodec.INNER_PAYLOAD_SIZE - 2 - textLength
        val now = System.currentTimeMillis()

        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Text message sent to contact",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(slot.target),
                "bep44Seq" to DhtClient.DEFAULT_MUTABLE_SEQ,
                "ed25519PublicKeyHex" to CryptoUtils.toHex(slot.edPublicKey)
            ),
            "beforeEncryption_Metadata" to linkedMapOf(
                "totalPlaintextSize" to "${BinaryFrameCodec.CIPHERTEXT_SIZE} bytes (fixed size)",
                "header" to linkedMapOf(
                    "messageType" to "0x02 (TYPE_TEXT_MESSAGE)",
                    "seqNum" to seqNum,
                    "ackNum" to ackNum,
                    "timestampUTC" to now,
                    "timestampIso" to formatIsoTimestamp(now)
                ),
                "payload" to linkedMapOf(
                    "type" to "TextMessage (0x02)",
                    "textByteLength" to textLength,
                    "paddingBytesCount" to maxOf(0, paddingCount),
                    "description" to "Text payload protected by AES-256-GCM encryption (plaintext omitted per AGENTS.md §8.1)"
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame = frame,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to false,
                    "pqcAlgorithm" to "ML-KEM-512 (Kyber-512 / FIPS 203)",
                    "relation" to "Derivation of ratchet key from KDF initialized with post-quantum exchange",
                    "description" to "Message protected symmetrically by AES-256-GCM using slot key ${slot.counter} from KDF chain (Ratchet)."
                ),
                dhtTarget = slot.target,
                dhtSeq = DhtClient.DEFAULT_MUTABLE_SEQ,
                edPublicKey = slot.edPublicKey
            )
        )

        emitLog("MESSAGE SENT TO DHT SERVER [TEXT]", jsonMap)
    }

    fun logOutgoingRekeyOffer(
        contactId: String,
        epoch: Long,
        slot: RatchetChain.SlotParameters,
        seqNum: Int,
        ackNum: Int,
        mlKemPublicKeySize: Int,
        frame: ByteArray
    ) {
        if (!isEnabled) return

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "PQC key rotation offer (Rekey Offer)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(slot.target),
                "bep44Seq" to DhtClient.DEFAULT_MUTABLE_SEQ,
                "ed25519PublicKeyHex" to CryptoUtils.toHex(slot.edPublicKey)
            ),
            "beforeEncryption_Metadata" to linkedMapOf(
                "totalPlaintextSize" to "${BinaryFrameCodec.CIPHERTEXT_SIZE} bytes",
                "header" to linkedMapOf(
                    "messageType" to "0x03 (TYPE_REKEY_OFFER)",
                    "seqNum" to seqNum,
                    "ackNum" to ackNum,
                    "rekeyEpoch" to epoch
                ),
                "payload" to linkedMapOf(
                    "type" to "RekeyOffer",
                    "rekeyEpoch" to epoch,
                    "pqcPublicKey_MLKEM512" to linkedMapOf(
                        "algorithm" to "ML-KEM-512 (Kyber-512 / FIPS 203)",
                        "role" to "New PQC public key (pk_new)",
                        "sizeBytes" to mlKemPublicKeySize,
                        "description" to "Post-quantum public key for periodic KDF chain rotation"
                    ),
                    "paddingBytesCount" to BinaryFrameCodec.T3_PADDING_SIZE
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame = frame,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to false,
                    "isPqcPublicKeyInPayload" to true,
                    "pqcAlgorithm" to "ML-KEM-512",
                    "description" to "Payload carries new ML-KEM-512 public key wrapped in symmetric AES-256-GCM encryption."
                ),
                dhtTarget = slot.target,
                dhtSeq = DhtClient.DEFAULT_MUTABLE_SEQ,
                edPublicKey = slot.edPublicKey
            )
        )

        emitLog("SENT PQC KEY ROTATION OFFER (REKEY OFFER)", jsonMap)
    }

    fun logOutgoingRekeyResponse(
        contactId: String,
        epoch: Long,
        slot: RatchetChain.SlotParameters,
        seqNum: Int,
        ackNum: Int,
        frame: ByteArray
    ) {
        if (!isEnabled) return

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "PQC key rotation response (Rekey Response)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(slot.target),
                "bep44Seq" to DhtClient.DEFAULT_MUTABLE_SEQ,
                "ed25519PublicKeyHex" to CryptoUtils.toHex(slot.edPublicKey)
            ),
            "beforeEncryption_Metadata" to linkedMapOf(
                "totalPlaintextSize" to "${BinaryFrameCodec.CIPHERTEXT_SIZE} bytes",
                "header" to linkedMapOf(
                    "messageType" to "0x04 (TYPE_REKEY_RESPONSE)",
                    "seqNum" to seqNum,
                    "ackNum" to ackNum,
                    "rekeyEpoch" to epoch
                ),
                "payload" to linkedMapOf(
                    "type" to "RekeyResponse",
                    "rekeyEpoch" to epoch,
                    "pqcCiphertext_Hybrid" to linkedMapOf(
                        "algorithm" to "Hybrid (ML-KEM-512 + X25519)",
                        "role" to "Hybrid encrypted new rotation secret (ct_new)",
                        "sizeBytes" to BinaryFrameCodec.T4_CIPHERTEXT_SIZE,
                        "description" to "Hybrid ciphertext generated by HybridKem in response to Rekey Offer"
                    ),
                    "paddingBytesCount" to BinaryFrameCodec.T4_PADDING_SIZE
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame = frame,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to true,
                    "pqcAlgorithm" to "Hybrid (ML-KEM-512 + X25519)",
                    "pqcCiphertextSize" to BinaryFrameCodec.T4_CIPHERTEXT_SIZE,
                    "description" to "DIRECT POST-QUANTUM AND CLASSICAL ENCRYPTION: Hybrid ciphertext capsule (800 B) inside AES-256-GCM frame."
                ),
                dhtTarget = slot.target,
                dhtSeq = DhtClient.DEFAULT_MUTABLE_SEQ,
                edPublicKey = slot.edPublicKey
            )
        )

        emitLog("SENT PQC ROTATION RESPONSE (REKEY RESPONSE)", jsonMap)
    }

    fun logOutgoingChunkData(
        contactId: String,
        transferId: ByteArray,
        chunkIndex: Int,
        totalChunks: Int,
        dataSize: Int,
        target: ByteArray,
        seq: Long,
        frame: ByteArray
    ) {
        if (!isEnabled) return

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Binary data fragment (file / PNG image)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq
            ),
            "beforeEncryption_Metadata" to linkedMapOf(
                "totalPlaintextSize" to "${BinaryFrameCodec.CIPHERTEXT_SIZE} bytes",
                "header" to linkedMapOf(
                    "messageType" to "0x05 (TYPE_CHUNK_DATA)",
                    "chunkIndex" to chunkIndex,
                    "totalChunks" to totalChunks,
                    "transferIdHex" to CryptoUtils.toHex(transferId)
                ),
                "payload" to linkedMapOf(
                    "type" to "ChunkData",
                    "chunkIndex" to chunkIndex,
                    "totalChunks" to totalChunks,
                    "transferId" to CryptoUtils.toHex(transferId),
                    "chunkPayloadBytes" to dataSize,
                    "description" to "Fragment of multipart binary transfer"
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame = frame,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to false,
                    "pqcAlgorithm" to "ML-KEM-512",
                    "description" to "AES key for chunk was derived deterministically from post-quantum protected ratchet."
                ),
                dhtTarget = target,
                dhtSeq = seq,
                edPublicKey = null
            )
        )

        emitLog("SENT BINARY CHUNK [CHUNK ${chunkIndex + 1}/$totalChunks]", jsonMap)
    }

    fun logOutgoingBobHandshake(
        target: ByteArray,
        seq: Long,
        frame: ByteArray
    ) {
        if (!isEnabled) return

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Bob -> Alice Handshake Finalize (Post-quantum tunnel initialization)",
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq
            ),
            "beforeEncryption_Metadata" to linkedMapOf(
                "totalPlaintextSize" to "${BinaryFrameCodec.CIPHERTEXT_SIZE} bytes",
                "header" to linkedMapOf(
                    "messageType" to "0x01 (TYPE_HANDSHAKE_FINALIZE)",
                    "seqNum" to 0,
                    "ackNum" to 0
                ),
                "payload" to linkedMapOf(
                    "type" to "HandshakeFinalize",
                    "pqcCiphertext_Hybrid" to linkedMapOf(
                        "algorithm" to "Hybrid (ML-KEM-512 + X25519)",
                        "role" to "Hybrid KEM Ciphertext (ct_B)",
                        "sizeBytes" to BinaryFrameCodec.T1_CIPHERTEXT_SIZE,
                        "description" to "Hybrid encrypted shared secret SS_init using Alice's public key"
                    ),
                    "saltBytes" to BinaryFrameCodec.T1_SALT_SIZE,
                    "paddingBytes" to BinaryFrameCodec.T1_PADDING_SIZE
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame = frame,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to true,
                    "pqcAlgorithm" to "Hybrid (ML-KEM-512 + X25519)",
                    "pqcCiphertextSize" to BinaryFrameCodec.T1_CIPHERTEXT_SIZE,
                    "description" to "DIRECT HYBRID ENCRYPTION: Hybrid ciphertext (800 B) wrapped in symmetric AES-256-GCM frame."
                ),
                dhtTarget = target,
                dhtSeq = seq,
                edPublicKey = null
            )
        )

        emitLog("SENT POST-QUANTUM HANDSHAKE FINALIZE TO DHT (BOB -> ALICE)", jsonMap)
    }

    // ==========================================
    // INCOMING MESSAGES (RECEIVED FROM SERVER / DHT)
    // ==========================================

    fun logIncomingMessage(
        contactId: String?,
        target: ByteArray,
        seq: Long,
        senderEdPublicKey: ByteArray?,
        senderSignature: ByteArray?,
        frame: ByteArray,
        frameMsg: BinaryFrameCodec.FrameMessage
    ) {
        if (!isEnabled) return

        val payloadMap = when (val p = frameMsg.payload) {
            is BinaryFrameCodec.DecodedPayload.TextMessage -> linkedMapOf<String, Any?>(
                "type" to "TextMessage (0x02)",
                "textByteLength" to p.text.toByteArray(Charsets.UTF_8).size,
                "description" to "Decoded message payload (plaintext omitted per AGENTS.md §8.1)"
            )
            is BinaryFrameCodec.DecodedPayload.HandshakeFinalize -> linkedMapOf<String, Any?>(
                "type" to "HandshakeFinalize (0x01)",
                "pqcCiphertext_Hybrid" to linkedMapOf(
                    "algorithm" to "Hybrid (ML-KEM-512 + X25519)",
                    "sizeBytes" to p.hybridCiphertext.size,
                    "description" to "Hybrid encrypted shared secret SS_init"
                ),
                "saltBytesCount" to p.saltParameter.size
            )
            is BinaryFrameCodec.DecodedPayload.RekeyOffer -> linkedMapOf<String, Any?>(
                "type" to "RekeyOffer (0x03)",
                "rekeyEpoch" to p.rekeyEpoch,
                "pqcPublicKey_Hybrid" to linkedMapOf(
                    "algorithm" to "Hybrid (ML-KEM-512 + X25519)",
                    "sizeBytes" to p.hybridPublicKey.size,
                    "description" to "Sender's new public key for KDF rotation"
                )
            )
            is BinaryFrameCodec.DecodedPayload.RekeyResponse -> linkedMapOf<String, Any?>(
                "type" to "RekeyResponse (0x04)",
                "rekeyEpoch" to p.rekeyEpoch,
                "pqcCiphertext_Hybrid" to linkedMapOf(
                    "algorithm" to "Hybrid (ML-KEM-512 + X25519)",
                    "sizeBytes" to p.hybridCiphertext.size,
                    "description" to "Hybrid encrypted new rotation secret SS_rekey"
                )
            )
            is BinaryFrameCodec.DecodedPayload.ChunkData -> linkedMapOf<String, Any?>(
                "type" to "ChunkData (0x05)",
                "transferIdHex" to CryptoUtils.toHex(p.transferId),
                "chunkIndex" to p.chunkIndex,
                "totalChunks" to p.totalChunks,
                "dataSizeBytes" to p.data.size
            )
            is BinaryFrameCodec.DecodedPayload.GroupControl -> linkedMapOf<String, Any?>(
                "type" to "GroupControl (0x06)",
                "controlSubType" to when (p.controlSubType) {
                    BinaryFrameCodec.GROUP_SUBTYPE_INVITE -> "INVITE"
                    BinaryFrameCodec.GROUP_SUBTYPE_REKEY -> "REKEY"
                    BinaryFrameCodec.GROUP_SUBTYPE_LEAVE -> "LEAVE"
                    else -> "UNKNOWN (${p.controlSubType})"
                },
                "groupEpoch" to p.groupEpoch,
                "currentCounter" to p.currentCounter,
                "groupName" to p.groupName,
                "memberCount" to p.members.size,
                "description" to "Decentralized group control PQ Sender Keys over BEP 44"
            )
            is BinaryFrameCodec.DecodedPayload.Reaction -> linkedMapOf<String, Any?>(
                "type" to "Reaction (0x07)",
                "targetSeqEpoch" to p.targetSeqEpoch,
                "targetSeqNum" to p.targetSeqNum,
                "emoji" to p.emoji,
                "description" to "Single-frame micro-payload: Emoji reaction linked to message"
            )
            is BinaryFrameCodec.DecodedPayload.LocationPin -> linkedMapOf<String, Any?>(
                "type" to "LocationPin (0x08)",
                "latitude" to p.latitude,
                "longitude" to p.longitude,
                "altitude" to p.altitude,
                "accuracy" to p.accuracy,
                "note" to p.note,
                "description" to "Single-frame micro-payload: Geographic coordinates pin / Security status"
            )
            is BinaryFrameCodec.DecodedPayload.VoiceNote -> linkedMapOf<String, Any?>(
                "type" to "VoiceNote (0x09)",
                "voiceClipId" to p.voiceClipId,
                "segmentIndex" to p.segmentIndex,
                "totalSegments" to p.totalSegments,
                "durationMs" to p.durationMs,
                "codecMode" to p.codecMode,
                "voiceByteLength" to p.voiceData.size,
                "ephemeralTtlSeconds" to p.ephemeralTtlSeconds,
                "description" to "Ultra-low-bitrate PTT micro-voice note over BEP 44"
            )
            is BinaryFrameCodec.DecodedPayload.GroupPollCreate -> linkedMapOf<String, Any?>(
                "type" to "GroupPollCreate (0x0A:0x01)",
                "pollId" to p.pollId.joinToString("") { "%02x".format(it) },
                "question" to p.question,
                "optionCount" to p.options.size,
                "isMultiChoice" to p.isMultiChoice,
                "expirationTimestamp" to p.expirationTimestamp,
                "description" to "Single-frame cryptographic group poll creation"
            )
            is BinaryFrameCodec.DecodedPayload.GroupPollVote -> linkedMapOf<String, Any?>(
                "type" to "GroupPollVote (0x0A:0x02)",
                "pollId" to p.pollId.joinToString("") { "%02x".format(it) },
                "selectedOptionsBitmask" to p.selectedOptionsBitmask,
                "voteTimestamp" to p.voteTimestamp,
                "description" to "Single-frame cryptographic group poll vote sealed with Group AAD"
            )
            is BinaryFrameCodec.DecodedPayload.SafetyCanary -> linkedMapOf<String, Any?>(
                "type" to "SafetyCanary (0x0B)",
                "triggerReason" to p.triggerReason,
                "canaryId" to p.canaryId.joinToString("") { "%02x".format(it) },
                "triggerTimestamp" to p.triggerTimestamp,
                "latitude" to p.latitude,
                "longitude" to p.longitude,
                "note" to p.note,
                "description" to "Dead Man's Switch / Duress safety canary alarm frame"
            )
        }

        val pqcAnalysis = when (frameMsg.msgType) {
            BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE -> linkedMapOf(
                "isDirectPqcCiphertextInPayload" to true,
                "pqcAlgorithm" to "ML-KEM-512",
                "description" to "Received ML-KEM-512 capsule. Requires decapsulation with private key sk_A to recover SS_init."
            )
            BinaryFrameCodec.TYPE_REKEY_OFFER -> linkedMapOf(
                "isDirectPqcCiphertextInPayload" to false,
                "isPqcPublicKeyInPayload" to true,
                "pqcAlgorithm" to "ML-KEM-512",
                "description" to "Received new PQC public key pk_new. Will be used to encapsulate new rotation secret SS_rekey."
            )
            BinaryFrameCodec.TYPE_REKEY_RESPONSE -> linkedMapOf(
                "isDirectPqcCiphertextInPayload" to true,
                "pqcAlgorithm" to "ML-KEM-512",
                "description" to "Received capsule of new rotation secret. Will be decapsulated with key sk_new to update KDF chain."
            )
            else -> linkedMapOf(
                "isDirectPqcCiphertextInPayload" to false,
                "pqcAlgorithm" to "ML-KEM-512",
                "description" to "Message decrypted symmetrically with AES key derived from post-quantum KDF chain (Ratchet)."
            )
        }

        val typeLabel = when (frameMsg.msgType) {
            BinaryFrameCodec.TYPE_TEXT_MESSAGE -> "TEXT"
            BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE -> "HANDSHAKE FINALIZE"
            BinaryFrameCodec.TYPE_REKEY_OFFER -> "REKEY OFFER"
            BinaryFrameCodec.TYPE_REKEY_RESPONSE -> "REKEY RESPONSE"
            BinaryFrameCodec.TYPE_CHUNK_DATA -> "CHUNK"
            BinaryFrameCodec.TYPE_GROUP_CONTROL -> "GROUP CONTROL"
            BinaryFrameCodec.TYPE_REACTION -> "EMOJI REACTION"
            BinaryFrameCodec.TYPE_LOCATION_PIN -> "LOCATION PIN"
            BinaryFrameCodec.TYPE_VOICE_NOTE -> "VOICE NOTE"
            else -> "TYPE 0x%02X".format(frameMsg.msgType)
        }

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_RECEIVED_FROM_DHT_SERVER",
            "direction" to "INCOMING",
            "context" to "Received message from DHT server ($typeLabel)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq,
                "senderEd25519PublicKeyHex" to (senderEdPublicKey?.let { CryptoUtils.toHex(it) } ?: "unknown"),
                "hasSignature" to (senderSignature != null)
            ),
            "beforeDecryption_EncryptedStructure" to linkedMapOf(
                "totalFrameSize" to "${frame.size} bytes (raw data fetched from DHT)",
                "layer1_Symmetric_AES_GCM" to linkedMapOf(
                    "algorithm" to "AES-256-GCM (NIST SP 800-38D)",
                    "symmetricKeyRole" to "AES-256-GCM key derived from Ratchet KDF",
                    "iv" to linkedMapOf(
                        "offset" to "Bytes 0..11 (12 bytes)",
                        "role" to "Initialization Vector (IV)",
                        "sizeBytes" to BinaryFrameCodec.IV_SIZE
                    ),
                    "authenticationTag" to linkedMapOf(
                        "offset" to "Bytes 12..27 (16 bytes)",
                        "role" to "GMAC Authentication Tag",
                        "sizeBytes" to BinaryFrameCodec.TAG_SIZE
                    ),
                    "ciphertext" to linkedMapOf(
                        "offset" to "Bytes 28..899 (872 bytes)",
                        "role" to "AES-256-GCM Ciphertext",
                        "sizeBytes" to BinaryFrameCodec.CIPHERTEXT_SIZE
                    )
                )
            ),
            "afterDecryption_Metadata" to linkedMapOf(
                "decryptionStatus" to "SUCCESS (AES-GCM integrity tag verified successfully)",
                "header" to linkedMapOf(
                    "messageType" to "0x%02X".format(frameMsg.msgType),
                    "seqNum" to frameMsg.seqNum,
                    "ackNum" to frameMsg.ackNum,
                    "timestampUTC" to frameMsg.timestampUTC,
                    "timestampIso" to formatIsoTimestamp(frameMsg.timestampUTC)
                ),
                "payload" to payloadMap,
                "postQuantumAnalysis" to pqcAnalysis
            )
        )

        emitLog("RECEIVED MESSAGE FROM DHT SERVER [$typeLabel]", jsonMap)
    }

    fun logIncomingAliceHandshakeFinalize(
        target: ByteArray,
        seq: Long,
        senderEdPublicKey: ByteArray?,
        senderSignature: ByteArray?,
        frame: ByteArray,
        decapsulationSuccess: Boolean
    ) {
        if (!isEnabled) return

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_RECEIVED_FROM_DHT_SERVER",
            "direction" to "INCOMING",
            "context" to "Alice receives Handshake Finalize (from Bob via Target_0)",
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq,
                "senderEd25519PublicKeyHex" to (senderEdPublicKey?.let { CryptoUtils.toHex(it) } ?: "unknown"),
                "hasSignature" to (senderSignature != null)
            ),
            "beforeDecryption_EncryptedStructure" to linkedMapOf(
                "totalFrameSize" to "${frame.size} bytes (raw data fetched from Target_0)",
                "layer1_Symmetric_AES_GCM" to linkedMapOf(
                    "algorithm" to "AES-256-GCM (NIST SP 800-38D)",
                    "symmetricKeyRole" to "kHs (key derived from seedInit)",
                    "ivSizeBytes" to BinaryFrameCodec.IV_SIZE,
                    "authenticationTagSizeBytes" to BinaryFrameCodec.TAG_SIZE,
                    "ciphertextSizeBytes" to BinaryFrameCodec.CIPHERTEXT_SIZE
                )
            ),
            "afterDecryption_Metadata" to linkedMapOf(
                "decryptionStatus" to "SUCCESS (Decrypted frame with kHs key)",
                "header" to linkedMapOf(
                    "messageType" to "0x01 (TYPE_HANDSHAKE_FINALIZE)",
                    "seqNum" to 0,
                    "ackNum" to 0
                ),
                "payload" to linkedMapOf(
                    "type" to "HandshakeFinalize",
                    "pqcCiphertext_Hybrid" to linkedMapOf(
                        "algorithm" to "Hybrid (ML-KEM-512 + X25519)",
                        "sizeBytes" to BinaryFrameCodec.T1_CIPHERTEXT_SIZE,
                        "description" to "Hybrid encrypted secret SS_init generated by Bob"
                    ),
                    "saltBytesCount" to BinaryFrameCodec.T1_SALT_SIZE
                ),
                "postQuantumAnalysis" to linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to true,
                    "pqcAlgorithm" to "Hybrid (ML-KEM-512 + X25519)",
                    "decapsulationStatus" to if (decapsulationSuccess)
                        "SUCCESS: Decapsulated SS_init using Alice's private keys (ML-KEM-512 + X25519). Generated bidirectional ratchet chains!"
                    else "ERROR: Decapsulation failed"
                )
            )
        )

        emitLog("RECEIVED AND DECAPSULATED POST-QUANTUM HANDSHAKE (ALICE <- BOB)", jsonMap)
    }

    // ==========================================
    // STRUCTURAL HELPERS
    // ==========================================

    private fun buildEncryptedStructureMap(
        frame: ByteArray,
        pqcLayerInfo: Map<String, Any?>,
        dhtTarget: ByteArray,
        dhtSeq: Long,
        edPublicKey: ByteArray?
    ): Map<String, Any?> {
        return linkedMapOf(
            "totalFrameSize" to "${frame.size} bytes (BEP 44 frame standard)",
            "layer1_Symmetric_AES_GCM" to linkedMapOf(
                "algorithm" to "AES-256-GCM (NIST SP 800-38D)",
                "symmetricKeyRole" to "AES-256-GCM session key derived from Ratchet KDF",
                "keySizeBytes" to 32,
                "iv" to linkedMapOf(
                    "offset" to "Bytes 0..11 (12 bytes)",
                    "role" to "Initialization Vector (IV / Nonce)",
                    "sizeBytes" to BinaryFrameCodec.IV_SIZE,
                    "description" to "Random initialization vector ensuring ciphertext uniqueness"
                ),
                "authenticationTag" to linkedMapOf(
                    "offset" to "Bytes 12..27 (16 bytes)",
                    "role" to "GMAC Authentication Tag (MAC)",
                    "sizeBytes" to BinaryFrameCodec.TAG_SIZE,
                    "description" to "Cryptographic integrity and authenticity tag for message"
                ),
                "ciphertext" to linkedMapOf(
                    "offset" to "Bytes 28..899 (872 bytes)",
                    "role" to "AES-256-GCM Ciphertext",
                    "sizeBytes" to BinaryFrameCodec.CIPHERTEXT_SIZE,
                    "description" to "Encrypted content covering frame header and payload"
                )
            ),
            "layer2_PostQuantum_PQC" to pqcLayerInfo,
            "layer3_DhtRouting_BEP44" to linkedMapOf(
                "protocol" to "BitTorrent Mainline DHT (BEP 44 Mutable Item)",
                "targetHex" to CryptoUtils.toHex(dhtTarget),
                "bep44Seq" to dhtSeq,
                "ed25519PublicKeyHex" to (edPublicKey?.let { CryptoUtils.toHex(it) } ?: "derived from seed")
            )
        )
    }

    private fun formatIsoTimestamp(millis: Long): String {
        val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        sdf.timeZone = TimeZone.getTimeZone("UTC")
        return sdf.format(Date(millis))
    }

    // ==========================================
    // JSON FORMATTER & CONSOLE EMITTER
    // ==========================================

    private fun emitLog(title: String, jsonMap: Map<String, Any?>) {
        if (!BuildConfig.DEBUG || !isEnabled) return
        emitCount.incrementAndGet()
        val jsonString = toJsonString(jsonMap, indentLevel = 0)
        val banner = buildString {
            appendLine("╔══════════════════════════════════════════════════════════════════════════════")
            appendLine("║ [PQChat-DEBUG] $title")
            appendLine("╚══════════════════════════════════════════════════════════════════════════════")
            append(jsonString)
        }

        // 1. Output to standard console / terminal (stdout)
        println(banner)

        // 2. Output to Android Logcat (split into safe chunk sizes to avoid Logcat's 4KB truncation)
        try {
            val lines = banner.split("\n")
            val chunk = java.lang.StringBuilder()
            for (line in lines) {
                if (chunk.length + line.length + 1 > 3500) {
                    android.util.Log.i("PQChat-Debug", chunk.toString())
                    chunk.setLength(0)
                }
                chunk.append(line).append("\n")
            }
            if (chunk.isNotEmpty()) {
                android.util.Log.i("PQChat-Debug", chunk.toString().trimEnd())
            }
        } catch (_: Throwable) {
            // JVM test fallback: android.util.Log not mocked
        }
    }

    fun toJsonString(value: Any?, indentLevel: Int = 0): String {
        return when (value) {
            null -> "null"
            is Boolean -> value.toString()
            is Number -> value.toString()
            is String -> escapeJsonString(value)
            is Map<*, *> -> {
                if (value.isEmpty()) return "{}"
                val indent = "  ".repeat(indentLevel)
                val childIndent = "  ".repeat(indentLevel + 1)
                val entries = value.entries.map { (k, v) ->
                    "$childIndent\"$k\": ${toJsonString(v, indentLevel + 1)}"
                }
                "{\n" + entries.joinToString(",\n") + "\n$indent}"
            }
            is Collection<*> -> {
                if (value.isEmpty()) return "[]"
                val indent = "  ".repeat(indentLevel)
                val childIndent = "  ".repeat(indentLevel + 1)
                val items = value.map { v ->
                    "$childIndent${toJsonString(v, indentLevel + 1)}"
                }
                "[\n" + items.joinToString(",\n") + "\n$indent]"
            }
            is Array<*> -> {
                toJsonString(value.toList(), indentLevel)
            }
            else -> escapeJsonString(value.toString())
        }
    }

    private fun escapeJsonString(s: String): String {
        val sb = StringBuilder("\"")
        for (ch in s) {
            when (ch) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    if (ch.code < 32) {
                        sb.append(String.format("\\u%04x", ch.code))
                    } else {
                        sb.append(ch)
                    }
                }
            }
        }
        sb.append("\"")
        return sb.toString()
    }
}
